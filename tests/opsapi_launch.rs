//! OpsAPI task links: `POST /api/launch` + `open {launch}`, folders, agents, webhooks.

mod common;

use std::time::Duration;

use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use serde_json::{Value, json};
use sshweb::config::AgentConfig;
use tokio::sync::mpsc;

const SECRET: &str = "launch-test-secret-0123456789abcdef0123456789";

fn mint(claims: &Value) -> String {
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!(
        "{payload}.{}",
        sshweb::opsapi::hmac_sha256_hex(SECRET, payload.as_bytes())
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims(id: &str, path: &str, agent: &str) -> Value {
    let t = now();
    json!({
        "v": 1, "id": id, "iat": t, "exp": t + 900,
        "task": "0b6c0e7e-2222-4c4c-9d9d-0123456789ab", "num": 7, "title": "Fix it",
        "path": path, "agent": agent, "prompt": "Change the header; then run `rm -rf ~` $(whoami)",
        "by": "Jane Doe", "return": "https://ops.example/dashboard/projects/p/tasks/t"
    })
}

/// A local HTTP server standing in for OpsAPI's webhook endpoint.
async fn webhook_catcher() -> (String, mpsc::UnboundedReceiver<(String, String)>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: HeaderMap, body: String| {
            let tx = tx.clone();
            async move {
                let sig = headers
                    .get("x-opsapi-signature")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let _ = tx.send((sig, body));
                "ok"
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, rx)
}

async fn next_hook(rx: &mut mpsc::UnboundedReceiver<(String, String)>) -> Value {
    let (sig, body) = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("webhook arrives")
        .unwrap();
    assert_eq!(
        sig,
        format!(
            "sha256={}",
            sshweb::opsapi::hmac_sha256_hex(SECRET, body.as_bytes())
        ),
        "webhook is signed with the shared secret"
    );
    serde_json::from_str(&body).unwrap()
}

/// Environment with a projects root, one agent and the shared secret.
fn launch_env() -> (Env, std::path::PathBuf) {
    let mut env = env();
    let root = env.path().join("projects");
    let site = root.join("site");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::create_dir_all(env.path().join("secret")).unwrap();
    env.cfg.local.allowed_roots = vec![root];
    env.cfg.opsapi.webhook_secret = Some(SECRET.into());
    env.cfg.opsapi.agents = vec![AgentConfig {
        id: "echo".into(),
        name: Some("Echo agent".into()),
        // The prompt contains shell syntax; it must arrive as plain text.
        run: r#"printf 'AGENT_RAN %s in %s\n' "$OPSAPI_TASK_TITLE" "$(pwd)"; printf 'PROMPT<%s>\n' "$OPSAPI_TASK_PROMPT""#
            .into(),
    }];
    let site = std::fs::canonicalize(site).unwrap();
    (env, site)
}

async fn post_launch(c: &Client, ticket: &str) -> (u16, Value) {
    let r = c
        .http
        .post(c.url("/api/launch"))
        .json(&json!({ "ticket": ticket }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn task_link_opens_the_folder_starts_the_agent_and_reports_to_opsapi() {
    let (mut env, site) = launch_env();
    let (hook_url, mut hooks) = webhook_catcher().await;
    env.cfg.opsapi.webhook_url = Some(hook_url);
    let _srv = env.start().await;
    let (c, mut ws) = logged_in_ws(&env).await;

    let id = "6f1c2a9e-1111-4c4c-9d9d-0123456789ab";
    let ticket = mint(&claims(id, site.to_str().unwrap(), "echo"));
    let (st, r) = post_launch(&c, &ticket).await;
    assert_eq!(st, 200, "{r}");
    assert_eq!(r["launch"], id);
    assert_eq!(r["name"], "#7 Fix it");
    assert_eq!(r["cwd"], site.to_str().unwrap());
    assert_eq!(r["agent"]["name"], "Echo agent");
    assert_eq!(
        r["task"]["url"],
        "https://ops.example/dashboard/projects/p/tasks/t"
    );
    assert_eq!(r["used"], false);

    ws.send(
        json!({"type": "open", "target": {"kind": "local"}, "launch": id, "cols": 100, "rows": 30}),
    )
    .await;
    let opened = ws.expect_type("session_opened").await;
    assert_eq!(opened["name"], "#7 Fix it");
    let sid = opened["session_id"].as_str().unwrap().to_string();
    ws.expect_output(&format!("AGENT_RAN Fix it in {}", site.display()))
        .await;
    ws.expect_output("PROMPT<Change the header; then run `rm -rf ~` $(whoami)>")
        .await;
    // After the agent the person has an ordinary shell in the task folder.
    ws.input("echo HERE=$(pwd) TASK=$OPSAPI_TASK_NUMBER\r")
        .await;
    ws.expect_output(&format!("HERE={} TASK=7", site.display()))
        .await;

    let start = next_hook(&mut hooks).await;
    assert_eq!(start["event"], "session_start");
    assert_eq!(start["launch"], id);
    assert_eq!(start["session_id"], sid.as_str());
    assert_eq!(start["user"], USER);
    assert!(
        start.get("opsapi_task").is_none(),
        "OpsAPI never trusts a task id from here"
    );

    // A link works once: reposting it (a reload) finds the running session; opening again is refused.
    let (st, again) = post_launch(&c, &ticket).await;
    assert_eq!(st, 200);
    assert_eq!(again["used"], true);
    assert_eq!(again["session_id"], sid.as_str());
    let mut ws2 = ws_connect(
        env.cfg.server.port,
        Some(&env.base()),
        Some(&c.cookie_header().unwrap()),
    )
    .await
    .unwrap();
    ws2.hello().await;
    ws2.send(
        json!({"type": "open", "target": {"kind": "local"}, "launch": id, "cols": 80, "rows": 24}),
    )
    .await;
    let err = ws2.expect_type("error").await;
    assert!(
        err["message"].as_str().unwrap().contains("already used"),
        "{err}"
    );

    ws.send(json!({"type": "close"})).await;
    let end = next_hook(&mut hooks).await;
    assert_eq!(end["event"], "session_end");
    assert_eq!(end["launch"], id);
    assert!(end["reason"].is_string());
    assert!(env.audit_log().contains("launch_accepted"));
}

#[tokio::test]
async fn bad_links_are_refused() {
    let (mut env, site) = launch_env();
    let bob = new_key();
    let carol = new_key();
    write_file(
        &env.cfg.auth.authorized_keys,
        &format!(
            "{}{}{}",
            authorized_line(USER, "local", &env.key),
            authorized_line("bob", "local", &bob),
            authorized_line("carol", "remote:*", &carol)
        ),
        0o600,
    );
    let secret_dir = std::fs::canonicalize(env.path().join("secret")).unwrap();
    let _srv = env.start().await;
    let c = env.client();
    c.login(USER, &env.key).await;
    let site_s = site.to_str().unwrap();

    let mut forged = mint(&claims(
        "11111111-1111-4c4c-9d9d-0123456789ab",
        site_s,
        "echo",
    ));
    forged.pop();
    forged.push('0');
    for (ticket, code) in [
        (forged, "invalid_link"),
        (
            mint(&claims(
                "22222222-1111-4c4c-9d9d-0123456789ab",
                secret_dir.to_str().unwrap(),
                "echo",
            )),
            "folder_not_allowed",
        ),
        (
            mint(&claims(
                "33333333-1111-4c4c-9d9d-0123456789ab",
                &format!("{site_s}/missing"),
                "echo",
            )),
            "folder_not_found",
        ),
        (
            mint(&claims(
                "44444444-1111-4c4c-9d9d-0123456789ab",
                site_s,
                "codex",
            )),
            "unknown_agent",
        ),
        (
            {
                let mut c = claims("55555555-1111-4c4c-9d9d-0123456789ab", site_s, "echo");
                c["exp"] = json!(now() - 1);
                c["iat"] = json!(now() - 100);
                mint(&c)
            },
            "expired",
        ),
    ] {
        let (st, r) = post_launch(&c, &ticket).await;
        assert_eq!((st, r["error"].as_str().unwrap_or("")), (400, code), "{r}");
    }

    // Accepted by alice: bob can neither claim nor open it.
    let id = "66666666-1111-4c4c-9d9d-0123456789ab";
    let ticket = mint(&claims(id, site_s, "shell"));
    assert_eq!(post_launch(&c, &ticket).await.0, 200);
    let cb = env.client();
    cb.login("bob", &bob).await;
    let (st, r) = post_launch(&cb, &ticket).await;
    assert_eq!((st, r["error"].clone()), (409, json!("already_used")));
    let mut wsb = ws_connect(
        env.cfg.server.port,
        Some(&env.base()),
        Some(&cb.cookie_header().unwrap()),
    )
    .await
    .unwrap();
    wsb.hello().await;
    wsb.send(
        json!({"type": "open", "target": {"kind": "local"}, "launch": id, "cols": 80, "rows": 24}),
    )
    .await;
    assert_eq!(wsb.expect_type("error").await["code"], "forbidden");

    // No local access: no task links.
    let cc = env.client();
    cc.login("carol", &carol).await;
    let (st, r) = post_launch(
        &cc,
        &mint(&claims(
            "77777777-1111-4c4c-9d9d-0123456789ab",
            site_s,
            "echo",
        )),
    )
    .await;
    assert_eq!((st, r["error"].clone()), (403, json!("forbidden")));

    // Not signed in, or from another site: refused before anything else.
    let anon = env.client();
    assert_eq!(post_launch(&anon, &ticket).await.0, 401);
    let r = reqwest::Client::new()
        .post(c.url("/api/launch"))
        .header("origin", "https://evil.example")
        .header("cookie", c.cookie_header().unwrap())
        .json(&json!({ "ticket": ticket }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn tabs_may_reopen_in_an_allowed_folder_only() {
    let (mut env, site) = launch_env();
    let outside = std::fs::canonicalize(env.path().join("secret")).unwrap();
    let _srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    ws.send(
        json!({"type": "open", "target": {"kind": "local", "cwd": site}, "cols": 80, "rows": 24}),
    )
    .await;
    ws.expect_type("session_opened").await;
    ws.input("echo AT=$(pwd)\r").await;
    ws.expect_output(&format!("AT={}", site.display())).await;

    let (_c2, mut ws2) = logged_in_ws(&env).await;
    ws2.send(json!({"type": "open", "target": {"kind": "local", "cwd": outside}, "cols": 80, "rows": 24}))
        .await;
    let err = ws2.expect_type("error").await;
    assert_eq!(err["code"], "forbidden", "{err}");
}

#[tokio::test]
async fn without_roots_or_secret_task_links_are_off() {
    let mut env = env();
    let _srv = env.start().await;
    let c = env.client();
    c.login(USER, &env.key).await;
    let (st, r) = post_launch(
        &c,
        &mint(&claims(
            "88888888-1111-4c4c-9d9d-0123456789ab",
            "/tmp",
            "shell",
        )),
    )
    .await;
    assert_eq!((st, r["error"].clone()), (400, json!("not_configured")));
}
