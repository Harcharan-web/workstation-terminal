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
    // Change the signature's last digit (to one it isn't, or the "forgery" is the real link).
    let last = forged.pop().unwrap();
    forged.push(if last == '0' { '1' } else { '0' });
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

// ---------- auto sign-in (`POST /api/launch/login`) ----------

/// A link that asks OpsAPI's auto sign-in for `email`, with a report link and a claim this
/// terminal doesn't know.
fn login_claims(id: &str, path: &str, email: &str) -> Value {
    let mut c = claims(id, path, "report");
    let t = now();
    c["exp"] = json!(t + 120);
    c["login"] =
        json!({"email": email, "user": "9a8b7c6d-1111-4c4c-9d9d-0123456789ab", "stepup": t - 600});
    c["report"] = json!({
        "url": "https://ops.example/api/v2/ai-runner/public/terminal/report",
        "token": "rt_0123456789abcdefghijklmnopqrstuvwxyz"
    });
    c["newer_opsapi_claim"] = json!({"ignored": true});
    c
}

/// Launch environment with auto sign-in on for alice (any case) and carol (who has no local key).
fn autologin_env() -> (Env, std::path::PathBuf) {
    let (mut env, site) = launch_env();
    let carol = new_key();
    write_file(
        &env.cfg.auth.authorized_keys,
        &format!(
            "{}{}",
            authorized_line(USER, "local", &env.key),
            authorized_line("carol", "remote:*", &carol)
        ),
        0o600,
    );
    let a = &mut env.cfg.opsapi.autologin;
    a.enabled = true;
    a.users = [
        ("Alice@Example.com".to_string(), USER.to_string()),
        ("carol@example.com".to_string(), "carol".to_string()),
    ]
    .into();
    let agent = AgentConfig {
        id: "report".into(),
        name: Some("Reporter".into()),
        run: r#"printf 'REPORT<%s|%s>\n' "$OPSAPI_REPORT_URL" "$OPSAPI_REPORT_TOKEN""#.into(),
    };
    env.cfg.opsapi.agents.push(agent);
    (env, site)
}

async fn post_login(c: &Client, ticket: &str) -> (u16, Value) {
    let r = c
        .http
        .post(c.url("/api/launch/login"))
        .json(&json!({ "ticket": ticket }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn a_link_with_login_signs_in_once_and_then_opens_the_task() {
    let (mut env, site) = autologin_env();
    let _srv = env.start().await;
    let id = "aaaaaaaa-1111-4c4c-9d9d-0123456789ab";
    let ticket = mint(&login_claims(
        id,
        site.to_str().unwrap(),
        "alice@EXAMPLE.com",
    ));

    let c = env.client();
    assert_eq!(
        c.http.get(c.url("/api/me")).send().await.unwrap().status(),
        401
    );
    let (st, r) = post_login(&c, &ticket).await;
    assert_eq!(st, 200, "{r}");
    assert_eq!(r["user"], USER);
    assert_eq!(r["access"], "local");
    let me: Value = c
        .http
        .get(c.url("/api/me"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["user"], USER);

    // Then the usual launch with the same ticket, and the agent sees the report link.
    let (st, r) = post_launch(&c, &ticket).await;
    assert_eq!(st, 200, "{r}");
    assert_eq!(r["launch"], id);
    let mut ws = ws_connect(
        env.cfg.server.port,
        Some(&env.base()),
        Some(&c.cookie_header().unwrap()),
    )
    .await
    .unwrap();
    ws.hello().await;
    ws.send(
        json!({"type": "open", "target": {"kind": "local"}, "launch": id, "cols": 100, "rows": 30}),
    )
    .await;
    ws.expect_type("session_opened").await;
    ws.expect_output(
        "REPORT<https://ops.example/api/v2/ai-runner/public/terminal/report|rt_0123456789abcdefghijklmnopqrstuvwxyz>",
    )
    .await;

    // A link signs someone in once, from any browser.
    let (st, r) = post_login(&env.client(), &ticket).await;
    assert_eq!(
        (st, r["error"].clone()),
        (409, json!("already_used")),
        "{r}"
    );

    let audit = env.audit_log();
    let ok = audit
        .lines()
        .find(|l| l.contains("auth_success") && l.contains("opsapi_launch"))
        .expect("auth_success audited");
    assert!(
        ok.contains("alice@EXAMPLE.com") && ok.contains("9a8b7c6d-1111-4c4c-9d9d-0123456789ab"),
        "{ok}"
    );
    assert!(
        !audit.contains("rt_0123456789abcdef"),
        "the report token isn't logged"
    );
    assert!(
        audit
            .lines()
            .any(|l| l.contains("auth_failure") && l.contains("already_used")),
        "{audit}"
    );
}

#[tokio::test]
async fn links_that_may_not_sign_in_are_refused() {
    let (mut env, site) = autologin_env();
    env.cfg.rate_limit.max_failures = 100;
    let _srv = env.start().await;
    let site_s = site.to_str().unwrap();
    let id = |n: u32| format!("{n:08x}-2222-4c4c-9d9d-0123456789ab");
    let with = |n: u32, f: &dyn Fn(&mut Value)| {
        let mut c = login_claims(&id(n), site_s, "alice@example.com");
        f(&mut c);
        mint(&c)
    };
    let mut forged = with(1, &|_| {});
    let last = forged.pop().unwrap();
    forged.push(if last == '0' { '1' } else { '0' });
    for (ticket, status, code) in [
        (forged, 400, "invalid_link"),
        (
            with(2, &|c| c["login"]["email"] = json!("mallory@example.com")),
            403,
            "autologin_not_allowed",
        ),
        (
            with(3, &|c| c["login"]["email"] = json!("carol@example.com")),
            403,
            "autologin_not_allowed",
        ),
        (
            with(4, &|c| c["login"]["stepup"] = json!(now() - 43_300)),
            403,
            "stepup_stale",
        ),
        (
            with(5, &|c| c["login"]["stepup"] = json!(now() + 5)),
            400,
            "invalid_link",
        ),
        (
            with(6, &|c| c["exp"] = json!(now() + 600)),
            400,
            "invalid_link",
        ),
        (
            with(7, &|c| {
                c.as_object_mut().unwrap().remove("login");
            }),
            403,
            "autologin_not_allowed",
        ),
    ] {
        let c = env.client();
        let (st, r) = post_login(&c, &ticket).await;
        assert_eq!(
            (st, r["error"].as_str().unwrap_or("")),
            (status, code),
            "{r}"
        );
        assert_eq!(
            c.http.get(c.url("/api/me")).send().await.unwrap().status(),
            401,
            "{code}"
        );
    }
    // Refusals didn't lock anyone out of a good link.
    let c = env.client();
    assert_eq!(post_login(&c, &with(8, &|_| {})).await.0, 200);
    let audit = env.audit_log();
    assert!(
        audit.contains("stepup_stale") && audit.contains("mallory@example.com"),
        "{audit}"
    );

    // From another site: refused before anything else.
    let r = reqwest::Client::new()
        .post(c.url("/api/launch/login"))
        .header("origin", "https://evil.example")
        .json(&json!({ "ticket": with(9, &|_| {}) }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn auto_sign_in_is_off_by_default_and_failures_lock_out() {
    let (mut env, site) = launch_env();
    let _off = env.start().await;
    let site_s = site.to_str().unwrap();
    let ticket = mint(&login_claims(
        "bbbbbbbb-1111-4c4c-9d9d-0123456789ab",
        site_s,
        "alice@example.com",
    ));
    let (st, r) = post_login(&env.client(), &ticket).await;
    assert_eq!(
        (st, r["error"].clone()),
        (403, json!("autologin_off")),
        "{r}"
    );

    // Bad signatures count towards the same lock-out as SSH sign-in.
    let (mut env, site) = autologin_env();
    let _srv = env.start().await;
    let site_s = site.to_str().unwrap();
    let good = mint(&login_claims(
        "cccccccc-1111-4c4c-9d9d-0123456789ab",
        site_s,
        "alice@example.com",
    ));
    let bad = format!("{}.{}", good.split('.').next().unwrap(), "0".repeat(64));
    for _ in 0..env.cfg.rate_limit.max_failures {
        assert_eq!(post_login(&env.client(), &bad).await.0, 400);
    }
    let (st, r) = post_login(&env.client(), &good).await;
    assert_eq!((st, r["error"].clone()), (429, json!("locked_out")), "{r}");
    let c = env.client();
    assert_eq!(
        c.challenge(USER).await.status(),
        429,
        "SSH sign-in is locked out too"
    );
}
