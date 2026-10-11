//! Saved tabs (workspace) and resuming sessions after the browser login has gone.

mod common;

use std::time::Duration;

use common::*;
use serde_json::{Value, json};

fn sample() -> Value {
    json!({
        "tabs": [
            {"id": "t1", "target": {"kind": "local"}, "name": "  build  ", "session_id": null},
            {"id": "t2", "target": {"kind": "remote", "profile": "web1"}, "name": null, "session_id": "abcdef0123"}
        ],
        "active": "t2"
    })
}

#[tokio::test]
async fn workspace_is_saved_per_user_and_survives_restart() {
    let mut env = env();
    let bob = new_key();
    write_file(
        &env.cfg.auth.authorized_keys,
        &format!(
            "{}{}",
            authorized_line(USER, "local", &env.key),
            authorized_line("bob", "local", &bob)
        ),
        0o600,
    );
    let state_dir = env.cfg.server.state_dir.clone();
    let srv = env.start().await;
    let c = env.client();
    assert_eq!(
        c.http
            .get(c.url("/api/workspace"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    c.login(USER, &env.key).await;

    let empty: Value = c
        .http
        .get(c.url("/api/workspace"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(empty["tabs"].as_array().unwrap().len(), 0);

    let r = c
        .http
        .put(c.url("/api/workspace"))
        .json(&sample())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let saved: Value = r.json().await.unwrap();
    assert_eq!(saved["tabs"][0]["name"], "build", "names are normalised");

    // Invalid workspaces are refused.
    for bad in [
        json!({"tabs": [{"id": "../x", "target": {"kind": "local"}}]}),
        json!({"tabs": [{"id": "a", "target": {"kind": "shell", "cmd": "rm -rf /"}}]}),
        json!({"tabs": [{"id": "a", "target": {"kind": "local"}, "session_id": "../../etc"}]}),
        json!({"tabs": (0..17).map(|i| json!({"id": format!("t{i}"), "target": {"kind": "local"}})).collect::<Vec<_>>()}),
    ] {
        let st = c
            .http
            .put(c.url("/api/workspace"))
            .json(&bad)
            .send()
            .await
            .unwrap()
            .status();
        assert!(st == 400 || st == 422, "{bad} -> {st}");
    }
    // Cross-site writes are refused.
    let r = reqwest::Client::new()
        .put(c.url("/api/workspace"))
        .header("cookie", c.cookie_header().unwrap())
        .json(&json!({"tabs": []}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Another user has their own (empty) workspace.
    let cb = env.client();
    cb.login("bob", &bob).await;
    let other: Value = cb
        .http
        .get(cb.url("/api/workspace"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other["tabs"].as_array().unwrap().len(), 0);
    srv.shutdown().await;

    // A fresh server process with the same state dir restores it after a new login.
    let mut env2 = common::env();
    env2.cfg.server.state_dir = state_dir;
    env2.cfg.auth.authorized_keys = env.cfg.auth.authorized_keys.clone();
    let srv2 = env2.start().await;
    let c2 = env2.client();
    c2.login(USER, &env.key).await;
    let restored: Value = c2
        .http
        .get(c2.url("/api/workspace"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(restored, saved);
    srv2.shutdown().await;
}

#[tokio::test]
async fn detached_session_outlives_login_and_is_resumed_after_new_login() {
    let mut env = env();
    env.cfg.auth.session_idle_timeout_secs = 1; // browser login expires almost immediately
    let srv = env.start().await;
    let (c1, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    ws.input("echo before=$((2+2))\r").await;
    ws.expect_output("before=4").await;
    drop(ws); // browser closed

    // Let the login expire and housekeeping run (every 5 s).
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        c1.http
            .get(c1.url("/api/me"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "old login expired"
    );
    let s = srv
        .app
        .sessions
        .get(&id)
        .expect("detached shell still running");
    assert_eq!(s.info().state, "detached");

    // Sign in again with the key and re-attach.
    let (c2, mut ws2) = logged_in_ws(&env).await;
    ws2.send(json!({"type": "attach", "session_id": id, "cols": 80, "rows": 24}))
        .await;
    assert_eq!(ws2.expect_type("session_opened").await["resumed"], true);
    ws2.expect_output("before=4").await;
    ws2.input("echo after=$((3+3))\r").await;
    ws2.expect_output("after=6").await;
    let me: Value = c2
        .http
        .get(c2.url("/api/me"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        s.login_id(),
        me["login_id"].as_str().unwrap(),
        "session rebound to the new login"
    );

    // Logging out of the new login ends the session it now owns.
    c2.http
        .post(c2.url("/api/auth/logout"))
        .send()
        .await
        .unwrap();
    let closed = ws2.expect_type("session_closed").await;
    assert_eq!(closed["reason"], "logged out");
    srv.shutdown().await;
}

#[tokio::test]
async fn revoking_key_ends_detached_sessions_even_without_a_login() {
    let mut env = env();
    env.cfg.auth.session_idle_timeout_secs = 1;
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let id = ws.open_local().await;
    let pid = srv.app.sessions.get(&id).unwrap().pid().unwrap();
    drop(ws);
    tokio::time::sleep(Duration::from_secs(2)).await; // login gone, shell detached
    write_file(&env.cfg.auth.authorized_keys, "# all keys revoked\n", 0o600);
    for _ in 0..40 {
        if srv.app.sessions.get(&id).is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        srv.app.sessions.get(&id).is_none(),
        "session closed after key revocation"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!pid_alive(pid));
    srv.shutdown().await;
    assert!(env.audit_log().contains("key revoked"));
}

#[tokio::test]
async fn open_with_name_sets_session_name() {
    let mut env = env();
    let srv = env.start().await;
    let (c, mut ws) = logged_in_ws(&env).await;
    ws.send(json!({"type": "open", "target": {"kind": "local"}, "cols": 80, "rows": 24, "name": "logs"}))
        .await;
    ws.expect_type("session_opened").await;
    let list: Value = c
        .http
        .get(c.url("/api/sessions"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list["sessions"][0]["name"], "logs");
    ws.send(json!({"type": "open", "target": {"kind": "local"}, "cols": 80, "rows": 24, "name": "a\u{1b}b"}))
        .await;
    assert_eq!(ws.expect_type("error").await["code"], "bad_message");
    srv.shutdown().await;
}
