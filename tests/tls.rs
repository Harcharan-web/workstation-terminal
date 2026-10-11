//! HTTPS mode: serves over TLS with HSTS and Secure/__Host- cookies, and the https origin policy.
//! Uses the system `openssl` to make a throwaway certificate and `curl` as the client.

mod common;

use std::process::Command;

use common::*;

fn have(bin: &str) -> bool {
    Command::new("which")
        .arg(bin)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn https_mode_sets_secure_cookies_and_hsts() {
    if !have("openssl") || !have("curl") {
        eprintln!("skipping: openssl/curl not available");
        return;
    }
    let mut env = env();
    let cert = env.path().join("cert.pem");
    let key = env.path().join("key.pem");
    let st = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    env.cfg.server.tls.cert = Some(cert);
    env.cfg.server.tls.key = Some(key);
    assert!(
        env.cfg.validate_files().is_empty(),
        "{:?}",
        env.cfg.validate_files()
    );
    let srv = env.start().await;
    let port = env.cfg.server.port;
    let origin = format!("https://127.0.0.1:{port}");

    let curl = |args: &[&str]| {
        let o = Command::new("curl")
            .args(["-sk", "-i", "--max-time", "10"])
            .args(args)
            .output()
            .unwrap();
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    let out = tokio::task::spawn_blocking({
        let origin = origin.clone();
        move || {
            let health = curl(&[&format!("{origin}/healthz")]);
            let ch = curl(&[
                "-H",
                &format!("Origin: {origin}"),
                "-H",
                "Content-Type: application/json",
                "-d",
                r#"{"user":"alice"}"#,
                &format!("{origin}/api/auth/challenge"),
            ]);
            let wrong_scheme = curl(&[
                "-H",
                &format!("Origin: http://127.0.0.1:{port}"),
                "-H",
                "Content-Type: application/json",
                "-d",
                r#"{"user":"alice"}"#,
                &format!("{origin}/api/auth/challenge"),
            ]);
            let plain = Command::new("curl")
                .args([
                    "-s",
                    "--max-time",
                    "5",
                    &format!("http://127.0.0.1:{port}/healthz"),
                ])
                .output()
                .unwrap();
            (health, ch, wrong_scheme, plain.stdout)
        }
    })
    .await
    .unwrap();
    let (health, ch, wrong_scheme, plain) = out;
    assert!(health.starts_with("HTTP/"), "{health}");
    assert!(health.contains("{\"status\":\"ok\"}"));
    assert!(
        health
            .to_lowercase()
            .contains("strict-transport-security: max-age=31536000")
    );
    let ch_l = ch.to_lowercase();
    assert!(ch_l.contains("set-cookie: __host-sshweb_pre="), "{ch}");
    assert!(ch_l.contains("; secure"), "{ch}");
    assert!(ch.contains(&format!("origin={origin}")));
    assert!(
        wrong_scheme.contains(" 403"),
        "http origin refused in https mode: {wrong_scheme}"
    );
    assert!(
        !String::from_utf8_lossy(&plain).contains("\"ok\""),
        "plain HTTP must not be served"
    );
    srv.shutdown().await;
}
