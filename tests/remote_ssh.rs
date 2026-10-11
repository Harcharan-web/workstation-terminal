//! Remote SSH gateway tests against a disposable, unprivileged OpenSSH server.
//! Skipped (with a message) when /usr/sbin/sshd is unavailable.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::*;
use serde_json::json;
use sshweb::config::RemoteProfile;

struct Sshd {
    child: Child,
    port: u16,
    host_pub: String,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn keygen(path: &Path) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(st.success());
}

/// Start sshd on a free port, accepting `client_pub` for the current user.
fn start_sshd(dir: &Path, client_pub: &str) -> Option<Sshd> {
    let sshd = find_bin("/usr/sbin/sshd")?;
    let host_key = dir.join("sshd_host_key");
    keygen(&host_key);
    let ak = dir.join("sshd_authorized_keys");
    std::fs::write(&ak, client_pub).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = dir.join("sshd_config");
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\n\
             StrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\n",
            host_key.display(),
            dir.join("sshd.pid").display(),
            ak.display()
        ),
    )
    .unwrap();
    let child = Command::new(sshd)
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Wait until it accepts connections.
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let host_pub = std::fs::read_to_string(host_key.with_extension("pub")).unwrap();
            return Some(Sshd {
                child,
                port,
                host_pub,
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn current_user() -> String {
    std::env::var("USER").unwrap()
}

/// Environment with remote mode on and a `test` profile pointing at the sshd.
fn remote_env(port: u16, identity: &Path) -> Env {
    let mut env = env();
    env.cfg.remote.enabled = true;
    env.cfg.remote.connect_timeout_secs = 3;
    env.cfg.remote.profiles = vec![RemoteProfile {
        id: "test".into(),
        name: Some("Test sshd".into()),
        host: "127.0.0.1".into(),
        port,
        user: current_user(),
        identity_file: Some(identity.to_path_buf()),
    }];
    env
}

fn client_identity(dir: &Path) -> (std::path::PathBuf, String) {
    let id = dir.join("client_id");
    keygen(&id);
    let pubk = std::fs::read_to_string(id.with_extension("pub")).unwrap();
    (id, pubk)
}

async fn open_remote(ws: &mut Ws, profile: &str) {
    ws.send(json!({"type": "open", "target": {"kind": "remote", "profile": profile}, "cols": 80, "rows": 24}))
        .await;
}

#[tokio::test]
async fn unknown_host_key_is_rejected() {
    let scratch = tempfile::tempdir().unwrap();
    let (id, pubk) = client_identity(scratch.path());
    let Some(sshd) = start_sshd(scratch.path(), &pubk) else {
        eprintln!("skipping: cannot start sshd");
        return;
    };
    let mut env = remote_env(sshd.port, &id);
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    open_remote(&mut ws, "test").await;
    ws.expect_type("session_opened").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["exit_code"], 255);
    assert!(
        ws.output.contains("Host key verification failed"),
        "{}",
        ws.output
    );
    assert!(
        !ws.output
            .contains("Are you sure you want to continue connecting")
    );
    // Nothing was added to known_hosts behind the administrator's back.
    assert_eq!(
        std::fs::read_to_string(&env.cfg.remote.known_hosts).unwrap(),
        ""
    );
    srv.shutdown().await;
}

#[tokio::test]
async fn trusted_host_gives_interactive_remote_shell() {
    let scratch = tempfile::tempdir().unwrap();
    let (id, pubk) = client_identity(scratch.path());
    let Some(sshd) = start_sshd(scratch.path(), &pubk) else {
        eprintln!("skipping: cannot start sshd");
        return;
    };
    let mut env = remote_env(sshd.port, &id);
    let key = ssh_key::PublicKey::from_openssh(sshd.host_pub.trim()).unwrap();
    assert!(
        sshweb::ssh::known_hosts::add_trusted(
            &env.cfg.remote.known_hosts,
            "127.0.0.1",
            sshd.port,
            &key
        )
        .unwrap()
    );
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    open_remote(&mut ws, "test").await;
    let opened = ws.expect_type("session_opened").await;
    assert_eq!(opened["kind"], "remote");
    ws.input("echo remote=$((20+22)); stty size\r").await;
    ws.expect_output("remote=42").await;
    ws.expect_output("24 80").await;
    ws.send(json!({"type": "resize", "cols": 101, "rows": 33}))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ws.input("stty size\r").await;
    ws.expect_output("33 101").await;
    ws.input("sleep 100\r").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ws.input("\x03echo after=int\r").await;
    ws.expect_output("after=int").await;
    ws.input("exit\r").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["exit_code"], 0);
    srv.shutdown().await;
    let log = env.audit_log();
    assert!(log.contains("\"remote_host\":\"127.0.0.1\""));
}

#[tokio::test]
async fn changed_host_key_is_rejected() {
    let scratch = tempfile::tempdir().unwrap();
    let (id, pubk) = client_identity(scratch.path());
    let Some(sshd) = start_sshd(scratch.path(), &pubk) else {
        eprintln!("skipping: cannot start sshd");
        return;
    };
    let mut env = remote_env(sshd.port, &id);
    // Trust a *different* key for this host:port (simulates a MITM or rebuilt server).
    let imposter = new_key();
    sshweb::ssh::known_hosts::add_trusted(
        &env.cfg.remote.known_hosts,
        "127.0.0.1",
        sshd.port,
        imposter.public_key(),
    )
    .unwrap();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    open_remote(&mut ws, "test").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["exit_code"], 255);
    assert!(
        ws.output.contains("REMOTE HOST IDENTIFICATION HAS CHANGED"),
        "{}",
        ws.output
    );
    srv.shutdown().await;
}

#[tokio::test]
async fn auth_failure_and_unauthorised_profiles() {
    let scratch = tempfile::tempdir().unwrap();
    let (id, _pubk) = client_identity(scratch.path());
    // sshd accepts a different key than the one the profile uses.
    let (_, other_pub) = {
        let d = scratch.path().join("other");
        std::fs::create_dir(&d).unwrap();
        client_identity(&d)
    };
    let Some(sshd) = start_sshd(scratch.path(), &other_pub) else {
        eprintln!("skipping: cannot start sshd");
        return;
    };
    let mut env = remote_env(sshd.port, &id);
    let key = ssh_key::PublicKey::from_openssh(sshd.host_pub.trim()).unwrap();
    sshweb::ssh::known_hosts::add_trusted(
        &env.cfg.remote.known_hosts,
        "127.0.0.1",
        sshd.port,
        &key,
    )
    .unwrap();
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    open_remote(&mut ws, "test").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["exit_code"], 255);
    assert!(ws.output.contains("Permission denied"), "{}", ws.output);

    // Unknown profile and ad-hoc targets are refused (no arbitrary proxying).
    let (_c, mut ws) = logged_in_ws(&env).await;
    open_remote(&mut ws, "nope").await;
    assert_eq!(ws.expect_type("error").await["code"], "forbidden");
    ws.send(json!({"type": "open", "target": {"kind": "adhoc", "host": "example.com", "user": "root"}, "cols": 80, "rows": 24}))
        .await;
    let e = ws.expect_type("error").await;
    assert!(e["message"].as_str().unwrap().contains("ad-hoc"));
    srv.shutdown().await;
}

#[tokio::test]
async fn profile_access_is_enforced() {
    let scratch = tempfile::tempdir().unwrap();
    let (id, _) = client_identity(scratch.path());
    let mut env = remote_env(22, &id);
    write_file(
        &env.cfg.auth.authorized_keys,
        &authorized_line(USER, "local,remote:other", &env.key),
        0o600,
    );
    let srv = env.start().await;
    let (c, mut ws) = logged_in_ws(&env).await;
    let me: serde_json::Value = c
        .http
        .get(c.url("/api/me"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["remote"]["profiles"].as_array().unwrap().len(), 0);
    open_remote(&mut ws, "test").await;
    let e = ws.expect_type("error").await;
    assert_eq!(e["code"], "forbidden");
    srv.shutdown().await;
}

#[tokio::test]
async fn connection_timeout_is_enforced() {
    // A listener that accepts TCP but never speaks SSH.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    let scratch = tempfile::tempdir().unwrap();
    let (id, _) = client_identity(scratch.path());
    let mut env = remote_env(port, &id);
    env.cfg.remote.connect_timeout_secs = 2;
    let srv = env.start().await;
    let (_c, mut ws) = logged_in_ws(&env).await;
    let started = std::time::Instant::now();
    open_remote(&mut ws, "test").await;
    let closed = ws.expect_type("session_closed").await;
    assert_eq!(closed["exit_code"], 255);
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "took {:?}",
        started.elapsed()
    );
    srv.shutdown().await;
    drop(silent);
}
