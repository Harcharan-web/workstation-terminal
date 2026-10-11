//! CLI tests run against the compiled binary; they need no running server.

mod common;

use std::path::Path;
use std::process::{Command, Output, Stdio};

use common::*;

fn sshweb(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sshweb"))
        .args(args)
        .env("SSHWEB_HOME", home)
        .env_remove("SSHWEB_CONFIG")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ssh_keygen(dir: &Path, name: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    let st = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "test@cli", "-f"])
        .arg(&p)
        .status()
        .unwrap();
    assert!(st.success());
    p
}

#[test]
fn help_and_version() {
    let d = tempfile::tempdir().unwrap();
    let o = sshweb(d.path(), &["--help"]);
    assert!(o.status.success());
    for cmd in [
        "serve", "config", "keys", "hosts", "sessions", "health", "sign", "version",
    ] {
        assert!(text(&o).contains(cmd), "help lists {cmd}");
    }
    let o = sshweb(d.path(), &["version"]);
    assert!(text(&o).starts_with("sshweb "));
}

#[test]
fn config_init_validate_and_key_management() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("cfg");
    let o = sshweb(&home, &["config", "init"]);
    assert!(o.status.success(), "{}", text(&o));
    use std::os::unix::fs::PermissionsExt;
    for f in ["config.yaml", "authorized_keys", "known_hosts"] {
        let mode = std::fs::metadata(home.join(f))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{f} must be private");
    }
    assert!(
        !sshweb(&home, &["config", "init"]).status.success(),
        "no silent overwrite"
    );

    let o = sshweb(&home, &["config", "validate"]);
    assert!(o.status.success(), "{}", text(&o));

    let key = ssh_keygen(d.path(), "id_ed25519");
    let pubf = key.with_extension("pub");
    let o = sshweb(&home, &["keys", "fingerprint", pubf.to_str().unwrap()]);
    assert!(o.status.success());
    let fp_line = text(&o);
    let ours = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(&pubf)
        .output()
        .unwrap();
    let theirs = String::from_utf8_lossy(&ours.stdout);
    let fp = fp_line.split_whitespace().next().unwrap().to_string();
    assert!(
        theirs.contains(&fp),
        "fingerprint matches ssh-keygen: {fp} vs {theirs}"
    );

    // Private keys are refused outright.
    let o = sshweb(&home, &["keys", "fingerprint", key.to_str().unwrap()]);
    assert!(!o.status.success());
    assert!(text(&o).contains("PRIVATE"));
    let o = sshweb(
        &home,
        &[
            "keys",
            "add",
            "--user",
            "alice",
            "--access",
            "local",
            key.to_str().unwrap(),
        ],
    );
    assert!(!o.status.success());

    let o = sshweb(
        &home,
        &[
            "keys",
            "add",
            "--user",
            "alice",
            "--access",
            "local,remote:web1",
            pubf.to_str().unwrap(),
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    let o = sshweb(
        &home,
        &[
            "keys",
            "add",
            "--user",
            "bob",
            "--access",
            "local",
            pubf.to_str().unwrap(),
        ],
    );
    assert!(!o.status.success(), "duplicate key refused");
    let o = sshweb(
        &home,
        &[
            "keys",
            "add",
            "--user",
            "Bad User",
            "--access",
            "local",
            pubf.to_str().unwrap(),
        ],
    );
    assert!(!o.status.success());
    let o = sshweb(
        &home,
        &[
            "keys",
            "add",
            "--user",
            "carol",
            "--access",
            "root",
            pubf.to_str().unwrap(),
        ],
    );
    assert!(!o.status.success());

    let o = sshweb(&home, &["keys", "list"]);
    let t = text(&o);
    assert!(
        t.contains("alice") && t.contains(&fp) && t.contains("local,remote:web1"),
        "{t}"
    );

    let o = sshweb(&home, &["keys", "revoke", &fp]);
    assert!(o.status.success(), "{}", text(&o));
    let o = sshweb(&home, &["keys", "list"]);
    assert!(text(&o).contains("no authorised keys"));
    let ak = std::fs::read_to_string(home.join("authorized_keys")).unwrap();
    assert!(ak.contains("# revoked"));
    let mode = std::fs::metadata(home.join("authorized_keys"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "permissions preserved on rewrite");

    let audit = std::fs::read_to_string(home.join("audit.log")).unwrap();
    assert!(audit.contains("admin_key_add") && audit.contains("admin_key_revoke"));
}

#[test]
fn validate_reports_unsafe_settings() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("cfg");
    assert!(sshweb(&home, &["config", "init"]).status.success());
    let cfg = home.join("config.yaml");
    let text0 = std::fs::read_to_string(&cfg).unwrap();
    std::fs::write(&cfg, text0.replace("bind: 127.0.0.1", "bind: 0.0.0.0")).unwrap();
    let o = sshweb(&home, &["config", "validate"]);
    assert!(!o.status.success());
    let t = text(&o);
    assert!(t.contains("allow_remote_access"), "{t}");
    assert!(t.contains("requires TLS"), "{t}");

    // Group-writable authorized_keys is refused.
    std::fs::write(&cfg, &text0).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        home.join("authorized_keys"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    let o = sshweb(&home, &["config", "validate"]);
    assert!(!o.status.success());
    assert!(text(&o).contains("writable"));

    // Unknown fields are rejected rather than silently ignored.
    std::fs::set_permissions(
        home.join("authorized_keys"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(&cfg, format!("{text0}\nunexpected_option: true\n")).unwrap();
    let o = sshweb(&home, &["config", "validate"]);
    assert!(!o.status.success());
    assert!(text(&o).contains("unexpected_option"));
}

#[test]
fn serve_refuses_unsafe_remote_exposure() {
    let d = tempfile::tempdir().unwrap();
    let home = d.path().join("cfg");
    assert!(sshweb(&home, &["config", "init"]).status.success());
    let o = Command::new(env!("CARGO_BIN_EXE_sshweb"))
        .args(["serve"])
        .env("SSHWEB_HOME", &home)
        .env("SSHWEB_BIND", "0.0.0.0")
        .env("SSHWEB_ALLOW_REMOTE_ACCESS", "true")
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(text(&o).contains("requires TLS"));
}

#[test]
fn ssh_keygen_signature_interoperates() {
    // Real OpenSSH signature over a real challenge format, verified by our verifier.
    let d = tempfile::tempdir().unwrap();
    let key = ssh_keygen(d.path(), "id");
    let pubk = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let ak = sshweb::auth::keys::AuthorizedKeys::parse(
        &format!("user=\"alice\",access=\"local\" {pubk}"),
        2048,
    )
    .unwrap();
    let store = sshweb::auth::challenge::ChallengeStore::new(std::time::Duration::from_secs(60));
    let ch = store.issue("alice", "http://127.0.0.1:7681", "b").unwrap();

    // Via the `sshweb sign` helper (which runs ssh-keygen -Y sign with separate arguments).
    let o = Command::new(env!("CARGO_BIN_EXE_sshweb"))
        .args(["sign", "-f", key.to_str().unwrap(), &ch.message])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let sig = String::from_utf8(o.stdout).unwrap();
    assert!(sig.contains("BEGIN SSH SIGNATURE"));
    let k = sshweb::auth::challenge::verify_signature(&ak, "alice", &ch.message, &sig).unwrap();
    assert_eq!(k.user, "alice");
    // The same signature does not verify a different challenge.
    let ch2 = store.issue("alice", "http://127.0.0.1:7681", "b").unwrap();
    assert!(sshweb::auth::challenge::verify_signature(&ak, "alice", &ch2.message, &sig).is_err());

    // Exactly the command shown in the browser: printf '%s' MSG | ssh-keygen -Y sign ...
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "sshweb-auth", "-f"])
        .arg(&key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ch2.message.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let sig2 = String::from_utf8(out.stdout).unwrap();
    assert!(sshweb::auth::challenge::verify_signature(&ak, "alice", &ch2.message, &sig2).is_ok());

    // A signature made for a different namespace (e.g. git signing) is rejected.
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "git", "-f"])
        .arg(&key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ch2.message.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let sig3 = String::from_utf8(out.stdout).unwrap();
    assert!(sshweb::auth::challenge::verify_signature(&ak, "alice", &ch2.message, &sig3).is_err());
}

#[test]
fn rsa_keys_supported_and_weak_rsa_rejected() {
    let d = tempfile::tempdir().unwrap();
    for (bits, ok) in [("3072", true), ("1024", false)] {
        let p = d.path().join(format!("rsa{bits}"));
        let st = Command::new("ssh-keygen")
            .args(["-q", "-t", "rsa", "-b", bits, "-N", "", "-f"])
            .arg(&p)
            .status()
            .unwrap();
        if !st.success() {
            eprintln!("ssh-keygen refused rsa {bits}; skipping");
            continue;
        }
        let pubk = std::fs::read_to_string(p.with_extension("pub")).unwrap();
        let r =
            sshweb::auth::keys::parse_line(&format!("user=\"a\",access=\"local\" {pubk}"), 1, 2048);
        assert_eq!(r.is_ok(), ok, "rsa {bits}: {r:?}");
        if ok {
            // RSA SSHSIG produced by OpenSSH verifies.
            let ak = sshweb::auth::keys::AuthorizedKeys::parse(
                &format!("user=\"a\",access=\"local\" {pubk}"),
                2048,
            )
            .unwrap();
            let mut child = Command::new("ssh-keygen")
                .args(["-Y", "sign", "-n", "sshweb-auth", "-f"])
                .arg(&p)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            use std::io::Write;
            child.stdin.take().unwrap().write_all(b"msg").unwrap();
            let sig = String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap();
            assert!(sshweb::auth::challenge::verify_signature(&ak, "a", "msg", &sig).is_ok());
        }
    }
    let _ = new_key();
}
