//! Shells inside `local.sandbox_profile` (macOS sandbox-exec): blocked files and connections, and
//! the shell can still be stopped. Runs the real packaging/sshweb-shell.sb with a test home.
#![cfg(target_os = "macos")]

use std::path::Path;
use std::time::Duration;

use sshweb::config::Config;
use sshweb::terminal::{PtyProcess, check_sandbox, local_shell_spec};

#[tokio::test]
async fn shells_stay_in_their_folder_and_on_the_web() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().canonicalize().unwrap().join("home");
    std::fs::create_dir_all(home.join("projects/app")).unwrap();
    std::fs::write(home.join(".zprofile"), "# shared\n").unwrap();
    // Outside the shells' folder: another folder under /Users stands in for other people's files.
    let outside = std::env::var("HOME").unwrap();
    let profile = tmp.path().join("shell.sb");
    std::fs::write(&profile, std::fs::read_to_string("packaging/sshweb-shell.sb").unwrap()).unwrap();
    // A service on this machine the shell must not reach.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let mut cfg = Config::default();
    cfg.local.login_shell = false;
    cfg.local.sandbox_profile = Some(profile);
    check_sandbox(&cfg).expect("the profile loads");
    let mut spec = local_shell_spec(&cfg, Some(Path::new("/bin/sh")), 80, 24).unwrap();
    // The test runs as the developer, so point the profile's HOME at the test home.
    let sb = spec.sandbox.as_mut().unwrap();
    sb.params.retain(|(k, _)| k != "HOME");
    sb.params.push(("HOME".into(), home.display().to_string()));
    spec.cwd = home.join("projects/app");
    spec.args = vec![
        "-c".into(),
        format!(
            "echo hi > notes.txt && echo WRITE_PROJECT_OK; \
             ls '{outside}' >/dev/null 2>&1 && echo OUTSIDE_READABLE || echo OUTSIDE_BLOCKED; \
             echo x >> '{home}/.zprofile' 2>/dev/null && echo SETUP_CHANGED || echo SETUP_LOCKED; \
             /usr/bin/nc -z -G 2 127.0.0.1 {port} >/dev/null 2>&1 && echo LOCAL_REACHED || echo LOCAL_BLOCKED; \
             echo PID=$$; trap '' HUP; sleep 300 & wait",
            outside = outside,
            home = home.display()
        )
        .into(),
    ];

    let (p, mut rx) = PtyProcess::spawn(&spec).unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(b) = rx.recv().await {
            out.push_str(&String::from_utf8_lossy(&b));
            if out.contains("PID=") && out.ends_with('\n') {
                break;
            }
        }
    })
    .await
    .expect("shell output");
    for want in ["WRITE_PROJECT_OK", "OUTSIDE_BLOCKED", "SETUP_LOCKED", "LOCAL_BLOCKED"] {
        assert!(out.contains(want), "missing {want} in {out:?}");
    }
    assert!(home.join("projects/app/notes.txt").is_file());
    assert_eq!(std::fs::read_to_string(home.join(".zprofile")).unwrap(), "# shared\n");
    // sandbox-exec handed over: the process the gateway holds is the shell.
    assert!(out.contains(&format!("PID={}", p.pid().unwrap())), "{out}");
    p.terminate(Duration::from_millis(500)).await;
    assert!(p.exit_status().is_some());
    drop(listener);
}

#[test]
fn a_broken_profile_is_refused_with_the_reason() {
    let tmp = tempfile::tempdir().unwrap();
    let profile = tmp.path().join("shell.sb");
    std::fs::write(&profile, "(version 1)\n(allow nonsense)\n").unwrap();
    let mut cfg = Config::default();
    cfg.local.sandbox_profile = Some(profile);
    let err = check_sandbox(&cfg).unwrap_err();
    assert!(err.contains("didn't start in the sandbox"), "{err}");
}
