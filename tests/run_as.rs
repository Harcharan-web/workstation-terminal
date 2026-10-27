//! Shells started as another account through sudo (`local.run_as`). This needs two accounts and the
//! sudoers rule, so it only runs when SSHWEB_TEST_RUN_AS names the shells' account:
//! scripts/test-run-as.sh runs it in a Linux container.

use std::path::Path;
use std::time::Duration;

use sshweb::config::{Config, lookup_account};
use sshweb::terminal::{PtyProcess, check_run_as, local_shell_spec};

fn owner_uid(pid: i32) -> Option<u32> {
    let out = std::process::Command::new("ps").args(["-o", "uid=", "-p", &pid.to_string()]).output().ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

fn gone(pid: i32) -> bool {
    // Another account's process: kill(…, 0) says EPERM while it lives, ESRCH once it's gone.
    // SAFETY: probe only.
    let rc = unsafe { libc::kill(pid, 0) };
    rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[tokio::test]
async fn shells_run_as_the_other_account_and_can_still_be_stopped() {
    let Ok(user) = std::env::var("SSHWEB_TEST_RUN_AS") else {
        eprintln!("skipped: set SSHWEB_TEST_RUN_AS (scripts/test-run-as.sh)");
        return;
    };
    let account = lookup_account(&user).expect("the shells' account exists");
    check_run_as(&account).expect("sudo is set up as packaging/sshweb.sudoers says");

    let mut cfg = Config::default();
    cfg.local.run_as = Some(user.clone());
    cfg.local.login_shell = false;
    let mut spec = local_shell_spec(&cfg, Some(Path::new("/bin/sh")), 80, 24).unwrap();
    assert_eq!(spec.program, Path::new("/bin/sh"), "the session still names the shell, not sudo");
    assert_eq!(spec.cwd, account.home, "tabs start in the account's home");
    spec.env.push(("OPSAPI_TASK".into(), "t-1".into()));
    spec.env.push(("SSHWEB_TAB_TOKEN".into(), "ab12".into()));
    spec.env.push(("GATEWAY_SECRET".into(), "must-not-reach".into()));
    spec.args = vec![
        "-c".into(),
        "echo \"who=$(id -un) home=$HOME user=$USER task=$OPSAPI_TASK tab=$SSHWEB_TAB_TOKEN \
         leak=${GATEWAY_SECRET:-none} tmp=${TMPDIR:-none} pwd=$(pwd) cols=$(stty size)\"; \
         trap '' HUP; sleep 300 & echo BG:$!; wait"
            .into(),
    ];

    let (p, mut rx) = PtyProcess::spawn(&spec).unwrap();
    let mut out = String::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(b) = rx.recv().await {
            out.push_str(&String::from_utf8_lossy(&b));
            if out.contains("BG:") && out.ends_with('\n') {
                break;
            }
        }
    })
    .await
    .expect("shell output");
    let home = account.home.display().to_string();
    for want in [
        format!("who={user} "),
        format!("home={home} "),
        format!("user={user} "),
        "task=t-1 ".into(),
        "tab=ab12 ".into(),
        "leak=none ".into(),
        "tmp=none ".into(),
        format!("pwd={home} "),
        "cols=24 80".into(),
    ] {
        assert!(out.contains(&want), "missing {want:?} in {out:?}");
    }

    // sudo handed over: the process the gateway holds is the shell itself, owned by the account.
    let pid = p.pid().unwrap();
    assert_eq!(owner_uid(pid), Some(account.uid));

    let bg: i32 = out.split("BG:").nth(1).and_then(|s| s.split_whitespace().next()).and_then(|s| s.parse().ok()).unwrap();
    p.resize(100, 30).unwrap();
    assert_eq!(p.size(), Some((100, 30)));
    // Ignores SIGHUP, so this needs the SIGKILL that goes through sudo.
    p.terminate(Duration::from_millis(500)).await;
    assert!(p.exit_status().is_some(), "the shell was stopped");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(gone(bg), "background job {bg} survived");
}

#[test]
fn the_check_names_what_is_wrong_when_sudo_refuses() {
    let Ok(user) = std::env::var("SSHWEB_TEST_RUN_AS_REFUSED") else {
        eprintln!("skipped: set SSHWEB_TEST_RUN_AS_REFUSED (scripts/test-run-as.sh)");
        return;
    };
    let account = lookup_account(&user).expect("account exists");
    let err = check_run_as(&account).unwrap_err();
    assert!(err.contains("sudo won't start shells") && err.contains("sshweb.sudoers"), "{err}");
}
