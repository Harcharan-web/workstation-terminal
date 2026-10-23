//! Pseudo-terminal processes: local shells and the OpenSSH client both run inside a PTY.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::sync::{mpsc, watch};

use crate::config::Config;

pub const MIN_COLS: u16 = 2;
pub const MAX_COLS: u16 = 1000;
pub const MIN_ROWS: u16 = 1;
pub const MAX_ROWS: u16 = 500;
const READ_CHUNK: usize = 16 * 1024;

/// What to run inside the PTY. Arguments are passed as a vector; nothing goes through a shell.
#[derive(Debug, Clone)]
pub struct PtySpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// Full environment (the child does not inherit the gateway's environment).
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub cols: u16,
    pub rows: u16,
}

pub fn clamp_size(cols: u16, rows: u16) -> (u16, u16) {
    (
        cols.clamp(MIN_COLS, MAX_COLS),
        rows.clamp(MIN_ROWS, MAX_ROWS),
    )
}

/// Environment passed to child processes: a small allowlist plus terminal settings.
pub fn base_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    for k in [
        "HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE",
    ] {
        if let Ok(v) = std::env::var(k) {
            env.push((k.to_string(), v));
        }
    }
    if !env.iter().any(|(k, _)| k == "PATH") {
        env.push(("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into()));
    }
    if !env.iter().any(|(k, _)| k == "LANG") {
        env.push(("LANG".into(), "en_US.UTF-8".into()));
    }
    env.push(("TERM".into(), "xterm-256color".into()));
    env.push(("COLORTERM".into(), "truecolor".into()));
    env.push(("TERM_PROGRAM".into(), "sshweb".into()));
    env
}

/// Build the spec for a local interactive shell.
pub fn local_shell_spec(
    cfg: &Config,
    shell: Option<&std::path::Path>,
    cols: u16,
    rows: u16,
) -> Result<PtySpec, String> {
    let shell = match shell {
        Some(s) => {
            if !cfg.shell_allowed(s) {
                return Err(format!("shell {} is not permitted", s.display()));
            }
            s.to_path_buf()
        }
        None => cfg.effective_default_shell(),
    };
    if !shell.is_file() {
        return Err(format!("shell {} not found", shell.display()));
    }
    let mut args = Vec::new();
    if cfg.local.login_shell {
        args.push(OsString::from("-l"));
    }
    let cwd = cfg
        .local
        .working_dir
        .clone()
        .unwrap_or_else(crate::config::home_dir);
    let mut env = base_env();
    env.push(("SHELL".into(), shell.to_string_lossy().into_owned()));
    let (cols, rows) = clamp_size(cols, rows);
    Ok(PtySpec {
        program: shell,
        args,
        env,
        cwd,
        cols,
        rows,
    })
}

/// A shell for an OpsAPI task: started in `cwd` with `extra_env`. With an agent command line
/// (from the gateway's config, never from a link), the shell runs it first and then becomes an
/// ordinary interactive shell in the same folder. `-i` makes the user's rc files set PATH etc.
/// exactly as in a normal terminal; the task text is only reachable through `extra_env`.
pub fn task_shell_spec(
    cfg: &Config,
    cwd: std::path::PathBuf,
    extra_env: Vec<(String, String)>,
    run: Option<&str>,
    cols: u16,
    rows: u16,
) -> Result<PtySpec, String> {
    let mut spec = local_shell_spec(cfg, None, cols, rows)?;
    spec.cwd = cwd;
    spec.env.extend(extra_env);
    if let Some(run) = run {
        let shell = spec.program.to_string_lossy().into_owned();
        let login = if cfg.local.login_shell { " -l" } else { "" };
        // Newline, not `;`, so a `# comment` in the run line can't swallow the exec.
        spec.args.push(OsString::from("-i"));
        spec.args.push(OsString::from("-c"));
        spec.args
            .push(OsString::from(format!("{run}\nexec '{shell}'{login}")));
    }
    Ok(spec)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub code: Option<u32>,
}

/// A running process attached to a PTY.
pub struct PtyProcess {
    master: Mutex<Box<dyn MasterPty + Send>>,
    input_tx: mpsc::Sender<Bytes>,
    pid: Option<i32>,
    exit_rx: watch::Receiver<Option<ExitInfo>>,
}

impl PtyProcess {
    /// Spawn the process. Returns the handle and the output stream (closed at EOF).
    pub fn spawn(spec: &PtySpec) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize {
                rows: spec.rows,
                cols: spec.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("openpty failed")?;
        let mut cmd = CommandBuilder::new(&spec.program);
        cmd.args(&spec.args);
        cmd.env_clear();
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        cmd.cwd(&spec.cwd);
        let mut child = pair
            .slave
            .spawn_command(cmd)
            .with_context(|| format!("failed to start {}", spec.program.display()))?;
        // The child holds the only slave descriptor; closing ours makes EOF reach the reader.
        drop(pair.slave);
        let pid = child.process_id().map(|p| p as i32);

        let mut reader = pair.master.try_clone_reader().context("pty reader")?;
        let mut writer = pair.master.take_writer().context("pty writer")?;

        let (out_tx, out_rx) = mpsc::channel::<Bytes>(32);
        std::thread::Builder::new()
            .name("pty-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; READ_CHUNK];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            // Blocks when the consumer is slow: backpressure into the PTY.
                            if out_tx
                                .blocking_send(Bytes::copy_from_slice(&buf[..n]))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break, // EIO once the slave side is closed
                    }
                }
            })?;

        let (input_tx, mut input_rx) = mpsc::channel::<Bytes>(64);
        std::thread::Builder::new()
            .name("pty-write".into())
            .spawn(move || {
                while let Some(data) = input_rx.blocking_recv() {
                    if writer
                        .write_all(&data)
                        .and_then(|_| writer.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            })?;

        let (exit_tx, exit_rx) = watch::channel(None);
        std::thread::Builder::new()
            .name("pty-wait".into())
            .spawn(move || {
                let code = child.wait().ok().map(|s| s.exit_code());
                let _ = exit_tx.send(Some(ExitInfo { code }));
            })?;

        Ok((
            Self {
                master: Mutex::new(pair.master),
                input_tx,
                pid,
                exit_rx,
            },
            out_rx,
        ))
    }

    pub fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// Queue input for the PTY. Waits (backpressure) if the process is not reading.
    pub async fn write(&self, data: Bytes) -> Result<(), ()> {
        self.input_tx.send(data).await.map_err(|_| ())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let (cols, rows) = clamp_size(cols, rows);
        self.master
            .lock()
            .unwrap()
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .context("resize failed")
    }

    pub fn size(&self) -> Option<(u16, u16)> {
        self.master
            .lock()
            .unwrap()
            .get_size()
            .ok()
            .map(|s| (s.cols, s.rows))
    }

    pub fn exit_status(&self) -> Option<ExitInfo> {
        *self.exit_rx.borrow()
    }

    pub async fn wait_exit(&self) -> ExitInfo {
        let mut rx = self.exit_rx.clone();
        loop {
            if let Some(e) = *rx.borrow_and_update() {
                return e;
            }
            if rx.changed().await.is_err() {
                return ExitInfo { code: None };
            }
        }
    }

    fn signal_group(&self, sig: i32) {
        if let Some(pid) = self.pid
            && pid > 0
        {
            // The child is a session leader (setsid), so its pid is the process group id.
            // SAFETY: plain syscalls with a positive pid; errors (e.g. ESRCH) are ignored.
            unsafe {
                if libc::killpg(pid, sig) != 0 {
                    libc::kill(pid, sig);
                }
            }
        }
    }

    /// Terminate the process group: SIGHUP, then SIGKILL if it is still running after `grace`.
    pub async fn terminate(&self, grace: Duration) -> ExitInfo {
        if let Some(e) = self.exit_status() {
            // Shell gone; clean up any background jobs left in its group.
            self.signal_group(libc::SIGHUP);
            return e;
        }
        self.signal_group(libc::SIGHUP);
        self.signal_group(libc::SIGCONT);
        match tokio::time::timeout(grace, self.wait_exit()).await {
            Ok(e) => e,
            Err(_) => {
                self.signal_group(libc::SIGKILL);
                tokio::time::timeout(Duration::from_secs(2), self.wait_exit())
                    .await
                    .unwrap_or(ExitInfo { code: None })
            }
        }
    }
}

impl Drop for PtyProcess {
    fn drop(&mut self) {
        if self.exit_status().is_none() {
            self.signal_group(libc::SIGKILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh_spec(script: &str) -> PtySpec {
        PtySpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            env: base_env(),
            cwd: std::env::temp_dir(),
            cols: 80,
            rows: 24,
        }
    }

    async fn read_until(rx: &mut mpsc::Receiver<Bytes>, needle: &str) -> String {
        let mut acc = String::new();
        let fut = async {
            while let Some(b) = rx.recv().await {
                acc.push_str(&String::from_utf8_lossy(&b));
                if acc.contains(needle) {
                    break;
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"));
        acc
    }

    #[tokio::test]
    async fn runs_interactive_shell_and_reports_exit() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec("read line; echo got:$line; exit 3")).unwrap();
        p.write(Bytes::from_static(b"hello\r")).await.unwrap();
        let out = read_until(&mut rx, "got:hello").await;
        assert!(out.contains("got:hello"));
        assert_eq!(p.wait_exit().await.code, Some(3));
    }

    #[tokio::test]
    async fn pty_is_a_tty_and_resizes() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec(
            "stty size; read x; stty size; test -t 0 && echo IS_TTY",
        ))
        .unwrap();
        read_until(&mut rx, "24 80").await;
        p.resize(132, 40).unwrap();
        assert_eq!(p.size(), Some((132, 40)));
        p.write(Bytes::from_static(b"\r")).await.unwrap();
        let out = read_until(&mut rx, "IS_TTY").await;
        assert!(out.contains("40 132"), "{out}");
    }

    #[tokio::test]
    async fn ctrl_c_interrupts_foreground_process() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec(
            "trap 'echo TRAPPED; exit 7' INT; echo READY; while :; do sleep 1; done",
        ))
        .unwrap();
        read_until(&mut rx, "READY").await;
        p.write(Bytes::from_static(b"\x03")).await.unwrap();
        read_until(&mut rx, "TRAPPED").await;
        assert_eq!(p.wait_exit().await.code, Some(7));
    }

    #[tokio::test]
    async fn ctrl_d_ends_cat() {
        let (p, mut rx) = PtyProcess::spawn(&sh_spec("cat; echo CAT_DONE")).unwrap();
        p.write(Bytes::from_static(b"\x04")).await.unwrap();
        read_until(&mut rx, "CAT_DONE").await;
        assert_eq!(p.wait_exit().await.code, Some(0));
    }

    #[tokio::test]
    async fn terminate_kills_process_group() {
        let (p, mut rx) =
            PtyProcess::spawn(&sh_spec("trap '' HUP; sleep 300 & echo BG:$!; wait")).unwrap();
        let out = read_until(&mut rx, "\n").await;
        let bg: i32 = out
            .split("BG:")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .expect("background pid");
        let start = std::time::Instant::now();
        p.terminate(Duration::from_millis(500)).await;
        assert!(p.exit_status().is_some());
        assert!(start.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(200)).await;
        // SAFETY: probe only.
        let alive = unsafe { libc::kill(bg, 0) } == 0;
        assert!(!alive, "background child {bg} survived");
    }

    #[test]
    fn size_is_clamped() {
        assert_eq!(clamp_size(0, 0), (MIN_COLS, MIN_ROWS));
        assert_eq!(clamp_size(60000, 60000), (MAX_COLS, MAX_ROWS));
    }

    #[test]
    fn local_shell_policy() {
        let cfg = Config::default();
        assert!(
            local_shell_spec(&cfg, Some(std::path::Path::new("/usr/bin/python3")), 80, 24).is_err()
        );
        let spec = local_shell_spec(&cfg, Some(std::path::Path::new("/bin/sh")), 80, 24).unwrap();
        assert_eq!(spec.args, vec![OsString::from("-l")]);
        assert!(
            spec.env
                .iter()
                .any(|(k, v)| k == "TERM" && v == "xterm-256color")
        );
        assert!(!spec.env.iter().any(|(k, _)| k.starts_with("SSHWEB_")));
    }
}
