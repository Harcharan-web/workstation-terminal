//! Remote SSH gateway: target authorisation and a hardened OpenSSH client invocation.
//!
//! The system `ssh` runs inside a gateway-owned PTY. Every value is passed as a separate
//! argv element (never through a shell), the user's `~/.ssh/config` is ignored (`-F none`),
//! host keys are only accepted from the managed known_hosts file with
//! `StrictHostKeyChecking=yes`, and forwarding, proxy and local-command features are disabled.

pub mod known_hosts;

use std::ffi::OsString;

use serde::Serialize;

use crate::auth::keys::Access;
use crate::config::{Config, RemoteProfile};
use crate::terminal::{PtySpec, base_env, clamp_size};

pub fn valid_profile_id(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Hostname or IP literal. Rejects anything that could be parsed as an ssh option.
pub fn valid_host(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 || s.starts_with('-') || s.starts_with('.') {
        return false;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

pub fn valid_remote_user(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RemoteTarget {
    /// Profile id, or None for an ad-hoc target.
    pub profile: Option<String>,
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(skip)]
    pub identity_file: Option<std::path::PathBuf>,
}

impl RemoteTarget {
    pub fn label(&self) -> String {
        if self.port == 22 {
            format!("{}@{}", self.user, self.host)
        } else {
            format!("{}@{}:{}", self.user, self.host, self.port)
        }
    }
}

impl From<&RemoteProfile> for RemoteTarget {
    fn from(p: &RemoteProfile) -> Self {
        Self {
            profile: Some(p.id.clone()),
            host: p.host.clone(),
            port: p.port,
            user: p.user.clone(),
            identity_file: p.identity_file.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TargetError {
    #[error("remote SSH is disabled")]
    Disabled,
    #[error("unknown connection profile")]
    UnknownProfile,
    #[error("you are not authorised for this connection")]
    Forbidden,
    #[error("ad-hoc connections are disabled; use a configured profile")]
    AdhocDisabled,
    #[error("destination {0} is not in the allowlist")]
    NotAllowed(&'static str),
    #[error("invalid {0}")]
    Invalid(&'static str),
}

/// Resolve a profile the caller is authorised to use.
pub fn resolve_profile(
    cfg: &Config,
    access: &Access,
    id: &str,
) -> Result<RemoteTarget, TargetError> {
    if !cfg.remote.enabled {
        return Err(TargetError::Disabled);
    }
    let p = cfg
        .remote
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or(TargetError::UnknownProfile)?;
    if !access.allows_remote(&p.id) {
        return Err(TargetError::Forbidden);
    }
    Ok(p.into())
}

/// Resolve an ad-hoc target (only if enabled, the caller has `remote:*`, and it passes every
/// allowlist).
pub fn resolve_adhoc(
    cfg: &Config,
    access: &Access,
    host: &str,
    port: u16,
    user: &str,
) -> Result<RemoteTarget, TargetError> {
    let r = &cfg.remote;
    if !r.enabled {
        return Err(TargetError::Disabled);
    }
    if !r.allow_adhoc {
        return Err(TargetError::AdhocDisabled);
    }
    if !access.remote_all {
        return Err(TargetError::Forbidden);
    }
    if !valid_host(host) {
        return Err(TargetError::Invalid("host"));
    }
    if !valid_remote_user(user) {
        return Err(TargetError::Invalid("user"));
    }
    if !r.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return Err(TargetError::NotAllowed("host"));
    }
    if !r.allowed_ports.contains(&port) {
        return Err(TargetError::NotAllowed("port"));
    }
    if !r.allowed_users.iter().any(|u| u == user) {
        return Err(TargetError::NotAllowed("user"));
    }
    Ok(RemoteTarget {
        profile: None,
        host: host.to_ascii_lowercase(),
        port,
        user: user.into(),
        identity_file: None,
    })
}

/// Build the argv for OpenSSH. Exposed for tests and auditing.
pub fn ssh_args(cfg: &Config, t: &RemoteTarget) -> Vec<OsString> {
    let r = &cfg.remote;
    // Ignore ~/.ssh/config so nothing below can be overridden.
    let mut a: Vec<OsString> = vec!["-F".into(), "none".into()];
    let mut opt = |s: String| {
        a.push("-o".into());
        a.push(s.into());
    };
    opt("StrictHostKeyChecking=yes".into());
    opt(format!(
        "UserKnownHostsFile=\"{}\"",
        r.known_hosts.display()
    ));
    opt("GlobalKnownHostsFile=/dev/null".into());
    opt("UpdateHostKeys=no".into());
    opt("CheckHostIP=no".into());
    opt(format!("ConnectTimeout={}", r.connect_timeout_secs));
    opt(format!("ServerAliveInterval={}", r.keepalive_interval_secs));
    opt(format!("ServerAliveCountMax={}", r.keepalive_count_max));
    opt("PreferredAuthentications=publickey".into());
    opt("PasswordAuthentication=no".into());
    opt("KbdInteractiveAuthentication=no".into());
    opt("ForwardAgent=no".into());
    opt("ForwardX11=no".into());
    opt("ClearAllForwardings=yes".into());
    opt("PermitLocalCommand=no".into());
    opt("ProxyCommand=none".into());
    opt("ProxyJump=none".into());
    opt("ControlMaster=no".into());
    opt("ControlPath=none".into());
    opt("EscapeChar=none".into());
    opt("RequestTTY=force".into());
    opt("AddKeysToAgent=no".into());
    if t.identity_file.is_some() {
        opt("IdentitiesOnly=yes".into());
    }
    if let Some(id) = &t.identity_file {
        a.push("-i".into());
        a.push(id.clone().into_os_string());
    }
    a.push("-p".into());
    a.push(t.port.to_string().into());
    a.push("-l".into());
    a.push(t.user.clone().into());
    a.push("--".into());
    a.push(t.host.clone().into());
    a
}

pub fn ssh_spec(cfg: &Config, t: &RemoteTarget, cols: u16, rows: u16) -> PtySpec {
    let mut env = base_env();
    if cfg.remote.use_agent
        && let Ok(sock) = std::env::var("SSH_AUTH_SOCK")
    {
        env.push(("SSH_AUTH_SOCK".into(), sock));
    }
    let (cols, rows) = clamp_size(cols, rows);
    PtySpec {
        program: cfg.remote.ssh_binary.clone(),
        args: ssh_args(cfg, t),
        env,
        cwd: crate::config::home_dir(),
        cols,
        rows,
        // The ssh client needs the gateway's known_hosts and keys, so it runs as the gateway.
        run_as: None,
    }
}

/// Profiles visible to a user.
pub fn permitted_profiles<'a>(
    cfg: &'a Config,
    access: &'a Access,
) -> impl Iterator<Item = &'a RemoteProfile> + 'a {
    cfg.remote
        .profiles
        .iter()
        .filter(move |p| cfg.remote.enabled && access.allows_remote(&p.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.remote.enabled = true;
        c.remote.known_hosts = "/tmp/kh".into();
        c.remote.profiles.push(RemoteProfile {
            id: "web1".into(),
            name: None,
            host: "web1.example.net".into(),
            port: 2222,
            user: "deploy".into(),
            identity_file: Some("/keys/id".into()),
        });
        c
    }

    #[test]
    fn host_and_user_validation() {
        for ok in ["example.com", "a-b.c", "10.0.0.1", "::1", "localhost"] {
            assert!(valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "-oProxyCommand=x",
            "a b",
            "a;b",
            "a/b",
            ".a",
            "a..b",
            "a_b",
            "$(x)",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
        assert!(valid_remote_user("deploy.user-1"));
        assert!(!valid_remote_user("-l"));
        assert!(!valid_remote_user("a b"));
        assert!(!valid_remote_user("root@x"));
    }

    #[test]
    fn profile_authorisation() {
        let c = cfg();
        let web = Access::parse("remote:web1").unwrap();
        let local = Access::parse("local").unwrap();
        assert!(resolve_profile(&c, &web, "web1").is_ok());
        assert_eq!(
            resolve_profile(&c, &local, "web1"),
            Err(TargetError::Forbidden)
        );
        assert_eq!(
            resolve_profile(&c, &web, "nope"),
            Err(TargetError::UnknownProfile)
        );
        let mut off = c.clone();
        off.remote.enabled = false;
        assert_eq!(
            resolve_profile(&off, &web, "web1"),
            Err(TargetError::Disabled)
        );
    }

    #[test]
    fn adhoc_requires_allowlists() {
        let mut c = cfg();
        let all = Access::parse("remote:*").unwrap();
        assert_eq!(
            resolve_adhoc(&c, &all, "h.example", 22, "u"),
            Err(TargetError::AdhocDisabled)
        );
        c.remote.allow_adhoc = true;
        c.remote.allowed_hosts = vec!["h.example".into()];
        c.remote.allowed_users = vec!["u".into()];
        assert!(resolve_adhoc(&c, &all, "H.example", 22, "u").is_ok());
        assert_eq!(
            resolve_adhoc(&c, &all, "other", 22, "u"),
            Err(TargetError::NotAllowed("host"))
        );
        assert_eq!(
            resolve_adhoc(&c, &all, "h.example", 23, "u"),
            Err(TargetError::NotAllowed("port"))
        );
        assert_eq!(
            resolve_adhoc(&c, &all, "h.example", 22, "root"),
            Err(TargetError::NotAllowed("user"))
        );
        assert_eq!(
            resolve_adhoc(&c, &all, "-oX", 22, "u"),
            Err(TargetError::Invalid("host"))
        );
        let some = Access::parse("remote:web1").unwrap();
        assert_eq!(
            resolve_adhoc(&c, &some, "h.example", 22, "u"),
            Err(TargetError::Forbidden)
        );
    }

    #[test]
    fn ssh_args_are_hardened() {
        let c = cfg();
        let t = resolve_profile(&c, &Access::parse("remote:*").unwrap(), "web1").unwrap();
        let args: Vec<String> = ssh_args(&c, &t)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        assert_eq!(&args[..2], &["-F", "none"]);
        let joined = args.join(" ");
        for must in [
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=\"/tmp/kh\"",
            "GlobalKnownHostsFile=/dev/null",
            "ProxyCommand=none",
            "ForwardAgent=no",
            "EscapeChar=none",
            "PasswordAuthentication=no",
            "IdentitiesOnly=yes",
        ] {
            assert!(joined.contains(must), "missing {must}");
        }
        assert!(!joined.contains("StrictHostKeyChecking=no"));
        assert!(!joined.contains("accept-new"));
        let n = args.len();
        assert_eq!(&args[n - 2..], &["--", "web1.example.net"]);
        let p = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[p + 1], "2222");
        let l = args.iter().position(|a| a == "-l").unwrap();
        assert_eq!(args[l + 1], "deploy");
    }

    #[test]
    fn agent_socket_only_when_enabled() {
        let mut c = cfg();
        let t: RemoteTarget = (&c.remote.profiles[0]).into();
        // SAFETY: test-only env mutation.
        unsafe { std::env::set_var("SSH_AUTH_SOCK", "/tmp/agent.sock") };
        assert!(
            !ssh_spec(&c, &t, 80, 24)
                .env
                .iter()
                .any(|(k, _)| k == "SSH_AUTH_SOCK")
        );
        c.remote.use_agent = true;
        assert!(
            ssh_spec(&c, &t, 80, 24)
                .env
                .iter()
                .any(|(k, _)| k == "SSH_AUTH_SOCK")
        );
    }
}
