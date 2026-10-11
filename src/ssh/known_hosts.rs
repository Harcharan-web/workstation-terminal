//! Managed known_hosts file: listing, scanning and explicit, fingerprint-confirmed trust.
//!
//! Nothing is ever added automatically at connection time. An administrator either supplies
//! the host's public key file obtained out of band, or scans the host and confirms the
//! expected SHA256 fingerprint (obtained out of band, e.g. `ssh-keygen -lf
//! /etc/ssh/ssh_host_ed25519_key.pub` on the server).

use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ssh_key::{HashAlg, PublicKey};

#[derive(Debug, Clone)]
pub struct HostKey {
    pub hosts: String,
    pub key: PublicKey,
    pub fingerprint: String,
    pub marker: Option<String>,
}

/// known_hosts pattern for a host/port as OpenSSH writes it.
pub fn host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

pub fn parse_known_hosts(text: &str) -> Vec<HostKey> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let mut parts = t.splitn(2, char::is_whitespace);
        let mut first = parts.next().unwrap_or_default();
        let mut rest = parts.next().unwrap_or_default().trim_start();
        let mut marker = None;
        if first.starts_with('@') {
            marker = Some(first.to_string());
            let mut p = rest.splitn(2, char::is_whitespace);
            first = p.next().unwrap_or_default();
            rest = p.next().unwrap_or_default().trim_start();
        }
        if let Ok(key) = PublicKey::from_openssh(rest) {
            out.push(HostKey {
                hosts: first.to_string(),
                fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                key,
                marker,
            });
        }
    }
    out
}

/// Run ssh-keyscan (arguments passed separately, no shell) and parse the result.
pub async fn scan(
    keyscan: &Path,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<PublicKey>> {
    if !super::valid_host(host) {
        bail!("invalid host {host:?}");
    }
    let out = tokio::process::Command::new(keyscan)
        .arg("-T")
        .arg(timeout.as_secs().max(1).to_string())
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(host)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .await
        .with_context(|| format!("failed to run {}", keyscan.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let keys: Vec<PublicKey> = parse_known_hosts(&text)
        .into_iter()
        .map(|h| h.key)
        .collect();
    if keys.is_empty() {
        bail!("no host keys received from {host} port {port}");
    }
    Ok(keys)
}

/// Append a trusted key for host:port unless an identical entry exists.
pub fn add_trusted(path: &Path, host: &str, port: u16, key: &PublicKey) -> Result<bool> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let pattern = host_pattern(host, port);
    for hk in parse_known_hosts(&existing) {
        if hk.hosts.split(',').any(|h| h == pattern) && hk.key.key_data() == key.key_data() {
            return Ok(false);
        }
    }
    let mut stripped = key.clone();
    stripped.set_comment("");
    let line = format!("{pattern} {}\n", stripped.to_openssh()?.trim_end());
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        f.write_all(b"\n")?;
    }
    f.write_all(line.as_bytes())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmNHtCYmT0r8CqW6TWE2YXnhZcp1ox9IGrtOrfB/QRa";

    #[test]
    fn patterns() {
        assert_eq!(host_pattern("h", 22), "h");
        assert_eq!(host_pattern("h", 2222), "[h]:2222");
    }

    #[test]
    fn parse_and_add() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("kh");
        std::fs::write(&p, format!("# c\n@revoked old {KEY}\n")).unwrap();
        let key = PublicKey::from_openssh(KEY).unwrap();
        assert!(add_trusted(&p, "h", 2222, &key).unwrap());
        assert!(!add_trusted(&p, "h", 2222, &key).unwrap(), "no duplicate");
        let entries = parse_known_hosts(&std::fs::read_to_string(&p).unwrap());
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].marker.as_deref(), Some("@revoked"));
        assert_eq!(entries[1].hosts, "[h]:2222");
        assert!(entries[1].fingerprint.starts_with("SHA256:"));
    }
}
