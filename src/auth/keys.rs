//! Administrator-managed authorisation file, inspired by OpenSSH `authorized_keys`.
//!
//! Each non-comment line is:
//!
//! ```text
//! user="alice",access="local,remote:web1" ssh-ed25519 AAAAC3Nza... alice@laptop
//! ```
//!
//! * `user` (required): gateway identity, `[a-z_][a-z0-9_.-]{0,31}`.
//! * `access` (required): comma list of `local`, `remote:*` or `remote:<profile-id>`.
//!
//! Only public keys are stored. A key may appear once; a user may have many keys.
//! Revocation: delete or comment out the line (`sshweb keys revoke`). The file is re-read
//! whenever it changes, and sessions authenticated with a removed key are terminated.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct Access {
    pub local: bool,
    pub remote_all: bool,
    pub remote_profiles: BTreeSet<String>,
}

impl Access {
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut a = Access::default();
        for item in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
            match item {
                "local" => a.local = true,
                "remote:*" => a.remote_all = true,
                other => match other.strip_prefix("remote:") {
                    Some(id) if crate::ssh::valid_profile_id(id) => {
                        a.remote_profiles.insert(id.to_string());
                    }
                    _ => return Err(format!("unknown access item {other:?}")),
                },
            }
        }
        if !a.local && !a.remote_all && a.remote_profiles.is_empty() {
            return Err("access must grant at least one mode".into());
        }
        Ok(a)
    }

    pub fn allows_remote(&self, profile_id: &str) -> bool {
        self.remote_all || self.remote_profiles.contains(profile_id)
    }

    pub fn allows_any_remote(&self) -> bool {
        self.remote_all || !self.remote_profiles.is_empty()
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.local {
            parts.push("local".to_string());
        }
        if self.remote_all {
            parts.push("remote:*".to_string());
        }
        for p in &self.remote_profiles {
            parts.push(format!("remote:{p}"));
        }
        f.write_str(&parts.join(","))
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizedKey {
    pub user: String,
    pub access: Access,
    pub key: PublicKey,
    pub fingerprint: String,
    pub line: usize,
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizedKeys {
    pub keys: Vec<AuthorizedKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

pub fn valid_user(u: &str) -> bool {
    let mut chars = u.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
        && u.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_.-".contains(c))
}

pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Accepted key algorithms and sizes.
pub fn check_key_strength(key: &KeyData, min_rsa_bits: usize) -> Result<(), String> {
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } => Ok(()),
        Algorithm::Rsa { .. } => {
            let rsa = key.rsa().ok_or("malformed RSA key")?;
            let n = rsa.n.as_bytes();
            let n = n.iter().skip_while(|b| **b == 0).count();
            let bits = n * 8;
            if bits < min_rsa_bits {
                Err(format!(
                    "RSA key is {bits} bits; at least {min_rsa_bits} required"
                ))
            } else {
                Ok(())
            }
        }
        other => Err(format!("key algorithm {other} is not supported")),
    }
}

/// Parse `name="value",name2="value2"` options.
fn parse_options(s: &str) -> Result<HashMap<String, String>, String> {
    let mut out = HashMap::new();
    let mut rest = s;
    while !rest.is_empty() {
        let (name, after) = rest
            .split_once("=\"")
            .ok_or_else(|| format!("malformed options near {rest:?}"))?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(format!("invalid option name {name:?}"));
        }
        let (value, after) = after
            .split_once('"')
            .ok_or("unterminated quoted option value")?;
        if out.insert(name.to_string(), value.to_string()).is_some() {
            return Err(format!("duplicate option {name:?}"));
        }
        rest = match after.strip_prefix(',') {
            Some(r) if !r.is_empty() => r,
            Some(_) => return Err("trailing comma in options".into()),
            None if after.is_empty() => "",
            None => return Err(format!("unexpected text after option {name:?}")),
        };
    }
    Ok(out)
}

/// Split the leading options field from the rest, honouring quotes.
fn split_options(line: &str) -> (&str, &str) {
    let mut in_quote = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            c if c.is_whitespace() && !in_quote => return (&line[..i], line[i..].trim_start()),
            _ => {}
        }
    }
    (line, "")
}

pub fn parse_line(
    line: &str,
    line_no: usize,
    min_rsa_bits: usize,
) -> Result<Option<AuthorizedKey>, String> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return Ok(None);
    }
    if t.len() > 16 * 1024 {
        return Err("line too long".into());
    }
    let (opts, keypart) = split_options(t);
    if opts.starts_with("ssh-") || opts.starts_with("ecdsa-") || opts.starts_with("sk-") {
        return Err("missing user=\"...\",access=\"...\" options before the key".into());
    }
    let opts = parse_options(opts)?;
    for k in opts.keys() {
        if k != "user" && k != "access" {
            return Err(format!("unknown option {k:?}"));
        }
    }
    let user = opts.get("user").ok_or("missing user option")?;
    if !valid_user(user) {
        return Err(format!("invalid user {user:?}"));
    }
    let access = Access::parse(opts.get("access").ok_or("missing access option")?)?;
    if keypart.is_empty() {
        return Err("missing public key".into());
    }
    let key = PublicKey::from_openssh(keypart).map_err(|e| format!("invalid public key: {e}"))?;
    check_key_strength(key.key_data(), min_rsa_bits)?;
    Ok(Some(AuthorizedKey {
        user: user.clone(),
        access,
        fingerprint: fingerprint(&key),
        key,
        line: line_no,
    }))
}

impl AuthorizedKeys {
    /// Parse the whole file. Any malformed record is an error (fail closed).
    pub fn parse(text: &str, min_rsa_bits: usize) -> Result<Self, Vec<ParseError>> {
        let mut keys: Vec<AuthorizedKey> = Vec::new();
        let mut errs = Vec::new();
        for (i, line) in text.lines().enumerate() {
            match parse_line(line, i + 1, min_rsa_bits) {
                Ok(Some(k)) => {
                    if let Some(prev) = keys.iter().find(|p| p.key.key_data() == k.key.key_data()) {
                        errs.push(ParseError {
                            line: i + 1,
                            message: format!(
                                "key {} already listed on line {} (user {})",
                                k.fingerprint, prev.line, prev.user
                            ),
                        });
                    } else {
                        keys.push(k);
                    }
                }
                Ok(None) => {}
                Err(message) => errs.push(ParseError {
                    line: i + 1,
                    message,
                }),
            }
        }
        if errs.is_empty() {
            Ok(Self { keys })
        } else {
            Err(errs)
        }
    }

    pub fn for_user<'a>(&'a self, user: &'a str) -> impl Iterator<Item = &'a AuthorizedKey> + 'a {
        self.keys.iter().filter(move |k| k.user == user)
    }

    pub fn by_fingerprint(&self, fp: &str) -> Option<&AuthorizedKey> {
        self.keys.iter().find(|k| k.fingerprint == fp)
    }
}

/// Cached parse keyed by (mtime, size) of the file.
type CacheEntry = (Option<SystemTime>, u64, Arc<AuthorizedKeys>);

/// Loads the authorisation file and reloads it when it changes on disk.
pub struct KeyStore {
    path: PathBuf,
    min_rsa_bits: usize,
    cache: Mutex<Option<CacheEntry>>,
}

impl KeyStore {
    pub fn new(path: PathBuf, min_rsa_bits: usize) -> Self {
        Self {
            path,
            min_rsa_bits,
            cache: Mutex::new(None),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Current keys. If the file is missing, unsafe or malformed, an error is returned and
    /// no key is accepted (fail closed).
    pub fn current(&self) -> Result<Arc<AuthorizedKeys>, String> {
        crate::security::perms::check_admin_file(&self.path)?;
        let md = std::fs::metadata(&self.path).map_err(|e| e.to_string())?;
        let stamp = (md.modified().ok(), md.len());
        let mut cache = self.cache.lock().unwrap();
        if let Some((m, l, keys)) = cache.as_ref()
            && (*m, *l) == stamp
        {
            return Ok(keys.clone());
        }
        let text = std::fs::read_to_string(&self.path).map_err(|e| e.to_string())?;
        match AuthorizedKeys::parse(&text, self.min_rsa_bits) {
            Ok(k) => {
                let k = Arc::new(k);
                *cache = Some((stamp.0, stamp.1, k.clone()));
                tracing::info!(path = %self.path.display(), keys = k.keys.len(), "loaded authorized keys");
                Ok(k)
            }
            Err(errs) => {
                *cache = None;
                let msg = errs
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                tracing::error!(path = %self.path.display(), errors = %msg, "authorized keys file is invalid; rejecting all logins");
                Err(msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const ED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOmNHtCYmT0r8CqW6TWE2YXnhZcp1ox9IGrtOrfB/QRa test@example";

    #[test]
    fn parses_valid_line() {
        let line = format!("user=\"alice\",access=\"local,remote:web1\" {ED}");
        let k = parse_line(&line, 1, 2048).unwrap().unwrap();
        assert_eq!(k.user, "alice");
        assert!(k.access.local);
        assert!(k.access.allows_remote("web1"));
        assert!(!k.access.allows_remote("db"));
        assert!(k.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn rejects_malformed() {
        let cases = [
            ED.to_string(),
            format!("user=\"alice\" {ED}"),
            format!("access=\"local\" {ED}"),
            format!("user=\"Alice\",access=\"local\" {ED}"),
            format!("user=\"alice\",access=\"root\" {ED}"),
            format!("user=\"alice\",access=\"\" {ED}"),
            format!("user=\"alice\",access=\"local\",command=\"x\" {ED}"),
            "user=\"alice\",access=\"local\" ssh-ed25519 AAAAnotbase64!".to_string(),
            "user=\"alice\",access=\"local\"".to_string(),
            format!("user=\"alice,access=\"local\" {ED}"),
        ];
        for c in cases {
            assert!(parse_line(&c, 1, 2048).is_err(), "should reject: {c}");
        }
    }

    #[test]
    fn comments_and_blank_lines() {
        let text = format!("# comment\n\n  user=\"bob\",access=\"remote:*\" {ED}\n");
        let ak = AuthorizedKeys::parse(&text, 2048).unwrap();
        assert_eq!(ak.keys.len(), 1);
        assert_eq!(ak.keys[0].line, 3);
        assert!(ak.keys[0].access.allows_remote("anything"));
    }

    #[test]
    fn duplicate_key_rejected() {
        let text = format!("user=\"a\",access=\"local\" {ED}\nuser=\"b\",access=\"local\" {ED}\n");
        let errs = AuthorizedKeys::parse(&text, 2048).unwrap_err();
        assert_eq!(errs[0].line, 2);
    }

    #[test]
    fn user_validation() {
        assert!(valid_user("alice"));
        assert!(valid_user("_svc.ops-1"));
        assert!(!valid_user(""));
        assert!(!valid_user("1abc"));
        assert!(!valid_user("a b"));
        assert!(!valid_user(&"a".repeat(33)));
    }

    #[test]
    fn access_display_roundtrip() {
        let a = Access::parse("remote:b,local,remote:a").unwrap();
        assert_eq!(a.to_string(), "local,remote:a,remote:b");
        assert_eq!(Access::parse(&a.to_string()).unwrap(), a);
    }

    #[test]
    fn keystore_reloads_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ak");
        crate::security::perms::write_new_file(
            &p,
            format!("user=\"a\",access=\"local\" {ED}\n").as_bytes(),
            0o600,
            false,
        )
        .unwrap();
        let ks = KeyStore::new(p.clone(), 2048);
        assert_eq!(ks.current().unwrap().keys.len(), 1);
        // Different length guarantees the change is detected even within mtime granularity.
        std::fs::write(&p, "garbage line here\n").unwrap();
        assert!(ks.current().is_err());
        std::fs::write(&p, "# empty\n").unwrap();
        assert_eq!(ks.current().unwrap().keys.len(), 0);
    }
}
