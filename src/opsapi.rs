//! OpsAPI task bridge.
//!
//! - **Launch links.** OpsAPI opens `https://<gateway>/#launch=<ticket>` from a task page. The ticket
//!   is `base64url(json).hex(hmac_sha256(secret, base64url(json)))`. The page posts it to
//!   `/api/launch` once the user has signed in with their SSH key; the gateway verifies it, checks the
//!   folder against `local.allowed_roots` and the agent against `opsapi.agents`, and the next `open`
//!   with that launch id starts a shell there. A launch link never signs anyone in.
//! - **Webhook.** When a launched session starts or ends, an HMAC-signed POST tells OpsAPI.
//!
//! See docs/OPSAPI.md for the full contract.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::config::{AgentConfig, Config, OpsapiConfig};

/// Longest lifetime OpsAPI may give a link (it uses 15 minutes).
pub const MAX_LINK_LIFETIME_SECS: u64 = 3600;
/// Allowed clock difference between OpsAPI and this machine.
const CLOCK_SKEW_SECS: u64 = 300;
const MAX_TICKET_BYTES: usize = 24 * 1024;
pub const MAX_PROMPT_CHARS: usize = 8000;

pub fn valid_agent_id(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn valid_uuidish(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// A verified launch link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    pub id: String,
    pub task: String,
    pub num: Option<i64>,
    pub title: String,
    pub path: String,
    pub agent: String,
    pub prompt: String,
    pub by: String,
    pub return_url: String,
    pub workspace: Option<String>,
    pub exp: u64,
}

impl Launch {
    /// Tab name: `#12 Fix the header` (at most 64 characters, see session::normalize_name).
    pub fn tab_name(&self) -> String {
        let base = match self.num {
            Some(n) => format!("#{n} {}", self.title),
            None => self.title.clone(),
        };
        let name: String = base.chars().take(crate::session::MAX_NAME_CHARS).collect();
        name.trim().to_string()
    }
}

#[derive(Deserialize)]
struct Claims {
    v: u32,
    id: String,
    iat: u64,
    exp: u64,
    task: String,
    #[serde(default)]
    num: Option<i64>,
    title: String,
    path: String,
    agent: String,
    #[serde(default)]
    prompt: String,
    #[serde(default)]
    by: String,
    #[serde(rename = "return")]
    return_url: String,
    #[serde(default)]
    ws: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("this link isn't valid; open it again from OpsAPI")]
    Invalid,
    #[error("this link has expired; open it again from OpsAPI")]
    Expired,
    #[error("task links aren't set up on this terminal")]
    NotConfigured,
}

/// One line of text: no control characters, at most `max` characters.
fn one_line(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    (t.chars().count() <= max && !t.chars().any(char::is_control)).then(|| t.to_string())
}

/// Keep newlines and tabs, drop other control characters (escape sequences, NUL).
fn clean_prompt(s: &str) -> String {
    s.replace("\r\n", "\n")
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

fn valid_return_url(u: &str) -> bool {
    let ok_scheme = u.starts_with("https://")
        || u.starts_with("http://localhost")
        || u.starts_with("http://127.0.0.1");
    ok_scheme
        && u.len() <= 2048
        && !u.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '<' || c == '>')
}

/// Verify a launch ticket's signature, lifetime and fields.
pub fn verify_ticket(secret: &str, ticket: &str, now: u64) -> Result<Launch, LinkError> {
    if secret.is_empty() {
        return Err(LinkError::NotConfigured);
    }
    if ticket.len() > MAX_TICKET_BYTES {
        return Err(LinkError::Invalid);
    }
    let (payload, sig) = ticket.rsplit_once('.').ok_or(LinkError::Invalid)?;
    let want = hmac_sha256_hex(secret, payload.as_bytes());
    if !crate::security::ct_eq(want.as_bytes(), sig.to_ascii_lowercase().as_bytes()) {
        return Err(LinkError::Invalid);
    }
    let raw = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| LinkError::Invalid)?;
    let c: Claims = serde_json::from_slice(&raw).map_err(|_| LinkError::Invalid)?;
    if c.v != 1 {
        return Err(LinkError::Invalid);
    }
    if c.exp <= now {
        return Err(LinkError::Expired);
    }
    if c.exp < c.iat || c.exp - c.iat > MAX_LINK_LIFETIME_SECS || c.iat > now + CLOCK_SKEW_SECS {
        return Err(LinkError::Invalid);
    }
    let bad = |ok: bool| if ok { Ok(()) } else { Err(LinkError::Invalid) };
    bad(valid_uuidish(&c.id) && valid_uuidish(&c.task))?;
    bad(valid_agent_id(&c.agent))?;
    bad(c.path.starts_with('/') && c.path.len() <= 1024 && !c.path.chars().any(char::is_control))?;
    bad(valid_return_url(&c.return_url))?;
    bad(c.prompt.chars().count() <= MAX_PROMPT_CHARS)?;
    let title = one_line(&c.title, 200).ok_or(LinkError::Invalid)?;
    let by = one_line(&c.by, 120).ok_or(LinkError::Invalid)?;
    let workspace = match c.ws {
        Some(w) => Some(one_line(&w, 120).ok_or(LinkError::Invalid)?),
        None => None,
    };
    Ok(Launch {
        id: c.id.to_ascii_lowercase(),
        task: c.task.to_ascii_lowercase(),
        num: c.num,
        title,
        path: c.path,
        agent: c.agent,
        prompt: clean_prompt(&c.prompt),
        by,
        return_url: c.return_url,
        workspace,
        exp: c.exp,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FolderError {
    #[error("opening a folder isn't allowed on this terminal (no local.allowed_roots)")]
    NoRoots,
    #[error("folder {0} doesn't exist on this machine")]
    NotFound(String),
    #[error("{0} isn't one of the folders this terminal may open")]
    NotAllowed(String),
}

/// Resolve a requested folder: it must exist, be a directory, and (after resolving symlinks)
/// lie inside one of `local.allowed_roots`.
pub fn resolve_folder(roots: &[PathBuf], requested: &str) -> Result<PathBuf, FolderError> {
    if roots.is_empty() {
        return Err(FolderError::NoRoots);
    }
    let p = Path::new(requested);
    if !p.is_absolute() || requested.chars().any(char::is_control) {
        return Err(FolderError::NotAllowed(requested.to_string()));
    }
    let real = std::fs::canonicalize(p).map_err(|_| FolderError::NotFound(requested.to_string()))?;
    if !real.is_dir() {
        return Err(FolderError::NotFound(requested.to_string()));
    }
    let inside = roots.iter().any(|r| {
        std::fs::canonicalize(r)
            .map(|root| real.starts_with(&root))
            .unwrap_or(false)
    });
    if inside {
        Ok(real)
    } else {
        Err(FolderError::NotAllowed(requested.to_string()))
    }
}

/// The agent a launch asks for. `shell` means none.
pub fn find_agent<'a>(cfg: &'a OpsapiConfig, id: &str) -> Result<Option<&'a AgentConfig>, String> {
    if id == "shell" {
        return Ok(None);
    }
    cfg.agents
        .iter()
        .find(|a| a.id == id)
        .map(Some)
        .ok_or_else(|| format!("the agent {id:?} isn't set up on this terminal"))
}

/// Ties a session to the OpsAPI launch it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchTag {
    pub id: String,
    pub task: String,
}

/// What `/api/launch` accepted, waiting for (or used by) a terminal session.
#[derive(Debug, Clone)]
pub struct Pending {
    pub user: String,
    pub launch: Launch,
    pub cwd: PathBuf,
    pub agent: Option<AgentConfig>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    #[error("this link was already used by someone else")]
    OtherUser,
}

/// Accepted launches, kept until shortly after they expire so each link works once.
#[derive(Default)]
pub struct LaunchStore {
    map: Mutex<HashMap<String, Pending>>,
}

impl LaunchStore {
    fn purge(map: &mut HashMap<String, Pending>, now: u64) {
        map.retain(|_, p| p.launch.exp + MAX_LINK_LIFETIME_SECS > now);
    }

    /// Record a verified launch for `user`. The same user posting the same link again gets the
    /// existing entry back (a page reload); another user is refused.
    pub fn accept(&self, p: Pending, now: u64) -> Result<Pending, ClaimError> {
        let mut map = self.map.lock().unwrap();
        Self::purge(&mut map, now);
        match map.get(&p.launch.id) {
            Some(existing) if existing.user != p.user => Err(ClaimError::OtherUser),
            Some(existing) => Ok(existing.clone()),
            None => {
                map.insert(p.launch.id.clone(), p.clone());
                Ok(p)
            }
        }
    }

    /// Claim an accepted, unused launch for `user` to open a session (atomically, so two tabs
    /// can't both use one link). None when it is unknown, someone else's or already used.
    /// Follow with [`Self::mark_used`] or, if opening failed, [`Self::release`].
    pub fn take_for_open(&self, id: &str, user: &str) -> Option<Pending> {
        let mut map = self.map.lock().unwrap();
        let p = map
            .get_mut(id)
            .filter(|p| p.user == user && p.session_id.is_none())?;
        p.session_id = Some(String::new()); // opening
        Some(p.clone())
    }

    pub fn mark_used(&self, id: &str, session_id: &str) {
        if let Some(p) = self.map.lock().unwrap().get_mut(id) {
            p.session_id = Some(session_id.to_string());
        }
    }

    pub fn release(&self, id: &str) {
        if let Some(p) = self.map.lock().unwrap().get_mut(id)
            && p.session_id.as_deref() == Some("")
        {
            p.session_id = None;
        }
    }
}

/// Environment for a launched shell. The prompt reaches the agent only through these variables,
/// so its text is never parsed as shell syntax.
pub fn launch_env(l: &Launch) -> Vec<(String, String)> {
    vec![
        ("OPSAPI_LAUNCH".into(), l.id.clone()),
        ("OPSAPI_TASK".into(), l.task.clone()),
        (
            "OPSAPI_TASK_NUMBER".into(),
            l.num.map(|n| n.to_string()).unwrap_or_default(),
        ),
        ("OPSAPI_TASK_TITLE".into(), l.title.clone()),
        ("OPSAPI_TASK_URL".into(), l.return_url.clone()),
        ("OPSAPI_TASK_PROMPT".into(), l.prompt.clone()),
    ]
}

/// Fire-and-forget HMAC-signed POST to OpsAPI for a launched session (a few retries).
/// No-op when the webhook isn't configured.
pub fn notify(
    cfg: &Config,
    event: &str,
    tag: &LaunchTag,
    session_id: &str,
    user: &str,
    exit_code: Option<u32>,
    reason: Option<&str>,
) {
    let o = &cfg.opsapi;
    let (Some(url), Some(secret)) = (
        o.webhook_url.as_deref().filter(|u| !u.is_empty()),
        o.webhook_secret.as_deref().filter(|s| !s.is_empty()),
    ) else {
        debug!("opsapi webhook not configured; skip");
        return;
    };
    let body = json!({
        "event": event,
        "launch": tag.id,
        "session_id": session_id,
        "user": user,
        "ts": unix_now(),
        "exit_code": exit_code,
        "reason": reason,
    })
    .to_string();
    let sig = hmac_sha256_hex(secret, body.as_bytes());
    let url = url.to_string();
    tokio::spawn(async move {
        for (attempt, wait) in [0u64, 2, 10].into_iter().enumerate() {
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
            }
            match post(&url, &body, &sig).await {
                Ok(()) => return,
                Err(e) => warn!(error = %e, attempt = attempt + 1, "opsapi webhook failed"),
            }
        }
    });
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// HMAC-SHA256 (RFC 2104) as lowercase hex.
pub fn hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut key = secret.as_bytes().to_vec();
    if key.len() > BLOCK {
        key = Sha256::digest(&key).to_vec();
    }
    key.resize(BLOCK, 0);
    let mut inner = Sha256::new();
    inner.update(key.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(body);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(key.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

async fn post(url: &str, body: &str, sig_hex: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let res = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Opsapi-Signature", format!("sha256={sig_hex}"))
        .header("User-Agent", "sshweb-opsapi-webhook")
        .body(body.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("status {}", res.status()));
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const SECRET: &str = "0123456789abcdef0123456789abcdef-test-secret";

    /// Mint a ticket the way OpsAPI does.
    pub fn mint(secret: &str, claims: serde_json::Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        let sig = hmac_sha256_hex(secret, payload.as_bytes());
        format!("{payload}.{sig}")
    }

    pub fn claims(now: u64, path: &str) -> serde_json::Value {
        json!({
            "v": 1, "id": "6f1c2a9e-1111-4c4c-9d9d-0123456789ab", "iat": now, "exp": now + 900,
            "task": "0b6c0e7e-2222-4c4c-9d9d-0123456789ab", "num": 12, "title": "Fix the header",
            "path": path, "agent": "claude", "prompt": "Do it\r\nwell\u{1b}[31m",
            "by": "Jane Doe", "return": "https://ops.example/dashboard/projects/p/tasks/t", "ws": "Acme"
        })
    }

    #[test]
    fn hmac_known_vectors() {
        assert_eq!(
            hmac_sha256_hex("", b""),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
        // RFC 4231 test case 2.
        assert_eq!(
            hmac_sha256_hex("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn valid_ticket_verifies_and_is_cleaned() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        assert_eq!(l.agent, "claude");
        assert_eq!(l.num, Some(12));
        assert_eq!(l.prompt, "Do it\nwell[31m", "CR and ESC dropped, newline kept");
        assert_eq!(l.tab_name(), "#12 Fix the header");
        assert_eq!(l.workspace.as_deref(), Some("Acme"));
    }

    #[test]
    fn tampered_wrong_key_expired_and_long_lived_links_are_refused() {
        let now = 1_800_000_000;
        let t = mint(SECRET, claims(now, "/srv/x"));
        assert_eq!(verify_ticket("another-secret-another-secret-xx", &t, now), Err(LinkError::Invalid));
        let (payload, sig) = t.rsplit_once('.').unwrap();
        let mut c = claims(now, "/srv/x");
        c["path"] = json!("/etc");
        let forged = format!("{}.{sig}", URL_SAFE_NO_PAD.encode(c.to_string()));
        assert_eq!(verify_ticket(SECRET, &forged, now), Err(LinkError::Invalid));
        assert_eq!(verify_ticket(SECRET, &format!("{payload}.00"), now), Err(LinkError::Invalid));
        assert_eq!(verify_ticket(SECRET, &t, now + 901), Err(LinkError::Expired));
        let mut long = claims(now, "/srv/x");
        long["exp"] = json!(now + MAX_LINK_LIFETIME_SECS + 1);
        assert_eq!(verify_ticket(SECRET, &mint(SECRET, long), now), Err(LinkError::Invalid));
        let mut future = claims(now + 3000, "/srv/x");
        future["exp"] = json!(now + 3500);
        assert_eq!(verify_ticket(SECRET, &mint(SECRET, future), now), Err(LinkError::Invalid));
        assert_eq!(verify_ticket("", &t, now), Err(LinkError::NotConfigured));
    }

    #[test]
    fn bad_fields_are_refused() {
        let now = 1_800_000_000;
        for (k, v) in [
            ("v", json!(2)),
            ("agent", json!("rm -rf /")),
            ("agent", json!("Claude")),
            ("path", json!("relative/path")),
            ("path", json!("/tmp/a\nb")),
            ("return", json!("javascript:alert(1)")),
            ("return", json!("https://x/\"><img src=x>")),
            ("title", json!("two\nlines")),
            ("id", json!("not a uuid!")),
            ("prompt", json!("x".repeat(MAX_PROMPT_CHARS + 1))),
        ] {
            let mut c = claims(now, "/srv/x");
            c[k] = v;
            assert_eq!(verify_ticket(SECRET, &mint(SECRET, c), now), Err(LinkError::Invalid), "{k}");
        }
    }

    #[test]
    fn folders_must_be_real_directories_inside_a_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("projects");
        let site = root.join("site");
        std::fs::create_dir_all(site.join("src")).unwrap();
        std::fs::write(root.join("notes.txt"), "x").unwrap();
        let outside = base.path().join("secret");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let roots = vec![root.clone()];
        let real_site = std::fs::canonicalize(&site).unwrap();
        assert_eq!(resolve_folder(&roots, site.to_str().unwrap()), Ok(real_site.clone()));
        assert_eq!(
            resolve_folder(&roots, &format!("{}/src/..", site.display())),
            Ok(real_site)
        );
        assert!(matches!(
            resolve_folder(&roots, root.join("escape").to_str().unwrap()),
            Err(FolderError::NotAllowed(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, &format!("{}/../secret", root.display())),
            Err(FolderError::NotAllowed(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, root.join("notes.txt").to_str().unwrap()),
            Err(FolderError::NotFound(_))
        ));
        assert!(matches!(
            resolve_folder(&roots, root.join("missing").to_str().unwrap()),
            Err(FolderError::NotFound(_))
        ));
        assert!(matches!(resolve_folder(&roots, "relative"), Err(FolderError::NotAllowed(_))));
        assert_eq!(resolve_folder(&[], "/tmp"), Err(FolderError::NoRoots));
    }

    #[test]
    fn launches_are_single_use_per_user() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        let store = LaunchStore::default();
        let p = Pending {
            user: "alice".into(),
            launch: l.clone(),
            cwd: "/srv/x".into(),
            agent: None,
            session_id: None,
        };
        store.accept(p.clone(), now).unwrap();
        assert_eq!(
            store.accept(Pending { user: "bob".into(), ..p.clone() }, now).err(),
            Some(ClaimError::OtherUser)
        );
        assert!(store.take_for_open(&l.id, "bob").is_none());
        assert!(store.take_for_open(&l.id, "alice").is_some());
        assert!(store.take_for_open(&l.id, "alice").is_none(), "claimed while opening");
        store.release(&l.id);
        assert!(store.take_for_open(&l.id, "alice").is_some(), "released after a failed open");
        store.mark_used(&l.id, "abc123");
        assert!(store.take_for_open(&l.id, "alice").is_none(), "used once");
        let again = store.accept(p, now).unwrap();
        assert_eq!(again.session_id.as_deref(), Some("abc123"), "reload finds the session");
        // Purged an hour after expiry.
        let later = l.exp + MAX_LINK_LIFETIME_SECS + 1;
        store.accept(Pending { user: "carol".into(), launch: l, cwd: "/srv/x".into(), agent: None, session_id: None }, later)
            .unwrap();
    }

    #[test]
    fn env_carries_the_task() {
        let now = 1_800_000_000;
        let l = verify_ticket(SECRET, &mint(SECRET, claims(now, "/srv/x")), now).unwrap();
        let env: HashMap<_, _> = launch_env(&l).into_iter().collect();
        assert_eq!(env["OPSAPI_TASK_NUMBER"], "12");
        assert_eq!(env["OPSAPI_TASK_PROMPT"], "Do it\nwell[31m");
        assert_eq!(env["OPSAPI_TASK_URL"], "https://ops.example/dashboard/projects/p/tasks/t");
    }
}
