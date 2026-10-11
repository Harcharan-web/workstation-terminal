//! Per-user workspace: the browser's open terminal tabs, persisted on the server so that
//! re-opening the page (in any browser) restores them.
//!
//! A tab records *what* to run (target), the user's name for it, and the terminal session it
//! is currently showing. Sessions are not part of the workspace: when a tab's session has
//! ended, the client starts a fresh one for the same target. Nothing secret is stored here.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::auth::keys::valid_user;
use crate::security::perms;

pub const MAX_TABS: usize = 16;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workspace {
    #[serde(default)]
    pub tabs: Vec<Tab>,
    /// Id of the selected tab.
    #[serde(default)]
    pub active: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tab {
    /// Client-generated stable id.
    pub id: String,
    pub target: TabTarget,
    #[serde(default)]
    pub name: Option<String>,
    /// Session the tab was last showing, if any.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TabTarget {
    Local {
        #[serde(default)]
        shell: Option<String>,
    },
    Remote {
        profile: String,
    },
}

fn valid_tab_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

impl Workspace {
    /// Validate and normalise in place (names trimmed, empty names cleared).
    pub fn validate(&mut self) -> Result<(), String> {
        if self.tabs.len() > MAX_TABS {
            return Err(format!("at most {MAX_TABS} tabs"));
        }
        let mut seen = std::collections::HashSet::new();
        for t in &mut self.tabs {
            if !valid_tab_id(&t.id) {
                return Err("invalid tab id".into());
            }
            if !seen.insert(t.id.clone()) {
                return Err("duplicate tab id".into());
            }
            t.name = match &t.name {
                Some(n) => crate::session::normalize_name(n).map_err(str::to_string)?,
                None => None,
            };
            if let Some(sid) = &t.session_id
                && (sid.is_empty() || sid.len() > 64 || !sid.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err("invalid session id".into());
            }
            match &t.target {
                TabTarget::Local { shell: Some(s) } if s.len() > 256 || !s.starts_with('/') => {
                    return Err("invalid shell".into());
                }
                TabTarget::Remote { profile } if !crate::ssh::valid_profile_id(profile) => {
                    return Err("invalid profile".into());
                }
                _ => {}
            }
        }
        if let Some(a) = &self.active
            && !self.tabs.iter().any(|t| &t.id == a)
        {
            self.active = None;
        }
        Ok(())
    }
}

/// Stores one JSON file per user in a private directory.
pub struct WorkspaceStore {
    dir: PathBuf,
    write_lock: Mutex<()>,
}

impl WorkspaceStore {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            write_lock: Mutex::new(()),
        }
    }

    fn path(&self, user: &str) -> Option<PathBuf> {
        // User names are validated, so they are safe as file names.
        valid_user(user).then(|| self.dir.join(format!("{user}.json")))
    }

    /// The user's saved workspace; empty if none, or if the stored file is unreadable.
    pub fn load(&self, user: &str) -> Workspace {
        let Some(p) = self.path(user) else {
            return Workspace::default();
        };
        let Ok(text) = std::fs::read_to_string(&p) else {
            return Workspace::default();
        };
        let parsed = serde_json::from_str::<Workspace>(&text)
            .ok()
            .and_then(|mut w| w.validate().is_ok().then_some(w));
        match parsed {
            Some(w) => w,
            None => {
                tracing::warn!(path = %p.display(), "ignoring invalid workspace file");
                Workspace::default()
            }
        }
    }

    pub fn save(&self, user: &str, ws: &Workspace) -> std::io::Result<()> {
        let p = self
            .path(user)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid user"))?;
        let _guard = self.write_lock.lock().unwrap();
        perms::ensure_private_dir(&self.dir)?;
        let tmp = tmp_path(&p);
        let json = serde_json::to_vec_pretty(ws).map_err(std::io::Error::other)?;
        perms::write_new_file(&tmp, &json, 0o600, true)?;
        std::fs::rename(&tmp, &p)
    }
}

fn tmp_path(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(id: &str) -> Tab {
        Tab {
            id: id.into(),
            target: TabTarget::Local { shell: None },
            name: None,
            session_id: None,
        }
    }

    #[test]
    fn validates_and_normalises() {
        let mut w = Workspace {
            tabs: vec![
                Tab {
                    name: Some("  build  ".into()),
                    ..tab("a")
                },
                Tab {
                    name: Some("   ".into()),
                    ..tab("b")
                },
            ],
            active: Some("zzz".into()),
        };
        w.validate().unwrap();
        assert_eq!(w.tabs[0].name.as_deref(), Some("build"));
        assert_eq!(w.tabs[1].name, None);
        assert_eq!(w.active, None, "unknown active tab is dropped");
    }

    #[test]
    fn rejects_bad_input() {
        let bad = [
            Workspace {
                tabs: (0..17).map(|i| tab(&i.to_string())).collect(),
                active: None,
            },
            Workspace {
                tabs: vec![tab("a"), tab("a")],
                active: None,
            },
            Workspace {
                tabs: vec![tab("../x")],
                active: None,
            },
            Workspace {
                tabs: vec![Tab {
                    session_id: Some("../../etc".into()),
                    ..tab("a")
                }],
                active: None,
            },
            Workspace {
                tabs: vec![Tab {
                    target: TabTarget::Remote {
                        profile: "-oX".into(),
                    },
                    ..tab("a")
                }],
                active: None,
            },
            Workspace {
                tabs: vec![Tab {
                    target: TabTarget::Local {
                        shell: Some("zsh".into()),
                    },
                    ..tab("a")
                }],
                active: None,
            },
            Workspace {
                tabs: vec![Tab {
                    name: Some("a\u{7}b".into()),
                    ..tab("a")
                }],
                active: None,
            },
        ];
        for mut w in bad {
            assert!(w.validate().is_err(), "{w:?}");
        }
        assert!(serde_json::from_str::<Workspace>(r#"{"tabs":[],"extra":1}"#).is_err());
    }

    #[test]
    fn save_and_load_roundtrip_privately() {
        let d = tempfile::tempdir().unwrap();
        let store = WorkspaceStore::new(d.path().join("ws"));
        assert_eq!(store.load("alice"), Workspace::default());
        let w = Workspace {
            tabs: vec![Tab {
                target: TabTarget::Remote {
                    profile: "web1".into(),
                },
                name: Some("prod".into()),
                session_id: Some("abcdef01".into()),
                ..tab("t1")
            }],
            active: Some("t1".into()),
        };
        store.save("alice", &w).unwrap();
        assert_eq!(store.load("alice"), w);
        assert_eq!(store.load("bob"), Workspace::default(), "per user");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(d.path().join("ws/alice.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0);
        assert!(store.save("../evil", &w).is_err());
        std::fs::write(d.path().join("ws/alice.json"), "corrupt").unwrap();
        assert_eq!(store.load("alice"), Workspace::default());
    }
}
