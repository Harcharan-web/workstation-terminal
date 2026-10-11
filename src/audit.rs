//! Append-only JSON-lines audit log. Never records terminal contents, tokens or signatures.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::{AuditConfig, AuditDestination};

pub struct AuditEvent {
    fields: Map<String, Value>,
}

impl AuditEvent {
    pub fn new(event: &str) -> Self {
        let mut fields = Map::new();
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();
        fields.insert("ts".into(), Value::String(ts));
        fields.insert("event".into(), Value::String(event.into()));
        Self { fields }
    }

    pub fn field(mut self, k: &str, v: &str) -> Self {
        self.fields.insert(k.into(), Value::String(sanitize(v)));
        self
    }

    pub fn num(mut self, k: &str, v: i64) -> Self {
        self.fields.insert(k.into(), Value::from(v));
        self
    }

    pub fn ip(self, ip: &str) -> Self {
        self.field("ip", ip)
    }

    pub fn user(self, u: &str) -> Self {
        self.field("user", u)
    }

    pub fn to_json(&self) -> String {
        Value::Object(self.fields.clone()).to_string()
    }
}

/// Bound field length and strip control characters so log lines cannot be forged.
fn sanitize(v: &str) -> String {
    v.chars().filter(|c| !c.is_control()).take(512).collect()
}

enum Sink {
    File(Mutex<File>),
    Stderr,
    Off,
}

pub struct Audit {
    sink: Sink,
}

impl Audit {
    pub fn open(cfg: &AuditConfig) -> std::io::Result<Self> {
        let sink = match cfg.destination {
            AuditDestination::File => Sink::File(Mutex::new(open_append(&cfg.path)?)),
            AuditDestination::Stderr => Sink::Stderr,
            AuditDestination::Off => Sink::Off,
        };
        Ok(Self { sink })
    }

    pub fn disabled() -> Self {
        Self { sink: Sink::Off }
    }

    pub fn log(&self, ev: AuditEvent) {
        let line = ev.to_json();
        // With a file or stderr sink the line is already persisted; keep the log quieter.
        if matches!(self.sink, Sink::Off) {
            tracing::info!(target: "audit", "{line}");
        } else {
            tracing::debug!(target: "audit", "{line}");
        }
        match &self.sink {
            Sink::File(f) => {
                let mut f = f.lock().unwrap();
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::error!(error = %e, "failed to write audit log");
                }
            }
            Sink::Stderr => eprintln!("{line}"),
            Sink::Off => {}
        }
    }
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_json_lines_and_sanitizes() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = AuditConfig {
            destination: AuditDestination::File,
            path: dir.path().join("audit.log"),
        };
        let a = Audit::open(&cfg).unwrap();
        a.log(AuditEvent::new("auth_failure").user("al\nice").num("n", 3));
        let text = std::fs::read_to_string(&cfg.path).unwrap();
        assert_eq!(text.lines().count(), 1);
        let v: Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(v["event"], "auth_failure");
        assert_eq!(v["user"], "alice");
        assert_eq!(v["n"], 3);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cfg.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
    }
}
