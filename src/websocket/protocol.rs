//! Versioned WebSocket protocol (v1). See docs/PROTOCOL.md.
//!
//! Client → server: JSON text frames ([`ClientMsg`]). Binary frames are rejected.
//! Server → client: JSON text frames ([`ServerMsg`]) for control, and binary frames that
//! carry raw terminal output bytes for the bound session.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMsg {
    Hello {
        version: u32,
    },
    AuthRequest {
        user: String,
    },
    AuthResponse {
        challenge_id: String,
        signature: String,
    },
    Open {
        target: OpenTarget,
        cols: u16,
        rows: u16,
        /// Initial session name (e.g. the restored tab's name).
        #[serde(default)]
        name: Option<String>,
        /// Id of a launch accepted by `POST /api/launch` (OpsAPI task link). The folder, agent
        /// and task come from the verified launch, never from this message.
        #[serde(default)]
        launch: Option<String>,
    },
    Attach {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    Input {
        data: String,
        /// When true, each char in `data` is a byte value 0-255 (xterm.js `onBinary`).
        #[serde(default)]
        binary: bool,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Detach,
    Close,
    Ping {
        #[serde(default)]
        ts: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpenTarget {
    Local {
        #[serde(default)]
        shell: Option<String>,
        /// Start in this folder; it must be inside `local.allowed_roots`.
        #[serde(default)]
        cwd: Option<String>,
    },
    Remote {
        profile: String,
    },
    Adhoc {
        host: String,
        #[serde(default = "default_port")]
        port: u16,
        user: String,
    },
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    Hello {
        version: u32,
        server: &'static str,
        authenticated: bool,
        user: Option<String>,
    },
    AuthChallenge {
        challenge_id: String,
        namespace: &'static str,
        message: String,
        expires_unix: u64,
    },
    AuthOk {
        user: String,
        expires_unix: u64,
    },
    AuthFailed {
        code: &'static str,
        message: String,
    },
    SessionOpened {
        session_id: String,
        kind: &'static str,
        title: String,
        name: Option<String>,
        resumed: bool,
    },
    SessionClosed {
        session_id: String,
        reason: String,
        exit_code: Option<u32>,
    },
    Status {
        state: &'static str,
        message: String,
    },
    Pong {
        ts: Option<u64>,
    },
    Error {
        code: &'static str,
        message: String,
        fatal: bool,
    },
}

impl ServerMsg {
    pub fn error(code: &'static str, message: impl Into<String>, fatal: bool) -> Self {
        ServerMsg::Error {
            code,
            message: message.into(),
            fatal,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("ServerMsg serialises")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("message too large")]
    TooLarge,
    #[error("malformed message: {0}")]
    Malformed(String),
    #[error("invalid field: {0}")]
    Invalid(&'static str),
}

pub const MAX_ID_LEN: usize = 128;

/// Parse and validate a client message.
pub fn decode(text: &str, max_bytes: usize) -> Result<ClientMsg, DecodeError> {
    if text.len() > max_bytes {
        return Err(DecodeError::TooLarge);
    }
    let msg: ClientMsg = serde_json::from_str(text).map_err(|e| {
        // serde messages can echo input; keep them short.
        let mut s = e.to_string();
        s.truncate(120);
        DecodeError::Malformed(s)
    })?;
    validate(&msg)?;
    Ok(msg)
}

fn size_ok(cols: u16, rows: u16) -> bool {
    (1..=crate::terminal::MAX_COLS).contains(&cols)
        && (1..=crate::terminal::MAX_ROWS).contains(&rows)
}

fn validate(m: &ClientMsg) -> Result<(), DecodeError> {
    match m {
        ClientMsg::AuthRequest { user } if user.len() > 32 => Err(DecodeError::Invalid("user")),
        ClientMsg::AuthResponse { challenge_id, .. } if challenge_id.len() > MAX_ID_LEN => {
            Err(DecodeError::Invalid("challenge_id"))
        }
        ClientMsg::Open {
            cols,
            rows,
            target,
            name,
            launch,
        } => {
            if !size_ok(*cols, *rows) {
                return Err(DecodeError::Invalid("size"));
            }
            if name
                .as_deref()
                .is_some_and(|n| crate::session::normalize_name(n).is_err())
            {
                return Err(DecodeError::Invalid("name"));
            }
            if launch.as_deref().is_some_and(|t| {
                t.is_empty()
                    || t.len() > 64
                    || !t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            }) {
                return Err(DecodeError::Invalid("launch"));
            }
            match target {
                OpenTarget::Local { shell: Some(s), .. } if s.len() > 256 => {
                    Err(DecodeError::Invalid("shell"))
                }
                OpenTarget::Local { cwd: Some(c), .. }
                    if c.len() > 1024 || !c.starts_with('/') || c.chars().any(char::is_control) =>
                {
                    Err(DecodeError::Invalid("cwd"))
                }
                OpenTarget::Remote { profile } if !crate::ssh::valid_profile_id(profile) => {
                    Err(DecodeError::Invalid("profile"))
                }
                _ => Ok(()),
            }
        }
        ClientMsg::Attach {
            session_id,
            cols,
            rows,
        } => {
            if session_id.len() > MAX_ID_LEN || !session_id.chars().all(|c| c.is_ascii_hexdigit()) {
                Err(DecodeError::Invalid("session_id"))
            } else if !size_ok(*cols, *rows) {
                Err(DecodeError::Invalid("size"))
            } else {
                Ok(())
            }
        }
        ClientMsg::Resize { cols, rows } if !size_ok(*cols, *rows) => {
            Err(DecodeError::Invalid("size"))
        }
        ClientMsg::Input { data, binary: true } if data.chars().any(|c| c as u32 > 255) => {
            Err(DecodeError::Invalid("binary data"))
        }
        _ => Ok(()),
    }
}

/// Bytes to write to the PTY for an input message.
pub fn input_bytes(data: String, binary: bool) -> bytes::Bytes {
    if binary {
        data.chars()
            .map(|c| c as u32 as u8)
            .collect::<Vec<u8>>()
            .into()
    } else {
        data.into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_valid_messages() {
        assert_eq!(
            decode(r#"{"type":"hello","version":1}"#, 1024).unwrap(),
            ClientMsg::Hello { version: 1 }
        );
        assert_eq!(
            decode(r#"{"type":"input","data":"ls\r"}"#, 1024).unwrap(),
            ClientMsg::Input {
                data: "ls\r".into(),
                binary: false
            }
        );
        assert_eq!(
            decode(r#"{"type":"close"}"#, 1024).unwrap(),
            ClientMsg::Close
        );
        assert!(matches!(
            decode(r#"{"type":"open","target":{"kind":"remote","profile":"web1"},"cols":80,"rows":24}"#, 1024).unwrap(),
            ClientMsg::Open { target: OpenTarget::Remote { .. }, .. }
        ));
        assert!(matches!(
            decode(
                r#"{"type":"open","target":{"kind":"local"},"cols":80,"rows":24}"#,
                1024
            )
            .unwrap(),
            ClientMsg::Open {
                target: OpenTarget::Local {
                    shell: None,
                    cwd: None
                },
                ..
            }
        ));
    }

    #[test]
    fn rejects_malformed_and_invalid() {
        let bad = [
            "",
            "not json",
            "[]",
            r#"{"type":"nope"}"#,
            r#"{"type":"hello"}"#,
            r#"{"type":"hello","version":1,"extra":true}"#,
            r#"{"type":"input","data":5}"#,
            r#"{"type":"resize","cols":0,"rows":24}"#,
            r#"{"type":"resize","cols":80,"rows":-1}"#,
            r#"{"type":"resize","cols":5000,"rows":24}"#,
            r#"{"type":"open","target":{"kind":"remote","profile":"-oProxyCommand"},"cols":80,"rows":24}"#,
            r#"{"type":"open","target":{"kind":"shell","cmd":"rm"},"cols":80,"rows":24}"#,
            r#"{"type":"attach","session_id":"../../x","cols":80,"rows":24}"#,
            r#"{"type":"input","data":"Ā","binary":true}"#,
        ];
        for b in bad {
            assert!(decode(b, 1024).is_err(), "should reject {b}");
        }
    }

    #[test]
    fn rejects_oversized() {
        let big = format!(r#"{{"type":"input","data":"{}"}}"#, "a".repeat(2000));
        assert_eq!(decode(&big, 1024).unwrap_err(), DecodeError::TooLarge);
    }

    #[test]
    fn binary_input_maps_bytes() {
        assert_eq!(&input_bytes("\u{1b}\u{ff}".into(), true)[..], &[0x1b, 0xff]);
        assert_eq!(&input_bytes("é".into(), false)[..], "é".as_bytes());
    }

    #[test]
    fn server_messages_serialise_with_type_tag() {
        let j = ServerMsg::error("x", "y", true).to_json();
        assert_eq!(
            j,
            r#"{"type":"error","code":"x","message":"y","fatal":true}"#
        );
    }
}
