# sshweb: implementation plan and status

Single-binary SSH-over-Web gateway for macOS (Rust, Tokio, Axum, xterm.js).

## Key decisions

| Decision | Choice | Reason |
|---|---|---|
| Browser → gateway auth | OpenSSH `SSHSIG` challenge-response (`ssh-keygen -Y sign`), verified with RustCrypto `ssh-key` | Browsers can't reach `~/.ssh` or ssh-agent. `ssh-keygen -Y sign` works with key files, encrypted keys and the agent, and needs no custom helper. No private key touches the browser or gateway. |
| Remote SSH transport | System OpenSSH (`/usr/bin/ssh`) inside a gateway-owned PTY | Mature strict host-key checking against a managed `known_hosts`, agent and encrypted-key support, keepalives, resize via SIGWINCH. Arguments are an argv vector and never go through a shell. Allowed explicitly by the brief. Simpler and safer than re-implementing the client with `russh`. |
| PTY | `portable-pty` 0.9 | Maintained (wezterm), works on macOS, `setsid` + controlling TTY, so process-group kill works. |
| YAML | `serde_yaml_ng` | `serde_yaml` is unmaintained. |
| TLS | `axum-server` + `rustls` with the `ring` provider | No OpenSSL or cmake build dependency. |
| Frontend | Vanilla JS + vendored xterm.js 5.5.0 (UMD) embedded with `rust-embed` | No Node at build or run time, no framework. 5.5.0 is the last UMD build loadable with plain `<script>` under a strict CSP. |
| Admin interface | Unix socket `<state_dir>/admin.sock` (0600) | `sessions`/`health` CLI without exposing admin endpoints on TCP or inventing an admin token. |
| State | In memory | No database required. A restart logs everyone out (fail safe). |

## Phases

- [x] **Phase 0: Inspect.** The repo was empty (only `.serena/`). rustc 1.97, arm64, OpenSSH 10.3 present.
- [x] **Phase 1: Vertical slice.** Axum server, embedded UI, xterm.js, authenticated WebSocket, real PTY.
- [x] **Phase 2: SSH-key auth.** Authorisation file, SSHSIG challenge-response (HTTP and WebSocket variants), revocation, logins.
- [x] **Phase 3: Remote SSH.** Profiles, hardened OpenSSH argv, managed `known_hosts`, `hosts scan/trust`, ad-hoc allowlists.
- [x] **Phase 4: Security and reliability.** Rate limits, lockouts, idle/absolute expiry, Host/Origin checks, CSP, limits and backpressure, audit, metrics, graceful shutdown, root refusal, access re-enforcement.
- [x] **Phase 5: Release readiness.** 109 automated tests, docs, release, Intel and universal builds, install script, launchd agent.

## Verified status (2026-10-09, macOS 26 arm64, rustc 1.97.0)

| Check | Result |
|---|---|
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets -- -D warnings` | pass (0 warnings) |
| `cargo test` | 109 passed, 0 failed, run 4 times with no flakes (66 unit, 6 cli, 13 http_auth, 6 remote_ssh against a real sshd, 1 tls, 17 ws_terminal) |
| `cargo build --release` (aarch64) | pass, 6.6 MB, links only libSystem and libiconv |
| `cargo build --release --target x86_64-apple-darwin` | pass (not executed: Rosetta isn't installed on the build machine) |
| `lipo` universal binary | pass (x86_64 + arm64) |
| Release-binary smoke test | `config init` → `keys add` → `config validate` → `serve` → `/healthz`, `/readyz` → login with a real `ssh-keygen -Y sign` signature → replay refused (401) → `/api/me` → `sshweb health` → `sessions list` → SIGTERM shutdown → audit trail complete |

Issues found and fixed during verification:
- The admin socket path could exceed macOS's 104-byte `sun_path` limit, so `serve` failed to start. Config validation now catches it and suggests `server.state_dir`.
- The WebSocket's periodic login check refreshed the idle timer, so an idle open tab kept the login alive. Background checks no longer touch it.
- Narrowing a key's `access` didn't close already-running sessions. The housekeeping loop now enforces current access.
- A wildcard bind without `allowed_origins` produced a gateway no browser could use. It's now a validation error.

## Outstanding / future work

- [ ] **Real-browser automation.** No Chromium is installed and safaridriver needs admin enablement, so UI checks
      are manual (`docs/TESTING.md`). The browser-equivalent WebSocket client tests cover the protocol and PTY
      behaviour end to end.
- [ ] FIDO `sk-ssh-ed25519` / `sk-ecdsa` keys in `authorized_keys` (signing works with ssh-keygen; the verifier path isn't enabled yet).
- [ ] Optional native helper or browser extension for origin-bound signing (would remove the relay-phishing residual risk).
- [ ] Persisted lockout state across restarts.
- [ ] UI for ad-hoc remote targets (server support exists, off by default).
- [ ] Signed and notarized release artifacts.
