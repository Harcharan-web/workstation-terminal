# Testing

## Automated

```sh
cargo test                                   # everything
cargo test --lib                             # unit tests
cargo test --test ws_terminal                # browser-equivalent client → real PTY
cargo test --test remote_ssh                 # gateway → disposable sshd (skips if /usr/sbin/sshd missing)
cargo test --test http_auth                  # login flow, origin/host, rate limits, lockout, revocation
cargo test --test tls                        # HTTPS mode (needs openssl + curl; skips otherwise)
cargo test --test cli                        # binary: config/keys/sign + real ssh-keygen interop
cargo fmt --check && cargo clippy --all-targets -- -D warnings
```

All tests use temporary directories and generated throwaway keys. No real credentials are read.

| Requirement | Where |
|---|---|
| Config parsing and validation | `config::tests`, `cli::validate_reports_unsafe_settings`, `cli::serve_refuses_unsafe_remote_exposure` |
| Public-key parsing and fingerprints | `auth::keys::tests`, `cli::config_init_validate_and_key_management` (matches `ssh-keygen -lf`) |
| SSH signature verification | `auth::challenge::tests`, `cli::ssh_keygen_signature_interoperates`, `cli::rsa_keys_supported_and_weak_rsa_rejected` |
| Challenge expiry and replay | `challenge_expiry`, `challenge_single_use`, `challenge_binding`, `full_login_flow_and_replay_prevention` |
| Authentication and authorisation | `http_auth.rs`, `sessions_are_bound_to_their_owner`, `profile_access_is_enforced`, `narrowing_access_closes_running_sessions` |
| Session lifecycle | `workspace_resume.rs` (resume after login expiry, rebinding, revocation of detached sessions, saved tabs), `session::tests`, `sessions_can_be_renamed_by_their_owner`, `reconnect_resumes_session_without_replaying_input`, `revoked_login_terminates_terminal`, `admin_can_list_and_revoke_sessions` |
| WebSocket message validation | `websocket::protocol::tests`, `malformed_messages_are_recoverable_errors` |
| Origin validation | `security::origin::tests`, `rejects_cross_site_websocket`, `state_changing_requests_require_origin`, `rejects_foreign_host_header` |
| PTY creation and teardown | `terminal::tests`, `explicit_close_kills_process`, `terminate_kills_process_group` |
| Resize | `pty_is_a_tty_and_resizes`, `resize_ctrl_c_and_tty_behaviour`, `trusted_host_gives_interactive_remote_shell` |
| Ctrl+C / Ctrl+D / Ctrl+Z | `ctrl_c_interrupts_foreground_process`, `ctrl_d_ends_cat`, `resize_ctrl_c_and_tty_behaviour` |
| Full-screen apps | `full_screen_application_uses_alternate_screen` (vim, alternate screen on/off) |
| Connection timeouts | `connection_timeout_is_enforced` |
| Host-key verification | `unknown_host_key_is_rejected`, `changed_host_key_is_rejected` |
| Rate limiting and lockout | `security::rate_limit::tests`, `challenge_rate_limit`, `lockout_after_repeated_failures` |
| Malformed and oversized input | `malformed_and_oversized_requests`, `oversized_message_closes_connection`, `too_many_protocol_errors_close_the_socket` |
| Graceful shutdown | `graceful_shutdown_closes_sessions_and_sockets`, `limits_enforced` |
| TLS | `https_mode_sets_secure_cookies_and_hsts` |

## Manual browser test procedure

Do this before each release, in Safari and Chrome. Use a throwaway key:

```sh
cargo build --release
export SSHWEB_HOME=$(mktemp -d)
./target/release/sshweb config init
ssh-keygen -q -t ed25519 -N '' -f "$SSHWEB_HOME/testkey"
./target/release/sshweb keys add --user tester --access local "$SSHWEB_HOME/testkey.pub"
./target/release/sshweb serve
```

1. **Login.** Open `http://127.0.0.1:7681/`, enter `tester`, put `$SSHWEB_HOME/testkey` in the key field
   and press *Get challenge*. Check the origin in the shown message. Run the command and paste.
   ✅ Signed in. ❌ Paste a signature from an older challenge: *authentication failed*.
2. **Shell.** Choose *This Mac*, then *Connect*. Run `echo $TERM` (expect `xterm-256color`), `ls --color`
   or `ls -G`, and `printf '\e[31mred\e[0m\n'`. ✅ Colours render.
3. **Full screen.** Run `vim`, type `ihello<Esc>`, `:q!`. Run `top` and quit with `q`. Run `less /etc/services` and quit with `q`.
   ✅ Alternate screen enters and exits cleanly, and the prompt is intact.
4. **Signals.** `sleep 100` then Ctrl+C returns to the prompt. `cat` then Ctrl+D ends cat.
   `sleep 100` then Ctrl+Z, then `fg`, then Ctrl+C.
5. **Resize.** Resize the window and run `stty size`. ✅ It matches the visible grid. Open `vim` and resize again. ✅ It redraws.
6. **Reconnect.** In the Wi-Fi menu, switch Wi-Fi off and on, or stop and restart the dev tools network.
   Alternatively kill the socket with `sshweb sessions list`, then close the tab and reopen it and attach
   from the *Sessions* list. ✅ Output is replayed and commands typed while disconnected are not executed.
7. **Disconnect / End session.** *Disconnect* leaves the session listed as `detached`. *End session* removes it,
   and `ps` shows no leftover shell.
8. **Exit.** Type `exit`. ✅ "[session closed: process exited, exit code 0]".
9. **Revocation.** While connected, run `sshweb keys revoke <fingerprint>`. ✅ Within about 5 s the terminal
   closes and the page returns to login.
10. **Theme and settings.** Toggle the theme, change the font size and check the *Settings* page lists permitted profiles.
11. **Cross-origin.** From another origin (e.g. `python3 -m http.server 8000` serving a page that opens
    `new WebSocket("ws://127.0.0.1:7681/ws")`). ✅ The browser console shows the handshake rejected (403).
12. **Shutdown.** Press Ctrl+C in the `serve` terminal. ✅ The page shows *server is shutting down* and no shell processes remain.

For remote mode, repeat 2–8 with a profile (see README → Remote SSH hosts).
