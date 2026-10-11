//! Command-line interface.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use ssh_key::PublicKey;

use crate::audit::{Audit, AuditEvent};
use crate::auth::keys::{self, Access, AuthorizedKeys};
use crate::config::{self, Config, LogFormat};
use crate::security::perms;

#[derive(Parser)]
#[command(
    name = "sshweb",
    version,
    about = "SSH-over-Web gateway: a browser terminal for this Mac and authorised SSH hosts",
    after_help = "Quick start:\n  sshweb config init\n  sshweb keys add --user $USER --access local ~/.ssh/id_ed25519.pub\n  sshweb serve\n  open http://127.0.0.1:7681/"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct ConfigArg {
    /// Configuration file [default: $SSHWEB_HOME/config.yaml or ~/.sshweb/config.yaml]
    #[arg(long, short = 'c', env = "SSHWEB_CONFIG", global = true)]
    config: Option<PathBuf>,
}

impl ConfigArg {
    fn path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(config::default_config_path)
    }
    fn load(&self) -> Result<Config> {
        Config::load(&self.path())
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run the gateway (foreground; stops on SIGINT/SIGTERM)
    Serve(ConfigArg),
    /// Create, validate or show configuration
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Inspect and manage authorised public keys (works offline)
    #[command(subcommand)]
    Keys(KeysCmd),
    /// Manage trusted SSH host keys for remote profiles
    #[command(subcommand)]
    Hosts(HostsCmd),
    /// List or revoke sessions on the running server (via the local admin socket)
    #[command(subcommand)]
    Sessions(SessionsCmd),
    /// Check the running server's health (exit code 0 when ready)
    Health(ConfigArg),
    /// Sign a login challenge with ssh-keygen (helper for the browser login)
    Sign {
        /// Private key, or its .pub file when the key is held by ssh-agent
        #[arg(long, short = 'f', default_value = "~/.ssh/id_ed25519")]
        key: String,
        /// Challenge message; read from stdin when omitted
        message: Option<String>,
    },
    /// Print version information
    Version,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Create a config directory with a sample config and empty key files
    Init {
        /// Directory to create [default: ~/.sshweb]
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Overwrite an existing config.yaml
        #[arg(long)]
        force: bool,
    },
    /// Validate configuration and referenced files without starting the server
    Validate(ConfigArg),
    /// Print the effective configuration (after env overrides and path resolution)
    Show(ConfigArg),
}

#[derive(Subcommand)]
enum KeysCmd {
    /// List authorised keys with users, access and fingerprints
    List(ConfigArg),
    /// Print the SHA256 fingerprint of a public key file
    Fingerprint {
        /// Public key file (OpenSSH format), or - for stdin
        file: PathBuf,
    },
    /// Authorise a public key for a user (administrator action)
    Add {
        #[arg(long)]
        user: String,
        /// Comma list: local, remote:*, remote:<profile-id>
        #[arg(long)]
        access: String,
        /// Public key file (OpenSSH format), or - for stdin
        file: PathBuf,
        #[command(flatten)]
        cfg: ConfigArg,
    },
    /// Revoke a key by fingerprint; active logins using it are terminated
    Revoke {
        /// SHA256:... fingerprint as shown by `keys list`
        fingerprint: String,
        #[command(flatten)]
        cfg: ConfigArg,
    },
}

#[derive(Subcommand)]
enum HostsCmd {
    /// List trusted host keys
    List(ConfigArg),
    /// Fetch and display a profile's host key fingerprints (does not trust them)
    Scan {
        profile: String,
        #[command(flatten)]
        cfg: ConfigArg,
    },
    /// Trust a profile's host key, confirmed by fingerprint or supplied as a file
    Trust {
        profile: String,
        /// Expected SHA256 fingerprint obtained out of band
        #[arg(
            long,
            conflicts_with = "key_file",
            required_unless_present = "key_file"
        )]
        fingerprint: Option<String>,
        /// Host public key file obtained out of band (e.g. ssh_host_ed25519_key.pub)
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[command(flatten)]
        cfg: ConfigArg,
    },
}

#[derive(Subcommand)]
enum SessionsCmd {
    /// List terminal sessions and browser logins
    List(ConfigArg),
    /// Revoke a terminal session or a login by id
    Revoke {
        id: String,
        #[command(flatten)]
        cfg: ConfigArg,
    },
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Serve(c) => {
            if perms::current_uid() == 0 {
                bail!(
                    "refusing to run as root: run sshweb as an ordinary macOS user (terminals run as that user)"
                );
            }
            let path = c.path();
            let cfg = c.load()?;
            init_logging(&cfg);
            tracing::info!(config = %path.display(), version = env!("CARGO_PKG_VERSION"), "starting sshweb");
            if let Err(e) = perms::check_admin_file(&path) {
                bail!("config file: {e}");
            }
            cfg.validate()?;
            let audit = Audit::open(&cfg.audit)
                .with_context(|| format!("cannot open audit log {}", cfg.audit.path.display()))?;
            runtime()?.block_on(crate::server::serve(cfg, audit))?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Config(cmd) => config_cmd(cmd),
        Command::Keys(cmd) => keys_cmd(cmd),
        Command::Hosts(cmd) => runtime()?.block_on(hosts_cmd(cmd)),
        Command::Sessions(cmd) => runtime()?.block_on(sessions_cmd(cmd)),
        Command::Health(c) => {
            let cfg = c.load()?;
            let (status, body) = runtime()?.block_on(crate::admin_client::request(
                &cfg.admin_socket_path(),
                hyper::Method::GET,
                "/healthz",
            ))?;
            println!("{body}");
            let ready = status.is_success() && body.contains("\"status\":\"ready\"");
            Ok(if ready {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Command::Sign { key, message } => sign(&key, message),
        Command::Version => {
            println!(
                "sshweb {} ({} {})",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn init_logging(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("RUST_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.logging.level));
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match cfg.logging.format {
        LogFormat::Json => b.json().init(),
        LogFormat::Pretty => b.init(),
    }
}

const AUTHORIZED_KEYS_HEADER: &str = "\
# sshweb authorised keys. One key per line:
#   user=\"alice\",access=\"local,remote:web1\" ssh-ed25519 AAAA... comment
# access items: local | remote:* | remote:<profile-id>
# Manage with `sshweb keys add` / `sshweb keys revoke`. Only public keys belong here.
";

fn config_cmd(cmd: ConfigCmd) -> Result<ExitCode> {
    match cmd {
        ConfigCmd::Init { dir, force } => {
            let dir = dir.unwrap_or_else(config::default_config_dir);
            perms::ensure_private_dir(&dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
            let cfg_path = dir.join("config.yaml");
            if cfg_path.exists() && !force {
                bail!(
                    "{} already exists (use --force to overwrite)",
                    cfg_path.display()
                );
            }
            perms::write_new_file(&cfg_path, config::SAMPLE_CONFIG.as_bytes(), 0o600, force)?;
            println!("wrote {}", cfg_path.display());
            for (name, contents) in [
                ("authorized_keys", AUTHORIZED_KEYS_HEADER),
                (
                    "known_hosts",
                    "# Trusted host keys for remote profiles. Use `sshweb hosts trust`.\n",
                ),
            ] {
                let p = dir.join(name);
                if !p.exists() {
                    perms::write_new_file(&p, contents.as_bytes(), 0o600, false)?;
                    println!("wrote {}", p.display());
                }
            }
            perms::ensure_private_dir(&dir.join("run"))?;
            println!(
                "\nNext steps:\n  sshweb keys add --user {} --access local ~/.ssh/id_ed25519.pub\n  sshweb config validate\n  sshweb serve",
                std::env::var("USER")
                    .ok()
                    .filter(|u| keys::valid_user(u))
                    .unwrap_or_else(|| "alice".into())
            );
            Ok(ExitCode::SUCCESS)
        }
        ConfigCmd::Validate(c) => {
            let path = c.path();
            let cfg = c.load()?;
            let mut errs = Vec::new();
            if let Err(e) = perms::check_admin_file(&path) {
                errs.push(format!("config file: {e}"));
            }
            errs.extend(cfg.validate_static());
            errs.extend(cfg.validate_files());
            if let Ok(text) = std::fs::read_to_string(&cfg.auth.authorized_keys)
                && let Err(perrs) = AuthorizedKeys::parse(&text, cfg.auth.min_rsa_bits)
            {
                for e in perrs {
                    errs.push(format!("{}: {e}", cfg.auth.authorized_keys.display()));
                }
            }
            if errs.is_empty() {
                println!("configuration OK: {}", path.display());
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!("configuration has {} problem(s):", errs.len());
                for e in errs {
                    eprintln!("  - {e}");
                }
                Ok(ExitCode::from(2))
            }
        }
        ConfigCmd::Show(c) => {
            let cfg = c.load()?;
            print!("{}", serde_yaml_ng::to_string(&cfg)?);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read_input(file: &Path) -> Result<String> {
    if file == Path::new("-") {
        let mut s = String::new();
        std::io::stdin().take(64 * 1024).read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))
    }
}

fn parse_public_key(text: &str) -> Result<PublicKey> {
    let t = text.trim();
    if t.contains("PRIVATE KEY") {
        bail!(
            "this is a PRIVATE key; supply the .pub file instead (private keys are never needed)"
        );
    }
    let line = t
        .lines()
        .find(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .unwrap_or("");
    PublicKey::from_openssh(line.trim()).context("not a valid OpenSSH public key")
}

fn admin_audit(cfg: &Config) -> Audit {
    Audit::open(&cfg.audit).unwrap_or_else(|e| {
        eprintln!("warning: cannot open audit log ({e}); action not audited");
        Audit::disabled()
    })
}

fn invoking_user() -> String {
    std::env::var("USER").unwrap_or_else(|_| format!("uid:{}", perms::current_uid()))
}

fn keys_cmd(cmd: KeysCmd) -> Result<ExitCode> {
    match cmd {
        KeysCmd::Fingerprint { file } => {
            let key = parse_public_key(&read_input(&file)?)?;
            println!(
                "{} {} {}",
                keys::fingerprint(&key),
                key.algorithm(),
                if key.comment().is_empty() {
                    "(no comment)"
                } else {
                    key.comment()
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        KeysCmd::List(c) => {
            let cfg = c.load()?;
            let path = &cfg.auth.authorized_keys;
            if let Err(e) = perms::check_admin_file(path) {
                eprintln!("warning: {e}");
            }
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;
            match AuthorizedKeys::parse(&text, cfg.auth.min_rsa_bits) {
                Ok(ak) => {
                    if ak.keys.is_empty() {
                        println!("no authorised keys in {}", path.display());
                    }
                    for k in &ak.keys {
                        println!(
                            "{:<16} {:<28} {} {} {}",
                            k.user,
                            k.access.to_string(),
                            k.fingerprint,
                            k.key.algorithm(),
                            k.key.comment()
                        );
                    }
                    Ok(ExitCode::SUCCESS)
                }
                Err(errs) => {
                    eprintln!(
                        "{} is invalid (all logins are rejected until fixed):",
                        path.display()
                    );
                    for e in errs {
                        eprintln!("  - {e}");
                    }
                    Ok(ExitCode::from(2))
                }
            }
        }
        KeysCmd::Add {
            user,
            access,
            file,
            cfg,
        } => {
            let cfg = cfg.load()?;
            if !keys::valid_user(&user) {
                bail!("invalid user name {user:?} (lowercase letters, digits, _ . -; max 32)");
            }
            let access = Access::parse(&access).map_err(anyhow::Error::msg)?;
            let key = parse_public_key(&read_input(&file)?)?;
            keys::check_key_strength(key.key_data(), cfg.auth.min_rsa_bits)
                .map_err(anyhow::Error::msg)?;
            let path = &cfg.auth.authorized_keys;
            perms::check_admin_file(path).map_err(anyhow::Error::msg)?;
            let existing = std::fs::read_to_string(path)?;
            let ak = AuthorizedKeys::parse(&existing, cfg.auth.min_rsa_bits).map_err(|errs| {
                anyhow::anyhow!(
                    "{} is invalid; fix it first: {}",
                    path.display(),
                    errs.iter()
                        .map(|e| e.to_string())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            })?;
            let fp = keys::fingerprint(&key);
            if let Some(k) = ak.by_fingerprint(&fp) {
                bail!(
                    "key {fp} is already authorised for user {} (line {})",
                    k.user,
                    k.line
                );
            }
            let line = format!("user=\"{user}\",access=\"{access}\" {}", key.to_openssh()?);
            keys::parse_line(&line, 0, cfg.auth.min_rsa_bits).map_err(anyhow::Error::msg)?;
            let mut text = existing;
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&line);
            text.push('\n');
            atomic_write(path, &text)?;
            admin_audit(&cfg).log(
                AuditEvent::new("admin_key_add")
                    .field("admin", &invoking_user())
                    .user(&user)
                    .field("key", &fp)
                    .field("access", &access.to_string()),
            );
            println!("authorised {fp} for {user} ({access})");
            Ok(ExitCode::SUCCESS)
        }
        KeysCmd::Revoke { fingerprint, cfg } => {
            let cfg = cfg.load()?;
            let path = &cfg.auth.authorized_keys;
            perms::check_admin_file(path).map_err(anyhow::Error::msg)?;
            let text = std::fs::read_to_string(path)?;
            let mut out = String::new();
            let mut revoked = Vec::new();
            for (i, line) in text.lines().enumerate() {
                match keys::parse_line(line, i + 1, 0) {
                    Ok(Some(k)) if k.fingerprint == fingerprint => {
                        revoked.push(k.user.clone());
                        let ts = time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default();
                        out.push_str(&format!("# revoked {ts}: {line}\n"));
                    }
                    _ => {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
            }
            if revoked.is_empty() {
                bail!("no authorised key with fingerprint {fingerprint}");
            }
            atomic_write(path, &out)?;
            admin_audit(&cfg).log(
                AuditEvent::new("admin_key_revoke")
                    .field("admin", &invoking_user())
                    .user(&revoked.join(","))
                    .field("key", &fingerprint),
            );
            println!(
                "revoked {fingerprint} (user {}); a running server terminates its logins within seconds",
                revoked.join(",")
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Replace a file atomically, preserving its permissions.
fn atomic_write(path: &Path, text: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|f| f.to_str()).unwrap_or("f"),
        std::process::id()
    ));
    perms::write_new_file(&tmp, text.as_bytes(), mode & 0o644, true)?;
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}

fn find_profile<'a>(cfg: &'a Config, id: &str) -> Result<&'a config::RemoteProfile> {
    cfg.remote
        .profiles
        .iter()
        .find(|p| p.id == id)
        .with_context(|| format!("no remote profile {id:?} in the configuration"))
}

async fn hosts_cmd(cmd: HostsCmd) -> Result<ExitCode> {
    use crate::ssh::known_hosts;
    match cmd {
        HostsCmd::List(c) => {
            let cfg = c.load()?;
            let text = std::fs::read_to_string(&cfg.remote.known_hosts)
                .with_context(|| format!("cannot read {}", cfg.remote.known_hosts.display()))?;
            let entries = known_hosts::parse_known_hosts(&text);
            if entries.is_empty() {
                println!(
                    "no trusted host keys in {}",
                    cfg.remote.known_hosts.display()
                );
            }
            for e in entries {
                println!(
                    "{}{:<32} {} {}",
                    e.marker.map(|m| format!("{m} ")).unwrap_or_default(),
                    e.hosts,
                    e.fingerprint,
                    e.key.algorithm()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        HostsCmd::Scan { profile, cfg } => {
            let cfg = cfg.load()?;
            let p = find_profile(&cfg, &profile)?;
            let keys = known_hosts::scan(
                &cfg.remote.ssh_keyscan_binary,
                &p.host,
                p.port,
                Duration::from_secs(cfg.remote.connect_timeout_secs),
            )
            .await?;
            println!("Host keys offered by {}:{} (NOT verified):", p.host, p.port);
            for k in keys {
                println!("  {} {}", keys::fingerprint(&k), k.algorithm());
            }
            println!(
                "\nCompare with the server's real fingerprint (e.g. run `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on it), then:\n  sshweb hosts trust {profile} --fingerprint SHA256:..."
            );
            Ok(ExitCode::SUCCESS)
        }
        HostsCmd::Trust {
            profile,
            fingerprint,
            key_file,
            cfg,
        } => {
            let cfg = cfg.load()?;
            let p = find_profile(&cfg, &profile)?;
            let key = match (fingerprint, key_file) {
                (_, Some(f)) => parse_public_key(&read_input(&f)?)?,
                (Some(fp), None) => {
                    let keys = known_hosts::scan(
                        &cfg.remote.ssh_keyscan_binary,
                        &p.host,
                        p.port,
                        Duration::from_secs(cfg.remote.connect_timeout_secs),
                    )
                    .await?;
                    let offered: Vec<String> = keys.iter().map(keys::fingerprint).collect();
                    keys.into_iter()
                        .find(|k| keys::fingerprint(k) == fp)
                        .with_context(|| {
                            format!(
                                "host did not offer a key with fingerprint {fp}; offered: {} — NOT trusting anything",
                                offered.join(", ")
                            )
                        })?
                }
                (None, None) => unreachable!("clap requires one"),
            };
            let added = known_hosts::add_trusted(&cfg.remote.known_hosts, &p.host, p.port, &key)?;
            let fp = keys::fingerprint(&key);
            if added {
                admin_audit(&cfg).log(
                    AuditEvent::new("admin_host_trust")
                        .field("admin", &invoking_user())
                        .field("profile", &profile)
                        .field("host", &known_hosts::host_pattern(&p.host, p.port))
                        .field("key", &fp),
                );
                println!(
                    "trusted {fp} for {}",
                    known_hosts::host_pattern(&p.host, p.port)
                );
            } else {
                println!(
                    "{fp} is already trusted for {}",
                    known_hosts::host_pattern(&p.host, p.port)
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn sessions_cmd(cmd: SessionsCmd) -> Result<ExitCode> {
    match cmd {
        SessionsCmd::List(c) => {
            let cfg = c.load()?;
            let (status, body) = crate::admin_client::request(
                &cfg.admin_socket_path(),
                hyper::Method::GET,
                "/admin/sessions",
            )
            .await?;
            if !status.is_success() {
                bail!("server returned {status}: {body}");
            }
            let v: serde_json::Value = serde_json::from_str(&body)?;
            let now = crate::auth::sessions::unix_now();
            println!("TERMINAL SESSIONS");
            let sessions = v["sessions"].as_array().cloned().unwrap_or_default();
            if sessions.is_empty() {
                println!("  (none)");
            }
            for s in sessions {
                println!(
                    "  {}  {:<10} {:<7} {:<9} age={}s idle={}s  {}",
                    s["id"].as_str().unwrap_or("?"),
                    s["user"].as_str().unwrap_or("?"),
                    s["kind"].as_str().unwrap_or("?"),
                    s["state"].as_str().unwrap_or("?"),
                    now.saturating_sub(s["created_unix"].as_u64().unwrap_or(now)),
                    s["idle_secs"].as_u64().unwrap_or(0),
                    s["title"].as_str().unwrap_or(""),
                );
            }
            println!("LOGINS");
            let logins = v["logins"].as_array().cloned().unwrap_or_default();
            if logins.is_empty() {
                println!("  (none)");
            }
            for l in logins {
                println!(
                    "  {}  {:<10} ip={:<15} via={:<9} expires_in={}s key={}",
                    l["id"].as_str().unwrap_or("?"),
                    l["user"].as_str().unwrap_or("?"),
                    l["ip"].as_str().unwrap_or("?"),
                    l["via"].as_str().unwrap_or("?"),
                    l["expires_unix"]
                        .as_u64()
                        .unwrap_or(now)
                        .saturating_sub(now),
                    l["key_fingerprint"].as_str().unwrap_or("?"),
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        SessionsCmd::Revoke { id, cfg } => {
            let cfg = cfg.load()?;
            if !id.chars().all(|c| c.is_ascii_hexdigit()) || id.len() > 64 {
                bail!("invalid id {id:?}");
            }
            let (status, body) = crate::admin_client::request(
                &cfg.admin_socket_path(),
                hyper::Method::DELETE,
                &format!("/admin/sessions/{id}"),
            )
            .await?;
            if status.is_success() {
                println!("{body}");
                Ok(ExitCode::SUCCESS)
            } else {
                eprintln!("no session or login with id {id}");
                Ok(ExitCode::from(1))
            }
        }
    }
}

fn sign(key: &str, message: Option<String>) -> Result<ExitCode> {
    let key = config::resolve_path(Path::new(key), Path::new("."));
    if !key.exists() {
        bail!("key file {} not found", key.display());
    }
    let message = match message {
        Some(m) => m,
        None => {
            let mut s = String::new();
            std::io::stdin().take(4096).read_to_string(&mut s)?;
            s
        }
    };
    let message = message.trim_end_matches(['\r', '\n']).to_string();
    if !message.starts_with("sshweb-auth-v1 ") {
        bail!("this does not look like an sshweb login challenge");
    }
    eprintln!(
        "Signing challenge:\n  {message}\nCheck that the origin above is the gateway you are logging in to."
    );
    let mut child = std::process::Command::new("ssh-keygen")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg(crate::auth::challenge::NAMESPACE)
        .arg("-f")
        .arg(&key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("cannot run ssh-keygen (OpenSSH 8.1+ required)")?;
    use std::io::Write;
    child.stdin.take().unwrap().write_all(message.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("ssh-keygen failed");
    }
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(ExitCode::SUCCESS)
}
