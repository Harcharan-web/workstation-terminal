//! HTTP server: static assets, auth API, WebSocket, health, metrics, admin socket, shutdown.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path as UrlPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::assets;
use crate::audit::{Audit, AuditEvent};
use crate::auth::sessions::Login;
use crate::auth::{AuthError, AuthService};
use crate::config::Config;
use crate::metrics::Metrics;
use crate::security::origin::OriginPolicy;
use crate::session::SessionManager;

pub struct AppState {
    pub cfg: Arc<Config>,
    pub auth: AuthService,
    pub sessions: Arc<SessionManager>,
    pub audit: Arc<Audit>,
    pub metrics: Arc<Metrics>,
    pub origin: OriginPolicy,
    pub shutdown: CancellationToken,
    pub ws_slots: Arc<Semaphore>,
    pub workspaces: crate::workspace::WorkspaceStore,
    pub ready: AtomicBool,
}

pub type App = Arc<AppState>;

impl AppState {
    pub fn new(cfg: Config, audit: Audit) -> App {
        let cfg = Arc::new(cfg);
        let audit = Arc::new(audit);
        let metrics = Arc::new(Metrics::default());
        Arc::new(Self {
            auth: AuthService::new(&cfg, audit.clone(), metrics.clone()),
            sessions: SessionManager::new(cfg.clone(), audit.clone(), metrics.clone()),
            origin: OriginPolicy::from_config(&cfg),
            ws_slots: Arc::new(Semaphore::new(cfg.limits.max_websockets)),
            workspaces: crate::workspace::WorkspaceStore::new(
                cfg.server.state_dir.join("workspaces"),
            ),
            shutdown: CancellationToken::new(),
            ready: AtomicBool::new(false),
            cfg,
            audit,
            metrics,
        })
    }

    pub fn session_cookie(&self) -> &'static str {
        if self.cfg.tls_enabled() {
            "__Host-sshweb_session"
        } else {
            "sshweb_session"
        }
    }

    fn pre_cookie(&self) -> &'static str {
        if self.cfg.tls_enabled() {
            "__Host-sshweb_pre"
        } else {
            "sshweb_pre"
        }
    }

    fn cookie(&self, name: &str, value: &str, max_age: u64) -> HeaderValue {
        let secure = if self.cfg.tls_enabled() {
            "; Secure"
        } else {
            ""
        };
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}"
        ))
        .expect("cookie is ASCII")
    }
}

// ---------- helpers ----------

pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty() && v.len() <= 128)
}

/// The client IP used for rate limiting, lockouts and auditing. `X-Forwarded-For` is honoured
/// only when the TCP peer is a configured trusted proxy; the right-most address that is not
/// itself a trusted proxy is used. A trusted proxy that sends no `X-Forwarded-For` may report
/// the client in `X-Real-IP` instead (single value, nginx `$remote_addr`). Anything unparsable
/// falls back to the peer address.
pub fn client_ip(cfg: &Config, peer: SocketAddr, headers: &HeaderMap) -> std::net::IpAddr {
    let trusted = &cfg.server.trusted_proxies;
    if !trusted.contains(&peer.ip()) {
        return peer.ip();
    }
    if !headers.contains_key("x-forwarded-for") {
        return headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .filter(|ip| !trusted.contains(ip))
            .unwrap_or(peer.ip());
    }
    let mut chain = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        let Ok(s) = v.to_str() else {
            return peer.ip();
        };
        for part in s.split(',') {
            match part.trim().parse::<std::net::IpAddr>() {
                Ok(ip) => chain.push(ip),
                Err(_) => return peer.ip(),
            }
        }
    }
    chain
        .into_iter()
        .rev()
        .find(|ip| !trusted.contains(ip))
        .unwrap_or(peer.ip())
}

pub fn session_token_from_headers(app: &AppState, headers: &HeaderMap) -> Option<String> {
    get_cookie(headers, app.session_cookie())
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after: Option<u64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }
    fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "login required",
        )
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        let (status, retry) = match &e {
            AuthError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, Some(60)),
            AuthError::LockedOut(s) => (StatusCode::TOO_MANY_REQUESTS, Some(*s)),
            AuthError::InvalidUser => (StatusCode::BAD_REQUEST, None),
            AuthError::Challenge(_) | AuthError::Verify(_) => (StatusCode::UNAUTHORIZED, None),
            AuthError::KeysUnavailable => (StatusCode::SERVICE_UNAVAILABLE, None),
        };
        Self {
            status,
            code: e.code(),
            message: e.to_string(),
            retry_after: retry,
        }
    }
}

impl From<JsonRejection> for ApiError {
    fn from(e: JsonRejection) -> Self {
        let status = e.status();
        let mut m = e.body_text();
        m.truncate(200);
        let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
            "too_large"
        } else {
            "bad_request"
        };
        Self::new(status, code, m)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = (
            self.status,
            Json(json!({"error": self.code, "message": self.message})),
        )
            .into_response();
        if let Some(s) = self.retry_after {
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(s));
        }
        r
    }
}

fn require_login(app: &AppState, headers: &HeaderMap) -> Result<(String, Login), ApiError> {
    let tok = session_token_from_headers(app, headers).ok_or_else(ApiError::unauthenticated)?;
    let login = app
        .auth
        .validate(&tok)
        .ok_or_else(ApiError::unauthenticated)?;
    Ok((tok, login))
}

// ---------- middleware ----------

/// Reject requests whose Host is not ours (DNS rebinding) and add security headers.
async fn security_layer(State(app): State<App>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()));
    if !app.origin.host_allowed(host.as_deref()) {
        return (StatusCode::MISDIRECTED_REQUEST, "unknown host").into_response();
    }
    // CSRF: state-changing API calls must come from one of our origins.
    let is_api = req.uri().path().starts_with("/api/");
    if is_api && req.method() != Method::GET && req.method() != Method::HEAD {
        let headers = req.headers();
        let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
        // Browsers that withhold the origin (`null` or absent) still mark same-origin requests
        // with Sec-Fetch-Site, which page scripts cannot set.
        let same_origin_fetch = matches!(origin, None | Some("null"))
            && headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("same-origin");
        if !app.origin.origin_allowed(origin) && !same_origin_fetch {
            app.audit.log(
                AuditEvent::new("csrf_rejected")
                    .field("origin", origin.unwrap_or("-"))
                    .field("method", req.method().as_str())
                    .field("path", req.uri().path()),
            );
            return ApiError::new(
                StatusCode::FORBIDDEN,
                "bad_origin",
                format!(
                    "cross-origin request rejected (origin {}); if this is a legitimate address, \
                     add it to server.allowed_origins",
                    origin.unwrap_or("missing")
                ),
            )
            .into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
         font-src 'self'; connect-src 'self'; manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    // Not "no-referrer": under that policy some browsers send `Origin: null` on same-origin
    // POSTs, which the CSRF check would then reject.
    set(h, "referrer-policy", "same-origin");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), usb=()",
    );
    if is_api {
        set(h, "cache-control", "no-store");
    }
    if app.cfg.tls_enabled() {
        set(h, "strict-transport-security", "max-age=31536000");
    }
    resp
}

// ---------- handlers ----------

async fn healthz() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

fn is_ready(app: &AppState) -> bool {
    app.ready.load(Ordering::Relaxed)
        && !app.shutdown.is_cancelled()
        && app.auth.keys.current().is_ok()
}

async fn readyz(State(app): State<App>) -> impl IntoResponse {
    if is_ready(&app) {
        (StatusCode::OK, Json(json!({"status": "ready"})))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        )
    }
}

async fn metrics_public(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Response {
    if !app.cfg.metrics.enabled || !peer.ip().is_loopback() {
        return StatusCode::NOT_FOUND.into_response();
    }
    prometheus(&app)
}

fn prometheus(app: &AppState) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        app.metrics.render_prometheus(),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeReq {
    user: String,
}

async fn auth_challenge(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<ChallengeReq>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = body?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let binding = crate::security::random_token(32);
    let ch = app.auth.issue_challenge(
        &req.user,
        &origin,
        &binding,
        &client_ip(&app.cfg, peer, &headers).to_string(),
    )?;
    let mut resp = Json(json!({
        "challenge_id": ch.id,
        "namespace": crate::auth::challenge::NAMESPACE,
        "message": ch.message,
        "expires_unix": ch.expires_unix,
    }))
    .into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        app.cookie(app.pre_cookie(), &binding, app.cfg.auth.challenge_ttl_secs),
    );
    Ok(resp)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyReq {
    challenge_id: String,
    signature: String,
}

async fn auth_verify(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Result<Json<VerifyReq>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = body?;
    let binding = get_cookie(&headers, app.pre_cookie()).unwrap_or_default();
    let (token, login) = app.auth.verify(
        &req.challenge_id,
        &req.signature,
        &binding,
        &client_ip(&app.cfg, peer, &headers).to_string(),
        "http",
    )?;
    let mut resp = Json(json!({
        "user": login.user,
        "access": login.access.to_string(),
        "expires_unix": login.expires_unix,
    }))
    .into_response();
    let h = resp.headers_mut();
    h.append(
        header::SET_COOKIE,
        app.cookie(app.session_cookie(), &token, app.cfg.auth.session_ttl_secs),
    );
    h.append(header::SET_COOKIE, app.cookie(app.pre_cookie(), "", 0));
    Ok(resp)
}

async fn auth_logout(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(tok) = session_token_from_headers(&app, &headers)
        && let Some(login) = app.auth.logins.revoke_token(&tok)
    {
        let n = app
            .sessions
            .close_where("logged out", |s| s.login_id() == login.id);
        app.audit.log(
            AuditEvent::new("logout")
                .ip(&client_ip(&app.cfg, peer, &headers).to_string())
                .user(&login.user)
                .field("login_id", &login.id)
                .num("sessions_closed", n as i64),
        );
    }
    let mut resp = Json(json!({"ok": true})).into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, app.cookie(app.session_cookie(), "", 0));
    resp
}

async fn me(State(app): State<App>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (_, login) = require_login(&app, &headers)?;
    let cfg = &app.cfg;
    let profiles: Vec<_> = crate::ssh::permitted_profiles(cfg, &login.access)
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name.clone().unwrap_or_else(|| p.id.clone()),
                "host": p.host,
                "port": p.port,
                "user": p.user,
            })
        })
        .collect();
    let local = cfg.local.enabled && login.access.local;
    Ok(Json(json!({
        "user": login.user,
        "login_id": login.id,
        "access": login.access.to_string(),
        "key_fingerprint": login.key_fingerprint,
        "expires_unix": login.expires_unix,
        "host": crate::session::hostname(),
        "local": {
            "enabled": local,
            "default_shell": if local { Some(cfg.effective_default_shell()) } else { None },
            "shells": if local { cfg.local.allowed_shells.clone() } else { Vec::new() },
        },
        "remote": {
            "enabled": cfg.remote.enabled && login.access.allows_any_remote(),
            "profiles": profiles,
            "allow_adhoc": cfg.remote.enabled && cfg.remote.allow_adhoc && login.access.remote_all,
        },
        "limits": {
            "max_per_user": cfg.sessions.max_per_user,
            "detach_grace_secs": cfg.sessions.detach_grace_secs,
            "idle_timeout_secs": cfg.sessions.idle_timeout_secs,
        },
    }))
    .into_response())
}

async fn list_sessions(State(app): State<App>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (_, login) = require_login(&app, &headers)?;
    Ok(Json(json!({"sessions": app.sessions.list_for_user(&login.user)})).into_response())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameReq {
    name: String,
}

async fn rename_session(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
    body: Result<Json<RenameReq>, JsonRejection>,
) -> Result<Response, ApiError> {
    let (_, login) = require_login(&app, &headers)?;
    let Json(req) = body?;
    // Same error for "missing" and "someone else's" so ids cannot be probed.
    let s = app
        .sessions
        .get(&id)
        .filter(|s| s.user == login.user)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such session"))?;
    let name = crate::session::normalize_name(&req.name)
        .map_err(|m| ApiError::new(StatusCode::BAD_REQUEST, "invalid_name", m))?;
    s.set_name(name.clone());
    app.audit.log(
        AuditEvent::new("session_rename")
            .ip(&client_ip(&app.cfg, peer, &headers).to_string())
            .user(&login.user)
            .field("session_id", &s.id)
            .field("name", name.as_deref().unwrap_or("")),
    );
    Ok(Json(json!({"ok": true, "name": name})).into_response())
}

async fn close_session(
    State(app): State<App>,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Result<Response, ApiError> {
    let (_, login) = require_login(&app, &headers)?;
    match app.sessions.get(&id) {
        Some(s) if s.user == login.user => {
            app.sessions.close(&id, "closed by user");
            Ok(Json(json!({"ok": true})).into_response())
        }
        _ => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no such session",
        )),
    }
}

async fn get_workspace(State(app): State<App>, headers: HeaderMap) -> Result<Response, ApiError> {
    let (_, login) = require_login(&app, &headers)?;
    Ok(Json(app.workspaces.load(&login.user)).into_response())
}

async fn put_workspace(
    State(app): State<App>,
    headers: HeaderMap,
    body: Result<Json<crate::workspace::Workspace>, JsonRejection>,
) -> Result<Response, ApiError> {
    let (_, login) = require_login(&app, &headers)?;
    let Json(mut ws) = body?;
    ws.validate()
        .map_err(|m| ApiError::new(StatusCode::BAD_REQUEST, "invalid_workspace", m))?;
    app.workspaces.save(&login.user, &ws).map_err(|e| {
        tracing::error!(error = %e, "cannot save workspace");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "save_failed",
            "could not save workspace",
        )
    })?;
    Ok(Json(ws).into_response())
}

async fn index() -> Response {
    assets::serve("index.html")
}

async fn asset(UrlPath(path): UrlPath<String>) -> Response {
    assets::serve(&path)
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/{*path}", get(asset))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_public))
        .route("/api/auth/challenge", post(auth_challenge))
        .route("/api/auth/verify", post(auth_verify))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/me", get(me))
        .route("/api/sessions", get(list_sessions))
        .route("/api/workspace", get(get_workspace).put(put_workspace))
        .route(
            "/api/sessions/{id}",
            delete(close_session).patch(rename_session),
        )
        .route("/ws", get(crate::websocket::ws_handler))
        .layer(DefaultBodyLimit::max(app.cfg.limits.max_http_body_bytes))
        .layer(middleware::from_fn_with_state(app.clone(), security_layer))
        .with_state(app)
}

// ---------- admin socket ----------

async fn admin_health(State(app): State<App>) -> Response {
    let keys = app.auth.keys.current();
    Json(json!({
        "status": if is_ready(&app) { "ready" } else { "not_ready" },
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "listen": format!("{}:{}", app.cfg.server.bind, app.cfg.server.port),
        "tls": app.cfg.tls_enabled(),
        "authorized_keys": match &keys { Ok(k) => json!({"ok": true, "keys": k.keys.len()}), Err(e) => json!({"ok": false, "error": e}) },
        "sessions": app.sessions.count(),
        "logins": app.auth.logins.list().len(),
        "metrics": app.metrics.snapshot(),
    }))
    .into_response()
}

async fn admin_metrics(State(app): State<App>) -> Response {
    prometheus(&app)
}

async fn admin_sessions(State(app): State<App>) -> Response {
    Json(json!({
        "sessions": app.sessions.list(),
        "logins": app.auth.logins.list(),
    }))
    .into_response()
}

async fn admin_revoke(State(app): State<App>, UrlPath(id): UrlPath<String>) -> Response {
    let mut what = Vec::new();
    if app.sessions.close(&id, "revoked by administrator") {
        what.push("session");
    }
    if let Some(l) = app.auth.logins.revoke_id(&id) {
        app.sessions
            .close_where("login revoked by administrator", |s| s.login_id() == l.id);
        what.push("login");
    }
    if what.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "not_found"}))).into_response();
    }
    app.audit.log(
        AuditEvent::new("admin_revoke")
            .field("id", &id)
            .field("revoked", &what.join(",")),
    );
    Json(json!({"revoked": what})).into_response()
}

pub fn admin_router(app: App) -> Router {
    Router::new()
        .route("/healthz", get(admin_health))
        .route("/metrics", get(admin_metrics))
        .route("/admin/sessions", get(admin_sessions))
        .route("/admin/sessions/{id}", delete(admin_revoke))
        .with_state(app)
}

fn bind_admin_socket(path: &Path) -> Result<tokio::net::UnixListener> {
    let dir = path
        .parent()
        .context("admin socket has no parent directory")?;
    crate::security::perms::ensure_private_dir(dir)
        .with_context(|| format!("cannot create state dir {}", dir.display()))?;
    if path.exists() {
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            bail!(
                "another sshweb instance is running (admin socket {} is live)",
                path.display()
            );
        }
        std::fs::remove_file(path)?;
    }
    let l = tokio::net::UnixListener::bind(path)
        .with_context(|| format!("cannot bind admin socket {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

// ---------- lifecycle ----------

pub struct Running {
    pub app: App,
    pub addr: SocketAddr,
    handle: axum_server::Handle<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    admin_path: std::path::PathBuf,
}

impl Running {
    /// Graceful shutdown: refuse new work, close sessions, drain connections.
    pub async fn shutdown(self) {
        let app = &self.app;
        app.ready.store(false, Ordering::Relaxed);
        app.shutdown.cancel();
        app.sessions.shutdown().await;
        self.handle.graceful_shutdown(Some(Duration::from_secs(5)));
        for t in self.tasks {
            let _ = tokio::time::timeout(Duration::from_secs(7), t).await;
        }
        let _ = std::fs::remove_file(&self.admin_path);
        app.audit.log(AuditEvent::new("server_stop"));
        tracing::info!("shutdown complete");
    }
}

/// Start serving on an already-bound listener. `cfg.server.port` must match the listener.
pub async fn start(cfg: Config, audit: Audit, listener: std::net::TcpListener) -> Result<Running> {
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let app = AppState::new(cfg, audit);
    let cfg = app.cfg.clone();

    let admin_path = cfg.admin_socket_path();
    let admin_listener = bind_admin_socket(&admin_path)?;

    let handle: axum_server::Handle<SocketAddr> = axum_server::Handle::new();
    let svc = router(app.clone()).into_make_service_with_connect_info::<SocketAddr>();
    let mut tasks = Vec::new();

    if cfg.tls_enabled() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert, key) = (
            cfg.server.tls.cert.as_ref().unwrap(),
            cfg.server.tls.key.as_ref().unwrap(),
        );
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .with_context(|| {
                format!(
                    "cannot load TLS certificate {} / key {}",
                    cert.display(),
                    key.display()
                )
            })?;
        let server = axum_server::from_tcp_rustls(listener, tls)?.handle(handle.clone());
        tasks.push(tokio::spawn(async move {
            if let Err(e) = server.serve(svc).await {
                tracing::error!(error = %e, "HTTPS server failed");
            }
        }));
    } else {
        let server = axum_server::from_tcp(listener)?.handle(handle.clone());
        tasks.push(tokio::spawn(async move {
            if let Err(e) = server.serve(svc).await {
                tracing::error!(error = %e, "HTTP server failed");
            }
        }));
    }

    let admin_app = admin_router(app.clone());
    let stop = app.shutdown.clone();
    tasks.push(tokio::spawn(async move {
        let r = axum::serve(admin_listener, admin_app)
            .with_graceful_shutdown(async move { stop.cancelled().await })
            .await;
        if let Err(e) = r {
            tracing::error!(error = %e, "admin socket server failed");
        }
    }));

    // Housekeeping: expiry, revocation, idle and detach timeouts.
    let a = app.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tokio::select! {
                _ = a.shutdown.cancelled() => break,
                _ = tick.tick() => {
                    a.auth.purge();
                    for id in a.auth.sweep_revoked_keys() {
                        a.sessions.close_where("key revoked", |s| s.login_id() == id);
                    }
                    a.sessions.reap();
                    enforce_current_access(&a);
                }
            }
        }
    });

    app.ready.store(true, Ordering::Relaxed);
    let scheme = if cfg.tls_enabled() { "https" } else { "http" };
    app.audit.log(
        AuditEvent::new("server_start")
            .field("listen", &addr.to_string())
            .field("scheme", scheme),
    );
    Ok(Running {
        app,
        addr,
        handle,
        tasks,
        admin_path,
    })
}

/// Close sessions whose owning key was revoked, or no longer grants access to the session's
/// target. Checked against the key fingerprint, so it applies to detached sessions whose
/// browser login has already expired.
fn enforce_current_access(app: &AppState) {
    let Ok(keys) = app.auth.keys.current() else {
        // Fail closed, like logins: an invalid authorisation file ends every session.
        app.sessions
            .close_where("authorized keys file invalid", |_| true);
        return;
    };
    app.sessions.close_where(
        "key revoked",
        |s| !matches!(keys.by_fingerprint(&s.key_fingerprint()), Some(k) if k.user == s.user),
    );
    app.sessions.close_where("access revoked", |s| {
        matches!(keys.by_fingerprint(&s.key_fingerprint()), Some(k) if !s.permitted_by(&k.access))
    });
}

/// Bind the configured address and run until SIGINT/SIGTERM.
pub async fn serve(cfg: Config, audit: Audit) -> Result<()> {
    let addr = SocketAddr::new(cfg.server.bind, cfg.server.port);
    let listener = std::net::TcpListener::bind(addr)
        .with_context(|| format!("cannot listen on {addr} (is another instance running?)"))?;
    let scheme = if cfg.tls_enabled() { "https" } else { "http" };
    let running = start(cfg, audit, listener).await?;
    let app = running.app.clone();
    let cfg = &app.cfg;
    tracing::info!(
        url = %format!("{scheme}://{}:{}/", if cfg.server.bind.is_loopback() { "127.0.0.1".to_string() } else { cfg.server.bind.to_string() }, cfg.server.port),
        local = cfg.local.enabled,
        remote = cfg.remote.enabled,
        profiles = cfg.remote.profiles.len(),
        authorized_keys = %cfg.auth.authorized_keys.display(),
        admin_socket = %cfg.admin_socket_path().display(),
        "sshweb listening"
    );
    match app.auth.keys.current() {
        Ok(k) if k.keys.is_empty() => tracing::warn!(
            "no keys in {}; nobody can log in. Add one with `sshweb keys add`",
            cfg.auth.authorized_keys.display()
        ),
        Ok(k) => tracing::info!(keys = k.keys.len(), "authorized keys loaded"),
        Err(e) => tracing::error!(error = %e, "authorized keys file invalid; logins will fail"),
    }
    if !cfg.server.bind.is_loopback() {
        tracing::warn!("remote access is ENABLED on {}", cfg.server.bind);
    }

    wait_for_signal().await;
    tracing::info!("shutdown signal received; closing sessions");
    running.shutdown().await;
    Ok(())
}

async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(xff: &[&str]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for v in xff {
            m.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        m
    }

    #[test]
    fn client_ip_trusts_forwarded_for_only_from_trusted_proxies() {
        let mut cfg = Config::default();
        let proxy: SocketAddr = "172.16.0.99:5000".parse().unwrap();
        let other: SocketAddr = "172.16.0.50:5000".parse().unwrap();
        // No trusted proxies: header ignored.
        assert_eq!(client_ip(&cfg, proxy, &h(&["10.0.0.7"])), proxy.ip());
        cfg.server.trusted_proxies =
            vec!["172.16.0.99".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        assert_eq!(
            client_ip(&cfg, proxy, &h(&["10.0.0.7"])).to_string(),
            "10.0.0.7"
        );
        // Right-most untrusted hop wins; a client-supplied left-most value is ignored.
        assert_eq!(
            client_ip(&cfg, proxy, &h(&["6.6.6.6, 10.0.0.7, 10.0.0.1"])).to_string(),
            "10.0.0.7"
        );
        assert_eq!(
            client_ip(&cfg, proxy, &h(&["6.6.6.6", "10.0.0.7"])).to_string(),
            "10.0.0.7"
        );
        // Untrusted peers cannot spoof.
        assert_eq!(client_ip(&cfg, other, &h(&["10.0.0.7"])), other.ip());
        // Garbage or absent header: fall back to the peer.
        assert_eq!(client_ip(&cfg, proxy, &h(&["not-an-ip"])), proxy.ip());
        assert_eq!(client_ip(&cfg, proxy, &h(&[])), proxy.ip());
    }

    #[test]
    fn client_ip_falls_back_to_x_real_ip_from_trusted_proxies() {
        let real = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert("x-real-ip", v.parse().unwrap());
            m
        };
        let mut cfg = Config::default();
        let proxy: SocketAddr = "172.16.0.99:5000".parse().unwrap();
        let other: SocketAddr = "172.16.0.50:5000".parse().unwrap();
        // No trusted proxies: header ignored.
        assert_eq!(client_ip(&cfg, proxy, &real("10.0.0.7")), proxy.ip());
        cfg.server.trusted_proxies = vec!["172.16.0.99".parse().unwrap()];
        assert_eq!(
            client_ip(&cfg, proxy, &real(" 10.0.0.7 ")).to_string(),
            "10.0.0.7"
        );
        assert_eq!(
            client_ip(&cfg, proxy, &real("2001:db8::7")).to_string(),
            "2001:db8::7"
        );
        // Untrusted peers cannot spoof.
        assert_eq!(client_ip(&cfg, other, &real("10.0.0.7")), other.ip());
        // Garbage, a list, or the proxy itself: fall back to the peer.
        assert_eq!(client_ip(&cfg, proxy, &real("not-an-ip")), proxy.ip());
        assert_eq!(
            client_ip(&cfg, proxy, &real("10.0.0.7, 10.0.0.8")),
            proxy.ip()
        );
        assert_eq!(client_ip(&cfg, proxy, &real("172.16.0.99")), proxy.ip());
        // X-Forwarded-For wins when both are present.
        let mut both = h(&["10.0.0.8"]);
        both.insert("x-real-ip", "10.0.0.7".parse().unwrap());
        assert_eq!(client_ip(&cfg, proxy, &both).to_string(), "10.0.0.8");
    }
}
