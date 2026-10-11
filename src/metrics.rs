//! Process-wide counters and gauges with Prometheus text rendering.

use std::fmt::Write;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub challenges_issued: AtomicU64,
    pub auth_success: AtomicU64,
    pub auth_failure: AtomicU64,
    pub auth_lockouts: AtomicU64,
    pub ws_connections_total: AtomicU64,
    pub ws_connections_active: AtomicI64,
    pub ws_rejected_origin: AtomicU64,
    pub ws_protocol_errors: AtomicU64,
    pub sessions_opened_local: AtomicU64,
    pub sessions_opened_remote: AtomicU64,
    pub sessions_active: AtomicI64,
    pub session_open_failures: AtomicU64,
    pub remote_connect_failures: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl Metrics {
    pub fn inc(&self, c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn gauge_add(&self, g: &AtomicI64, n: i64) {
        g.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let gi = |a: &AtomicI64| a.load(Ordering::Relaxed);
        serde_json::json!({
            "challenges_issued": g(&self.challenges_issued),
            "auth_success": g(&self.auth_success),
            "auth_failure": g(&self.auth_failure),
            "auth_lockouts": g(&self.auth_lockouts),
            "ws_connections_total": g(&self.ws_connections_total),
            "ws_connections_active": gi(&self.ws_connections_active),
            "sessions_active": gi(&self.sessions_active),
            "session_open_failures": g(&self.session_open_failures),
            "remote_connect_failures": g(&self.remote_connect_failures),
        })
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        let mut counter = |name: &str, help: &str, v: u64| {
            let _ = writeln!(
                out,
                "# HELP sshweb_{name} {help}\n# TYPE sshweb_{name} counter\nsshweb_{name} {v}"
            );
        };
        let l = |a: &AtomicU64| a.load(Ordering::Relaxed);
        counter(
            "auth_challenges_total",
            "Login challenges issued.",
            l(&self.challenges_issued),
        );
        counter(
            "auth_success_total",
            "Successful logins.",
            l(&self.auth_success),
        );
        counter(
            "auth_failure_total",
            "Failed logins.",
            l(&self.auth_failure),
        );
        counter(
            "auth_lockouts_total",
            "Lockouts triggered.",
            l(&self.auth_lockouts),
        );
        counter(
            "ws_connections_total",
            "WebSocket connections accepted.",
            l(&self.ws_connections_total),
        );
        counter(
            "ws_rejected_origin_total",
            "WebSocket upgrades rejected for origin/host.",
            l(&self.ws_rejected_origin),
        );
        counter(
            "ws_protocol_errors_total",
            "Malformed or invalid client messages.",
            l(&self.ws_protocol_errors),
        );
        counter(
            "sessions_opened_local_total",
            "Local terminal sessions opened.",
            l(&self.sessions_opened_local),
        );
        counter(
            "sessions_opened_remote_total",
            "Remote SSH sessions opened.",
            l(&self.sessions_opened_remote),
        );
        counter(
            "session_open_failures_total",
            "Terminal sessions that failed to start.",
            l(&self.session_open_failures),
        );
        counter(
            "remote_connect_failures_total",
            "Remote SSH sessions that ended with an ssh connection error.",
            l(&self.remote_connect_failures),
        );
        counter(
            "terminal_input_bytes_total",
            "Bytes of terminal input.",
            l(&self.bytes_in),
        );
        counter(
            "terminal_output_bytes_total",
            "Bytes of terminal output.",
            l(&self.bytes_out),
        );
        let mut gauge = |name: &str, help: &str, v: i64| {
            let _ = writeln!(
                out,
                "# HELP sshweb_{name} {help}\n# TYPE sshweb_{name} gauge\nsshweb_{name} {v}"
            );
        };
        gauge(
            "ws_connections_active",
            "Open WebSocket connections.",
            self.ws_connections_active.load(Ordering::Relaxed),
        );
        gauge(
            "sessions_active",
            "Live terminal sessions.",
            self.sessions_active.load(Ordering::Relaxed),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus() {
        let m = Metrics::default();
        m.inc(&m.auth_failure);
        m.gauge_add(&m.sessions_active, 2);
        let t = m.render_prometheus();
        assert!(t.contains("sshweb_auth_failure_total 1"));
        assert!(t.contains("sshweb_sessions_active 2"));
        assert!(t.contains("# TYPE sshweb_sessions_active gauge"));
    }
}
