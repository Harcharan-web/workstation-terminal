//! Origin and Host validation (cross-site WebSocket hijacking, CSRF and DNS-rebinding defence).

use std::collections::HashSet;

use crate::config::Config;

/// Parse `scheme://host[:port]` into a normalised origin string with an explicit port.
pub fn parse_origin(s: &str) -> Option<String> {
    let (scheme, rest) = s.split_once("://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    if rest.is_empty() || rest.contains('/') || rest.contains('@') || rest.contains('?') {
        return None;
    }
    let (host, port) = split_host_port(rest)?;
    let port = port.unwrap_or(default_port);
    Some(format!("{scheme}://{}:{port}", host.to_ascii_lowercase()))
}

/// Split `host[:port]`, handling `[v6]:port`.
pub fn split_host_port(s: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse().ok()?),
        };
        return Some((h, port)).filter(|(h, _)| !h.is_empty());
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h, Some(p.parse().ok()?))),
        Some(_) => None,
        None => Some((s, None)),
    }
    .filter(|(h, _)| {
        !h.is_empty()
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    })
}

/// Allowed origins and Host header values, derived from the configuration.
#[derive(Debug, Clone)]
pub struct OriginPolicy {
    origins: HashSet<String>,
    hosts: HashSet<String>,
}

impl OriginPolicy {
    pub fn from_config(cfg: &Config) -> Self {
        let scheme = if cfg.tls_enabled() { "https" } else { "http" };
        let port = cfg.server.port;
        let mut names: Vec<String> = Vec::new();
        let bind = cfg.server.bind;
        if bind.is_loopback() || bind.is_unspecified() {
            names.extend(["127.0.0.1".into(), "localhost".into(), "[::1]".into()]);
        }
        if !bind.is_unspecified() {
            names.push(match bind {
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
                v4 => v4.to_string(),
            });
        }
        let mut origins = HashSet::new();
        let mut hosts = HashSet::new();
        for n in names {
            if let Some(o) = parse_origin(&format!("{scheme}://{n}:{port}")) {
                origins.insert(o);
            }
            hosts.insert(format!("{n}:{port}").to_ascii_lowercase());
        }
        for o in &cfg.server.allowed_origins {
            if let Some(norm) = parse_origin(o) {
                // Host header as a browser sends it for this origin.
                let rest = o.split_once("://").map(|x| x.1).unwrap_or_default();
                if let Some((h, p)) = split_host_port(rest) {
                    let default = if o.starts_with("https") { 443 } else { 80 };
                    let p = p.unwrap_or(default);
                    let h = h.to_ascii_lowercase();
                    let h = if h.contains(':') { format!("[{h}]") } else { h };
                    hosts.insert(format!("{h}:{p}"));
                    if p == default {
                        hosts.insert(h);
                    }
                }
                origins.insert(norm);
            }
        }
        Self { origins, hosts }
    }

    /// Is this `Origin` header value allowed? Missing or `null` origins are rejected.
    pub fn origin_allowed(&self, origin: Option<&str>) -> bool {
        match origin.and_then(parse_origin) {
            Some(o) => self.origins.contains(&o),
            None => false,
        }
    }

    /// Is this `Host` header allowed? Guards against DNS rebinding.
    pub fn host_allowed(&self, host: Option<&str>) -> bool {
        match host {
            Some(h) => self.hosts.contains(&h.to_ascii_lowercase()),
            None => false,
        }
    }

    pub fn origins(&self) -> impl Iterator<Item = &String> {
        self.origins.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_normalise() {
        assert_eq!(
            parse_origin("http://LocalHost:7681").unwrap(),
            "http://localhost:7681"
        );
        assert_eq!(
            parse_origin("https://a.example").unwrap(),
            "https://a.example:443"
        );
        assert_eq!(parse_origin("http://[::1]:80").unwrap(), "http://::1:80");
        assert!(parse_origin("null").is_none());
        assert!(parse_origin("file://x").is_none());
        assert!(parse_origin("http://a/b").is_none());
        assert!(parse_origin("http://u@a").is_none());
        assert!(parse_origin("http://a:notaport").is_none());
    }

    #[test]
    fn default_policy_is_loopback_only() {
        let cfg = Config::default();
        let p = OriginPolicy::from_config(&cfg);
        assert!(p.origin_allowed(Some("http://127.0.0.1:7681")));
        assert!(p.origin_allowed(Some("http://localhost:7681")));
        assert!(!p.origin_allowed(Some("https://127.0.0.1:7681")));
        assert!(!p.origin_allowed(Some("http://evil.example")));
        assert!(!p.origin_allowed(Some("http://127.0.0.1:7682")));
        assert!(!p.origin_allowed(None));
        assert!(!p.origin_allowed(Some("null")));
        assert!(p.host_allowed(Some("127.0.0.1:7681")));
        assert!(p.host_allowed(Some("LOCALHOST:7681")));
        assert!(!p.host_allowed(Some("evil.example:7681")));
        assert!(!p.host_allowed(None));
    }

    #[test]
    fn extra_origins() {
        let mut cfg = Config::default();
        cfg.server.allowed_origins = vec!["https://mac.example.net".into()];
        let p = OriginPolicy::from_config(&cfg);
        assert!(p.origin_allowed(Some("https://mac.example.net")));
        assert!(p.origin_allowed(Some("https://mac.example.net:443")));
        assert!(p.host_allowed(Some("mac.example.net")));
    }
}
