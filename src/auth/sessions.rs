//! Authenticated browser logins ("auth sessions"), keyed by a hash of a random bearer token.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use super::keys::Access;
use crate::security;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Login {
    /// Public identifier (not the secret token).
    pub id: String,
    pub user: String,
    pub key_fingerprint: String,
    pub access: Access,
    pub ip: String,
    pub created_unix: u64,
    pub expires_unix: u64,
    pub via: &'static str,
}

struct Entry {
    login: Login,
    expires_at: Instant,
    last_seen: Instant,
}

pub struct LoginStore {
    ttl: Duration,
    idle: Duration,
    map: Mutex<HashMap<[u8; 32], Entry>>,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginState {
    Valid(Login),
    Expired,
    Idle,
    Unknown,
}

impl LoginStore {
    pub fn new(ttl: Duration, idle: Duration) -> Self {
        Self {
            ttl,
            idle,
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Create a login, returning the secret bearer token and the login record.
    pub fn create(
        &self,
        user: &str,
        key_fingerprint: &str,
        access: Access,
        ip: &str,
        via: &'static str,
    ) -> (String, Login) {
        let token = security::random_token(32);
        let now = Instant::now();
        let login = Login {
            id: security::random_id(),
            user: user.into(),
            key_fingerprint: key_fingerprint.into(),
            access,
            ip: ip.into(),
            created_unix: unix_now(),
            expires_unix: unix_now() + self.ttl.as_secs(),
            via,
        };
        self.map.lock().unwrap().insert(
            security::hash_secret(&token),
            Entry {
                login: login.clone(),
                expires_at: now + self.ttl,
                last_seen: now,
            },
        );
        (token, login)
    }

    /// Look up a token, enforcing absolute and idle expiry. `touch` refreshes the idle timer.
    pub fn check(&self, token: &str, touch: bool) -> LoginState {
        self.check_at(token, touch, Instant::now())
    }

    pub fn check_at(&self, token: &str, touch: bool, now: Instant) -> LoginState {
        let key = security::hash_secret(token);
        let mut map = self.map.lock().unwrap();
        let Some(e) = map.get_mut(&key) else {
            return LoginState::Unknown;
        };
        if now >= e.expires_at {
            map.remove(&key);
            return LoginState::Expired;
        }
        if now.duration_since(e.last_seen) >= self.idle {
            map.remove(&key);
            return LoginState::Idle;
        }
        if touch {
            e.last_seen = now;
        }
        LoginState::Valid(e.login.clone())
    }

    /// Is the login with this public id still present and unexpired?
    pub fn is_live(&self, id: &str) -> bool {
        let now = Instant::now();
        self.map.lock().unwrap().values().any(|e| {
            e.login.id == id && now < e.expires_at && now.duration_since(e.last_seen) < self.idle
        })
    }

    /// Keep a login alive while it has active terminal traffic.
    pub fn touch_id(&self, id: &str) {
        let now = Instant::now();
        if let Some(e) = self
            .map
            .lock()
            .unwrap()
            .values_mut()
            .find(|e| e.login.id == id)
        {
            e.last_seen = now;
        }
    }

    pub fn update_access(&self, id: &str, access: Access) {
        if let Some(e) = self
            .map
            .lock()
            .unwrap()
            .values_mut()
            .find(|e| e.login.id == id)
        {
            e.login.access = access;
        }
    }

    pub fn revoke_token(&self, token: &str) -> Option<Login> {
        self.map
            .lock()
            .unwrap()
            .remove(&security::hash_secret(token))
            .map(|e| e.login)
    }

    pub fn revoke_id(&self, id: &str) -> Option<Login> {
        let mut map = self.map.lock().unwrap();
        let key = *map.iter().find(|(_, e)| e.login.id == id)?.0;
        map.remove(&key).map(|e| e.login)
    }

    /// Remove logins matching a predicate; returns the removed logins.
    pub fn revoke_where(&self, mut f: impl FnMut(&Login) -> bool) -> Vec<Login> {
        let mut map = self.map.lock().unwrap();
        let keys: Vec<_> = map
            .iter()
            .filter(|(_, e)| f(&e.login))
            .map(|(k, _)| *k)
            .collect();
        keys.into_iter()
            .filter_map(|k| map.remove(&k).map(|e| e.login))
            .collect()
    }

    pub fn list(&self) -> Vec<Login> {
        self.map
            .lock()
            .unwrap()
            .values()
            .map(|e| e.login.clone())
            .collect()
    }

    /// Drop expired entries; returns them for auditing.
    pub fn purge(&self) -> Vec<Login> {
        let now = Instant::now();
        let idle = self.idle;
        self.revoke_where_at(|e| now >= e.expires_at || now.duration_since(e.last_seen) >= idle)
    }

    fn revoke_where_at(&self, f: impl Fn(&Entry) -> bool) -> Vec<Login> {
        let mut map = self.map.lock().unwrap();
        let keys: Vec<_> = map.iter().filter(|(_, e)| f(e)).map(|(k, _)| *k).collect();
        keys.into_iter()
            .filter_map(|k| map.remove(&k).map(|e| e.login))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> Access {
        Access::parse("local").unwrap()
    }

    #[test]
    fn create_check_revoke() {
        let s = LoginStore::new(Duration::from_secs(100), Duration::from_secs(50));
        let (tok, login) = s.create("alice", "SHA256:x", access(), "127.0.0.1", "http");
        assert!(matches!(s.check(&tok, true), LoginState::Valid(l) if l.user == "alice"));
        assert_eq!(s.check("nope", true), LoginState::Unknown);
        assert!(s.is_live(&login.id));
        assert!(s.revoke_id(&login.id).is_some());
        assert_eq!(s.check(&tok, true), LoginState::Unknown);
    }

    #[test]
    fn absolute_and_idle_expiry() {
        let s = LoginStore::new(Duration::from_secs(100), Duration::from_secs(50));
        let (tok, _) = s.create("a", "f", access(), "ip", "http");
        let now = Instant::now();
        assert!(matches!(
            s.check_at(&tok, true, now + Duration::from_secs(40)),
            LoginState::Valid(_)
        ));
        assert!(matches!(
            s.check_at(&tok, true, now + Duration::from_secs(80)),
            LoginState::Valid(_)
        ));
        assert_eq!(
            s.check_at(&tok, true, now + Duration::from_secs(101)),
            LoginState::Expired
        );

        let (tok2, _) = s.create("a", "f", access(), "ip", "http");
        assert_eq!(
            s.check_at(&tok2, true, Instant::now() + Duration::from_secs(51)),
            LoginState::Idle
        );
    }

    #[test]
    fn background_checks_do_not_extend_idle_timeout() {
        let s = LoginStore::new(Duration::from_secs(100), Duration::from_secs(50));
        let (tok, _) = s.create("a", "f", access(), "ip", "http");
        let now = Instant::now();
        assert!(matches!(
            s.check_at(&tok, false, now + Duration::from_secs(40)),
            LoginState::Valid(_)
        ));
        assert_eq!(
            s.check_at(&tok, false, now + Duration::from_secs(55)),
            LoginState::Idle
        );
    }

    #[test]
    fn tokens_are_not_stored_in_clear() {
        let s = LoginStore::new(Duration::from_secs(100), Duration::from_secs(50));
        let (tok, _) = s.create("a", "f", access(), "ip", "http");
        let map = s.map.lock().unwrap();
        assert!(map.contains_key(&security::hash_secret(&tok)));
        assert!(
            !format!("{:?}", map.values().map(|e| &e.login).collect::<Vec<_>>()).contains(&tok)
        );
    }

    #[test]
    fn revoke_where_by_fingerprint() {
        let s = LoginStore::new(Duration::from_secs(100), Duration::from_secs(50));
        s.create("a", "f1", access(), "ip", "http");
        s.create("a", "f2", access(), "ip", "http");
        let gone = s.revoke_where(|l| l.key_fingerprint == "f1");
        assert_eq!(gone.len(), 1);
        assert_eq!(s.list().len(), 1);
    }
}
