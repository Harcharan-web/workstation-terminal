//! In-memory rate limiting, failure counting with temporary lockouts, and token buckets.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Allows at most `limit` events per `window` per key (sliding log).
pub struct RateLimiter {
    limit: usize,
    window: Duration,
    events: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimiter {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit: limit as usize,
            window,
            events: Mutex::new(HashMap::new()),
        }
    }

    /// Record an event; returns false if the key is over its limit.
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    pub fn check_at(&self, key: &str, now: Instant) -> bool {
        let mut map = self.events.lock().unwrap();
        let q = map.entry(key.to_string()).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) >= self.window)
        {
            q.pop_front();
        }
        if q.len() >= self.limit {
            return false;
        }
        q.push_back(now);
        true
    }

    pub fn purge(&self) {
        let now = Instant::now();
        let mut map = self.events.lock().unwrap();
        map.retain(|_, q| {
            q.back()
                .is_some_and(|t| now.duration_since(*t) < self.window)
        });
    }
}

/// Counts authentication failures per key and locks the key out after too many.
pub struct FailureTracker {
    max_failures: usize,
    window: Duration,
    lockout: Duration,
    state: Mutex<HashMap<String, FailState>>,
}

#[derive(Default)]
struct FailState {
    failures: VecDeque<Instant>,
    locked_until: Option<Instant>,
}

impl FailureTracker {
    pub fn new(max_failures: u32, window: Duration, lockout: Duration) -> Self {
        Self {
            max_failures: max_failures as usize,
            window,
            lockout,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Remaining lockout time, if the key is locked.
    pub fn locked(&self, key: &str) -> Option<Duration> {
        self.locked_at(key, Instant::now())
    }

    pub fn locked_at(&self, key: &str, now: Instant) -> Option<Duration> {
        let map = self.state.lock().unwrap();
        map.get(key)
            .and_then(|s| s.locked_until)
            .filter(|t| *t > now)
            .map(|t| t - now)
    }

    /// Record a failure; returns true if this failure triggered a lockout.
    pub fn record_failure(&self, key: &str) -> bool {
        self.record_failure_at(key, Instant::now())
    }

    pub fn record_failure_at(&self, key: &str, now: Instant) -> bool {
        let mut map = self.state.lock().unwrap();
        let s = map.entry(key.to_string()).or_default();
        while s
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) >= self.window)
        {
            s.failures.pop_front();
        }
        s.failures.push_back(now);
        if s.failures.len() >= self.max_failures {
            s.failures.clear();
            s.locked_until = Some(now + self.lockout);
            return true;
        }
        false
    }

    pub fn record_success(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
    }

    pub fn purge(&self) {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap();
        map.retain(|_, s| {
            s.locked_until.is_some_and(|t| t > now)
                || s.failures
                    .back()
                    .is_some_and(|t| now.duration_since(*t) < self.window)
        });
    }
}

/// Token bucket measured in bytes.
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: u64, burst: u64) -> Self {
        Self {
            rate: rate_per_sec as f64,
            burst: burst as f64,
            tokens: burst as f64,
            last: Instant::now(),
        }
    }

    /// Take `n` tokens, returning how long the caller must wait before they are available.
    /// Requests larger than the burst size are refused with `None`.
    pub fn take(&mut self, n: u64) -> Option<Duration> {
        self.take_at(n, Instant::now())
    }

    pub fn take_at(&mut self, n: u64, now: Instant) -> Option<Duration> {
        let n = n as f64;
        if n > self.burst {
            return None;
        }
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.tokens -= n;
        if self.tokens >= 0.0 {
            Some(Duration::ZERO)
        } else {
            Some(Duration::from_secs_f64(-self.tokens / self.rate))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_window() {
        let rl = RateLimiter::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0));
        assert!(rl.check_at("a", t0));
        assert!(!rl.check_at("a", t0));
        assert!(rl.check_at("b", t0), "keys are independent");
        assert!(rl.check_at("a", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn lockout_after_failures_and_expiry() {
        let ft = FailureTracker::new(3, Duration::from_secs(60), Duration::from_secs(300));
        let t0 = Instant::now();
        assert!(!ft.record_failure_at("ip", t0));
        assert!(!ft.record_failure_at("ip", t0));
        assert!(ft.locked_at("ip", t0).is_none());
        assert!(ft.record_failure_at("ip", t0));
        assert!(ft.locked_at("ip", t0 + Duration::from_secs(10)).is_some());
        assert!(ft.locked_at("ip", t0 + Duration::from_secs(301)).is_none());
    }

    #[test]
    fn failures_outside_window_forgotten() {
        let ft = FailureTracker::new(2, Duration::from_secs(10), Duration::from_secs(300));
        let t0 = Instant::now();
        ft.record_failure_at("k", t0);
        assert!(!ft.record_failure_at("k", t0 + Duration::from_secs(11)));
    }

    #[test]
    fn success_resets() {
        let ft = FailureTracker::new(2, Duration::from_secs(60), Duration::from_secs(300));
        ft.record_failure("k");
        ft.record_success("k");
        assert!(!ft.record_failure("k"));
    }

    #[test]
    fn token_bucket_throttles() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(100, 200);
        b.last = t0;
        assert_eq!(b.take_at(150, t0), Some(Duration::ZERO));
        let wait = b.take_at(100, t0).unwrap();
        assert!(wait > Duration::from_millis(400) && wait <= Duration::from_millis(500));
        assert_eq!(b.take_at(201, t0), None);
    }
}
