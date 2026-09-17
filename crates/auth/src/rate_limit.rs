use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// In-memory sliding-window lockout for login attempts, keyed by an arbitrary
/// string (typically `"{username}:{ip}"`). Process-local — a multi-instance
/// deployment would need this backed by shared storage instead, which is a
/// known limitation of this pass rather than an oversight.
pub struct LoginLimiter {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    max_attempts: usize,
    window: Duration,
}

impl LoginLimiter {
    pub fn new(max_attempts: usize, window: Duration) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window,
        }
    }

    pub fn is_locked(&self, key: &str) -> bool {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let now = Instant::now();
        if let Some(entries) = attempts.get_mut(key) {
            entries.retain(|t| now.duration_since(*t) < self.window);
            entries.len() >= self.max_attempts
        } else {
            false
        }
    }

    pub fn record_failure(&self, key: &str) {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let now = Instant::now();
        let entries = attempts.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < self.window);
        entries.push(now);
    }

    pub fn clear(&self, key: &str) {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        attempts.remove(key);
    }
}

impl Default for LoginLimiter {
    fn default() -> Self {
        // 10 failed attempts within 15 minutes locks out further attempts.
        Self::new(10, Duration::from_secs(15 * 60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_max_attempts_and_clears() {
        let limiter = LoginLimiter::new(3, Duration::from_secs(60));
        let key = "alice:127.0.0.1";
        assert!(!limiter.is_locked(key));
        for _ in 0..3 {
            limiter.record_failure(key);
        }
        assert!(limiter.is_locked(key));
        limiter.clear(key);
        assert!(!limiter.is_locked(key));
    }
}
