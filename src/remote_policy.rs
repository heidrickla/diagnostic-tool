//! Small deterministic retry and session-expiry policy for the GUI worker.
use std::time::{Duration, Instant};

pub struct RemotePolicy {
    until: Instant,
    errors: u8,
}
impl RemotePolicy {
    pub fn new(now: Instant, lifetime: Duration) -> Self {
        Self {
            until: now + lifetime,
            errors: 0,
        }
    }
    pub fn expired(&self, now: Instant) -> bool {
        now >= self.until
    }
    /// Returns whether the last successful cycle recovered from an interruption.
    pub fn success(&mut self) -> bool {
        let recovered = self.errors > 0;
        self.errors = 0;
        recovered
    }
    /// Returns a bounded retry delay. None ends the session after three errors.
    pub fn failure(&mut self) -> Option<Duration> {
        self.errors = self.errors.saturating_add(1);
        match self.errors {
            1 => Some(Duration::from_secs(2)),
            2 => Some(Duration::from_secs(4)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_network_retries_recover_or_end() {
        let now = Instant::now();
        let mut policy = RemotePolicy::new(now, Duration::from_secs(300));
        assert!(!policy.expired(now));
        assert_eq!(policy.failure(), Some(Duration::from_secs(2)));
        assert_eq!(policy.failure(), Some(Duration::from_secs(4)));
        assert!(policy.success());
        assert_eq!(policy.failure(), Some(Duration::from_secs(2)));
        assert_eq!(policy.failure(), Some(Duration::from_secs(4)));
        assert_eq!(policy.failure(), None);
        assert!(policy.expired(now + Duration::from_secs(300)));
    }
}
