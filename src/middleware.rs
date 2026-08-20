use moka::sync::Cache;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    /// When `false`, [`check`] always allows. Used when an upstream proxy (the
    /// API gateway) already rate-limits: this limiter keys on the peer socket
    /// address, which behind a proxy is the proxy's IP for every request, so it
    /// would otherwise collapse all clients into one shared bucket.
    enabled: bool,
    max_requests: usize,
    window: Duration,
    /// Per-key sliding window of request timestamps.
    /// Moka evicts entries that have been idle for >2× the window duration,
    /// bounding memory to `max_capacity` active IPs without manual eviction.
    counters: Cache<String, Arc<Mutex<Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        let window = Duration::from_secs(window_secs.max(1));
        let counters = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(window.saturating_mul(2))
            .build();
        Self {
            enabled: true,
            max_requests: max_requests as usize,
            window,
            counters,
        }
    }

    /// A no-op limiter that allows every request. Use when rate limiting is
    /// enforced upstream (e.g. behind the API gateway's forwardAuth limiter).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_requests: 0,
            window: Duration::from_secs(1),
            counters: Cache::builder().max_capacity(1).build(),
        }
    }

    /// Configured request allowance per window. Zero when disabled.
    pub fn max_requests(&self) -> usize {
        self.max_requests
    }

    /// Configured window length in seconds.
    pub fn window_secs(&self) -> u64 {
        self.window.as_secs()
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, key: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let now = Instant::now();
        let entry = self.counters.get_with(key.to_string(), || {
            Arc::new(Mutex::new(Vec::new()))
        });
        let mut timestamps = match entry.lock() {
            Ok(g) => g,
            // Recover from a poisoned mutex so a panicking thread cannot
            // permanently disable rate limiting for all future requests.
            Err(poisoned) => poisoned.into_inner(),
        };
        // Drop timestamps outside the sliding window.
        timestamps.retain(|t| now.duration_since(*t) < self.window);
        if timestamps.len() < self.max_requests {
            timestamps.push(now);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod config_tests {
    use super::RateLimiter;

    #[test]
    fn disabled_limiter_allows_everything() {
        let rl = RateLimiter::disabled();
        for _ in 0..10_000 {
            assert!(rl.check("1.2.3.4"), "disabled limiter must never reject");
        }
    }

    #[test]
    fn accessors_report_configured_values() {
        let rl = RateLimiter::new(25, 5);
        assert_eq!(rl.max_requests(), 25);
        assert_eq!(rl.window_secs(), 5);
    }

    #[test]
    fn zero_window_is_clamped_to_one_second() {
        // Duration::from_secs(0) would make time_to_idle zero and every entry
        // immediately evictable, silently disabling the limiter.
        let rl = RateLimiter::new(10, 0);
        assert_eq!(rl.window_secs(), 1);
    }

    #[test]
    fn custom_limit_is_enforced_at_the_configured_value() {
        let rl = RateLimiter::new(3, 60);
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(!rl.check("k"), "4th request must be rejected when max is 3");
    }
}
