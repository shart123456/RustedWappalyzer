use moka::sync::Cache;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    /// Per-key sliding window of request timestamps.
    /// Moka evicts entries that have been idle for >2× the window duration,
    /// bounding memory to `max_capacity` active IPs without manual eviction.
    counters: Cache<String, Arc<Mutex<Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        let window = Duration::from_secs(window_secs);
        let counters = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(window.saturating_mul(2))
            .build();
        Self {
            max_requests: max_requests as usize,
            window,
            counters,
        }
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    pub fn check(&self, key: &str) -> bool {
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
