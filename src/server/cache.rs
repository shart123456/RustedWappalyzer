use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use ::rusty_wappalyzer::{AnalysisResult, StandaloneWappalyzer};

/// Metadata for a recently-accessed cache entry.
pub struct HotEntry {
    pub url: String,
    pub confidence: u8,
    pub full_scan: bool,
    pub last_accessed: Instant,
}

/// Shared map from cache key → hot-entry metadata.
/// Lock is held briefly (never across await points).
pub type HotKeys = Arc<Mutex<HashMap<String, HotEntry>>>;

/// Background task: every `interval_secs`, find hot entries whose cache slot
/// has expired and re-analyze them, keeping the cache warm for active URLs.
///
/// - `interval_secs` — how often to check (should be < cache TTL, e.g. 45s for a 60s TTL)
/// - `hot_window_secs` — how long a URL stays "hot" after its last access (e.g. 600s)
pub async fn auto_refresh_loop(
    hot_keys: HotKeys,
    cache: Arc<moka::sync::Cache<String, Arc<AnalysisResult>>>,
    wappalyzer: Arc<StandaloneWappalyzer>,
    interval_secs: u64,
    hot_window_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    ticker.tick().await; // skip the immediate first tick so we don't run on startup

    loop {
        ticker.tick().await;

        let hot_cutoff = Duration::from_secs(hot_window_secs);
        let now = Instant::now();

        // Collect expired-but-hot entries; prune stale ones in the same pass.
        let to_refresh: Vec<(String, String, u8, bool)> = {
            let mut guard = hot_keys.lock().unwrap_or_else(|e| e.into_inner());
            guard.retain(|_, e| now.duration_since(e.last_accessed) < hot_cutoff);
            guard
                .iter()
                .filter(|(key, _)| cache.get(*key).is_none())
                .map(|(key, e)| (key.clone(), e.url.clone(), e.confidence, e.full_scan))
                .collect()
        };

        if !to_refresh.is_empty() {
            tracing::debug!(count = to_refresh.len(), "Cache auto-refresh: re-analyzing expired hot entries");
        }

        for (cache_key, url, confidence, full_scan) in to_refresh {
            let wap = Arc::clone(&wappalyzer);
            let cache = Arc::clone(&cache);
            tokio::spawn(async move {
                tracing::debug!(%url, "Background cache refresh");
                let result = wap.analyze_url(&url, confidence, full_scan).await;
                if result.error.is_none() {
                    cache.insert(cache_key, Arc::new(result));
                } else {
                    tracing::warn!(%url, error = ?result.error, "Background cache refresh failed");
                }
            });
        }
    }
}
