//! # rusty_wappalyzer
//!
//! A Rust implementation of the Wappalyzer technology-fingerprinting engine.
//!
//! ## Architecture
//! - [`TechnologyAnalyzer`] — compiles the Wappalyzer pattern database at startup
//!   and performs all regex-based detection against HTTP responses.
//! - [`StandaloneWappalyzer`] — thin wrapper that owns an `HttpClient` and a
//!   [`TechnologyAnalyzer`]; exposes [`analyze_url`](StandaloneWappalyzer::analyze_url)
//!   and [`analyze_urls_batch`](StandaloneWappalyzer::analyze_urls_batch).
//! - `HttpClient` — internal reqwest-based HTTP client (crate-private).
//! - [`WappalyzerConfig`] — runtime configuration (timeouts, concurrency limits).
//!
//! ## Feature flags
//! - `python` — exposes a PyO3 Python extension module.
//! - `python-bindings` — alias for `python` (backward compat).

pub mod types;
pub use types::*;

pub(crate) mod confidence;
use confidence::compute_noisy_or;

pub(crate) mod cache;
pub(crate) mod http_client;
pub use http_client::is_safe_url;
use http_client::HttpClient;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use regex::Regex;



pub mod analyzer;
pub use analyzer::TechnologyAnalyzer;

/// Number of leading bytes requested from each linked JS/CSS asset.
///
/// Asset inspection needs a window, not the whole bundle: the patterns it runs are
/// library banners (`/*! jQuery v3.7.1 ... */`), bundler markers and inline version
/// strings, and minifiers emit all of those at the top of the file. 16 KB comfortably
/// covers a minified bundle's license-header block plus the start of the code.
pub const ASSET_HEAD_BYTES: usize = 16 * 1024;

/// Number of trailing bytes requested from each linked JS asset, in a second `Range`
/// request, so that the `//# sourceMappingURL=` comment is visible.
///
/// Every bundler in common use (webpack, rollup, esbuild, vite, terser) APPENDS that
/// comment as the last line of the file it emits. On any bundle larger than
/// [`ASSET_HEAD_BYTES`] the comment therefore falls outside the head window, and
/// `TechnologyAnalyzer::try_source_map` — which looks for it in the body it is handed
/// — could never fire at all. Measured on a real target while fixing this: the
/// vercel.com main bundle is 36,100 bytes with `sourceMappingURL` at byte 36,063, i.e.
/// 37 bytes from EOF and roughly 20 KB past the end of the head window.
///
/// That path is worth keeping alive because a source map is the highest-precision
/// version signal in this tool: its `sources` array contains literal
/// `node_modules/<pkg>/<version>/...` paths, which is a ground-truth dependency
/// inventory rather than a regex guess.
///
/// 2 KB is generous for a trailing comment (a `sourceMappingURL` line is typically
/// under 100 bytes); the slack absorbs whatever else a bundler emits after the last
/// statement, such as a webpack runtime epilogue or a trailing `//# sourceURL=`.
pub const ASSET_TAIL_BYTES: usize = 2 * 1024;

/// Cache key under which an asset's TAIL window is stored.
///
/// The asset cache is keyed by URL and that key holds the HEAD window, so the tail
/// needs a key of its own — otherwise the two windows would overwrite each other and a
/// later reader could not tell which one it got back, feeding end-of-file bytes to
/// `analyze_asset` as if they were the start of the file (or vice versa).
///
/// The separator is a NUL byte. RFC 3986 admits no control character anywhere in a URI,
/// so a well-formed asset URL cannot contain one; the relative-href branch of
/// `inspect_assets` additionally builds its URLs through `url::Url::join`, whose
/// serialisation percent-encodes a NUL as `%00`. The absolute-href branch does pass the
/// `src` attribute through verbatim, so the guarantee ultimately rests on the page not
/// embedding a raw NUL inside a `src="http://…"` — which no browser would load either.
/// Short of that, the head and tail key spaces are disjoint.
fn asset_tail_cache_key(url: &str) -> String {
    format!("{}\u{0}tail", url)
}

/// Decide, from a 206 response's `Content-Range`, whether the head window we just
/// received is in fact the whole asset.
///
/// The header's form is `bytes <start>-<end>/<total>` (RFC 9110 §14.4), where `<total>`
/// may be `*` when the server does not know the full length. We return `true` only when
/// the range provably reaches the end of a known total. An absent, malformed or `*`
/// total is treated as "there may be more", which costs at most one extra suffix-range
/// request and can never cost a missed source map.
fn content_range_covers_whole_body(headers: &reqwest::header::HeaderMap) -> bool {
    let raw = match headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
    {
        Some(v) => v.trim(),
        None => return false,
    };
    // The unit token is almost always "bytes"; tolerate its absence rather than reject.
    let spec = raw.strip_prefix("bytes").map(|s| s.trim()).unwrap_or(raw);
    let (range, total) = match spec.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    let total: u64 = match total.trim().parse() {
        Ok(t) => t,
        Err(_) => return false, // "*" (unknown length) lands here, deliberately
    };
    let end: u64 = match range
        .trim()
        .split_once('-')
        .and_then(|(_, end)| end.trim().parse().ok())
    {
        Some(e) => e,
        None => return false,
    };
    end.saturating_add(1) >= total
}

/// Fetch the window(s) of a linked asset that detection actually reads: always the
/// first [`ASSET_HEAD_BYTES`], and — when `want_tail` is set and the asset is known to
/// be longer than that — the last [`ASSET_TAIL_BYTES`] as well.
///
/// Returns `(head, tail)`, where `tail` is `None` when the head already holds the whole
/// asset, when the caller did not ask for one, or when the server refused the suffix
/// range. A refused tail is never fatal: the head is still returned and analysis
/// continues, because losing the source map is strictly less bad than losing the asset.
///
/// Range handling, in the three shapes servers actually produce:
/// - **206 + `Content-Range`** — the normal case. The header says how big the file is,
///   so we know whether a tail request is needed without guessing.
/// - **200** — the server ignored `Range` and sent the entire body. There is then
///   nothing left to fetch, so the tail request is skipped entirely rather than being
///   issued and answered with a second full copy of the file.
/// - **416 / 400 / anything else on the TAIL request** — some servers and CDNs reject
///   suffix ranges (`bytes=-2048`) even though they accept `bytes=0-`. That is logged
///   and treated as "no tail".
///
/// Both windows go through the shared asset cache, under distinct keys (see
/// [`asset_tail_cache_key`]). A cached tail whose value is EMPTY is a sentinel meaning
/// "the head is the whole asset, do not ask again": without it, every asset smaller
/// than the head window would cost a wasted round trip on each analysis that links it,
/// since the head cache entry alone does not record how the server answered.
async fn fetch_asset_windows(
    client: &reqwest::Client,
    url: &str,
    cache: &moka::sync::Cache<String, Arc<String>>,
    timeout_secs: u64,
    want_tail: bool,
) -> Option<(Arc<String>, Option<Arc<String>>)> {
    let timeout = std::time::Duration::from_secs(timeout_secs);

    // --- head window ---
    // `None` means "served from cache, so we never saw the status line"; the length
    // heuristic below stands in for the Content-Range we no longer have.
    let (head, head_is_whole_asset): (Arc<String>, Option<bool>) = match cache.get(url) {
        Some(cached) => (cached, None),
        None => {
            let resp = match client
                .get(url)
                .header("Range", format!("bytes=0-{}", ASSET_HEAD_BYTES - 1))
                .timeout(timeout)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(url = %url, "asset fetch failed: {}", e);
                    return None;
                }
            };
            let status = resp.status().as_u16();
            if status != 200 && status != 206 {
                tracing::debug!(url = %url, status = status, "asset fetch returned unusable status");
                return None;
            }
            // 200 means the server ignored `Range` and handed over the complete file.
            let whole = status == 200 || content_range_covers_whole_body(resp.headers());
            let content = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::debug!(url = %url, "asset body read failed: {}", e);
                    return None;
                }
            };
            let arc = Arc::new(content);
            cache.insert(url.to_string(), Arc::clone(&arc));
            (arc, Some(whole))
        }
    };

    if !want_tail {
        return Some((head, None));
    }

    let tail_key = asset_tail_cache_key(url);
    if let Some(cached_tail) = cache.get(&tail_key) {
        // Empty is the "no tail exists" sentinel described above, not a tail of length 0.
        let tail = if cached_tail.is_empty() { None } else { Some(cached_tail) };
        return Some((head, tail));
    }

    // For a cache hit we no longer have the status line, so fall back on length: a
    // truncated head is exactly the size of the window we asked for, while a complete
    // one is shorter. (A body that happens to be exactly ASSET_HEAD_BYTES long costs one
    // needless suffix request; a decoded body that is *longer* than the window — which a
    // transfer-encoding could produce — is treated as truncated, which is the safe way
    // round.)
    let head_is_whole_asset =
        head_is_whole_asset.unwrap_or_else(|| head.len() < ASSET_HEAD_BYTES);
    if head_is_whole_asset {
        cache.insert(tail_key, Arc::new(String::new()));
        return Some((head, None));
    }

    // --- tail window ---
    let resp = match client
        .get(url)
        .header("Range", format!("bytes=-{}", ASSET_TAIL_BYTES))
        .timeout(timeout)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(url = %url, "asset tail fetch failed: {}", e);
            return Some((head, None));
        }
    };
    let status = resp.status().as_u16();
    if status != 200 && status != 206 {
        // 416 (Range Not Satisfiable) and 400 both show up here from servers that only
        // support a prefix range. Nothing is silently dropped: the head is still used.
        tracing::debug!(url = %url, status = status, "asset tail range refused");
        return Some((head, None));
    }
    let tail = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(url = %url, "asset tail body read failed: {}", e);
            return Some((head, None));
        }
    };
    let arc = Arc::new(tail);
    cache.insert(tail_key, Arc::clone(&arc));
    Some((head, Some(arc)))
}

/// Fold an incoming detection's version into an already-built [`Technology`], keeping
/// the better-sourced string rather than the one that happened to arrive first.
///
/// Both late layers that can produce a version — the probe layer and the source-map
/// layer — accumulate their findings in a FRESH `HashMap<String, TechDetection>` and
/// only meet the technology list here. So this fold, not
/// `TechnologyAnalyzer::update_detection`, is where a `/wp-includes/version.php` probe
/// result actually competes with the `?ver=` cache-buster that `analyze()` scraped off
/// a script tag. The two sites used to read `if t.version.is_none()`, i.e.
/// first-write-wins, which meant the probe result was dropped unread and the two
/// highest entries in `TechnologyAnalyzer::version_source_rank` — `probe` and
/// `source_map` — could not arbitrate anything at all.
///
/// The decision itself is deliberately NOT implemented here: it is
/// `TechnologyAnalyzer::version_outranks`, shared with `update_detection`. One rule,
/// one implementation — the defect this function exists to repair was created by a
/// second copy of the rule drifting out of step with the first.
///
/// Note what is approximated. `TechDetection` does not record which of its signals
/// produced its version, so the candidate's rank is the maximum rank over the incoming
/// signals (`version_rank_from_signals`, whose doc comment states the error direction
/// on each side). For the probe fold that maximum is exact, because every signal the
/// probe layer emits has signal_type `probe`. For the asset fold it can be an
/// over-estimate, since `inspect_assets` fills one map from two layers of different
/// rank.
///
/// Sanitisation is not skipped by taking this path: whichever string wins is
/// `sanitize_version`-ed later, once, in `TechnologyAnalyzer::finalize_gating`, which
/// runs after both folds.
fn merge_version_by_source_rank(
    tech: &mut Technology,
    candidate: Option<String>,
    candidate_signals: &[Signal],
) {
    if let Some(candidate) = candidate {
        let candidate_rank =
            TechnologyAnalyzer::version_rank_from_signals(candidate_signals, &candidate);
        // `tech.signals` is the incumbent's evidence and does not yet include the
        // incoming signals: callers extend it AFTER this returns, exactly as
        // `update_detection` appends its signal after deciding, so that a candidate
        // cannot raise the bar it then has to clear.
        if TechnologyAnalyzer::version_outranks(
            candidate_rank,
            tech.version.as_deref(),
            &tech.signals,
        ) {
            tech.version = Some(candidate);
        }
    }
}

/// Main application struct
pub struct StandaloneWappalyzer {
    pub(crate) analyzer: Arc<TechnologyAnalyzer>,
    pub(crate) http_client: HttpClient,
    pub(crate) config: WappalyzerConfig,
    pub(crate) asset_cache: Arc<moka::sync::Cache<String, Arc<String>>>,
}

impl StandaloneWappalyzer {
    pub async fn new(insecure: bool) -> Result<Self, WappalyzerError> {
        Self::with_config(insecure, WappalyzerConfig::default()).await
    }

    pub async fn with_config(insecure: bool, config: WappalyzerConfig) -> Result<Self, WappalyzerError> {
        tracing::info!("Initializing Standalone Wappalyzer");
        let analyzer = Arc::new(TechnologyAnalyzer::new().await?);

        let (tech_count, cat_count) = analyzer.get_stats();
        tracing::info!(technologies = tech_count, categories = cat_count, "Database loaded");
        crate::analyzer::log_skipped_pattern_summary();

        // Everything past this point is the cheap per-instance wrapper, and it is
        // shared verbatim with `with_shared_analyzer`. Keeping it in one place is
        // deliberate: if the two paths ever built their HTTP client or asset cache
        // differently, the server's per-request `-k` instance would silently stop
        // honouring the config (timeouts, SSRF protection, cache sizing) that the
        // primary instance was constructed with, and nothing would fail loudly.
        Self::with_shared_analyzer(analyzer, insecure, config)
    }

    /// Build a `StandaloneWappalyzer` around a [`TechnologyAnalyzer`] that has
    /// already been compiled, instead of compiling the pattern database again.
    ///
    /// Compiling the database is by far the expensive part of construction: ~7,500
    /// technologies with every regex compiled and retained for the process lifetime.
    /// Measured on a release build, a server that constructed two independent
    /// instances sat at 648 MB idle RSS versus 334 MB for one.
    ///
    /// That gap is what motivated this constructor. At the time, the k8s manifests
    /// capped the pod at `limits.memory: 512Mi` — below the 648 MB two-database
    /// footprint — so the two-instance server was OOMKilled before it could answer a
    /// single request. Those limits have since been raised (to `1Gi`, on the same
    /// branch as this constructor; see `deploy/k8s/wappalyzer.yaml`), so the OOMKill
    /// is history. The 314 MB of duplicated regex is not: sharing is what keeps the
    /// raised ceiling headroom rather than baseline. `TechnologyAnalyzer` is immutable
    /// once built and is only ever read during analysis, so a single allocation can
    /// safely back any number of wrappers.
    ///
    /// The wrappers still differ where it matters: each gets its OWN `HttpClient`
    /// (which is what carries `danger_accept_invalid_certs`) and its OWN asset cache.
    ///
    /// The separate asset cache is a security requirement, not an oversight. The
    /// insecure instance fetches linked JS/CSS with certificate validation disabled,
    /// so anyone able to intercept that connection chooses the body we store. Sharing
    /// one cache would let that attacker-chosen body be served back to an analysis
    /// performed by the secure instance — turning an explicit, per-request "I accept
    /// bad certs" into a silent downgrade for requests that never asked for it. The
    /// caches must stay per-instance for exactly as long as the TLS behaviour differs.
    pub fn with_shared_analyzer(
        analyzer: Arc<TechnologyAnalyzer>,
        insecure: bool,
        config: WappalyzerConfig,
    ) -> Result<Self, WappalyzerError> {
        let http_client = HttpClient::new_with_config(insecure, &config)?;

        let asset_cache = Arc::new(
            moka::sync::Cache::builder()
                .max_capacity(config.asset_cache_size)
                .time_to_live(std::time::Duration::from_secs(config.asset_cache_ttl_secs))
                .build()
        );

        Ok(Self {
            analyzer,
            http_client,
            config,
            asset_cache,
        })
    }

    /// Hand out a counted reference to the compiled pattern database.
    ///
    /// This is the supported way for a caller outside the crate to build a second
    /// wrapper (for example an insecure-mode instance) without paying for a second
    /// copy of the database; feed the result to [`Self::with_shared_analyzer`].
    pub fn shared_analyzer(&self) -> Arc<TechnologyAnalyzer> {
        Arc::clone(&self.analyzer)
    }

    /// Hand out a counted reference to this instance's linked-asset cache.
    ///
    /// Unlike [`Self::shared_analyzer`] this is NOT an invitation to share: it exists
    /// so that a caller which builds a second wrapper can *prove* the two caches are
    /// separate allocations (`!Arc::ptr_eq`). The server does exactly that, because
    /// the isolation is a security property — see the note on
    /// [`Self::with_shared_analyzer`] about bodies fetched with certificate
    /// validation disabled. Without an accessor that property is unobservable from
    /// outside the crate, and an unobservable property is an untestable one.
    pub fn asset_cache_handle(&self) -> Arc<moka::sync::Cache<String, Arc<String>>> {
        Arc::clone(&self.asset_cache)
    }

    /// Return (technology_count, category_count) from the loaded database
    pub fn get_stats(&self) -> (usize, usize) {
        self.analyzer.get_stats()
    }

    /// Maximum number of URLs accepted by the `/batch` API endpoint.
    pub fn max_batch_size(&self) -> usize {
        self.config.max_batch_size
    }

    /// Analyze a response the caller already fetched, without touching the network.
    ///
    /// This exists for callers that have the page in hand — a crawler, a proxy, a
    /// recon pipeline — and would otherwise have to make us fetch it a second time.
    /// Because nothing is requested, the layers that need network access are skipped:
    /// no DNS records, no linked-asset inspection, no favicon hashing, and no
    /// well-known endpoint probes. Expect fewer technologies and notably fewer
    /// extracted versions than `analyze_url`, since a lot of version strings live in
    /// linked JS rather than the HTML itself.
    ///
    /// The final exclude/require gate still runs, so results stay consistent with the
    /// fetching path for the layers that do apply.
    pub fn analyze_prefetched(&self, response: &HttpResponse, min_confidence: u8) -> Vec<Technology> {
        let mut technologies = self.analyzer.analyze(response, min_confidence);
        self.analyzer.finalize_gating(&mut technologies);
        technologies
    }

    /// Pre-warm regex compilation by running a trivial analysis against a synthetic response.
    /// Call once at server startup to avoid first-request latency spikes.
    pub async fn warm_up(&self) {
        let dummy = HttpResponse {
            url: "https://example.com/".to_string(),
            headers: std::collections::HashMap::new(),
            body: "<html><head><title>warmup</title></head><body></body></html>".to_string(),
            status_code: 200,
            response_time_ms: 0,
            set_cookie_headers: Vec::new(),
        };
        let _ = self.analyzer.analyze(&dummy, 1);
        tracing::info!("Wappalyzer warm-up complete");
    }

    /// Fetch linked JS/CSS assets and run pattern matching to fill in version numbers.
    async fn inspect_assets(
        analyzer: &TechnologyAnalyzer,
        client: &reqwest::Client,
        html: &str,
        base_url: &str,
        technologies: &mut Vec<Technology>,
        min_confidence: u8,
        config: &WappalyzerConfig,
        asset_cache: Arc<moka::sync::Cache<String, Arc<String>>>,
    ) {
        use tokio::sync::Semaphore;

        // --- extract asset URLs ---
        static SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<script[^>]+src=["']([^"']+)"#).unwrap()
        });
        static LINK_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<link[^>]+href=["']([^"']+\.css[^"']*)"#).unwrap()
        });

        let mut asset_urls: Vec<String> = Vec::new();
        let mut seen_assets: HashSet<String> = HashSet::new();
        for cap in SCRIPT_RE.captures_iter(html).chain(LINK_RE.captures_iter(html)) {
            if let Some(raw) = cap.get(1).map(|m| m.as_str()) {
                let resolved = if raw.starts_with("http://") || raw.starts_with("https://") {
                    raw.to_string()
                } else if let Ok(base) = url::Url::parse(base_url) {
                    match base.join(raw) {
                        Ok(u) => u.to_string(),
                        Err(_) => continue,
                    }
                } else {
                    continue
                };
                if seen_assets.insert(resolved.clone()) {
                    asset_urls.push(resolved);
                }
            }
        }

        if asset_urls.is_empty() { return; }

        // --- fetch the head (and, for JS, the tail) window of each asset concurrently ---
        //
        // The semaphore bounds outbound concurrency, and a permit is held across BOTH
        // requests an asset may make, so adding the tail fetch widens no concurrency
        // limit: it makes each slot occasionally do two sequential round trips instead of
        // one. Asset URLs were deduplicated above, so there is exactly one task per URL
        // and the head and tail requests for a given asset are ordered by the `.await`
        // between them rather than racing for the same cache entry.
        let semaphore = Arc::new(Semaphore::new(config.asset_concurrency));
        // Copy out scalar config values needed inside the spawned tasks.
        let asset_timeout_secs = config.asset_timeout_secs;
        let tasks: Vec<_> = asset_urls.into_iter().map(|url| {
            let client = client.clone();
            let sem = Arc::clone(&semaphore);
            let cache = Arc::clone(&asset_cache);
            tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                // Only JS gets a tail window, because the tail exists solely to expose the
                // trailing sourceMappingURL comment and `try_source_map` is skipped for
                // CSS below. The predicate is deliberately the same one as that skip, so
                // the two can't drift into fetching a tail nobody reads.
                let wants_source_map = !url.contains(".css");
                let (head, tail) = fetch_asset_windows(
                    &client, &url, &cache, asset_timeout_secs, wants_source_map,
                ).await?;
                Some((url, head, tail))
            })
        }).collect();

        let assets: Vec<(String, Arc<String>, Option<Arc<String>>)> =
            futures::future::join_all(tasks).await
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        // --- run pattern matching on each asset ---
        let mut new_detected: HashMap<String, TechDetection> = HashMap::new();
        for (url, head_arc, tail_arc) in &assets {
            let head: &str = head_arc;
            // Only the HEAD window is fed to pattern matching, never the tail. Two
            // reasons, in order of importance:
            //
            // 1. Double counting. A server that ignores `Range` answers the tail request
            //    with the whole body (see `fetch_asset_windows`), so every pattern that
            //    already matched in the head would match again and push a SECOND
            //    identical signal. `compute_noisy_or` reads two signals as more evidence
            //    than one, so the asset would silently inflate its own confidence —
            //    a detection deciding its own score, which is exactly what the
            //    signal-weight design exists to prevent.
            // 2. Yield. The things `analyze_asset` looks for — license banners, bundler
            //    preambles, `@version` comments — are emitted at the TOP of a bundle by
            //    every minifier, so the end of the file has close to nothing to offer.
            //
            // Discovering the trailing sourceMappingURL comment is the one job the tail
            // has, and `try_source_map` is the only thing that reads it.
            analyzer.analyze_asset(url, head, &mut new_detected);
            // Source map intelligence: parse .map files for exact npm package versions.
            //
            // Not attempted for CSS: `try_source_map` mines `node_modules/<pkg>/...`
            // paths out of the map's `sources` array, which is a JS dependency inventory.
            //
            // Considered and rejected: speculatively requesting `<asset-url>.map` when no
            // comment is found. Some builds do ship the map while stripping the comment,
            // so there is real yield there — but the cost is one extra request per JS
            // asset on EVERY analysis, and a typical page links five to twenty of them,
            // so it is a fixed multiplier on outbound traffic and wall-clock for a path
            // that 404s on the large majority of production sites. It is also a request
            // for a URL the target never advertised, which is the definition of the
            // probing that `full_scan` exists to gate. If we want it, it belongs behind
            // `full_scan` in the probe layer, not unconditionally here.
            if !url.contains(".css") {
                analyzer.try_source_map(
                    client,
                    url,
                    head,
                    tail_arc.as_ref().map(|t| t.as_str()),
                    &mut new_detected,
                    config.source_map_timeout_secs,
                ).await;
            }
        }

        // --- merge: update existing versions, append newly found techs ---
        for (name, detection) in new_detected {
            let confidence = compute_noisy_or(&detection.signals);
            if confidence < min_confidence { continue; }
            if let Some(t) = technologies.iter_mut().find(|t| t.name == name) {
                merge_version_by_source_rank(t, detection.version, &detection.signals);
                t.signals.extend(detection.signals);
            } else {
                let mut tech = analyzer.build_technology(&name, confidence, detection.version);
                tech.signals = detection.signals;
                technologies.push(tech);
            }
        }
    }

    /// Probe well-known version-disclosure endpoints on the target origin and
    /// merge any new findings into the technology list.
    async fn probe_version_endpoints(
        analyzer: &TechnologyAnalyzer,
        client: &reqwest::Client,
        base_url: &str,
        technologies: &mut Vec<Technology>,
        min_confidence: u8,
        config: &WappalyzerConfig,
        full_scan: bool,
    ) {
        use tokio::sync::Semaphore;

        // Preserve non-default ports so probes target the correct host:port.
        // Stripping the port would cause `https://example.com:8443/...` to probe
        // example.com:443 (the default), missing services on alternate ports.
        let origin = match url::Url::parse(base_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), h, p),
                None    => format!("{}://{}",    u.scheme(), h),
            }))
        {
            Some(o) => o,
            None => return,
        };

        let probes = analyzer::layers::probes::build_probe_list(&origin, technologies, full_scan);

        let probe_timeout_secs = config.probe_timeout_secs;
        let probe_concurrency = config.probe_concurrency;
        let sem = Arc::new(Semaphore::new(probe_concurrency));
        let tasks: Vec<_> = probes.into_iter().map(|(url, tag)| {
            let client = client.clone();
            let sem = Arc::clone(&sem);
            tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                let resp = client
                    .get(&url)
                    .timeout(std::time::Duration::from_secs(probe_timeout_secs))
                    .send()
                    .await
                    .ok()?;
                let status = resp.status().as_u16();
                let accept = analyzer::layers::probes::accepts_status_for_tag(tag, status);
                if accept {
                    let body = resp.text().await.ok().unwrap_or_default();
                    Some((tag, url, body, status))
                } else {
                    None
                }
            })
        }).collect();

        let responses: Vec<(&'static str, String, String, u16)> = futures::future::join_all(tasks)
            .await
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        let mut new_detected: HashMap<String, TechDetection> = HashMap::new();

        analyzer.parse_probe_responses(&responses, &mut new_detected);

        // Merge new_detected into the existing technology list
        for (name, detection) in new_detected {
            let confidence = compute_noisy_or(&detection.signals);
            if confidence < min_confidence { continue; }
            if let Some(t) = technologies.iter_mut().find(|t| t.name == name) {
                merge_version_by_source_rank(t, detection.version, &detection.signals);
                t.signals.extend(detection.signals);
            } else {
                let mut tech = analyzer.build_technology(&name, confidence, detection.version);
                tech.signals = detection.signals;
                technologies.push(tech);
            }
        }
    }

    /// Analyze a single URL. Pass `full_scan = true` to also probe well-known
    /// version-disclosure endpoints (`/wp-json/`, `/package.json`, etc.).
    pub async fn analyze_url(&self, url: &str, min_confidence: u8, full_scan: bool) -> AnalysisResult {
        let start = Instant::now();

        // Run HTTP fetch and DNS lookup concurrently
        let (fetch_result, dns_techs) = tokio::join!(
            self.http_client.fetch_page(url),
            self.analyzer.detect_from_dns(url, min_confidence),
        );

        match fetch_result {
            Ok(response) => {
                let mut technologies = self.analyzer.analyze(&response, min_confidence);
                {
                    let existing: HashSet<String> = technologies.iter().map(|t| t.name.clone()).collect();
                    for tech in dns_techs {
                        if !existing.contains(&tech.name) {
                            technologies.push(tech);
                        }
                    }
                }
                // Deep asset inspection: fetch linked JS/CSS to find version numbers
                Self::inspect_assets(
                    &self.analyzer,
                    &self.http_client.client,
                    &response.body,
                    url,
                    &mut technologies,
                    min_confidence,
                    &self.config,
                    Arc::clone(&self.asset_cache),
                ).await;
                // Favicon fingerprinting
                self.analyzer.detect_favicon(
                    &self.http_client.client,
                    url,
                    &response.body,
                    &mut technologies,
                    self.config.favicon_timeout_secs,
                ).await;
                // Probe well-known endpoints: always when full_scan is requested,
                // or automatically as a fallback when nothing was detected.
                if full_scan || technologies.is_empty() {
                    Self::probe_version_endpoints(
                        &self.analyzer,
                        &self.http_client.client,
                        url,
                        &mut technologies,
                        min_confidence,
                        &self.config,
                        full_scan,
                    ).await;
                }
                // Final gate: re-apply excludes / requires / requires_category over
                // the merged tech list so late-stage layers (assets, favicon, probes,
                // DNS) can't re-introduce techs whose dependencies are absent.
                self.analyzer.finalize_gating(&mut technologies);
                AnalysisResult {
                    url: url.to_string(),
                    technologies,
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: Some(response),
                    error: None,
                }
            }
            Err(e) => {
                AnalysisResult {
                    url: url.to_string(),
                    technologies: Vec::new(),
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Analyze multiple URLs concurrently.
    ///
    /// Reuses the HTTP client (and its TLS session cache / connection pool) that
    /// was configured at construction time.  The `insecure` flag is therefore
    /// controlled by the [`WappalyzerConfig`] passed to [`Self::with_config`].
    ///
    /// `concurrency` is clamped to `1..=urls.len()` — see
    /// [`clamp_batch_concurrency`] for why a raw value is never handed to the
    /// semaphore.
    pub async fn analyze_urls_batch(&self, urls: Vec<String>, concurrency: usize, min_confidence: u8, full_scan: bool) -> Result<Vec<AnalysisResult>, WappalyzerError> {
        use tokio::sync::Semaphore;

        // Defence in depth. The `/batch` HTTP handler already rejects an
        // out-of-range `concurrency` with a 400, but that guard only covers the
        // HTTP surface. This is a public library API: `rustywap batch
        // --concurrency N` passes the CLI flag straight through, the benchmark
        // command does the same, and external crates call it directly. Without
        // this clamp, `0` makes `Semaphore::new(0)` hand out no permits, so
        // every spawned task parks on `acquire()` forever and the call never
        // returns; and anything above tokio's MAX_PERMITS (usize::MAX >> 3),
        // such as `usize::MAX`, panics inside `Semaphore::new` and takes the
        // calling task -- an actix worker thread, in server mode -- down with
        // it. Both were reachable from a single JSON field.
        let concurrency = clamp_batch_concurrency(concurrency, urls.len());

        let semaphore = Arc::new(Semaphore::new(concurrency));
        use std::io::IsTerminal;
        let is_interactive = std::io::stderr().is_terminal();
        let pb = if is_interactive {
            let p = ProgressBar::new(urls.len() as u64);
            p.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap());
            Some(p)
        } else {
            None
        };

        let analyzer = Arc::clone(&self.analyzer);
        // Reuse the pre-built client (retains TLS sessions, connection pool, and
        // any installed SsrfDnsResolver) instead of allocating a fresh one per call.
        let client = self.http_client.client.clone();
        let config = Arc::new(self.config.clone());
        let pb = Arc::new(pb);
        let asset_cache = Arc::clone(&self.asset_cache);

        let tasks: Vec<(String, tokio::task::JoinHandle<AnalysisResult>)> = urls.into_iter().map(|url| {
            let url_for_err = url.clone();
            let analyzer = Arc::clone(&analyzer);
            let client = client.clone();
            let semaphore = Arc::clone(&semaphore);
            let pb = Arc::clone(&pb);
            let config = Arc::clone(&config);
            let asset_cache = Arc::clone(&asset_cache);

            let handle = tokio::spawn(async move {
                let _permit = match semaphore.acquire().await {
                    Ok(p) => p,
                    Err(_) => return AnalysisResult {
                        url: url.clone(),
                        technologies: Vec::new(),
                        analysis_time_ms: 0,
                        response_info: None,
                        error: Some("Semaphore closed".to_string()),
                    },
                };
                let result = Self::analyze_single_url_static(analyzer, &client, &url, min_confidence, full_scan, &config, asset_cache).await;
                if let Some(ref p) = *pb { p.inc(1); }
                result
            });
            (url_for_err, handle)
        }).collect();

        let results = futures::future::join_all(tasks.into_iter().map(|(url, handle)| async move {
            match handle.await {
                Ok(r) => r,
                Err(e) => AnalysisResult {
                    url,
                    technologies: Vec::new(),
                    analysis_time_ms: 0,
                    response_info: None,
                    error: Some(format!("Task panicked: {}", e)),
                },
            }
        })).await;

        if let Some(p) = Arc::try_unwrap(pb).ok().flatten() { p.finish_with_message("Analysis complete"); }
        Ok(results)
    }

    async fn analyze_single_url_static(
        analyzer: Arc<TechnologyAnalyzer>,
        client: &reqwest::Client,
        url: &str,
        min_confidence: u8,
        full_scan: bool,
        config: &WappalyzerConfig,
        asset_cache: Arc<moka::sync::Cache<String, Arc<String>>>,
    ) -> AnalysisResult {
        let start = Instant::now();

        let (fetch_result, dns_techs) = tokio::join!(
            http_client::fetch_with_client(client, url),
            analyzer.detect_from_dns(url, min_confidence),
        );

        match fetch_result {
            Ok(response) => {
                let mut technologies = analyzer.analyze(&response, min_confidence);
                {
                    let existing: HashSet<String> = technologies.iter().map(|t| t.name.clone()).collect();
                    for tech in dns_techs {
                        if !existing.contains(&tech.name) {
                            technologies.push(tech);
                        }
                    }
                }
                Self::inspect_assets(
                    &analyzer,
                    client,
                    &response.body,
                    url,
                    &mut technologies,
                    min_confidence,
                    config,
                    asset_cache,
                ).await;
                // Favicon fingerprinting
                analyzer.detect_favicon(client, url, &response.body, &mut technologies, config.favicon_timeout_secs).await;
                // Probe well-known endpoints: always when full_scan is requested,
                // or automatically as a fallback when nothing was detected.
                // Mirrors the single-URL path so /batch and /analyze behave identically.
                if full_scan || technologies.is_empty() {
                    Self::probe_version_endpoints(
                        &analyzer,
                        client,
                        url,
                        &mut technologies,
                        min_confidence,
                        config,
                        full_scan,
                    ).await;
                }
                // Same final gate as the single-URL path. Without this, /batch skipped
                // exclude/require post-processing entirely and returned a different
                // technology list than /analyze for the very same URL.
                analyzer.finalize_gating(&mut technologies);
                AnalysisResult {
                    url: url.to_string(),
                    technologies,
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: Some(response),
                    error: None,
                }
            }
            Err(e) => {
                AnalysisResult {
                    url: url.to_string(),
                    technologies: Vec::new(),
                    analysis_time_ms: start.elapsed().as_millis() as u64,
                    response_info: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

}

/// Clamp a caller-supplied batch concurrency into a range a semaphore can hold.
///
/// Returned value is always `>= 1` and never exceeds `url_count.max(1)`.
///
/// Two separate hazards motivate this, and they sit at opposite ends of the
/// range:
///
/// * `0` is not "no limit", it is "no permits". `Semaphore::new(0)` never
///   releases anyone, so every task parks on `acquire()` and the batch hangs
///   until the process dies. There is no timeout on that wait.
/// * Very large values panic rather than saturate: tokio asserts
///   `permits <= MAX_PERMITS` (`usize::MAX >> 3`) inside `Semaphore::new`, so a
///   value like `usize::MAX` aborts the task that constructed it.
///
/// The upper bound is `url_count` rather than some fixed ceiling because a
/// permit that no task can ever take is dead weight: with N URLs there are only
/// ever N tasks, so anything above N behaves identically to N while widening
/// the range in which the two hazards above live. `max(1)` keeps an empty batch
/// from producing `clamp(1, 0)`, which itself panics.
pub fn clamp_batch_concurrency(requested: usize, url_count: usize) -> usize {
    requested.clamp(1, url_count.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Dev-dependency, so these are unit-test-only imports; both fold tests below
    // serve every request they make from a loopback mock server.
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use wiremock::matchers::{method, path};

    /// Regression guard for a remote DoS: `/batch` accepted `concurrency`
    /// verbatim, so `0` hung the request forever and `u64::MAX` panicked the
    /// actix worker thread inside `Semaphore::new`. Pure and offline.
    #[test]
    fn test_clamp_batch_concurrency() {
        // Zero would mean a semaphore that never hands out a permit.
        assert_eq!(clamp_batch_concurrency(0, 10), 1);
        // usize::MAX is past tokio's MAX_PERMITS and used to panic.
        assert_eq!(clamp_batch_concurrency(usize::MAX, 10), 10);
        // Sane values pass through untouched.
        assert_eq!(clamp_batch_concurrency(5, 10), 5);
        assert_eq!(clamp_batch_concurrency(10, 10), 10);
        // More concurrency than URLs is capped at the number of tasks.
        assert_eq!(clamp_batch_concurrency(50, 3), 3);
        // An empty batch must not produce clamp(1, 0), which panics.
        assert_eq!(clamp_batch_concurrency(0, 0), 1);
        assert_eq!(clamp_batch_concurrency(usize::MAX, 0), 1);
    }

    /// The clamp is reached at its real call site, not merely as a pure function.
    ///
    /// `test_clamp_batch_concurrency` above proves the arithmetic, but nothing
    /// proved that `analyze_urls_batch` calls it before `Semaphore::new`: delete
    /// that one line and the pure test stays green while every batch caller passing
    /// `0` hangs forever. The `/batch` HTTP tests do not close that gap either —
    /// they send only private addresses, which the SSRF pre-flight rejects, so the
    /// handler short-circuits on an empty accepted list and never constructs a
    /// semaphore at all.
    ///
    /// The `timeout` is the mechanism of this test, not a safety net. Without the
    /// clamp, `Semaphore::new(0)` hands out no permits, every spawned task parks on
    /// `acquire()` forever and the join below never resolves — which would wedge the
    /// whole test binary instead of failing it. The timeout converts that infinite
    /// hang into a named failure.
    ///
    /// Why 30 s rather than a couple of seconds: the batch pipeline runs
    /// `detect_from_dns` concurrently with the fetch, and that resolver is built with
    /// a 3 s timeout and 2 attempts, so a host with no reachable resolver takes ~6 s
    /// to give up. A tighter bound would flake there. Any finite bound catches the
    /// regression, because the regression never completes at all.
    ///
    /// Network reach: the HTTP side stays on this machine. Nothing listens on
    /// 127.0.0.1 port 1, so the kernel refuses the connection immediately and no
    /// packet leaves the loopback interface. `WappalyzerConfig::default()` has
    /// `ssrf_protection: false`, so the library path does not pre-reject a loopback
    /// target the way the server path would. The DNS layer does still issue lookups
    /// for the literal names `127.0.0.1.` and `www.127.0.0.1.` — exactly as the
    /// existing wiremock tests in `tests/integration_test.rs` already do for their
    /// loopback mock server — but those names resolve to nothing, no target site is
    /// contacted, and the assertion below holds whether or not a resolver answers.
    ///
    /// Each URL therefore comes back as an `AnalysisResult` carrying a connection
    /// error, which is the expected outcome here; the assertion is on arity, not on
    /// detections.
    #[tokio::test]
    async fn test_analyze_urls_batch_clamps_zero_concurrency_at_the_call_site() {
        let wappalyzer = StandaloneWappalyzer::new(false).await
            .expect("StandaloneWappalyzer::new failed — is wappalyzer_cache.json present or network available?");

        let urls = vec![
            "http://127.0.0.1:1/".to_string(),
            "http://127.0.0.1:1/".to_string(),
        ];

        let results = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            wappalyzer.analyze_urls_batch(urls.clone(), 0, 50, false),
        )
        .await
        .expect(
            "analyze_urls_batch never returned: concurrency 0 reached Semaphore::new \
             unclamped, so no spawned task was ever granted a permit",
        )
        .expect("the batch call itself must succeed; per-URL failures are per-entry");

        assert_eq!(
            results.len(),
            urls.len(),
            "one AnalysisResult per input URL, even when every fetch is refused"
        );
    }

    #[tokio::test]
    async fn test_pattern_compilation() {
        // Test simple pattern
        let pattern = r"WordPress";
        let compiled = TechnologyAnalyzer::compile_single_pattern(pattern).unwrap();
        assert!(compiled.is_some());

        let compiled = compiled.unwrap();
        assert_eq!(compiled.confidence, 100); // default confidence
        assert_eq!(compiled.version, None); // no version pattern

        // Test pattern with confidence (using correct format)
        let pattern_with_confidence = r"WordPress\;confidence:80";
        let compiled2 = TechnologyAnalyzer::compile_single_pattern(pattern_with_confidence).unwrap();
        assert!(compiled2.is_some());

        let compiled2 = compiled2.unwrap();
        assert_eq!(compiled2.confidence, 80);
        assert_eq!(compiled2.version, None);

        // Test pattern with version (using correct format)
        let pattern_with_version = r"WordPress\;version:\1";
        let compiled3 = TechnologyAnalyzer::compile_single_pattern(pattern_with_version).unwrap();
        assert!(compiled3.is_some());

        let compiled3 = compiled3.unwrap();
        assert_eq!(compiled3.confidence, 100); // default
        assert_eq!(compiled3.version, Some("\\1".to_string()));
    }

    #[tokio::test]
    async fn test_version_extraction() {
        let pattern = Some("\\1".to_string());
        let regex = Regex::new(r"WordPress (\d+\.\d+)").unwrap();
        let captures = PatternCaptures::Fast(regex.captures("WordPress 5.8").unwrap());

        let version = TechnologyAnalyzer::extract_version(&pattern, &captures);
        assert_eq!(version, Some("5.8".to_string()));
    }

    #[tokio::test]
    async fn test_http_response_analysis() {
        let response = HttpResponse {
            url: "https://example.com".to_string(),
            headers: {
                let mut headers = HashMap::new();
                headers.insert("server".to_string(), "Apache/2.4.41".to_string());
                headers.insert("x-powered-by".to_string(), "PHP/7.4.0".to_string());
                headers
            },
            body: r#"<html>
                <head>
                    <meta name="generator" content="WordPress 5.8">
                    <title>Test Site</title>
                </head>
                <body>
                    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
                </body>
            </html>"#.to_string(),
            status_code: 200,
            response_time_ms: 150,
            set_cookie_headers: Vec::new(),
        };

        assert_eq!(response.status_code, 200);
        assert!(response.body.contains("WordPress"));
        assert!(response.headers.contains_key("server"));
    }

    // ── compute_noisy_or ─────────────────────────────────────────────────────

    #[test]
    fn test_noisy_or_empty() {
        assert_eq!(compute_noisy_or(&[]), 0);
    }

    #[test]
    fn test_noisy_or_single_full_confidence() {
        let s = Signal { signal_type: "html".into(), value: "x".into(), weight: 100 };
        assert_eq!(compute_noisy_or(&[s]), 100);
    }

    #[test]
    fn test_noisy_or_two_signals() {
        // weights 70 and 60 → P(none) = 0.30 × 0.40 = 0.12 → score ≈ 88
        let signals = vec![
            Signal { signal_type: "html".into(),   value: "a".into(), weight: 70 },
            Signal { signal_type: "header".into(), value: "b".into(), weight: 60 },
        ];
        assert_eq!(compute_noisy_or(&signals), 88);
    }

    #[test]
    fn test_noisy_or_zero_weight() {
        let s = Signal { signal_type: "html".into(), value: "x".into(), weight: 0 };
        assert_eq!(compute_noisy_or(&[s]), 0);
    }

    // ── compile_single_pattern ───────────────────────────────────────────────

    #[test]
    fn test_compile_empty_pattern_matches_all() {
        let p = TechnologyAnalyzer::compile_single_pattern("").unwrap().unwrap();
        assert_eq!(p.confidence, 100);
        assert!(p.version.is_none());
        assert!(p.regex.is_match("anything"));
    }

    #[test]
    fn test_compile_pattern_case_insensitive() {
        let p = TechnologyAnalyzer::compile_single_pattern("wordpress").unwrap().unwrap();
        assert!(p.regex.is_match("WORDPRESS"));
        assert!(p.regex.is_match("WordPress"));
    }

    #[test]
    fn test_compile_invalid_regex_returns_none() {
        let result = TechnologyAnalyzer::compile_single_pattern("[unclosed");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // ── extract_version ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_version_none_template() {
        let caps = PatternCaptures::Fast(Regex::new(r"(foo)").unwrap().captures("foo").unwrap());
        assert_eq!(TechnologyAnalyzer::extract_version(&None, &caps), None);
    }

    #[test]
    fn test_extract_version_empty_template_returns_none() {
        let caps = PatternCaptures::Fast(Regex::new(r"(foo)").unwrap().captures("foo").unwrap());
        assert_eq!(TechnologyAnalyzer::extract_version(&Some(String::new()), &caps), None);
    }

    #[test]
    fn test_extract_version_ternary_matched() {
        let caps = PatternCaptures::Fast(Regex::new(r"v(\d+)").unwrap().captures("v3").unwrap());
        let ver = TechnologyAnalyzer::extract_version(&Some(r"\1?major:fallback".to_string()), &caps);
        assert_eq!(ver, Some("major".to_string()));
    }

    #[test]
    fn test_extract_version_ternary_unmatched() {
        let caps = PatternCaptures::Fast(Regex::new(r"v(\d+)(\.\d+)?").unwrap().captures("v3").unwrap());
        let ver = TechnologyAnalyzer::extract_version(&Some(r"\2?major:fallback".to_string()), &caps);
        assert_eq!(ver, Some("fallback".to_string()));
    }

    // ── HttpClient uses WappalyzerConfig ─────────────────────────────────────

    #[test]
    fn test_http_client_new_with_config() {
        let cfg = WappalyzerConfig { http_timeout_secs: 5, connect_timeout_secs: 2, ..Default::default() };
        assert!(HttpClient::new_with_config(false, &cfg).is_ok());
        assert!(HttpClient::new_with_config(true,  &cfg).is_ok());
    }

    // ── Integration-style detection tests ────────────────────────────────────
    // These build a real TechnologyDatabase in-memory from the cache file and
    // verify that specific signals produce the expected detections.

    fn make_response(url: &str, headers: HashMap<String, String>, body: &str) -> HttpResponse {
        HttpResponse {
            url: url.to_string(),
            headers,
            body: body.to_string(),
            status_code: 200,
            response_time_ms: 10,
            set_cookie_headers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_detect_wordpress_meta_generator() {
        let analyzer = TechnologyAnalyzer::new().await
            .expect("TechnologyAnalyzer::new failed — is wappalyzer_cache.json present or network available?");
        let mut h = HashMap::new();
        h.insert("x-powered-by".to_string(), "PHP/8.1".to_string());
        let body = r#"<html><head><meta name="generator" content="WordPress 6.4.2"></head><body></body></html>"#;
        let resp = make_response("https://example.com/", h, body);
        let techs = analyzer.analyze(&resp, 50);
        assert!(
            techs.iter().any(|t| t.name.to_lowercase().contains("wordpress")),
            "Expected WordPress to be detected; got: {:?}", techs.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_detect_nextjs_html_signal() {
        let analyzer = TechnologyAnalyzer::new().await
            .expect("TechnologyAnalyzer::new failed — is wappalyzer_cache.json present or network available?");
        let headers = HashMap::new();
        // __NEXT_DATA__ id attribute is a strong Next.js signal added in our html scanner
        let body = r#"<html><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script></body></html>"#;
        let resp = make_response("https://example.com/", headers, body);
        let techs = analyzer.analyze(&resp, 50);
        assert!(
            techs.iter().any(|t| t.name.to_lowercase().contains("next")),
            "Expected Next.js to be detected; got: {:?}", techs.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_detect_django_csrftoken_cookie() {
        let analyzer = TechnologyAnalyzer::new().await
            .expect("TechnologyAnalyzer::new failed — is wappalyzer_cache.json present or network available?");
        let mut h = HashMap::new();
        h.insert("set-cookie".to_string(), "csrftoken=abc123; Path=/".to_string());
        let resp = make_response("https://example.com/", h, "<html></html>");
        let techs = analyzer.analyze(&resp, 50);
        assert!(
            techs.iter().any(|t| t.name.to_lowercase().contains("django")),
            "Expected Django to be detected via csrftoken cookie; got: {:?}", techs.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_detect_sentry_from_csp() {
        let analyzer = TechnologyAnalyzer::new().await
            .expect("TechnologyAnalyzer::new failed — is wappalyzer_cache.json present or network available?");
        let mut h = HashMap::new();
        h.insert(
            "content-security-policy".to_string(),
            "default-src 'self'; connect-src 'self' https://o123.ingest.sentry.io".to_string(),
        );
        let resp = make_response("https://example.com/", h, "<html></html>");
        let techs = analyzer.analyze(&resp, 50);
        assert!(
            techs.iter().any(|t| t.name.to_lowercase().contains("sentry")),
            "Expected Sentry to be detected via CSP header; got: {:?}", techs.iter().map(|t| &t.name).collect::<Vec<_>>()
        );
    }

    // ── build_probe_list ─────────────────────────────────────────────────────

    #[test]
    fn test_build_probe_list_universal_always_present() {
        let probes = analyzer::layers::probes::build_probe_list("https://example.com", &[], false);
        let tags: Vec<_> = probes.iter().map(|(_, t)| *t).collect();
        assert!(tags.contains(&"robots"), "robots.txt should always be probed");
        assert!(tags.contains(&"package-json"), "package.json should always be probed");
        assert!(tags.contains(&"healthz"), "healthz should always be probed");
    }

    #[test]
    fn test_build_probe_list_wordpress_conditional() {
        // Without WordPress detected and with at least one tech, WP probes should be skipped
        let fake_tech = Technology {
            name: "SomeOtherFramework".to_string(),
            confidence: 80,
            version: None,
            categories: vec![],
            website: None,
            description: None,
            icon: None,
            cpe: None,
            saas: None,
            pricing: None,
            signals: vec![],
        };
        let probes = analyzer::layers::probes::build_probe_list("https://example.com", &[fake_tech], false);
        let tags: Vec<_> = probes.iter().map(|(_, t)| *t).collect();
        assert!(!tags.contains(&"wp-json"), "wp-json should not be probed when WordPress not detected");
    }

    #[test]
    fn test_build_probe_list_sensitive_probes_gated_by_full_scan() {
        let origin = "https://example.com";
        // full_scan=false: .env and .git/HEAD should NOT be included
        let probes_no_full = analyzer::layers::probes::build_probe_list(origin, &[], false);
        let tags_no_full: Vec<_> = probes_no_full.iter().map(|(_, t)| *t).collect();
        assert!(!tags_no_full.contains(&"env-file"), ".env should not appear without full_scan");
        assert!(!tags_no_full.contains(&"git-head"), ".git/HEAD should not appear without full_scan");
        // full_scan=true: they SHOULD appear
        let probes_full = analyzer::layers::probes::build_probe_list(origin, &[], true);
        let tags_full: Vec<_> = probes_full.iter().map(|(_, t)| *t).collect();
        assert!(tags_full.contains(&"env-file"), ".env should appear with full_scan");
        assert!(tags_full.contains(&"git-head"), ".git/HEAD should appear with full_scan");
    }

    // ── version precedence at the fold sites ──────────────────────────────────
    //
    // These two tests exist because a test of `version_source_rank` alone proves
    // nothing about this file: the ranking function was already correct and already
    // unit-tested while BOTH folds below still read `if t.version.is_none()`, which is
    // first-write-wins and is the rule the ranking was written to replace. So they
    // drive the real fold code — `inspect_assets` and `probe_version_endpoints`,
    // through a wiremock origin — rather than the predicate underneath it. Restoring
    // either `if t.version.is_none() && detection.version.is_some()` guard makes the
    // corresponding assertion below fail.
    //
    // Offline: `wiremock::MockServer` binds a random loopback port and every URL used
    // here is that server. `WappalyzerConfig::default()` has `ssrf_protection: false`,
    // so the library path does not pre-reject a loopback target. No DNS layer runs —
    // neither `inspect_assets` nor `probe_version_endpoints` performs a lookup — and
    // the analyzer itself is built from the on-disk technology database
    // (`wappalyzer_cache.json`, or `$WAPPALYZER_CACHE`), not fetched.

    /// A `Technology` with only the fields these tests care about populated.
    fn bare_tech(name: &str, version: Option<&str>, signals: Vec<Signal>) -> Technology {
        Technology {
            name: name.to_string(),
            confidence: 80,
            version: version.map(|v| v.to_string()),
            categories: vec![],
            website: None,
            description: None,
            icon: None,
            cpe: None,
            saas: None,
            pricing: None,
            signals,
        }
    }

    /// The motivating case, end to end through the probe fold.
    ///
    /// A WordPress site whose assets carry `?ver=6.5.3` cache-busters: `analyze()`
    /// stores 6.5.3 off a script tag (a query-string version, rank 20), then the probe
    /// layer reads the site's own `/wp-json/` and gets 6.8.1 (rank 100). The fold used
    /// to test `t.version.is_none()`, so the true version was thrown away and the tool
    /// reported the cache-buster.
    ///
    /// Only `/wp-json/` is stubbed with content; every other probe in the list gets the
    /// catch-all 404 and is discarded by `accepts_status_for_tag`.
    #[tokio::test]
    async fn test_probe_version_replaces_lower_ranked_version_at_the_probe_fold() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/wp-json/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"name":"Test","description":"","url":"/","generator":"WordPress 6.8.1"}"#,
            ))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let wappalyzer = StandaloneWappalyzer::new(false).await
            .expect("StandaloneWappalyzer::new failed — is wappalyzer_cache.json present?");
        // Use the database's own spelling: the fold matches detections to technologies
        // by exact name, and so does `parse_probe_responses` when it resolves
        // "WordPress".
        let wp = wappalyzer.analyzer.find_tech_name("WordPress")
            .expect("WordPress missing from the technology database")
            .to_string();

        let mut technologies = vec![bare_tech(
            &wp,
            Some("6.5.3"),
            vec![Signal {
                signal_type: "script_src".to_string(),
                value: format!("{}/wp-includes/js/jquery.min.js?ver=6.5.3", mock_server.uri()),
                weight: 50,
            }],
        )];

        StandaloneWappalyzer::probe_version_endpoints(
            &wappalyzer.analyzer,
            &wappalyzer.http_client.client,
            &format!("{}/", mock_server.uri()),
            &mut technologies,
            0,
            &wappalyzer.config,
            true,
        ).await;

        let found = technologies.iter().find(|t| t.name == wp)
            .expect("WordPress disappeared from the technology list");
        assert_eq!(
            found.version.as_deref(),
            Some("6.8.1"),
            "a rank-100 probe version must displace the rank-20 `?ver=` cache-buster",
        );
    }

    /// Both directions at the asset fold, which is the other place a fresh detection
    /// map is folded into the built technology list.
    ///
    /// The same incoming evidence — a `/*! jQuery v3.7.1 */` banner, a rank-40
    /// `script_src` version — is folded onto two different incumbents:
    ///
    /// - one whose version came from a `?ver=` query string (rank 20): the banner is
    ///   better sourced and must replace it. This direction fails under
    ///   first-write-wins.
    /// - one whose version came from a `meta` generator tag (rank 80): the banner is
    ///   worse sourced and must NOT replace it. This direction passes under
    ///   first-write-wins too, which is exactly why it is asserted — without it the
    ///   test would be satisfied by "always overwrite", the opposite defect.
    #[tokio::test]
    async fn test_asset_fold_replaces_only_a_worse_sourced_version() {
        let mock_server = MockServer::start().await;
        // Deliberately minimal: the banner comment is the only occurrence of the
        // library's name in the body, so the incoming detection carries the
        // `script_src` banner signal and nothing else that could supply a version of
        // its own and change which rank is being tested.
        let banner = "/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n(function(){var a=1;return a;})();\n";
        for asset in ["/low.js", "/high.js"] {
            Mock::given(method("GET"))
                .and(path(asset))
                .respond_with(ResponseTemplate::new(200).set_body_string(banner))
                .mount(&mock_server)
                .await;
        }
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let wappalyzer = StandaloneWappalyzer::new(false).await
            .expect("StandaloneWappalyzer::new failed — is wappalyzer_cache.json present?");
        let jq = wappalyzer.analyzer.find_tech_name("jQuery")
            .expect("jQuery missing from the technology database")
            .to_string();
        let base = format!("{}/", mock_server.uri());

        // Direction 1: rank 40 banner over a rank 20 query-string version.
        let mut technologies = vec![bare_tech(
            &jq,
            Some("1.0.0"),
            vec![Signal {
                signal_type: "script_src".to_string(),
                value: format!("{}/js/jquery.min.js?ver=1.0.0", mock_server.uri()),
                weight: 50,
            }],
        )];
        StandaloneWappalyzer::inspect_assets(
            &wappalyzer.analyzer,
            &wappalyzer.http_client.client,
            r#"<html><head><script src="/low.js"></script></head><body></body></html>"#,
            &base,
            &mut technologies,
            0,
            &wappalyzer.config,
            Arc::clone(&wappalyzer.asset_cache),
        ).await;
        assert_eq!(
            technologies.iter().find(|t| t.name == jq).and_then(|t| t.version.as_deref()),
            Some("3.7.1"),
            "a rank-40 banner version must displace a rank-20 `?ver=` version",
        );

        // Direction 2: same banner, now against a rank 80 meta-generator version.
        let mut technologies = vec![bare_tech(
            &jq,
            Some("1.0.0"),
            vec![Signal {
                signal_type: "meta".to_string(),
                value: "generator:jQuery 1.0.0".to_string(),
                weight: 80,
            }],
        )];
        StandaloneWappalyzer::inspect_assets(
            &wappalyzer.analyzer,
            &wappalyzer.http_client.client,
            r#"<html><head><script src="/high.js"></script></head><body></body></html>"#,
            &base,
            &mut technologies,
            0,
            &wappalyzer.config,
            Arc::clone(&wappalyzer.asset_cache),
        ).await;
        assert_eq!(
            technologies.iter().find(|t| t.name == jq).and_then(|t| t.version.as_deref()),
            Some("1.0.0"),
            "a rank-40 banner version must NOT displace a rank-80 meta version",
        );
    }
}

// ─── PyO3 Python bindings ────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python;

// Re-export the pymodule entry point at crate root
#[cfg(feature = "python")]
pub use python::rusty_wappalyzer;
