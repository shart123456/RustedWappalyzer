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
        let http_client = HttpClient::new_with_config(insecure, &config)?;

        let (tech_count, cat_count) = analyzer.get_stats();
        tracing::info!(technologies = tech_count, categories = cat_count, "Database loaded");

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

    /// Return (technology_count, category_count) from the loaded database
    pub fn get_stats(&self) -> (usize, usize) {
        self.analyzer.get_stats()
    }

    /// Maximum number of URLs accepted by the `/batch` API endpoint.
    pub fn max_batch_size(&self) -> usize {
        self.config.max_batch_size
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

        // --- fetch first 4 KB of each asset concurrently ---
        let semaphore = Arc::new(Semaphore::new(config.asset_concurrency));
        let tasks: Vec<_> = asset_urls.into_iter().map(|url| {
            let client = client.clone();
            let sem = Arc::clone(&semaphore);
            let cache = Arc::clone(&asset_cache);
            tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                // Check cache before fetching
                let body_arc = if let Some(cached) = cache.get(&url) {
                    cached
                } else {
                    let resp = client.get(&url)
                        .header("Range", "bytes=0-16383")
                        .send().await.ok()?;
                    let status = resp.status().as_u16();
                    if status == 200 || status == 206 {
                        let content = resp.text().await.ok()?;
                        let arc = Arc::new(content);
                        cache.insert(url.clone(), Arc::clone(&arc));
                        arc
                    } else {
                        return None;
                    }
                };
                Some((url, body_arc))
            })
        }).collect();

        let assets: Vec<(String, Arc<String>)> = futures::future::join_all(tasks).await
            .into_iter()
            .filter_map(|r| r.ok().flatten())
            .collect();

        // --- run pattern matching on each asset ---
        let mut new_detected: HashMap<String, TechDetection> = HashMap::new();
        for (url, content_arc) in &assets {
            let content: &str = &content_arc;
            analyzer.analyze_asset(url, content, &mut new_detected);
            // Source map intelligence: parse .map files for exact npm package versions
            if !url.contains(".css") {
                analyzer.try_source_map(client, url, content, &mut new_detected, config.source_map_timeout_secs).await;
            }
        }

        // --- merge: update existing versions, append newly found techs ---
        for (name, detection) in new_detected {
            let confidence = compute_noisy_or(&detection.signals);
            if confidence < min_confidence { continue; }
            if let Some(t) = technologies.iter_mut().find(|t| t.name == name) {
                if t.version.is_none() && detection.version.is_some() {
                    t.version = detection.version;
                }
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

        let origin = match url::Url::parse(base_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| format!("{}://{}", u.scheme(), h)))
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
                if t.version.is_none() && detection.version.is_some() {
                    t.version = detection.version;
                }
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
    pub async fn analyze_urls_batch(&self, urls: Vec<String>, concurrency: usize, min_confidence: u8, full_scan: bool) -> Result<Vec<AnalysisResult>, WappalyzerError> {
        use tokio::sync::Semaphore;

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
                if full_scan {
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


#[cfg(test)]
mod tests {
    use super::*;

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
        let captures = regex.captures("WordPress 5.8").unwrap();

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
        let caps = Regex::new(r"(foo)").unwrap().captures("foo").unwrap();
        assert_eq!(TechnologyAnalyzer::extract_version(&None, &caps), None);
    }

    #[test]
    fn test_extract_version_empty_template_returns_none() {
        let caps = Regex::new(r"(foo)").unwrap().captures("foo").unwrap();
        assert_eq!(TechnologyAnalyzer::extract_version(&Some(String::new()), &caps), None);
    }

    #[test]
    fn test_extract_version_ternary_matched() {
        let caps = Regex::new(r"v(\d+)").unwrap().captures("v3").unwrap();
        let ver = TechnologyAnalyzer::extract_version(&Some(r"\1?major:fallback".to_string()), &caps);
        assert_eq!(ver, Some("major".to_string()));
    }

    #[test]
    fn test_extract_version_ternary_unmatched() {
        let caps = Regex::new(r"v(\d+)(\.\d+)?").unwrap().captures("v3").unwrap();
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
}

// ─── PyO3 Python bindings ────────────────────────────────────────────────────

#[cfg(feature = "python")]
mod python;

// Re-export the pymodule entry point at crate root
#[cfg(feature = "python")]
pub use python::rusty_wappalyzer;
