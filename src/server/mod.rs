pub(crate) mod handlers;
pub(crate) mod cache;

use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use ::rusty_wappalyzer::{StandaloneWappalyzer, WappalyzerConfig, AnalysisResult};

/// Start the HTTP API server on the given port.
pub async fn run(port: u16, insecure: bool) -> Result<()> {
    // Try VulnVault — fail gracefully if MongoDB is unavailable.
    let vault = crate::vuln::VulnVault::try_connect().await;
    if vault.is_none() {
        println!("⚠️  VulnVault unavailable — CVE fields will be omitted from responses");
    }
    let vault_data = actix_web::web::Data::new(Arc::new(vault));

    // Try PocVault — fail gracefully if MongoDB poc collection is unavailable.
    let poc_vault = crate::poc::PocVault::try_connect().await;
    if poc_vault.is_none() {
        println!("⚠️  PocVault unavailable — PoC fields will be omitted from responses");
    }
    let poc_vault_data = actix_web::web::Data::new(Arc::new(poc_vault));

    // Try AlertVault — fail gracefully if MongoDB alerts collections are unavailable.
    let alert_vault = crate::alert::AlertVault::try_connect().await;
    if alert_vault.is_none() {
        println!("⚠️  AlertVault unavailable — KEV/GHSA fields will be omitted from responses");
    }
    let alert_vault_data = actix_web::web::Data::new(Arc::new(alert_vault));

    println!("API listening on http://0.0.0.0:{} (insecure={})", port, insecure);

    // Server mode: enable SSRF protection in the HTTP client so that
    // every outbound TCP connection validates the resolved IP at dial
    // time (DNS rebinding mitigation on top of the is_safe_url pre-flight).
    let server_config = WappalyzerConfig { ssrf_protection: true, ..WappalyzerConfig::default() };
    let wappalyzer = Arc::new(StandaloneWappalyzer::with_config(insecure, server_config).await?);
    wappalyzer.warm_up().await;
    let wappalyzer_for_refresh = Arc::clone(&wappalyzer);
    let data = actix_web::web::Data::new(wappalyzer);
    let insecure_flag = actix_web::web::Data::new(insecure);

    // Pre-build an insecure wappalyzer instance so that per-request `-k` overrides
    // do not pay the full pattern-compilation cost.  Only needed when the server
    // itself starts in secure mode.
    let insecure_wappalyzer: Arc<Option<StandaloneWappalyzer>> = if !insecure {
        let insecure_config = WappalyzerConfig { ssrf_protection: true, ..WappalyzerConfig::default() };
        match StandaloneWappalyzer::with_config(true, insecure_config).await {
            Ok(w) => {
                tracing::info!("Pre-built insecure wappalyzer instance ready");
                Arc::new(Some(w))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Could not pre-build insecure wappalyzer; per-request insecure mode unavailable");
                Arc::new(None)
            }
        }
    } else {
        // Server already runs insecure — no second instance needed.
        Arc::new(None)
    };
    let insecure_data = actix_web::web::Data::new(insecure_wappalyzer);

    // Rate limiter: 600 requests per minute per IP (10 req/s sustained).
    // Sized for batch consumers; the analyzer's actual CPU work (regex + headers/body
    // scan) is sub-100ms per call, so this is well below what one core can serve.
    // Override at deploy time by changing the constants if you need stricter limits.
    let rate_limiter = actix_web::web::Data::new(crate::middleware::RateLimiter::new(600, 60));

    // Optional API key — only enforced when the environment variable is set.
    let api_key: Option<String> = std::env::var("API_KEY").ok();
    let api_key_data = actix_web::web::Data::new(api_key);

    // Response cache: 1,000 entries, 60-second TTL.
    let raw_cache: Arc<moka::sync::Cache<String, Arc<AnalysisResult>>> = Arc::new(
        moka::sync::Cache::builder()
            .max_capacity(1_000)
            .time_to_live(std::time::Duration::from_secs(60))
            .build(),
    );
    let response_cache = actix_web::web::Data::new(Arc::clone(&raw_cache));

    // Hot-URL tracker: used by the background refresh task and the analyze handler.
    let hot_keys: cache::HotKeys = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let hot_keys_data = actix_web::web::Data::new(Arc::clone(&hot_keys));

    // Spawn background auto-refresh: checks every 45 s, keeps URLs hot for 10 min.
    tokio::spawn(cache::auto_refresh_loop(
        Arc::clone(&hot_keys),
        Arc::clone(&raw_cache),
        wappalyzer_for_refresh,
        45,   // interval: 3/4 of the 60 s TTL
        600,  // hot window: 10 minutes of inactivity before eviction
    ));

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(tracing_actix_web::TracingLogger::default())
            .app_data(actix_web::web::JsonConfig::default().limit(65536)) // 64 KB max body
            .app_data(data.clone())
            .app_data(insecure_flag.clone())
            .app_data(vault_data.clone())
            .app_data(poc_vault_data.clone())
            .app_data(alert_vault_data.clone())
            .app_data(rate_limiter.clone())
            .app_data(api_key_data.clone())
            .app_data(insecure_data.clone())
            .app_data(response_cache.clone())
            .app_data(hot_keys_data.clone())
            .route("/health", actix_web::web::get().to(handlers::health))
            .route("/info", actix_web::web::get().to(handlers::info))
            .route("/analyze", actix_web::web::post().to(handlers::analyze))
            .route("/batch", actix_web::web::post().to(handlers::batch))
            .route("/wayback", actix_web::web::post().to(handlers::wayback_analyze))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await?;

    Ok(())
}
