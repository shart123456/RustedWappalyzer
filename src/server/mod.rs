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

    // Rate limiter: 600 requests per minute per IP by default (10 req/s sustained).
    // Sized for batch consumers; the analyzer's actual CPU work (regex + headers/body
    // scan) is sub-100ms per call, so this is well below what one core can serve.
    //
    // Configurable via env:
    //   RATE_LIMIT_DISABLED=true      → no-op limiter (use behind a proxy that already
    //                                    rate-limits; the per-IP limiter would otherwise
    //                                    see only the proxy IP and throttle everyone).
    //   RATE_LIMIT_MAX_REQS=<n>       → requests allowed per window (default 600).
    //   RATE_LIMIT_WINDOW_SECS=<n>    → window length in seconds (default 60).
    let rate_limiter = actix_web::web::Data::new(build_rate_limiter());

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

    let state = AppState {
        analyzer: data,
        insecure_flag,
        vault: vault_data,
        poc_vault: poc_vault_data,
        alert_vault: alert_vault_data,
        rate_limiter,
        api_key: api_key_data,
        insecure_analyzer: insecure_data,
        response_cache,
        hot_keys: hot_keys_data,
    };

    actix_web::HttpServer::new(move || {
        actix_web::App::new()
            .wrap(tracing_actix_web::TracingLogger::default())
            .configure(configure_app(state.clone()))
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run()
    .await?;

    Ok(())
}

/// Everything the HTTP layer needs, built once and shared by every worker.
///
/// Grouped into a struct so that [`configure_app`] is the single definition of
/// how the API is wired. `run()` and the HTTP-layer tests both go through it,
/// which is what keeps the tests honest: they exercise the same JSON config,
/// the same routes and the same default service as production.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) analyzer: actix_web::web::Data<Arc<StandaloneWappalyzer>>,
    pub(crate) insecure_flag: actix_web::web::Data<bool>,
    pub(crate) vault: actix_web::web::Data<Arc<Option<crate::vuln::VulnVault>>>,
    pub(crate) poc_vault: actix_web::web::Data<Arc<Option<crate::poc::PocVault>>>,
    pub(crate) alert_vault: actix_web::web::Data<Arc<Option<crate::alert::AlertVault>>>,
    pub(crate) rate_limiter: actix_web::web::Data<crate::middleware::RateLimiter>,
    pub(crate) api_key: actix_web::web::Data<Option<String>>,
    pub(crate) insecure_analyzer: actix_web::web::Data<Arc<Option<StandaloneWappalyzer>>>,
    pub(crate) response_cache:
        actix_web::web::Data<Arc<moka::sync::Cache<String, Arc<AnalysisResult>>>>,
    pub(crate) hot_keys: actix_web::web::Data<cache::HotKeys>,
}

/// Register shared state, the JSON body config, the routes and the fallback
/// service. Returns a closure so it can be passed straight to
/// `App::configure`.
pub(crate) fn configure_app(
    state: AppState,
) -> impl FnOnce(&mut actix_web::web::ServiceConfig) {
    move |cfg: &mut actix_web::web::ServiceConfig| {
        cfg
            // 64 KB max body. The error_handler keeps malformed-body rejections
            // in the same {"error": ...} envelope as every other failure; by
            // default actix returns them as bare text, so clients had to parse
            // two different shapes.
            .app_data(
                actix_web::web::JsonConfig::default()
                    .limit(65536)
                    .error_handler(|err, _req| {
                        let detail = err.to_string();
                        actix_web::error::InternalError::from_response(
                            err,
                            actix_web::HttpResponse::BadRequest()
                                .json(serde_json::json!({ "error": detail })),
                        )
                        .into()
                    }),
            )
            .app_data(state.analyzer)
            .app_data(state.insecure_flag)
            .app_data(state.vault)
            .app_data(state.poc_vault)
            .app_data(state.alert_vault)
            .app_data(state.rate_limiter)
            .app_data(state.api_key)
            .app_data(state.insecure_analyzer)
            .app_data(state.response_cache)
            .app_data(state.hot_keys)
            .route("/health", actix_web::web::get().to(handlers::health))
            .route("/info", actix_web::web::get().to(handlers::info))
            .route("/analyze", actix_web::web::post().to(handlers::analyze))
            .route("/batch", actix_web::web::post().to(handlers::batch))
            .route("/wayback", actix_web::web::post().to(handlers::wayback_analyze))
            // Unknown route / wrong method: answer with the same JSON envelope
            // rather than an empty body.
            .default_service(actix_web::web::to(|| async {
                actix_web::HttpResponse::NotFound()
                    .json(serde_json::json!({ "error": "Not found" }))
            }));
    }
}

/// Build the request rate limiter from environment configuration.
/// See the call site in [`run`] for the recognised variables.
fn build_rate_limiter() -> crate::middleware::RateLimiter {
    use crate::middleware::RateLimiter;

    let disabled = std::env::var("RATE_LIMIT_DISABLED")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    if disabled {
        tracing::info!("In-process rate limiter disabled (RATE_LIMIT_DISABLED); relying on upstream");
        return RateLimiter::disabled();
    }

    let max_reqs = std::env::var("RATE_LIMIT_MAX_REQS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(600);
    let window_secs = std::env::var("RATE_LIMIT_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    tracing::info!(max_reqs, window_secs, "In-process rate limiter enabled");
    RateLimiter::new(max_reqs, window_secs)
}

#[cfg(test)]
mod http_tests {
    //! HTTP-layer tests.
    //!
    //! These mount the real app through [`configure_app`], so the JSON body
    //! config, the routes and the fallback service under test are the same ones
    //! `run()` installs. Previously none of this layer had coverage: the error
    //! envelopes and the rate-limit response were verified by hand only.
    //!
    //! Requests that reach a handler deliberately target a private address, so
    //! the SSRF pre-flight rejects them with 400 and no traffic leaves the host.
    //! A 400 therefore means "auth and rate limiting let this through", which is
    //! what makes the status codes below meaningful.

    use super::*;
    use actix_web::{test, App};
    use crate::middleware::RateLimiter;

    /// One analyzer for the whole test binary — building it compiles every
    /// database pattern, which is far too slow to repeat per test.
    static ANALYZER: tokio::sync::OnceCell<Arc<StandaloneWappalyzer>> =
        tokio::sync::OnceCell::const_new();

    async fn analyzer() -> Arc<StandaloneWappalyzer> {
        ANALYZER
            .get_or_init(|| async {
                let cfg = WappalyzerConfig {
                    ssrf_protection: true,
                    ..WappalyzerConfig::default()
                };
                Arc::new(
                    StandaloneWappalyzer::with_config(false, cfg)
                        .await
                        .expect("build analyzer"),
                )
            })
            .await
            .clone()
    }

    /// Build app state with an overridable rate limiter and API key.
    async fn state(rate_limiter: RateLimiter, api_key: Option<String>) -> AppState {
        AppState {
            analyzer: actix_web::web::Data::new(analyzer().await),
            insecure_flag: actix_web::web::Data::new(false),
            vault: actix_web::web::Data::new(Arc::new(None)),
            poc_vault: actix_web::web::Data::new(Arc::new(None)),
            alert_vault: actix_web::web::Data::new(Arc::new(None)),
            rate_limiter: actix_web::web::Data::new(rate_limiter),
            api_key: actix_web::web::Data::new(api_key),
            insecure_analyzer: actix_web::web::Data::new(Arc::new(None)),
            response_cache: actix_web::web::Data::new(Arc::new(
                moka::sync::Cache::builder().max_capacity(16).build(),
            )),
            hot_keys: actix_web::web::Data::new(Arc::new(std::sync::Mutex::new(
                HashMap::new(),
            ))),
        }
    }

    /// Default state: permissive limiter, no API key.
    async fn default_state() -> AppState {
        state(RateLimiter::new(600, 60), None).await
    }

    /// A URL the SSRF pre-flight always rejects, so handler tests stay offline.
    const BLOCKED_URL: &str = r#"{"url":"http://10.0.0.1/"}"#;

    #[actix_web::test]
    async fn health_returns_ok() {
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/health").to_request(),
        )
        .await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["status"], "ok");
    }

    #[actix_web::test]
    async fn info_reports_database_size() {
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        let resp = test::call_service(&app, test::TestRequest::get().uri("/info").to_request()).await;
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["technologies"].as_u64().unwrap_or(0) > 0,
            "expected a non-empty technology count, got {body}"
        );
    }

    #[actix_web::test]
    async fn unknown_route_returns_json_envelope() {
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/no-such-route").to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Not found");
    }

    #[actix_web::test]
    async fn wrong_method_returns_json_envelope() {
        // GET on a POST-only route falls through to the default service.
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/analyze").to_request(),
        )
        .await;
        assert_eq!(resp.status(), 404);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["error"], "Not found");
    }

    #[actix_web::test]
    async fn malformed_json_body_returns_error_envelope() {
        // Regression guard for the JsonConfig error_handler: actix returns bare
        // text for these by default, which forced clients to parse two shapes.
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/analyze")
                .insert_header(("content-type", "application/json"))
                .set_payload(r#"{"url":"#)
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap_or_default().contains("Json deserialize error"),
            "expected a JSON envelope carrying the parse detail, got {body}"
        );
    }

    #[actix_web::test]
    async fn missing_required_field_returns_error_envelope() {
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/analyze")
                .insert_header(("content-type", "application/json"))
                .set_payload("{}")
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), 400);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert!(
            body["error"].as_str().unwrap_or_default().contains("missing field"),
            "expected the missing-field detail inside the envelope, got {body}"
        );
    }

    #[actix_web::test]
    async fn rate_limit_triggers_at_the_configured_value() {
        // Regression guard for the 429 body, which used to hardcode
        // "Max 600 requests per minute" regardless of configuration.
        let app = test::init_service(
            App::new().configure(configure_app(state(RateLimiter::new(2, 60), None).await)),
        )
        .await;

        let send = || {
            test::TestRequest::post()
                .uri("/analyze")
                .insert_header(("content-type", "application/json"))
                .set_payload(BLOCKED_URL)
                .to_request()
        };

        // Two allowed: 400 from the SSRF pre-flight means the limiter passed.
        assert_eq!(test::call_service(&app, send()).await.status(), 400);
        assert_eq!(test::call_service(&app, send()).await.status(), 400);

        let limited = test::call_service(&app, send()).await;
        assert_eq!(limited.status(), 429);
        let body: serde_json::Value = test::read_body_json(limited).await;
        assert_eq!(
            body["error"], "Rate limit exceeded. Max 2 requests per 60 seconds.",
            "the 429 body must report the configured limit, not a fixed one"
        );
    }

    #[actix_web::test]
    async fn disabled_rate_limiter_never_returns_429() {
        let app = test::init_service(
            App::new().configure(configure_app(state(RateLimiter::disabled(), None).await)),
        )
        .await;
        for i in 0..12 {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/analyze")
                    .insert_header(("content-type", "application/json"))
                    .set_payload(BLOCKED_URL)
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), 400, "request {i} should not be rate-limited");
        }
    }

    #[actix_web::test]
    async fn api_key_is_required_when_configured() {
        let app = test::init_service(
            App::new().configure(
                configure_app(state(RateLimiter::new(600, 60), Some("s3cret".into())).await),
            ),
        )
        .await;

        let no_key = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/analyze")
                .insert_header(("content-type", "application/json"))
                .set_payload(BLOCKED_URL)
                .to_request(),
        )
        .await;
        assert_eq!(no_key.status(), 401);
        let body: serde_json::Value = test::read_body_json(no_key).await;
        assert_eq!(body["error"], "Invalid or missing API key");

        let wrong_key = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/analyze")
                .insert_header(("content-type", "application/json"))
                .insert_header(("authorization", "Bearer wrong"))
                .set_payload(BLOCKED_URL)
                .to_request(),
        )
        .await;
        assert_eq!(wrong_key.status(), 401);

        // Correct key: reaches the handler, then the SSRF pre-flight rejects it.
        let good_key = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/analyze")
                .insert_header(("content-type", "application/json"))
                .insert_header(("authorization", "Bearer s3cret"))
                .set_payload(BLOCKED_URL)
                .to_request(),
        )
        .await;
        assert_eq!(good_key.status(), 400);
    }

    #[actix_web::test]
    async fn ssrf_preflight_rejects_private_targets_through_the_api() {
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        for url in [
            "http://127.0.0.1:80/",
            "http://0.0.0.0:80/",
            "http://169.254.169.254/latest/meta-data/",
            "http://100.64.0.1/",
            "http://[::1]:80/",
        ] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/analyze")
                    .insert_header(("content-type", "application/json"))
                    .set_payload(format!(r#"{{"url":"{url}"}}"#))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), 400, "{url} must be rejected");
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert!(
                body["error"].as_str().unwrap_or_default().contains("private/internal"),
                "{url} should report a private-address rejection, got {body}"
            );
        }
    }

    #[actix_web::test]
    async fn non_http_scheme_is_rejected() {
        let app = test::init_service(App::new().configure(configure_app(default_state().await))).await;
        for url in ["file:///etc/passwd", "gopher://127.0.0.1/", "not-a-url"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/analyze")
                    .insert_header(("content-type", "application/json"))
                    .set_payload(format!(r#"{{"url":"{url}"}}"#))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), 400, "{url} must be rejected");
        }
    }
}
