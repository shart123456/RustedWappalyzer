//! Set 1: Direct TechnologyAnalyzer detection tests — no real HTTP required.
//!
//! Each test constructs an `HttpResponse` by hand and calls
//! `TechnologyAnalyzer::analyze()` directly to verify that a specific
//! detection layer fires for a known signal.
//!
//! A single `TechnologyAnalyzer` is shared across all tests via
//! `tokio::sync::OnceCell` so the expensive pattern compilation happens only
//! once per test-binary run.

use std::sync::OnceLock;
use rusty_wappalyzer::{TechnologyAnalyzer, HttpResponse};

// ── Shared analyzer — lazily initialised on first test that needs it ─────────
//
// `tokio::sync::OnceCell` cannot be used as a static because `TechnologyAnalyzer`
// does not implement `Sync` (it contains `HashMap` field with `Vec<Regex>`).
// We work around this by building the analyzer *once* on a dedicated single-
// threaded tokio runtime during `get_or_init` on a `std::sync::OnceLock`,
// which only runs the closure once even across threads.
//
// The `#[tokio::test]` macro itself spawns a new multi-thread runtime per test,
// but we must NOT call `block_on` from *inside* a tokio runtime (that panics).
// The trick: we spin up a brand-new, separate runtime inside the OnceLock
// closure — the closure runs only once, before any `#[tokio::test]` runtime
// has a chance to call it a second time.

static ANALYZER: OnceLock<TechnologyAnalyzer> = OnceLock::new();

/// Returns a reference to the shared TechnologyAnalyzer, building it on first
/// call.  Must NOT be called from within an async context that already has a
/// tokio runtime on the current thread.
fn shared_analyzer() -> &'static TechnologyAnalyzer {
    ANALYZER.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio rt")
            .block_on(async {
                TechnologyAnalyzer::new().await
                    .expect("TechnologyAnalyzer::new() failed — is wappalyzer_cache.json present?")
            })
    })
}

// ── Helper ───────────────────────────────────────────────────────────────────

fn make_response(
    headers: Vec<(&str, &str)>,
    body: &str,
    cookies: Vec<&str>,
) -> HttpResponse {
    HttpResponse {
        url: "https://example.com/".to_string(),
        headers: headers.into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        body: body.to_string(),
        status_code: 200,
        response_time_ms: 10,
        set_cookie_headers: cookies.into_iter().map(|s| s.to_string()).collect(),
    }
}

fn tech_names(techs: &[rusty_wappalyzer::Technology]) -> Vec<&str> {
    techs.iter().map(|t| t.name.as_str()).collect()
}

// ── Set 1 tests ──────────────────────────────────────────────────────────────

/// 1. WordPress detected via meta[name=generator]
#[test]
fn test_detect_wordpress_meta_generator_version() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        r#"<html><head><meta name="generator" content="WordPress 6.4.3 (https://wordpress.org)"></head><body></body></html>"#,
        vec![],
    );
    let techs = analyzer.analyze(&resp, 50);
    let wp = techs.iter().find(|t| t.name.to_lowercase().contains("wordpress"));
    assert!(
        wp.is_some(),
        "Expected WordPress in detections; got: {:?}", tech_names(&techs)
    );
    let version = wp.unwrap().version.as_deref().unwrap_or("");
    assert!(
        version.contains("6.4.3"),
        "Expected version to contain '6.4.3'; got: {:?}", version
    );
}

/// 2. Next.js detected via __NEXT_DATA__ script id
#[test]
fn test_detect_nextjs_next_data_id() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        r#"<html><body><script id="__NEXT_DATA__" type="application/json">{"page":"/"}</script></body></html>"#,
        vec![],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("next")),
        "Expected Next.js in detections; got: {:?}", tech_names(&techs)
    );
}

/// 3. Django detected via csrftoken cookie (using set_cookie_headers vec)
#[test]
fn test_detect_django_csrftoken_cookie_set_cookie_vec() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        "<html></html>",
        vec!["csrftoken=abc123; Path=/"],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("django")),
        "Expected Django in detections; got: {:?}", tech_names(&techs)
    );
}

/// 4. Sentry detected via Content-Security-Policy header
#[test]
fn test_detect_sentry_via_csp_header() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![(
            "content-security-policy",
            "default-src 'self'; connect-src https://o123456.ingest.sentry.io",
        )],
        "<html></html>",
        vec![],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("sentry")),
        "Expected Sentry in detections; got: {:?}", tech_names(&techs)
    );
}

/// 5. Nginx detected via Server header with version
#[test]
fn test_detect_nginx_server_header_with_version() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![("server", "nginx/1.24.0")],
        "<html></html>",
        vec![],
    );
    let techs = analyzer.analyze(&resp, 50);
    let nginx = techs.iter().find(|t| t.name.to_lowercase().contains("nginx"));
    assert!(
        nginx.is_some(),
        "Expected Nginx in detections; got: {:?}", tech_names(&techs)
    );
    let version = nginx.unwrap().version.as_deref().unwrap_or("");
    assert_eq!(
        version, "1.24.0",
        "Expected Nginx version '1.24.0'; got: {:?}", version
    );
}

/// 6. PHP detected via X-Powered-By header with version
#[test]
fn test_detect_php_x_powered_by_with_version() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![("x-powered-by", "PHP/8.2.1")],
        "<html></html>",
        vec![],
    );
    let techs = analyzer.analyze(&resp, 50);
    let php = techs.iter().find(|t| t.name.to_lowercase() == "php");
    assert!(
        php.is_some(),
        "Expected PHP in detections; got: {:?}", tech_names(&techs)
    );
    let version = php.unwrap().version.as_deref().unwrap_or("");
    assert_eq!(
        version, "8.2.1",
        "Expected PHP version '8.2.1'; got: {:?}", version
    );
}

/// 7. Cloudflare detected via __cflb cookie
#[test]
fn test_detect_cloudflare_cflb_cookie() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        "<html></html>",
        vec!["__cflb=0H28vH3vbBMstmzKgGHKpAbcXYZ; Path=/"],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("cloudflare")),
        "Expected Cloudflare in detections; got: {:?}", tech_names(&techs)
    );
}

/// 8. jQuery detected via script src (presence only — version may or may not be
///    extracted depending on DB pattern coverage; we assert presence only).
#[test]
fn test_detect_jquery_via_script_src() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        r#"<html><head></head><body><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script></body></html>"#,
        vec![],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("jquery")),
        "Expected jQuery in detections; got: {:?}", tech_names(&techs)
    );
}

/// 9. Laravel detected via laravel_session cookie
#[test]
fn test_detect_laravel_laravel_session_cookie() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        "<html></html>",
        vec!["laravel_session=eyJpdiI6ImFiYw; Path=/; HttpOnly"],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("laravel")),
        "Expected Laravel in detections; got: {:?}", tech_names(&techs)
    );
}

/// 10. Express detected via connect.sid cookie
#[test]
fn test_detect_express_connect_sid_cookie() {
    let analyzer = shared_analyzer();
    let resp = make_response(
        vec![],
        "<html></html>",
        vec!["connect.sid=s%3Aabc.xyz; Path=/; HttpOnly"],
    );
    let techs = analyzer.analyze(&resp, 50);
    assert!(
        techs.iter().any(|t| t.name.to_lowercase().contains("express")),
        "Expected Express in detections; got: {:?}", tech_names(&techs)
    );
}
