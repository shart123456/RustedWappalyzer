//! Set 2: Full-pipeline tests using wiremock to serve real HTTP responses.
//!
//! These tests spin up a `wiremock::MockServer`, register mocked responses,
//! then call `StandaloneWappalyzer::analyze_url()` end-to-end to verify
//! the complete detection pipeline (fetch → analyze → asset inspection → probes).
//!
//! The mock server binds to a random localhost port so tests can run in parallel.

use rusty_wappalyzer::StandaloneWappalyzer;
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path};

// ── helper ────────────────────────────────────────────────────────────────────

fn tech_names(techs: &[rusty_wappalyzer::Technology]) -> Vec<&str> {
    techs.iter().map(|t| t.name.as_str()).collect()
}

// ── Set 2 tests ───────────────────────────────────────────────────────────────

/// Full pipeline: mock returns Server: nginx/1.24.0 + X-Powered-By: PHP/8.2.1.
/// Asserts that both Nginx and PHP are detected with correct versions.
#[tokio::test]
async fn test_full_pipeline_nginx_and_php() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Server", "nginx/1.24.0")
                .insert_header("X-Powered-By", "PHP/8.2.1")
                .set_body_string("<html><head></head><body>Hello</body></html>"),
        )
        .mount(&mock_server)
        .await;

    // Stub any additional paths that probes or asset fetcher may hit
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let wappalyzer = StandaloneWappalyzer::new(true).await
        .expect("StandaloneWappalyzer::new failed");

    let url = format!("{}/", mock_server.uri());
    let result = wappalyzer.analyze_url(&url, 50, false).await;

    assert!(
        result.error.is_none(),
        "Expected no error; got: {:?}", result.error
    );

    let names = tech_names(&result.technologies);

    // Nginx
    let nginx = result.technologies.iter().find(|t| t.name.to_lowercase().contains("nginx"));
    assert!(
        nginx.is_some(),
        "Expected Nginx in detections; got: {:?}", names
    );
    assert_eq!(
        nginx.unwrap().version.as_deref().unwrap_or(""),
        "1.24.0",
        "Expected Nginx version '1.24.0'"
    );

    // PHP
    let php = result.technologies.iter().find(|t| t.name.to_lowercase() == "php");
    assert!(
        php.is_some(),
        "Expected PHP in detections; got: {:?}", names
    );
    assert_eq!(
        php.unwrap().version.as_deref().unwrap_or(""),
        "8.2.1",
        "Expected PHP version '8.2.1'"
    );
}

/// Full pipeline: mock returns a WordPress meta-generator tag.
/// Asserts that WordPress is detected.
#[tokio::test]
async fn test_full_pipeline_wordpress_meta_generator() {
    let mock_server = MockServer::start().await;

    let body = r#"<!DOCTYPE html>
<html>
<head>
  <meta name="generator" content="WordPress 6.4">
  <title>Test WordPress Site</title>
</head>
<body><p>Hello world</p></body>
</html>"#;

    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html; charset=utf-8")
                .set_body_string(body),
        )
        .mount(&mock_server)
        .await;

    // Stub probes / asset fetches
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    let wappalyzer = StandaloneWappalyzer::new(true).await
        .expect("StandaloneWappalyzer::new failed");

    let url = format!("{}/", mock_server.uri());
    let result = wappalyzer.analyze_url(&url, 50, false).await;

    assert!(
        result.error.is_none(),
        "Expected no error; got: {:?}", result.error
    );

    assert!(
        result.technologies.iter().any(|t| t.name.to_lowercase().contains("wordpress")),
        "Expected WordPress in detections; got: {:?}", tech_names(&result.technologies)
    );
}
