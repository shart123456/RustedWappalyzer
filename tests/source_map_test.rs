//! Source-map intelligence, end to end, against a Range-honouring mock server.
//!
//! ## What this file is guarding
//!
//! `TechnologyAnalyzer::try_source_map` mines `node_modules/<pkg>/<version>/...` paths
//! out of a JS source map's `sources` array. That is the highest-precision version
//! signal in the tool — a literal dependency inventory rather than a regex guess — but
//! it only runs if the `//# sourceMappingURL=` comment is found in the asset body it is
//! handed.
//!
//! Every bundler appends that comment as the LAST line of the file it emits, while
//! `inspect_assets` fetches assets with `Range: bytes=0-<head window>`. So for any
//! bundle larger than the head window — which is to say, every real production bundle —
//! the comment sits outside the fetched bytes and the entire code path was structurally
//! unreachable. The fix is a second, suffix-range request for the last few KB.
//!
//! ## Why this test bites
//!
//! The mock server below behaves like a real Range-honouring origin: `bytes=0-16383`
//! gets a 206 carrying ONLY the first 16 KB, and `bytes=-2048` gets a 206 carrying only
//! the last 2 KB. The bundle it serves is deliberately bigger than the head window with
//! the sourceMappingURL comment on its final line, and the test asserts up front that
//! the head window really does not contain the comment. Remove the tail fetch and the
//! analyzer sees a truncated body with no comment in it, never requests the `.map`, and
//! the version assertion fails — as does the `expect(1)` on the tail mock.
//!
//! Everything here is served from a local `wiremock` instance; no test in this file
//! touches the network.

use rusty_wappalyzer::{StandaloneWappalyzer, ASSET_HEAD_BYTES, ASSET_TAIL_BYTES};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Point the analyzer at the pattern database that lives in the repo.
///
/// The default cache location is next to the running binary (`target/debug/deps/…`),
/// where there is no database, and a miss there makes `TechnologyAnalyzer::new()` go and
/// re-fetch all ~7,500 technologies from GitHub — which would both be slow and break the
/// "no test touches the real internet" rule. An already-set value is left alone so a CI
/// runner can override the path.
fn use_repo_database() {
    if std::env::var_os("WAPPALYZER_CACHE").is_none() {
        std::env::set_var(
            "WAPPALYZER_CACHE",
            concat!(env!("CARGO_MANIFEST_DIR"), "/wappalyzer_cache.json"),
        );
    }
}

/// Build a JS bundle that is comfortably larger than the head window and carries the
/// `sourceMappingURL` trailer on its last line, exactly where a bundler puts it.
///
/// The filler is pure ASCII so that slicing it at a byte offset can never land in the
/// middle of a multi-byte character.
fn oversized_bundle(map_url: &str) -> String {
    let mut bundle = String::with_capacity(ASSET_HEAD_BYTES + 8192);
    bundle.push_str("(function(){\"use strict\";\n");
    while bundle.len() < ASSET_HEAD_BYTES + 4096 {
        bundle.push_str("var pad=function(a,b){return a+b;};// minified filler line\n");
    }
    bundle.push_str("})();\n");
    bundle.push_str(&format!("//# sourceMappingURL={}\n", map_url));
    bundle
}

#[tokio::test]
async fn test_source_map_version_found_beyond_head_window() {
    use_repo_database();

    let mock_server = MockServer::start().await;

    let bundle = oversized_bundle("/static/bundle.js.map");

    // --- guards that keep this test honest -----------------------------------------
    // If either of these ever stops holding, the test would start passing with or
    // without the tail fetch and would be worthless.
    assert!(
        bundle.len() > ASSET_HEAD_BYTES,
        "bundle must exceed the {ASSET_HEAD_BYTES}-byte head window for this test to \
         mean anything; it is {} bytes",
        bundle.len()
    );
    assert!(
        !bundle[..ASSET_HEAD_BYTES].contains("sourceMappingURL"),
        "the sourceMappingURL comment must fall OUTSIDE the head window; if it is \
         inside, the head fetch alone would find it and the tail fetch would not be \
         under test"
    );
    assert!(
        bundle[bundle.len() - ASSET_TAIL_BYTES..].contains("sourceMappingURL"),
        "the sourceMappingURL comment must fall inside the {ASSET_TAIL_BYTES}-byte tail \
         window, or there is nothing for the fix to find"
    );

    let head_body = bundle[..ASSET_HEAD_BYTES].to_string();
    let tail_start = bundle.len() - ASSET_TAIL_BYTES;
    let tail_body = bundle[tail_start..].to_string();
    let total = bundle.len();

    // The page: one linked script, nothing else that could reveal React.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html; charset=utf-8")
                .set_body_string(
                    "<!DOCTYPE html><html><head>\
                     <script src=\"/static/bundle.js\"></script>\
                     </head><body>hello</body></html>",
                ),
        )
        .with_priority(1)
        .mount(&mock_server)
        .await;

    // Head window: a real origin answers a prefix range with 206 + Content-Range and
    // sends ONLY the requested bytes. Serving the whole body here would defeat the test.
    Mock::given(method("GET"))
        .and(path("/static/bundle.js"))
        .and(header("range", format!("bytes=0-{}", ASSET_HEAD_BYTES - 1).as_str()))
        .respond_with(
            ResponseTemplate::new(206)
                .insert_header("Content-Type", "application/javascript")
                .insert_header(
                    "Content-Range",
                    format!("bytes 0-{}/{}", ASSET_HEAD_BYTES - 1, total).as_str(),
                )
                .set_body_string(head_body),
        )
        .with_priority(1)
        .mount(&mock_server)
        .await;

    // Tail window: the suffix range the fix introduces. `expect(1)` turns "the tail
    // fetch happened exactly once" into a hard assertion, verified when the mock server
    // shuts down — so deleting the tail request fails the test even in the hypothetical
    // where the version was recovered some other way.
    Mock::given(method("GET"))
        .and(path("/static/bundle.js"))
        .and(header("range", format!("bytes=-{}", ASSET_TAIL_BYTES).as_str()))
        .respond_with(
            ResponseTemplate::new(206)
                .insert_header("Content-Type", "application/javascript")
                .insert_header(
                    "Content-Range",
                    format!("bytes {}-{}/{}", tail_start, total - 1, total).as_str(),
                )
                .set_body_string(tail_body),
        )
        .with_priority(1)
        .expect(1)
        .mount(&mock_server)
        .await;

    // The source map itself. `sources` carries the versioned node_modules layout that
    // pnpm and several CDN build pipelines produce, which is the form
    // `try_source_map`'s versioned regex reads a version out of.
    let source_map = r#"{
      "version": 3,
      "file": "bundle.js",
      "sources": [
        "webpack://_N_E/./node_modules/react/18.2.0/cjs/react.production.min.js",
        "webpack://_N_E/./src/index.js"
      ],
      "names": [],
      "mappings": ""
    }"#;
    Mock::given(method("GET"))
        .and(path("/static/bundle.js.map"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "application/json")
                .set_body_string(source_map),
        )
        .with_priority(1)
        .expect(1)
        .mount(&mock_server)
        .await;

    // Catch-all for the favicon fetch and anything else the pipeline reaches for.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .with_priority(10)
        .mount(&mock_server)
        .await;

    let wappalyzer = StandaloneWappalyzer::new(true)
        .await
        .expect("StandaloneWappalyzer::new failed");

    let url = format!("{}/", mock_server.uri());
    let result = wappalyzer.analyze_url(&url, 50, false).await;

    assert!(
        result.error.is_none(),
        "Expected no error; got: {:?}",
        result.error
    );

    let names: Vec<&str> = result
        .technologies
        .iter()
        .map(|t| t.name.as_str())
        .collect();

    let react = result
        .technologies
        .iter()
        .find(|t| t.name == "React")
        .unwrap_or_else(|| {
            panic!(
                "Expected React, recovered from the source map's sources array; got: {:?}",
                names
            )
        });

    assert_eq!(
        react.version.as_deref(),
        Some("18.2.0"),
        "Expected the exact version from the node_modules path in the source map"
    );

    // Provenance matters as much as the value: assert the evidence came from the source
    // map and not from some unrelated layer that happened to guess React. Without this,
    // a future change that detected React from, say, the filler text would keep the test
    // green while the source-map path was dead again.
    assert!(
        react
            .signals
            .iter()
            .any(|s| s.signal_type == "source_map"),
        "Expected a source_map signal on React; got: {:?}",
        react.signals
    );
}
