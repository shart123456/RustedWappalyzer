//! Probe-based technology detection: build probe lists, parse probe responses.

use crate::types::{Technology, TechDetection};
use crate::analyzer::TechnologyAnalyzer;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

/// Build the list of (full_url, tag) pairs to probe for a given origin.
///
/// Universal paths always run; CMS/framework-specific paths only run when the
/// relevant technology was already detected (or when nothing was detected, in
/// which case everything runs as a broad fallback).
pub fn build_probe_list(origin: &str, technologies: &[Technology], full_scan: bool) -> Vec<(String, &'static str)> {
    let detected_lower: Vec<String> = technologies.iter()
        .map(|t| t.name.to_lowercase())
        .collect();
    let has_any = |needles: &[&str]| -> bool {
        detected_lower.iter().any(|n| needles.iter().any(|needle| n.contains(needle)))
    };
    let nothing = technologies.is_empty();

    let mut probes: Vec<(String, &'static str)> = Vec::new();

    macro_rules! add {
        ($path:expr, $tag:expr) => {
            probes.push((format!("{}{}", origin, $path), $tag));
        };
    }

    macro_rules! add_t3 {
        ($path:expr, $tag:expr) => {
            if full_scan { probes.push((format!("{}{}", origin, $path), $tag)); }
        };
    }

    // ── Universal probes (always run) ────────────────────────────────────
    add!("/robots.txt",                "robots");
    add!("/sitemap.xml",               "sitemap");
    add!("/?feed=rss2",               "rss-feed");
    add!("/feed/",                     "rss-feed");
    add!("/package.json",              "package-json");
    add!("/composer.json",             "composer-json");
    add!("/.well-known/security.txt",  "security-txt");
    add!("/CHANGELOG.md",              "changelog");
    add!("/openapi.json",              "openapi");
    add!("/swagger.json",              "openapi");
    add!("/api/swagger.json",          "openapi");
    add!("/api/openapi.json",          "openapi");
    add!("/version.json",              "version-json");
    add!("/version",                   "version-json");
    add!("/api/version",               "version-json");
    add!("/health",                    "health-json");
    add!("/go.mod",                    "go-mod");
    add!("/Gemfile.lock",              "gemfile-lock");
    add!("/requirements.txt",          "requirements-txt");
    add!("/nginx_status",              "nginx-status");
    add!("/server-status",             "apache-status");
    add!("/server-info",               "apache-info");
    add_t3!("/.git/HEAD",              "git-head");
    add!("/graphql?query=%7B__typename%7D", "graphql");
    add!("/api/graphql?query=%7B__typename%7D", "graphql");
    // Error-page fingerprinting: guaranteed 404 reveals framework/server
    add!("/this-path-does-not-exist-wappalyzer-probe", "error-page");

    // ── WordPress ────────────────────────────────────────────────────────
    if nothing || has_any(&["wordpress"]) {
        add!("/wp-json/",                "wp-json");
        add!("/wp-login.php",            "wp-login");
        add!("/readme.html",             "wp-readme");
        add!("/wp-includes/version.php", "wp-version-php");
        add!("/wp-admin/",               "wp-admin");
        add!("/wp-cron.php",             "wp-cron");
        add!("/wp-includes/js/jquery/jquery.min.js", "wp-jquery");
        add!("/wp-content/uploads/", "wp-uploads");
        for slug in &[
            "woocommerce", "elementor", "contact-form-7", "wordpress-seo",
            "litespeed-cache", "jetpack", "wordfence", "akismet", "wpforms-lite",
            "classic-editor", "really-simple-ssl", "all-in-one-seo-pack",
            "updraftplus", "wp-super-cache", "advanced-custom-fields",
            "rank-math", "mailchimp-for-wp", "js_composer",
            "beaver-builder-plugin", "divi-builder",
        ] {
            probes.push((format!("{}/wp-content/plugins/{}/readme.txt", origin, slug), "wp-plugin-readme"));
        }
    }

    // ── Joomla ───────────────────────────────────────────────────────────
    if nothing || has_any(&["joomla"]) {
        add!("/administrator/manifests/files/joomla.xml", "joomla-manifest");
        add!("/language/en-GB/en-GB.xml",                 "joomla-lang");
    }

    // ── Drupal ───────────────────────────────────────────────────────────
    if nothing || has_any(&["drupal"]) {
        add!("/CHANGELOG.txt",       "drupal-changelog");
        add!("/core/CHANGELOG.txt",  "drupal-changelog");
        add!("/CHANGES.txt",         "changelog");
        add!("/update.php",          "drupal-update");
        add!("/core/lib/Drupal.php", "drupal-core-php");
    }

    // ── Spring Boot ──────────────────────────────────────────────────────
    if nothing || has_any(&["spring"]) {
        add!("/actuator/info",    "spring-actuator");
        add!("/actuator/health",  "spring-health");
        add_t3!("/actuator/env",  "spring-actuator-env");
        add!("/actuator/metrics", "spring-actuator");
    }

    // ── PHP / Laravel / Symfony ──────────────────────────────────────────
    if nothing || has_any(&["php", "laravel", "symfony", "codeigniter", "wordpress", "drupal", "joomla"]) {
        add_t3!("/phpinfo.php",                     "phpinfo");
        add_t3!("/vendor/composer/installed.json",  "composer-installed");
        add_t3!("/storage/logs/laravel.log",        "laravel-log");
        add_t3!("/.env",                            "env-file");
    }

    // ── Ruby / Rails ─────────────────────────────────────────────────────
    if nothing || has_any(&["ruby", "rails"]) {
        add_t3!("/rails/info/properties", "rails-info");
    }

    // ── .NET ─────────────────────────────────────────────────────────────
    if nothing || has_any(&["asp.net", ".net", "iis", "kestrel"]) {
        add_t3!("/elmah.axd", "elmah");
    }

    // ── TYPO3 ────────────────────────────────────────────────────────────
    if nothing || has_any(&["typo3"]) {
        add!("/typo3/",                              "typo3-admin");
        add_t3!("/typo3conf/LocalConfiguration.php", "typo3-config");
    }

    // ── Node.js / Express ────────────────────────────────────────────────
    if nothing || has_any(&["node", "express", "next", "nuxt", "remix"]) {
        add!("/_next/static/chunks/pages/_app.js", "next-chunk");
        add!("/api/health",                         "health-json");
    }

    // ── Python ───────────────────────────────────────────────────────────
    if nothing || has_any(&["django", "flask", "fastapi", "python"]) {
        add!("/static/admin/",   "django-admin");
        add!("/admin/",          "generic-admin");
    }

    // ── Go / Kubernetes ──────────────────────────────────────────────────
    add!("/healthz",  "healthz");
    add!("/readyz",   "readyz");
    add!("/livez",    "livez");
    add!("/_health",  "healthz");

    // ── Prometheus metrics ───────────────────────────────────────────────
    if nothing || has_any(&["prometheus", "grafana", "go", "node"]) {
        add!("/metrics", "prometheus-metrics");
    }

    probes
}

/// Returns true if the given HTTP status code should be accepted for the given probe tag.
pub fn accepts_status_for_tag(tag: &str, status: u16) -> bool {
    match tag {
        // Error page: any 4xx/5xx still reveals the framework
        "error-page" => status == 404 || status == 405 || status == 400 || status == 200,
        // Git/env exposure: 200 means it's publicly accessible
        "git-head" | "env-file" => status == 200,
        // Admin panels: 200 or 301/302 redirect = present
        "wp-admin" | "typo3-admin" | "django-admin" | "generic-admin" => {
            status == 200 || status == 301 || status == 302
        },
        // Drupal core PHP: 403 forbidden still confirms Drupal is present
        "drupal-core-php" => status == 200 || status == 403,
        // wp-uploads: 403 (directory listing off) still confirms WP presence
        "wp-uploads" => status == 200 || status == 403,
        // healthz/readyz/livez: 200 OK or 503 (unhealthy) both confirm the endpoint exists
        "healthz" | "readyz" | "livez" => status == 200 || status == 503,
        _ => status == 200,
    }
}

impl TechnologyAnalyzer {
    /// Parse collected probe responses and record detections into `new_detected`.
    pub(crate) fn parse_probe_responses(
        &self,
        responses: &[(&'static str, String, String, u16)],
        new_detected: &mut HashMap<String, TechDetection>,
    ) {
        let find_tech = |name: &str| -> Option<String> {
            self.find_tech_name(name).map(|s| s.to_string())
        };

        for (tag, probe_url, body, status) in responses {
            let _ = status; // used in specific arms below
            let _ = probe_url; // used in plugin-readme arm below
            match *tag {
                "wp-json" => {
                    // WordPress REST API: {"generator":"WordPress 6.4.3",...}
                    static WP_GEN_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r#""generator"\s*:\s*"WordPress\s+(\d+\.\d+(?:\.\d+)?)""#).unwrap()
                    });
                    if let Some(cap) = WP_GEN_RE.captures(body) {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-json", 100, Some(cap[1].to_string()));
                        }
                    }
                }
                "wp-login" => {
                    if body.contains("wp-login") || body.contains("WordPress") {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-login", 90, None);
                        }
                    }
                }
                "wp-readme" => {
                    // readme.html: "<br /> Version 6.4.3"
                    static WP_README_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)version\s+(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    if body.to_lowercase().contains("wordpress") {
                        if let Some(cap) = WP_README_RE.captures(body) {
                            if let Some(tech) = find_tech("WordPress") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-readme", 100, Some(cap[1].to_string()));
                            }
                        }
                    }
                }
                "package-json" => {
                    if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(body) {
                        // Top-level app name/version
                        if let (Some(name), Some(ver)) = (
                            pkg.get("name").and_then(|v| v.as_str()),
                            pkg.get("version").and_then(|v| v.as_str()),
                        ) {
                            if let Some(tech) = find_tech(name) {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "package.json", 90, Some(ver.to_string()));
                            }
                        }
                        // Dependency versions from dependencies / devDependencies
                        for dep_key in &["dependencies", "devDependencies"] {
                            if let Some(deps) = pkg.get(dep_key).and_then(|v| v.as_object()) {
                                for (dep_name, dep_ver) in deps {
                                    let ver_str = dep_ver.as_str().unwrap_or("")
                                        .trim_start_matches('^')
                                        .trim_start_matches('~')
                                        .trim_start_matches('=');
                                    if !ver_str.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                                        continue;
                                    }
                                    // Try short name (strip scope like "@org/")
                                    let short = dep_name.split('/').last().unwrap_or(dep_name);
                                    if let Some(tech) = find_tech(short).or_else(|| find_tech(dep_name)) {
                                        TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "package-json", 70, Some(ver_str.to_string()));
                                    }
                                }
                            }
                        }

                        // Express: explicit regex extraction from raw body to catch
                        // "express": "~4.18.2" or "express": "^4.18.2" in deps blocks.
                        static EXPRESS_PKG_RE: Lazy<Regex> = Lazy::new(|| {
                            Regex::new(r#""express"\s*:\s*"[~^]?(\d+\.\d+(?:\.\d+)?)"#).unwrap()
                        });
                        if let Some(cap) = EXPRESS_PKG_RE.captures(body) {
                            if let Some(tech) = find_tech("express") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "package-json", 70, Some(cap[1].to_string()));
                            }
                        }
                    }
                }
                "composer-json" => {
                    if let Ok(pkg) = serde_json::from_str::<serde_json::Value>(body) {
                        if let Some(require) = pkg.get("require").and_then(|v| v.as_object()) {
                            for (pkg_name, ver_val) in require {
                                let ver_str = ver_val.as_str().unwrap_or("")
                                    .trim_start_matches('^')
                                    .trim_start_matches('~');
                                if !ver_str.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                                    continue;
                                }
                                let short = pkg_name.split('/').last().unwrap_or(pkg_name.as_str());
                                if let Some(tech) = find_tech(short) {
                                    TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "package.json-dep", 75, Some(ver_str.to_string()));
                                }
                            }
                        }
                    }
                }
                "spring-actuator" => {
                    // {"build":{"version":"2.7.14",...},"java":{"version":"17.0.7"}}
                    if let Ok(info) = serde_json::from_str::<serde_json::Value>(body) {
                        if let Some(ver) = info.pointer("/build/version").and_then(|v| v.as_str()) {
                            // Match any Spring-related tech in the DB
                            if let Some(tech) = self.database.technologies.keys()
                                .find(|k| k.to_lowercase().contains("spring"))
                                .cloned()
                            {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "package.json", 100, Some(ver.to_string()));
                            }
                        }
                        if let Some(java_ver) = info.pointer("/java/version").and_then(|v| v.as_str()) {
                            if let Some(tech) = find_tech("Java") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "spring-actuator", 90, Some(java_ver.to_string()));
                            }
                        }
                    }
                }
                "robots" => {
                    if body.contains("generated by WordPress") || body.contains("/wp-content/") {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "robots", 75, None);
                        }
                    }
                    if body.to_lowercase().contains("/administrator/") {
                        if let Some(tech) = find_tech("Joomla") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "robots", 75, None);
                        }
                    }
                }
                "apache-status" => {
                    static APACHE_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"Apache(?:/(\d+\.\d+\.\d+))?").unwrap()
                    });
                    if let Some(cap) = APACHE_VER_RE.captures(body) {
                        if let Some(tech) = find_tech("Apache HTTP Server") {
                            let ver = cap.get(1).map(|m| m.as_str().to_string());
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "apache-status", 90, ver);
                        }
                    }
                }
                "elmah" => {
                    if body.to_lowercase().contains("error log") || body.to_lowercase().contains("elmah") {
                        if let Some(tech) = find_tech("ELMAH") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "elmah", 90, None);
                        }
                    }
                }
                "sitemap" => {
                    // Sitemap XML may have a WordPress generator comment
                    static SITEMAP_WP_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)generated by WordPress\s+(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    if body.contains("wp-content") || body.contains("WordPress") || body.contains("wordpress.com") {
                        let ver = SITEMAP_WP_RE.captures(body).map(|c| c[1].to_string());
                        let confidence = ver.as_ref().map(|_| 85u8).unwrap_or(60);
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "sitemap", confidence, ver);
                        }
                    }
                }
                "joomla-manifest" => {
                    // /administrator/manifests/files/joomla.xml
                    //   <extension type="framework" ...><version>5.1.2</version>
                    static JOOMLA_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)<version>\s*(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)\s*</version>").unwrap()
                    });
                    if body.contains("<extension") || body.to_lowercase().contains("joomla") {
                        if let Some(cap) = JOOMLA_VER_RE.captures(body) {
                            if let Some(tech) = find_tech("Joomla") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "joomla-manifest", 100, Some(cap[1].to_string()));
                            }
                        }
                    }
                }
                "drupal-changelog" => {
                    // CHANGELOG.txt format: "Drupal 10.2.3, 2024-01-17"
                    static DRUPAL_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)Drupal\s+(\d+\.\d+(?:\.\d+)?)\s*,\s*\d{4}-\d{2}-\d{2}").unwrap()
                    });
                    if let Some(cap) = DRUPAL_VER_RE.captures(body) {
                        if let Some(tech) = find_tech("Drupal") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "drupal-changelog", 95, Some(cap[1].to_string()));
                        }
                    }
                }
                "rss-feed" => {
                    // RSS/Atom <generator> tag: "WordPress 6.5.3", "Ghost/5.82.0", "Drupal 10"
                    static RSS_GEN_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)<generator[^>]*>([^<]+)</generator>").unwrap()
                    });
                    // WordPress emits two generator formats:
                    //   "WordPress 6.5.3"  (text)
                    //   "https://wordpress.org/?v=6.5.3"  (URL — the actual real-world default)
                    static RSS_WP_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)(?:WordPress\s+|wordpress\.org/\?v=)(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    static RSS_GHOST_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)Ghost/(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    static RSS_DRUPAL_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)Drupal\s+(\d+(?:\.\d+)*)").unwrap()
                    });
                    if let Some(gen_cap) = RSS_GEN_RE.captures(body) {
                        let gen = gen_cap[1].to_string();
                        if let Some(vc) = RSS_WP_VER_RE.captures(&gen) {
                            if let Some(tech) = find_tech("WordPress") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "rss-feed", 95, Some(vc[1].to_string()));
                            }
                        } else if let Some(vc) = RSS_GHOST_VER_RE.captures(&gen) {
                            if let Some(tech) = find_tech("Ghost") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "rss-feed", 95, Some(vc[1].to_string()));
                            }
                        } else if let Some(vc) = RSS_DRUPAL_VER_RE.captures(&gen) {
                            if let Some(tech) = find_tech("Drupal") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "rss-feed", 95, Some(vc[1].to_string()));
                            }
                        }
                    }
                }
                "error-page" => {
                    // Framework/server fingerprinting from 404 error page content.
                    // Spring Boot: JSON {"timestamp":...,"status":404,"error":"Not Found"}
                    static SPRING_BOOT_ERR_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r#""status"\s*:\s*404\s*,\s*"error"\s*:\s*"Not Found""#).unwrap()
                    });
                    // Django: "Page not found (404)" with Django branding
                    static DJANGO_ERR_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)Page not found\s*\(404\)").unwrap()
                    });
                    // Rails: ActionController::RoutingError or "Routing Error" heading
                    static RAILS_ERR_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"ActionController::RoutingError|<h1>Routing Error</h1>").unwrap()
                    });
                    // Express/Node.js: "Cannot GET /path" plain text response
                    static EXPRESS_ERR_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"Cannot GET /.+|Cannot POST /.+").unwrap()
                    });
                    // Laravel: "Not Found | 404" or Symfony exception page
                    static LARAVEL_ERR_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)laravel|symfony/http-kernel").unwrap()
                    });
                    // FastAPI / Starlette: {"detail":"Not Found"}
                    static FASTAPI_ERR_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r#"\{"detail"\s*:\s*"Not Found"\}"#).unwrap()
                    });

                    if SPRING_BOOT_ERR_RE.is_match(body) {
                        if let Some(tech) = find_tech("Spring Boot") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "endpoint", 75, None);
                        }
                    }
                    if DJANGO_ERR_RE.is_match(body) {
                        if let Some(tech) = find_tech("Django") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "endpoint", 75, None);
                        }
                    }
                    if RAILS_ERR_RE.is_match(body) {
                        if let Some(tech) = find_tech("Ruby on Rails") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "endpoint", 80, None);
                        }
                    }
                    if EXPRESS_ERR_RE.is_match(body) {
                        if let Some(tech) = find_tech("Express") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "endpoint", 70, None);
                        }
                    }
                    if LARAVEL_ERR_RE.is_match(body) {
                        if let Some(tech) = find_tech("Laravel") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "endpoint", 75, None);
                        }
                    }
                    if FASTAPI_ERR_RE.is_match(body) {
                        if let Some(tech) = find_tech("FastAPI") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "endpoint", 80, None);
                        }
                    }
                }
                "openapi" => {
                    // OpenAPI / Swagger spec: detect framework from info.title / x-generator
                    if let Ok(spec) = serde_json::from_str::<serde_json::Value>(body) {
                        // info.title sometimes names the framework: "Django REST framework", etc.
                        if let Some(title) = spec.pointer("/info/title").and_then(|v| v.as_str()) {
                            if let Some(tech) = find_tech(title) {
                                let ver = spec.pointer("/info/version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "openapi", 80, ver);
                            }
                        }
                        // x-generator field used by FastAPI, Django REST, etc.
                        if let Some(gen) = spec.get("x-generator").and_then(|v| v.as_str()) {
                            static OPENAPI_GEN_VER_RE: Lazy<Regex> = Lazy::new(|| {
                                Regex::new(r"^(.+?)\s+(\d+\.\d+(?:\.\d+)?)").unwrap()
                            });
                            let (name, ver) = if let Some(cap) = OPENAPI_GEN_VER_RE.captures(gen) {
                                (cap[1].trim().to_string(), Some(cap[2].to_string()))
                            } else {
                                (gen.trim().to_string(), None)
                            };
                            if let Some(tech) = find_tech(&name) {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "openapi-generator", 85, ver);
                            }
                        }
                        // Django REST framework emits "Django REST framework" in info.title
                        if body.contains("Django REST framework") || body.contains("django_rest") {
                            if let Some(tech) = find_tech("Django REST Framework") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "openapi", 85, None);
                            }
                        }
                        // FastAPI: "FastAPI" in title or x-generator
                        if body.contains("FastAPI") {
                            if let Some(tech) = find_tech("FastAPI") {
                                let ver = spec.pointer("/info/version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "openapi", 90, ver);
                            }
                        }
                    }
                }
                "version-json" => {
                    // Generic /version or /version.json endpoint
                    // Many apps return: {"version":"1.2.3"} or {"app":"myapp","version":"1.2.3"}
                    static VER_JSON_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r#""version"\s*:\s*"([^"]+)""#).unwrap()
                    });
                    static VER_APP_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r#""(?:app|name|service)"\s*:\s*"([^"]+)""#).unwrap()
                    });
                    if let Some(ver_cap) = VER_JSON_RE.captures(body) {
                        let ver = ver_cap[1].to_string();
                        // Try to pair with an app name from the same response
                        if let Some(name_cap) = VER_APP_RE.captures(body) {
                            let name = &name_cap[1];
                            if let Some(tech) = find_tech(name) {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "version-endpoint", 85, Some(ver));
                            }
                        }
                    }
                }
                "health-json" => {
                    // Spring Boot Actuator health, or generic {"status":"UP"/"ok"/"healthy"}
                    if body.contains("\"status\"") {
                        if body.contains("\"UP\"") || body.contains("\"up\"") {
                            if let Some(tech) = find_tech("Spring Boot") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "actuator-health", 60, None);
                            }
                        }
                    }
                }
                "go-mod" => {
                    // go.mod: first line is "module <name>", second may contain "go 1.22"
                    static GO_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"^go\s+(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    if body.starts_with("module ") {
                        if let Some(tech) = find_tech("Go") {
                            let ver = GO_VER_RE.captures(body).map(|c| c[1].to_string());
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "go.mod", 95, ver);
                        }
                    }
                }
                "gemfile-lock" => {
                    // Gemfile.lock: reveals Ruby + gem versions
                    static RUBY_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?m)^RUBY VERSION\s*\n\s*ruby (\d+\.\d+\.\d+)").unwrap()
                    });
                    static GEM_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?m)^\s{4}(\S+)\s+\((\d+\.\d+(?:\.\d+)?)\)").unwrap()
                    });
                    if body.contains("GEM") || body.contains("BUNDLED WITH") {
                        if let Some(tech) = find_tech("Ruby") {
                            let ver = RUBY_VER_RE.captures(body).map(|c| c[1].to_string());
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "Gemfile.lock", 90, ver);
                        }
                        for cap in GEM_VER_RE.captures_iter(body) {
                            let gem = &cap[1];
                            let ver = cap[2].to_string();
                            if let Some(tech) = find_tech(gem) {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "Gemfile.lock", 90, Some(ver));
                            }
                        }
                    }
                }
                "requirements-txt" => {
                    // requirements.txt: "Django==4.2.7" or "Flask>=2.3.0"
                    static REQ_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?m)^([A-Za-z][A-Za-z0-9_\-\.]+)[=<>!~]+(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    for cap in REQ_RE.captures_iter(body) {
                        let pkg = &cap[1];
                        let ver = cap[2].to_string();
                        if let Some(tech) = find_tech(pkg) {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "requirements.txt", 85, Some(ver));
                        }
                    }
                }
                "nginx-status" => {
                    // nginx stub_status: "Active connections: N"
                    if body.contains("Active connections:") || body.contains("server accepts handled") {
                        if let Some(tech) = find_tech("Nginx") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "nginx-status", 90, None);
                        }
                    }
                }
                "apache-info" => {
                    // Apache server-info page
                    static APACHE_INFO_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"Apache(?:/(\d+\.\d+\.\d+))?").unwrap()
                    });
                    if body.to_lowercase().contains("apache") {
                        if let Some(tech) = find_tech("Apache HTTP Server") {
                            let ver = APACHE_INFO_VER_RE.captures(body).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "server-info", 85, ver);
                        }
                    }
                }
                "wp-version-php" => {
                    // /wp-includes/version.php: $wp_version = '6.5.3';
                    static WP_PHP_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r#"\$wp_version\s*=\s*['"](\d+\.\d+(?:\.\d+)?)['"]"#).unwrap()
                    });
                    if let Some(cap) = WP_PHP_VER_RE.captures(body) {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "version.php", 100, Some(cap[1].to_string()));
                        }
                    }
                }
                "wp-admin" => {
                    if body.contains("wp-login") || body.contains("WordPress") || body.contains("wp-admin") {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-admin", 80, None);
                        }
                    }
                }
                "wp-cron" => {
                    // wp-cron.php returns a 200 empty body on real WordPress sites
                    if body.is_empty() || body.trim().is_empty() {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-cron", 65, None);
                        }
                    }
                }
                "wp-jquery" => {
                    // /wp-includes/js/jquery/jquery.min.js — confirms WordPress
                    // Also extract the jQuery version from the banner
                    static JQUERY_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"jQuery\s+v?(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    if !body.is_empty() {
                        if let Some(tech) = find_tech("WordPress") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-jquery", 85, None);
                        }
                        if let Some(cap) = JQUERY_BANNER_RE.captures(body) {
                            if let Some(tech) = find_tech("jQuery") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-jquery", 95, Some(cap[1].to_string()));
                            }
                        }
                    }
                }
                "joomla-lang" => {
                    // /language/en-GB/en-GB.xml: <version>5.1.2</version>
                    static JOOMLA_LANG_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)<version>\s*(\d+\.\d+(?:\.\d+)?)\s*</version>").unwrap()
                    });
                    if body.contains("<language") || body.to_lowercase().contains("joomla") {
                        if let Some(cap) = JOOMLA_LANG_VER_RE.captures(body) {
                            if let Some(tech) = find_tech("Joomla") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "joomla-lang", 90, Some(cap[1].to_string()));
                            }
                        }
                    }
                }
                "drupal-update" => {
                    // /update.php: Drupal update page — presence at 200 confirms Drupal
                    if body.to_lowercase().contains("drupal") {
                        if let Some(tech) = find_tech("Drupal") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "update.php", 80, None);
                        }
                    }
                }
                "drupal-core-php" => {
                    // 403 on /core/lib/Drupal.php is a strong Drupal signal
                    if *status == 403 || body.to_lowercase().contains("drupal") {
                        if let Some(tech) = find_tech("Drupal") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "drupal-core-php", 85, None);
                        }
                    }
                }
                "spring-health" => {
                    if body.contains("\"status\"") && (body.contains("\"UP\"") || body.contains("\"DOWN\"")) {
                        if let Some(tech) = find_tech("Spring Boot") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "actuator-health", 85, None);
                        }
                    }
                }
                "spring-actuator-env" => {
                    // /actuator/env exposes active profiles and property sources
                    if body.contains("\"activeProfiles\"") || body.contains("\"propertySources\"") {
                        if let Some(tech) = find_tech("Spring Boot") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "actuator-env", 90, None);
                        }
                        if let Some(tech) = find_tech("Java") {
                            static JAVA_VER_ENV_RE: Lazy<Regex> = Lazy::new(|| {
                                Regex::new(r#""java\.version"\s*:\s*\{[^}]*"value"\s*:\s*"([^"]+)""#).unwrap()
                            });
                            if let Some(cap) = JAVA_VER_ENV_RE.captures(body) {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "actuator-env", 90, Some(cap[1].to_string()));
                            }
                        }
                    }
                }
                "phpinfo" => {
                    // /phpinfo.php: full phpinfo page
                    static PHPINFO_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)PHP\s+Version\s+(\d+\.\d+\.\d+)").unwrap()
                    });
                    if body.to_lowercase().contains("php version") || body.contains("phpinfo()") {
                        if let Some(tech) = find_tech("PHP") {
                            let ver = PHPINFO_VER_RE.captures(body).map(|c| c[1].to_string());
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "phpinfo.php", 95, ver);
                        }
                    }
                }
                "composer-installed" => {
                    // /vendor/composer/installed.json: array of installed packages with versions
                    let packages = if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                        // Composer 2.x: {"packages":[...]}; Composer 1.x: [...]
                        v.get("packages")
                            .and_then(|p| p.as_array())
                            .cloned()
                            .unwrap_or_else(|| v.as_array().cloned().unwrap_or_default())
                    } else { vec![] };
                    for pkg in &packages {
                        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let ver  = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
                        let short = name.split('/').last().unwrap_or(name);
                        if let Some(tech) = find_tech(short).or_else(|| find_tech(name)) {
                            let ver_clean = ver.trim_start_matches('v').to_string();
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "composer-installed", 85, Some(ver_clean));
                        }
                    }
                }
                "laravel-log" => {
                    // storage/logs/laravel.log exposure confirms Laravel
                    if body.contains("[") && (body.contains("laravel") || body.contains("Illuminate")) {
                        if let Some(tech) = find_tech("Laravel") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "laravel.log", 90, None);
                        }
                    }
                }
                "env-file" => {
                    // Exposed .env file: can reveal APP_NAME, framework env vars
                    static ENV_APP_NAME_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?m)^APP_NAME=(.+)$").unwrap()
                    });
                    // Laravel-specific env vars
                    if body.contains("APP_KEY=") || body.contains("DB_CONNECTION=") {
                        if let Some(tech) = find_tech("Laravel") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", ".env", 85, None);
                        }
                    }
                    // Django: SECRET_KEY or DJANGO_SETTINGS_MODULE
                    if body.contains("SECRET_KEY=") && body.contains("DJANGO") {
                        if let Some(tech) = find_tech("Django") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", ".env", 85, None);
                        }
                    }
                    // Generic: surface the APP_NAME value
                    if let Some(cap) = ENV_APP_NAME_RE.captures(body) {
                        let app = cap[1].trim().trim_matches('"').trim_matches('\'');
                        if let Some(tech) = find_tech(app) {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", ".env:APP_NAME", 80, None);
                        }
                    }
                }
                "rails-info" => {
                    // /rails/info/properties: "Rails version: 7.1.3\nRuby version: 3.3.0"
                    static RAILS_VER_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)Rails version:\s*(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    static RUBY_VER_INFO_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)Ruby version:\s*(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    if let Some(cap) = RAILS_VER_RE.captures(body) {
                        if let Some(tech) = find_tech("Ruby on Rails") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "rails-info", 100, Some(cap[1].to_string()));
                        }
                    }
                    if let Some(cap) = RUBY_VER_INFO_RE.captures(body) {
                        if let Some(tech) = find_tech("Ruby") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "rails-info", 95, Some(cap[1].to_string()));
                        }
                    }
                }
                "graphql" => {
                    // GraphQL introspection or __typename probe
                    if body.contains("\"__typename\"") || body.contains("\"data\"") {
                        // Try to identify the server from the response
                        if body.contains("\"extensions\"") && body.contains("\"tracing\"") {
                            if let Some(tech) = find_tech("Apollo") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "graphql", 80, None);
                            }
                        }
                        // Hasura: x-hasura- headers or specific error format
                        if body.contains("hasura") {
                            if let Some(tech) = find_tech("Hasura") {
                                TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "graphql", 90, None);
                            }
                        }
                        // General: site has a GraphQL endpoint
                        if let Some(tech) = find_tech("GraphQL") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "graphql", 90, None);
                        }
                    }
                }
                "git-head" => {
                    // Exposed .git/HEAD: "ref: refs/heads/main" or a bare commit hash
                    static GIT_HEAD_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"^ref: refs/heads/|^[0-9a-f]{40}").unwrap()
                    });
                    if GIT_HEAD_RE.is_match(body.trim()) {
                        if let Some(tech) = find_tech("Git") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", ".git/HEAD", 100, None);
                        }
                    }
                }
                "typo3-admin" => {
                    if body.to_lowercase().contains("typo3") || body.contains("TYPO3") {
                        if let Some(tech) = find_tech("TYPO3") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "typo3-admin", 85, None);
                        }
                    }
                }
                "typo3-config" => {
                    if body.to_lowercase().contains("typo3") || body.contains("TYPO3") {
                        if let Some(tech) = find_tech("TYPO3") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "typo3-config", 90, None);
                        }
                    }
                }
                "django-admin" => {
                    if body.contains("Django administration") || body.contains("csrfmiddlewaretoken") {
                        if let Some(tech) = find_tech("Django") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "django-admin", 90, None);
                        }
                    }
                }
                "generic-admin" => {
                    // /admin/ — could be many things; only act if there's a strong keyword
                    if body.contains("Django administration") {
                        if let Some(tech) = find_tech("Django") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "admin", 85, None);
                        }
                    }
                    if body.to_lowercase().contains("strapi") {
                        if let Some(tech) = find_tech("Strapi") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "admin", 85, None);
                        }
                    }
                }
                "next-chunk" => {
                    // /_next/static/chunks/pages/_app.js — confirms Next.js
                    if !body.is_empty() {
                        if let Some(tech) = find_tech("Next.js") {
                            static NEXT_CHUNK_VER: Lazy<Regex> = Lazy::new(|| {
                                Regex::new(r#"["'](\d{1,2}\.\d+\.\d+)["'][^"']{0,50}next"#).unwrap()
                            });
                            let ver = NEXT_CHUNK_VER.captures(body).map(|c| c[1].to_string());
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "next-chunk", 90, ver);
                        }
                    }
                }
                "wp-uploads" => {
                    // /wp-content/uploads/ — 200 (directory listing) or 403 (listing disabled)
                    // both confirm WordPress is present.
                    if let Some(tech) = find_tech("WordPress") {
                        TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-uploads", 85, None);
                    }
                }
                "wp-plugin-readme" => {
                    // /wp-content/plugins/<slug>/readme.txt
                    // Typical format:
                    //   === Plugin Name ===
                    //   ...
                    //   Stable tag: 4.9.17
                    static WP_PLUGIN_README_SLUG_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"/wp-content/plugins/([a-z0-9][a-z0-9_-]*)/readme\.txt").unwrap()
                    });
                    static WP_STABLE_TAG_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?im)^stable tag:\s*(\d+\.\d+(?:\.\d+)?)").unwrap()
                    });
                    // Any readable plugin readme confirms WordPress
                    if let Some(tech) = find_tech("WordPress") {
                        TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-plugin-readme", 85, None);
                    }
                    // Extract the plugin slug from the URL and look it up in the DB
                    if let Some(slug_cap) = WP_PLUGIN_README_SLUG_RE.captures(probe_url) {
                        let slug = &slug_cap[1];
                        let version = WP_STABLE_TAG_RE.captures(body).map(|c| c[1].to_string());
                        if let Some(tech) = find_tech(slug) {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "wp-plugin-readme", 95, version);
                        }
                    }
                }
                "healthz" | "readyz" | "livez" => {
                    // Go/Kubernetes health endpoints. Body is typically "ok", "{}", or
                    // a JSON object like {"status":"ok"} or {"status":"pass"}.
                    let body_trim = body.trim();
                    let is_health_body = body_trim.eq_ignore_ascii_case("ok")
                        || body_trim == "{}"
                        || body.contains(r#""status""#)
                        || body.contains(r#""healthy""#)
                        || body.contains(r#""checks""#);
                    if is_health_body {
                        if let Some(tech) = find_tech("go") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "healthz", 60, None);
                        }
                    }
                }
                "prometheus-metrics" => {
                    // Prometheus text exposition format starts with "# HELP" or "# TYPE" lines.
                    if body.starts_with("# HELP") || body.starts_with("# TYPE") || body.contains("\n# HELP") {
                        if let Some(tech) = find_tech("prometheus") {
                            TechnologyAnalyzer::update_detection(new_detected, &tech, "probe", "/metrics", 92, None);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}
