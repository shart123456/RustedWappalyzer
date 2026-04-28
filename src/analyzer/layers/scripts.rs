//! Script source and asset analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Analyze script tags in HTML
    pub(crate) fn analyze_scripts(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        static SCRIPT_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<script[^>]*src=['"]([^'"]*)['"]*[^>]*>"#).unwrap()
        });
        // CSS link tags — same CDN version extraction pipeline as script srcs.
        // e.g. <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/bootstrap.min.css">
        static LINK_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<link[^>]*href=['"]([^'"]*\.css[^'"]*)['"]*[^>]*>"#).unwrap()
        });

        // Targeted script URL version patterns — for technologies with no DB version capture.
        // Compiled once per process via Lazy statics.
        static GPT_DATE_RE: Lazy<Regex> = Lazy::new(|| {
            // pubads_impl_20240304.js — date-stamped GPT build
            Regex::new(r"pubads_impl[_/](\d{8})").unwrap()
        });
        static HCAPTCHA_VER_RE: Lazy<Regex> = Lazy::new(|| {
            // https://js.hcaptcha.com/1/api.js (path segment is the major version)
            // https://newassets.hcaptcha.com/captcha/v1/1.0.0/hcaptcha.js
            Regex::new(r"hcaptcha\.com/(?:captcha/v\d+/)?(\d+\.\d+(?:\.\d+)?)").unwrap()
        });

        for script_match in SCRIPT_REGEX.captures_iter(html) {
            if let Some(script_src) = script_match.get(1) {
                let url = script_src.as_str();
                let url_lower = url.to_lowercase();

                // Whether this URL is a WordPress plugin asset path.
                // The Wappalyzer DB has WordPress patterns that match any wp-content URL and
                // extract ?ver= as the WP core version — which is wrong when the URL is a
                // plugin asset (the ?ver= there is the PLUGIN version). We suppress version
                // extraction from DB patterns for plugin paths; our custom code handles it
                // correctly below with per-plugin slug lookup.
                let is_wp_plugin_path = url_lower.contains("/wp-content/plugins/");

                for (tech_name, patterns) in &self.script_patterns {
                    for pattern in patterns {
                        if let Some(captures) = pattern.regex.captures(url) {
                            let version = Self::extract_version(&pattern.version, &captures);
                            // Suppress WP core version when coming from a plugin path
                            let version = if is_wp_plugin_path
                                && tech_name.to_lowercase().contains("wordpress")
                            {
                                None
                            } else {
                                version
                            };
                            Self::update_detection(detected, tech_name, "script_src", url, pattern.confidence, version);
                        }
                    }
                }

                // Google Publisher Tag: pubads_impl_YYYYMMDD.js (date-based version)
                if url_lower.contains("googlesyndication") || url_lower.contains("googletagservices") {
                    if let Some(cap) = GPT_DATE_RE.captures(url) {
                        if let Some(db_name) = self.find_tech_name("google publisher tag") {
                            Self::update_detection(detected, db_name, "script_src", url, 100, Some(cap[1].to_string()));
                        }
                    }
                }

                // hCaptcha: version embedded in CDN path
                if url_lower.contains("hcaptcha.com") {
                    if let Some(cap) = HCAPTCHA_VER_RE.captures(url) {
                        if let Some(db_name) = self.find_tech_name("hcaptcha") {
                            Self::update_detection(detected, db_name, "script_src", url, 100, cap.get(1).map(|m| m.as_str().to_string()));
                        }
                    }
                }

                // reCAPTCHA: v2 uses render=explicit (or no render param), v3 uses render=<site_key>
                if url_lower.contains("recaptcha") && url_lower.contains("api.js") {
                    let version = if url_lower.contains("render=explicit") || !url_lower.contains("render=") {
                        Some("v2".to_string())
                    } else if url_lower.contains("render=") {
                        Some("v3".to_string())
                    } else {
                        None
                    };
                    if let Some(db_name) = self.find_tech_name("recaptcha") {
                        Self::update_detection(detected, db_name, "script_src", url, 100, version);
                    }
                }

                // GeeTest: version in CDN URL path segment
                //   static.geetest.com/v4/gt4.js         → "v4"
                //   static.geetest.com/gt3/3.0.8/gt.js   → "3.0.8"
                static GEETEST_V4_RE: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r"geetest\.com/(v\d+)/").unwrap()
                });
                static GEETEST_SEMVER_RE: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r"geetest\.com/gt\d+/(\d+\.\d+(?:\.\d+)?)").unwrap()
                });
                if url_lower.contains("geetest.com") {
                    if let Some(db_name) = self.find_tech_name("geetest") {
                        if let Some(cap) = GEETEST_SEMVER_RE.captures(url) {
                            Self::update_detection(detected, db_name, "script_src", url, 100, Some(cap[1].to_string()));
                        } else if let Some(cap) = GEETEST_V4_RE.captures(url) {
                            Self::update_detection(detected, db_name, "script_src", url, 100, Some(cap[1].to_string()));
                        }
                    }
                }

                // Clearbit Reveal: no DB entry — detect from script URL.
                //   https://reveal.clearbit.com/v1/companies/find?...  (API, not versioned)
                //   https://reveal.clearbit.com/assets/v2/reveal.js    (versioned asset path)
                static CLEARBIT_VER_RE: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r"clearbit\.com/(?:assets/)?v(\d+(?:\.\d+)*)").unwrap()
                });
                if url_lower.contains("clearbit.com") {
                    if let Some(db_name) = self.find_tech_name("clearbit reveal") {
                        let version = CLEARBIT_VER_RE.captures(url)
                            .map(|cap| cap[1].to_string());
                        Self::update_detection(detected, db_name, "script_src", url, 100, version);
                    }
                }

                // Ensighten tag manager uses "Bootstrap.js" as its loader name —
                // this is NOT the Bootstrap CSS framework. Suppress false-positive.
                //   nexus.ensighten.com/<vendor>/<tag>/Bootstrap.js
                if url_lower.contains("ensighten.com") && url_lower.ends_with("bootstrap.js") {
                    if let Some(db_name) = self.find_tech_name("bootstrap") {
                        detected.remove(db_name);
                    }
                }

                // Klarna Checkout: version in CDN URL path
                //   x.klarnacdn.net/kp/lib/v1/api.js       → "v1"
                //   js.klarna.com/web-sdk/v1-stable/...    → "v1"
                //   cdn.klarna.com/1.0/code/...            → "1.0"
                static KLARNA_VER_RE: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r"klarna(?:cdn|services|\.com)[^?]*/(?:lib/|web-sdk/)?(v?\d+(?:\.\d+)*)(?:[/-]|/|stable)").unwrap()
                });
                static KLARNA_CDN_VER_RE: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r"klarna\.com/(\d+\.\d+(?:\.\d+)?)").unwrap()
                });
                if url_lower.contains("klarna") {
                    if let Some(db_name) = self.find_tech_name("klarna checkout") {
                        if let Some(cap) = KLARNA_VER_RE.captures(url) {
                            Self::update_detection(detected, db_name, "script_src", url, 100, Some(cap[1].to_string()));
                        } else if let Some(cap) = KLARNA_CDN_VER_RE.captures(url) {
                            Self::update_detection(detected, db_name, "script_src", url, 100, Some(cap[1].to_string()));
                        }
                    }
                }

                // ?ver= / ?v= query params: CMSs enqueue assets with the CMS core version.
                //   /wp-includes/js/wp-emoji-release.min.js?ver=6.5.3   → WordPress 6.5.3
                //   /core/misc/drupalSettingsLoader.js?v=10.1.6         → Drupal 10.1.6
                // Also fills in version gaps on any DB pattern match that captured no version.
                if let Some(qver) = Self::extract_query_version(url) {
                    // WordPress: only trust ?ver= when the asset's leaf filename is
                    // `wp-*` (core asset) or it sits under `/wp-includes/dist/` or
                    // `/wp-includes/blocks/` (block-editor / Gutenberg core). Vendored
                    // libraries under `/wp-includes/js/<lib>/...` (mediaelement, jquery,
                    // underscore, backbone, plupload, etc.) carry the LIBRARY version,
                    // not the WP core version, so they're excluded.
                    static WP_CORE_ASSET_RE: Lazy<Regex> = Lazy::new(|| {
                        Regex::new(r"(?i)/wp-includes/(?:dist/|blocks/|[^/]*/)?wp-[a-z0-9_-]+\.(?:min\.)?(?:js|css)(?:\?|$)").unwrap()
                    });
                    if WP_CORE_ASSET_RE.is_match(url) {
                        if let Some(db_name) = self.find_tech_name("wordpress") {
                            Self::update_detection(detected, db_name, "script_src", url, 85, Some(qver.clone()));
                        }
                    }
                    // Drupal: /misc/ or /core/misc/ assets carry the Drupal core version
                    if url_lower.contains("/misc/drupal") || url_lower.contains("/core/misc/") {
                        if let Some(db_name) = self.find_tech_name("drupal") {
                            Self::update_detection(detected, db_name, "script_src", url, 85, Some(qver.clone()));
                        }
                    }
                    // WordPress plugin assets: /wp-content/plugins/<slug>/...?ver=X.Y.Z
                    // The ?ver= on plugin assets is the PLUGIN version (not WP core).
                    // e.g. /wp-content/plugins/litespeed-cache/public/js/litespeed.min.js?ver=6.4.1
                    if url_lower.contains("/wp-content/plugins/") {
                        // Confirm WordPress presence
                        if let Some(db_name) = self.find_tech_name("wordpress") {
                            Self::update_detection(detected, db_name, "script_src", url, 75, None);
                        }
                        // Extract slug and look it up in the tech DB
                        static WP_PLUGIN_SCRIPT_RE: Lazy<Regex> = Lazy::new(|| {
                            Regex::new(r"/wp-content/plugins/([a-z0-9][a-z0-9_-]*)(?:/|$)").unwrap()
                        });
                        if let Some(slug_cap) = WP_PLUGIN_SCRIPT_RE.captures(&url_lower) {
                            let slug = &slug_cap[1];
                            if let Some(db_name) = self.find_tech_name(slug) {
                                Self::update_detection(detected, db_name, "script_src", url, 90, Some(qver.clone()));
                            }
                        }
                    }
                    // Generic: if a DB script pattern matched this URL but captured no version,
                    // backfill with the query-param version.
                    // For WordPress specifically, ONLY backfill from URLs that match the
                    // WP-core asset shape (`wp-*.js` under `/wp-includes/`). Other paths
                    // under `/wp-includes/` host vendored libraries (mediaelement, underscore,
                    // backbone, plupload, etc.) whose `?ver=` is the LIBRARY version, and
                    // `/wp-content/plugins/<slug>/...?ver=` is the PLUGIN version.
                    let url_is_wp_core = WP_CORE_ASSET_RE.is_match(url);
                    for (tech_name, patterns) in &self.script_patterns {
                        let tech_is_wp = tech_name.to_lowercase().contains("wordpress");
                        if tech_is_wp && !url_is_wp_core {
                            continue;
                        }
                        for pattern in patterns {
                            if pattern.version.is_none() && pattern.regex.is_match(url) {
                                if let Some(d) = detected.get_mut(tech_name) {
                                    if d.version.is_none() { d.version = Some(qver.clone()); }
                                }
                            }
                        }
                    }
                }
                // WordPress plugin path presence (even without ?ver=): any script from
                // /wp-content/plugins/ is a strong WordPress signal.
                if url_lower.contains("/wp-content/plugins/") {
                    if let Some(db_name) = self.find_tech_name("wordpress") {
                        Self::update_detection(detected, db_name, "script_src", url, 75, None);
                    }
                }
            }
        }

        // Scan <link href="*.css"> tags through the same DB script_patterns + CDN pipeline.
        // This catches CDN-versioned stylesheets that are invisible to the script-only scan.
        static CSS_CDN_URL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"[/@]v?(\d+\.\d+(?:\.\d+)?)(?:[/@]|\.min\.css|\.css|$)").unwrap()
        });
        static CSS_CDN_MAP: &[(&str, &str)] = &[
            ("bootstrap",    "Bootstrap"),
            ("tailwindcss",  "Tailwind CSS"),
            ("bulma",        "Bulma"),
            ("foundation",   "Foundation"),
            ("materialize",  "Materialize"),
            ("fontawesome",  "Font Awesome"),
            ("font-awesome", "Font Awesome"),
            ("@fortawesome", "Font Awesome"),
            ("animate.css",  "Animate.css"),
            ("animate",      "Animate.css"),
            ("normalize",    "Normalize.css"),
            ("vue",          "Vue.js"),
        ];
        for link_match in LINK_REGEX.captures_iter(html) {
            if let Some(href) = link_match.get(1) {
                let url = href.as_str();
                let url_lower = url.to_lowercase();

                // DB script patterns (some apply to CSS URLs too).
                // Same plugin-path guard as the <script> loop: suppress WP version from plugin CSS.
                let is_wp_plugin_path = url_lower.contains("/wp-content/plugins/");
                for (tech_name, patterns) in &self.script_patterns {
                    for pattern in patterns {
                        if let Some(captures) = pattern.regex.captures(url) {
                            let version = Self::extract_version(&pattern.version, &captures);
                            let version = if is_wp_plugin_path
                                && tech_name.to_lowercase().contains("wordpress")
                            {
                                None
                            } else {
                                version
                            };
                            Self::update_detection(detected, tech_name, "script_src", url, pattern.confidence, version);
                        }
                    }
                }

                // CDN version from URL path
                if let Some(ver_cap) = CSS_CDN_URL_RE.captures(url) {
                    let ver = ver_cap[1].to_string();
                    for (keyword, tech_name) in CSS_CDN_MAP {
                        if url_lower.contains(keyword) {
                            if let Some(db_name) = self.find_tech_name(tech_name) {
                                Self::update_detection(detected, db_name, "script_src", url, 100, Some(ver.clone()));
                            }
                            break;
                        }
                    }
                } else if let Some(qver) = Self::extract_query_version(url) {
                    // No path version found — try query param for CDN_CSS_MAP keywords
                    for (keyword, tech_name) in CSS_CDN_MAP {
                        if url_lower.contains(keyword) {
                            if let Some(db_name) = self.find_tech_name(tech_name) {
                                Self::update_detection(detected, db_name, "script_src", url, 85, Some(qver.clone()));
                            }
                            break;
                        }
                    }
                    // WordPress stylesheet path is a presence signal, but `?ver=` on a
                    // theme asset is the THEME version, not WP core — record presence
                    // only (no version) so a downstream signal (meta generator,
                    // /wp-includes/wp-*.{js,css}) can supply the real core version.
                    if url_lower.contains("/wp-content/themes/") {
                        if let Some(db_name) = self.find_tech_name("wordpress") {
                            Self::update_detection(detected, db_name, "script_src", url, 80, None);
                        }
                    }
                }
            }
        }
    }

    pub fn analyze_asset(&self, asset_url: &str, content: &str, detected: &mut HashMap<String, TechDetection>) {
        let is_css = asset_url.contains(".css")
            || asset_url.contains("css?")
            || asset_url.contains("stylesheet");
        if is_css {
            // Find a safe UTF-8 char boundary at or before 8192 bytes to avoid a panic
            // when the asset content contains multi-byte characters near the cap.
            let cap = {
                let mut idx = content.len().min(8192);
                while idx > 0 && !content.is_char_boundary(idx) { idx -= 1; }
                idx
            };
            let wrapped = format!("<style>\n{}\n</style>", &content[..cap]);
            self.analyze_html(&wrapped, detected);
            self.match_css_patterns(content, detected);
        } else {
            self.match_inline_script_patterns(content, detected);
            self.analyze_html(content, detected);
        }

        // Generic banner-comment scanner — two formats:
        //   /*! jQuery v3.7.1            (classic)
        //   /*!\n * Bootstrap  v5.3.3    (multi-line classic)
        //   @popperjs/core v2.11.8       (scoped npm package)
        static BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?im)/\*[!\s]*\*?\s*([A-Za-z][A-Za-z0-9_.]*(?:\.js)?)\s{1,4}v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static SCOPED_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?im)@([A-Za-z][A-Za-z0-9_-]*/[A-Za-z][A-Za-z0-9_-]*)\s+v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        // Scoped package → DB technology name aliases
        static SCOPED_ALIASES: &[(&str, &str)] = &[
            ("popperjs/core",     "Popper"),
            ("popperjs/core",     "Popper.js"),
            ("floating-ui/core",  "Floating UI"),
            ("floating-ui/dom",   "Floating UI"),
            ("tanstack/query",    "TanStack Query"),
            ("vue/reactivity",    "Vue.js"),
            ("vue/runtime-core",  "Vue.js"),
            ("zipkin/zipkin",     "Zipkin"),
        ];

        // Banner scanner now runs over the full fetched content (not just first 1 KB)
        for cap in BANNER_RE.captures_iter(content) {
            let (raw_name, version) = match (cap.get(1), cap.get(2)) {
                (Some(n), Some(v)) => (n.as_str().to_string(), v.as_str().to_string()),
                _ => continue,
            };
            let candidates = [raw_name.clone(), raw_name.trim_end_matches(".js").to_string()];
            for candidate in &candidates {
                if let Some(tech_name) = self.find_tech_name(candidate) {
                    Self::update_detection(detected, tech_name, "script_src", &format!("banner:{}", tech_name), 100, Some(version.clone()));
                    break;
                }
            }
        }

        for cap in SCOPED_RE.captures_iter(content) {
            let (pkg, version) = match (cap.get(1), cap.get(2)) {
                (Some(n), Some(v)) => (n.as_str().to_lowercase(), v.as_str().to_string()),
                _ => continue,
            };
            // Check alias map first
            if let Some(&alias) = SCOPED_ALIASES.iter().find(|(k, _)| *k == pkg.as_str()).map(|(_, v)| v) {
                if let Some(tech_name) = self.find_tech_name(alias) {
                    Self::update_detection(detected, tech_name, "script_src", &format!("banner:{}", tech_name), 100, Some(version.clone()));
                }
            }
        }

        // --- CDN URL version extraction ---
        // Many CDN-hosted libraries embed the version in the URL path:
        //   cdn.cookielaw.org/scripttemplates/6.33.0/otSDKStub.js
        //   cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js
        //   unpkg.com/react@18.2.0/umd/react.production.min.js
        static CDN_URL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"[/@]v?(\d+\.\d+(?:\.\d+)?)(?:[/@]|\.min\.js|\.js|$)").unwrap()
        });
        static CDN_MAP: &[(&str, &str)] = &[
            ("cookielaw",    "OneTrust"),
            ("onetrust",     "OneTrust"),
            ("otsdkstub",    "OneTrust"),
            ("jquery",       "jQuery"),
            ("bootstrap",    "Bootstrap"),
            ("react",        "React"),
            ("vue",          "Vue.js"),
            ("angular",      "Angular"),
            ("lodash",       "Lodash"),
            ("moment",       "Moment.js"),
            ("axios",        "Axios"),
            ("fontawesome",  "Font Awesome"),
            ("font-awesome", "Font Awesome"),
            ("@fortawesome", "Font Awesome"),
            ("video.js",     "VideoJS"),
            ("videojs",      "VideoJS"),
            ("vjs.zencdn",   "VideoJS"),
            ("highcharts",   "Highcharts"),
            ("swiper",       "Swiper"),
            ("gsap",         "GSAP"),
            ("three",        "Three.js"),
            ("d3",           "D3"),
            ("chart.js",     "Chart.js"),
            ("chartjs",      "Chart.js"),
            ("firebase",     "Firebase"),
            ("mapkit",       "Apple MapKit JS"),
            ("web-vitals",   "web-vitals"),
            ("nuxt",         "Nuxt.js"),
            ("zipkin",       "Zipkin"),
            ("plyr",         "Plyr"),
            ("sentry-cdn",   "Sentry"),
            ("sentry.io",    "Sentry"),
            ("marko",        "Marko"),
        ];
        let url_lower = asset_url.to_lowercase();
        if let Some(ver_cap) = CDN_URL_RE.captures(asset_url) {
            let ver = ver_cap[1].to_string();
            for (keyword, tech_name) in CDN_MAP {
                if url_lower.contains(keyword) {
                    if let Some(db_name) = self.find_tech_name(tech_name) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(ver.clone()));
                    }
                    break;
                }
            }
        }

        // --- Targeted bundle version patterns ---
        // These handle minified production bundles where banner comments are absent.
        if !is_css {
            // React: `.version="18.3.1"` near useTransition/useReducer in the React bundle.
            // Run on files that plausibly contain React (framework/vendor/react bundles).
            // Both `exports.version` (UMD) and `n.version` (minified) occur in the wild.
            static REACT_VER_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"useTransition[^"']{0,200}\.version=["'](\d+\.\d+\.\d+)["']"#).unwrap()
            });
            static REACT_VER_RE2: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"exports\.version=["'](\d+\.\d+\.\d+)["']"#).unwrap()
            });
            if url_lower.contains("react") || url_lower.contains("framework") || url_lower.contains("vendor") {
                let react_db = self.find_tech_name("react");
                if let Some(db_name) = react_db {
                    if let Some(cap) = REACT_VER_RE.captures(content) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    } else if let Some(cap) = REACT_VER_RE2.captures(content) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    }
                }
            }

            // webpack: exact version via `webpack/5.88.2` comment (only in some builds),
            // otherwise fingerprint the major version from the chunk-loading bootstrap pattern.
            //   webpack 5 → self.webpackChunk[name]
            //   webpack 4 → window.webpackJsonp / webpackJsonp
            static WEBPACK_EXACT_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"webpack/(\d+\.\d+\.\d+)").unwrap()
            });
            static WEBPACK5_CHUNK_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"self\.webpackChunk").unwrap()
            });
            static WEBPACK4_JSONP_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"(?:window\.webpackJsonp|webpackJsonp)").unwrap()
            });
            if let Some(db_name) = self.find_tech_name("webpack") {
                if let Some(cap) = WEBPACK_EXACT_RE.captures(content) {
                    // Exact version found in a banner comment
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if WEBPACK5_CHUNK_RE.is_match(content) {
                    // Major version 5 confirmed; "5.x" signals this without a false-exact claim
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some("5.x".to_string()));
                } else if WEBPACK4_JSONP_RE.is_match(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some("4.x".to_string()));
                }
            }

            // Next.js: `next/(\d+\.\d+\.\d+)` appears in Next.js framework chunks.
            static NEXTJS_VER_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"["']next/dist[^"']*["']|next/(\d+\.\d+\.\d+)"#).unwrap()
            });
            // More reliable: look for the version string Next.js embeds in _app chunks
            static NEXTJS_VER_RE2: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"__NEXT_VERSION\s*[=:]\s*["'](\d+\.\d+\.\d+)["']"#).unwrap()
            });
            // UMD/CJS build: `exports.version="14.2.3"` or `module.exports.version="14.2.3"`
            // emitted near Next.js-specific globals (__NEXT_DATA__, webpackChunk_N_E, etc.)
            static NEXT_BUNDLE_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"(?:exports|module\.exports)\.version\s*=\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
            });
            // Minified bundle pattern: version string adjacent to __NEXT_DATA__ or _N_E chunk marker
            // e.g. `self.webpackChunk_N_E` is Next.js's chunk array name
            static NEXT_CHUNK_VER_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"(?:webpackChunk_N_E|__NEXT_DATA__)[^\n]{0,200}["'](\d{1,2}\.\d+\.\d+)["']"#).unwrap()
            });
            if url_lower.contains("next") || url_lower.contains("_next") {
                let next_db = self.find_tech_name("next.js");
                if let Some(db_name) = next_db {
                    if let Some(cap) = NEXTJS_VER_RE.captures(content) {
                        if let Some(ver) = cap.get(1) {
                            Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(ver.as_str().to_string()));
                        }
                    }
                    if let Some(cap) = NEXTJS_VER_RE2.captures(content) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    }
                    if let Some(cap) = NEXT_BUNDLE_RE.captures(content) {
                        // Only use exports.version if there's a Next.js-specific indicator nearby
                        if content.contains("__NEXT_DATA__") || content.contains("webpackChunk_N_E")
                            || content.contains("_next/static") || content.contains("next/dist")
                        {
                            Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                        }
                    }
                    if let Some(cap) = NEXT_CHUNK_VER_RE.captures(content) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    }
                }
            }

            // OneTrust: two version formats observed in the wild:
            //   1. OT_SDK_VERSION / otSDKVersion / sdkVersion = "6.x.x"  (older builds)
            //   2. Version="202602.1.0"  — date-based (YYYYMM.major.minor), in SDK stub
            static ONETRUST_VER_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"(?:OT_SDK_VERSION|otSDKVersion|sdkVersion)\s*[=:]\s*["']([0-9][^"']{1,30})["']"#).unwrap()
            });
            static ONETRUST_DATE_VER_RE: Lazy<Regex> = Lazy::new(|| {
                // Matches date-based version: Version="202602.1.0"
                Regex::new(r#"[Vv]ersion=["'](\d{6}\.\d+\.\d+)["']"#).unwrap()
            });
            if url_lower.contains("onetrust") || url_lower.contains("cookielaw") || url_lower.contains("otsdkstub") {
                if let Some(db_name) = self.find_tech_name("onetrust") {
                    if let Some(cap) = ONETRUST_VER_RE.captures(content) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    } else if let Some(cap) = ONETRUST_DATE_VER_RE.captures(content) {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    }
                }
            }

            // Vue.js: `Vue.version = "3.x.x"` in the Vue runtime.
            // Run on any JS file — Vue is often self-hosted without "vue" in the URL.
            // Guard with `__VUE__` presence check to avoid false positives on large vendor bundles.
            static VUE_VER_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"(?i)(?:exports\.version|Vue\.version)\s*=\s*["'](\d+\.\d+\.\d+)["']"#).unwrap()
            });
            static VUE_GUARD_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"__VUE__|createApp|defineComponent").unwrap()
            });
            if url_lower.contains("vue") || VUE_GUARD_RE.is_match(content) {
                if let Some(cap) = VUE_VER_RE.captures(content) {
                    if let Some(db_name) = self.find_tech_name("vue.js") {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    }
                }
            }

            // Angular: `VERSION={full:"17.x.x"` in Angular platform bundles.
            static ANGULAR_VER_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"VERSION\s*=\s*\{[^}]*full:\s*["'](\d+\.\d+\.\d+)["']"#).unwrap()
            });
            if url_lower.contains("angular") || url_lower.contains("main.") {
                if let Some(cap) = ANGULAR_VER_RE.captures(content) {
                    if let Some(db_name) = self.find_tech_name("angular") {
                        Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                    }
                }
            }
        }

        // Firebase: SDK version in bundle content or CDN URL (@firebase/app@10.x.x)
        static FIREBASE_SDK_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)firebase(?:App)?\.SDK_VERSION\s*=\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        static FIREBASE_CDN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"firebase(?:app)?@(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if url_lower.contains("firebase") || url_lower.contains("firebaseapp") {
            if let Some(db_name) = self.find_tech_name("firebase") {
                if let Some(cap) = FIREBASE_SDK_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if let Some(cap) = FIREBASE_CDN_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }

        // RequireJS: banner comment or global assignment
        //   /** @license RequireJS 2.3.7 */
        //   requirejs.version = "2.3.7"   (in the bundle itself)
        static REQUIREJS_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)RequireJS\s+(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static REQUIREJS_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"requirejs\.version\s*=\s*["']([^"']+)["']"#).unwrap()
        });
        if let Some(db_name) = self.find_tech_name("requirejs") {
            if let Some(cap) = REQUIREJS_GLOBAL_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if let Some(cap) = REQUIREJS_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Prototype.js: global assignment present in the bundle
        //   Prototype.Version = "1.7.3"
        static PROTOTYPE_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"Prototype\.Version\s*=\s*["']([^"']+)["']"#).unwrap()
        });
        if let Some(db_name) = self.find_tech_name("prototype") {
            if let Some(cap) = PROTOTYPE_VER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Apple MapKit JS: version in JS global or CDN URL query param
        //   mapkit.version = "5.77.0"
        //   https://cdn.apple-mapkit.com/mk/5.77.0/mapkit.js
        static MAPKIT_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"mapkit\.version\s*=\s*["']([^"']+)["']"#).unwrap()
        });
        static MAPKIT_URL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"apple-mapkit\.com/mk/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if url_lower.contains("mapkit") || url_lower.contains("apple-mapkit") {
            if let Some(db_name) = self.find_tech_name("apple mapkit js") {
                if let Some(cap) = MAPKIT_GLOBAL_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if let Some(cap) = MAPKIT_URL_RE.captures(asset_url) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }

        // Bootstrap: banner comment in CSS/JS files.
        //   /*! * Bootstrap  v5.3.3 (https://getbootstrap.com/)
        //   /*! Bootstrap v4.6.2
        // Also caught by BANNER_RE generically, but this is an explicit fallback for
        // multi-line banners where the generic pattern may not fire.
        static BOOTSTRAP_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*Bootstrap\s+v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if let Some(db_name) = self.find_tech_name("bootstrap") {
            if let Some(cap) = BOOTSTRAP_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // web-vitals: CDN URL handled by CDN_MAP above; also check banner/global assignment.
        //   import{onCLS as ...} from "web-vitals"   (ESM — version in URL)
        //   webVitals.version = "3.5.2"              (UMD build)
        static WEB_VITALS_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)web.?vitals[^\n]{0,60}version\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        static WEB_VITALS_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*web-vitals\s+v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if url_lower.contains("web-vitals") || url_lower.contains("webvitals") {
            if let Some(db_name) = self.find_tech_name("web-vitals") {
                if let Some(cap) = WEB_VITALS_VER_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if let Some(cap) = WEB_VITALS_BANNER_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }

        // Nuxt.js: version in bundle URL (handled by CDN_MAP), inline script global,
        // or the __NUXT_VERSION__ constant injected by the build.
        //   window.__NUXT__ = {config:{...},version:"3.11.0"}
        //   __NUXT_VERSION__ = "3.11.0"
        static NUXT_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)(?:__NUXT_VERSION__|nuxt[_-]?version)\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        static NUXT_WINDOW_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"window\.__NUXT__\s*=[^;]{0,200}"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"#).unwrap()
        });
        if url_lower.contains("nuxt") || content.contains("__NUXT__") {
            if let Some(db_name) = self.find_tech_name("nuxt.js") {
                if let Some(cap) = NUXT_VER_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if let Some(cap) = NUXT_WINDOW_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }

        // Optimizely: `optimizelyClient.clientVersion` JS global in their SDK bundle.
        //   a.clientVersion="4.9.3"  or  clientVersion:"2.1.0"
        static OPTIMIZELY_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"clientVersion\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if url_lower.contains("optimizely") || url_lower.contains("optimizelysdk") {
            if let Some(db_name) = self.find_tech_name("optimizely") {
                if let Some(cap) = OPTIMIZELY_VER_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }

        // Sentry: SDK version from bundle content or CDN URL.
        //   Sentry.SDK_VERSION = "7.116.0"
        //   browser.sentry-cdn.com/7.116.0/bundle.min.js  (handled by BANNER_RE + CDN URL)
        //   __SENTRY_SDK_VERSION__ = "7.116.0"
        static SENTRY_SDK_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?:Sentry\.SDK_VERSION|__SENTRY_SDK_VERSION__|SDK_VERSION)\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        static SENTRY_CDN_RE: Lazy<Regex> = Lazy::new(|| {
            // browser.sentry-cdn.com/7.116.0/bundle.min.js
            Regex::new(r"sentry[_-]cdn\.com/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if url_lower.contains("sentry") || content.contains("__SENTRY__") {
            if let Some(db_name) = self.find_tech_name("sentry") {
                if let Some(cap) = SENTRY_SDK_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if let Some(cap) = SENTRY_CDN_RE.captures(asset_url) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }

        // Plyr: video player. Banner comment in JS/CSS or CDN URL (handled by CDN_MAP above).
        //   /*! Plyr v3.7.8 */
        //   plyr.version = "3.7.8"
        static PLYR_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*Plyr\s+v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static PLYR_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)Plyr\.version\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if let Some(db_name) = self.find_tech_name("plyr") {
            if let Some(cap) = PLYR_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if let Some(cap) = PLYR_GLOBAL_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Marko: eBay's server-side JS framework. Banner comment, CDN URL (CDN_MAP above),
        //   or global version property.
        //   /*! marko v5.32.0 */
        //   marko.version = "5.32.0"
        static MARKO_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*marko\s+v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static MARKO_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)marko(?:Js)?\.version\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if let Some(db_name) = self.find_tech_name("marko") {
            if let Some(cap) = MARKO_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if let Some(cap) = MARKO_GLOBAL_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Video.js: open-source HTML5 video player.
        //   /*! Video.js v8.10.0 */  or  /*! @license Video.js 8.10.0 */
        //   videojs.VERSION = "8.10.0"
        static VIDEOJS_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*(?:@license\s+)?[Vv]ideo\.js\s+v?(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static VIDEOJS_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)videojs\.VERSION\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if let Some(db_name) = self.find_tech_name("videojs") {
            if let Some(cap) = VIDEOJS_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if let Some(cap) = VIDEOJS_GLOBAL_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Font Awesome: icon library. Banner comment in CSS/JS.
        //   /*! Font Awesome Free 6.5.1 by @fontawesome */
        static FA_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*Font\s+Awesome[^*]*?(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if let Some(db_name) = self.find_tech_name("font awesome") {
            if let Some(cap) = FA_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Highcharts: charting library.
        //   /*! Highcharts v11.2.0 */
        //   Highcharts.version = "11.2.0"
        static HIGHCHARTS_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*Highcharts\s+(?:JS\s+)?v?(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static HIGHCHARTS_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)Highcharts\.version\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if let Some(db_name) = self.find_tech_name("highcharts") {
            if let Some(cap) = HIGHCHARTS_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if let Some(cap) = HIGHCHARTS_GLOBAL_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            }
        }

        // Tailwind CSS: version appears in banner comments of unminified/CDN-hosted builds.
        // Formats observed in the wild:
        //   /*! tailwindcss v3.4.1 | MIT License | https://tailwindcss.com */
        //   /* ! tailwindcss v4.0.0-beta.1 */
        //   tailwindcss@3.4.1  (CDN import in CSS/JS)
        //
        // For bundled CSS (no CDN URL, no banner comment), Tailwind 4.x embeds
        // `@layer base` and uses `@property --tw-*` declarations; Tailwind 3.x
        // uses `--tw-*` CSS variables (presence-only, no version encoded).
        // We detect presence via the DB css pattern; version requires the banner.
        static TAILWIND_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)tailwindcss\s*v(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?)").unwrap()
        });
        static TAILWIND_CDN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)tailwindcss@(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?)").unwrap()
        });
        // Tailwind 4.x specific: @property declarations for --tw-* variables are a v4 indicator.
        //   @property --tw-translate-x { syntax: '<length-percentage>'; ... }
        static TAILWIND_V4_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"@property\s+--tw-(?:translate|rotate|skew|scale|blur|brightness|contrast|saturate|hue-rotate|invert|backdrop)").unwrap()
        });
        if let Some(db_name) = self.find_tech_name("tailwind css") {
            if let Some(cap) = TAILWIND_BANNER_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if let Some(cap) = TAILWIND_CDN_RE.captures(content) {
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
            } else if TAILWIND_V4_RE.is_match(content) {
                // Tailwind v4 @property declarations — presence-only (no minor version available)
                Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some("4.x".to_string()));
            }
        }

        // Zipkin: version from JS bundle banner comment or global assignment.
        // Formats observed in the wild:
        //   /*! zipkin v0.22.0 */   or   /*! @zipkin/zipkin v0.22.0 */
        //   zipkin.version = "0.22.0"   (zipkin-js global)
        //   zipkinJs.version = "0.22.0" (older builds)
        //   @zipkin/zipkin@0.22.0  (scoped CDN URL, handled by SCOPED_ALIASES above)
        static ZIPKIN_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)/\*[!*\s]*zipkin[^\n]{0,40}v(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static ZIPKIN_GLOBAL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)zipkin(?:Js)?\.version\s*=\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if url_lower.contains("zipkin") {
            if let Some(db_name) = self.find_tech_name("zipkin") {
                if let Some(cap) = ZIPKIN_BANNER_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                } else if let Some(cap) = ZIPKIN_GLOBAL_RE.captures(content) {
                    Self::update_detection(detected, db_name, "script_src", &format!("banner:{}", db_name), 100, Some(cap[1].to_string()));
                }
            }
        }
    }
}
