//! HTML content analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Scan HTML for JS global/property patterns (window.X presence or window.X.Y matching a regex)
    pub(crate) fn analyze_js_patterns(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        for (tech_name, js_pats) in &self.js_patterns {
            for js_pat in js_pats {
                if !html.contains(&js_pat.path) {
                    continue; // cheap pre-filter
                }
                let (version, confidence) = match &js_pat.pattern {
                    None => (None, 75u8),
                    Some(cp) => {
                        if let Some(captures) = cp.regex.captures(html) {
                            let ver = Self::extract_version(&cp.version, &captures);
                            (ver, cp.confidence)
                        } else {
                            continue; // pattern present but regex didn't match
                        }
                    }
                };
                Self::update_detection(detected, tech_name, "js", &js_pat.path, confidence, version);
            }
        }
    }

    /// Broad HTML heuristics for sites where pattern-based detection finds nothing.
    /// Handles: meta[name=generator] catch-all, SPA mount-point patterns,
    /// hosted-platform asset URLs, and common JS global signals.
    pub(crate) fn scan_html_generic(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        // ── 1. <meta name="generator"> catch-all ────────────────────────────
        // Many CMSes, site builders, and static generators write their name here.
        // We try to match the value against the DB; if unknown we still surface it.
        static META_GEN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"'<]+)["']"#).unwrap()
        });
        static META_GEN_RE2: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<meta[^>]+content=["']([^"'<]+)["'][^>]+name=["']generator["']"#).unwrap()
        });
        static GEN_VER_SPLIT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"^(.+?)\s+v?(\d+\.\d+(?:\.\d+)?.*)$").unwrap()
        });

        let generator = META_GEN_RE.captures(html)
            .or_else(|| META_GEN_RE2.captures(html))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());

        if let Some(gen) = generator {
            let (gen_name, gen_version) = if let Some(cap) = GEN_VER_SPLIT_RE.captures(&gen) {
                (cap[1].trim().to_string(), Some(cap[2].to_string()))
            } else {
                (gen.clone(), None)
            };
            // Try progressively shorter candidates against the DB
            let candidates = [
                gen_name.clone(),
                gen.split_whitespace().next().unwrap_or("").to_string(),
            ];
            let mut found = false;
            for candidate in &candidates {
                if candidate.is_empty() { continue; }
                if let Some(db_name) = self.find_tech_name(candidate) {
                    Self::update_detection(detected, db_name, "html", "meta-generator", 90, gen_version.clone());
                    found = true;
                    break;
                }
            }
            // Surface even unknown generators so callers can see something
            if !found && !gen_name.is_empty() && gen_name.len() < 64 {
                Self::update_detection(detected, &gen_name, "html", "meta-generator", 75, gen_version);
            }
        }

        // ── 2. SPA framework mount-point patterns ───────────────────────────
        // React: data-reactroot or empty #root div (common SPA scaffold)
        static REACT_MOUNT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"data-reactroot|__reactFiber|<div\s+id="root"\s*></div>|<div\s+id="root"\s*/>"#).unwrap()
        });
        if REACT_MOUNT_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("react") {
                Self::update_detection(detected, db_name, "html", "dom-pattern", 70, None);
            }
        }

        // Angular: <app-root> element or ng-version attribute
        static NG_ROOT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"<app-root[\s>/]|ng-version=["']([^"']+)["']"#).unwrap()
        });
        if NG_ROOT_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("angular") {
                static NG_VER_RE: Lazy<Regex> = Lazy::new(|| {
                    Regex::new(r#"ng-version="([^"]+)""#).unwrap()
                });
                let ver = NG_VER_RE.captures(html).map(|c| c[1].to_string());
                Self::update_detection(detected, db_name, "html", "ng-version", 90, ver);
            }
        }

        // ── 3. Hosted-platform asset URL fingerprints ───────────────────────
        static WIXSTATIC_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"static\.wixstatic\.com|wix\.com/_static").unwrap()
        });
        if WIXSTATIC_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("wix") {
                Self::update_detection(detected, db_name, "html", "wixstatic.com", 95, None);
            }
        }

        static SQUARESPACE_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"static1\.squarespace\.com|squarespace-cdn\.com").unwrap()
        });
        if SQUARESPACE_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("squarespace") {
                Self::update_detection(detected, db_name, "html", "squarespace-cdn", 95, None);
            }
        }

        static WEBFLOW_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"assets\.website-files\.com|webflow\.com/[a-f0-9]{20}").unwrap()
        });
        if WEBFLOW_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("webflow") {
                Self::update_detection(detected, db_name, "html", "website-files.com", 95, None);
            }
        }

        static GHOST_CDN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"content="Ghost\s+(\d+\.\d+(?:\.\d+)?)"|ghost\.min\.js"#).unwrap()
        });
        if GHOST_CDN_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("ghost") {
                let ver = GHOST_CDN_RE.captures(html).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                Self::update_detection(detected, db_name, "html", "ghost-cdn", 90, ver);
            }
        }

        // ── 4. Common JS global signals in inline scripts ───────────────────
        static REDUX_DEVTOOLS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"__REDUX_DEVTOOLS_EXTENSION__|__REDUX_DEVTOOLS_EXTENSION_COMPOSE__").unwrap()
        });
        if REDUX_DEVTOOLS_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("redux") {
                Self::update_detection(detected, db_name, "html", "redux-devtools", 70, None);
            }
        }

        // Svelte: __svelte or Svelte-specific data- attributes
        static SVELTE_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"__svelte|svelte-[a-z0-9]{6,}").unwrap()
        });
        if SVELTE_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("svelte") {
                Self::update_detection(detected, db_name, "html", "svelte-attr", 80, None);
            }
        }

        // Astro: data-astro-cid- attributes (Astro scoped CSS fingerprint)
        static ASTRO_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"data-astro-cid-|astro-island|<astro-dev-toolbar").unwrap()
        });
        if ASTRO_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("astro") {
                Self::update_detection(detected, db_name, "html", "astro-cid", 85, None);
            }
        }

        // SvelteKit: __sveltekit global or data-sveltekit attributes
        static SVELTEKIT_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"__sveltekit|data-sveltekit-").unwrap()
        });
        if SVELTEKIT_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("sveltekit") {
                Self::update_detection(detected, db_name, "html", "sveltekit-global", 85, None);
            }
        }

        // Remix: __remixContext global injected by all Remix apps
        static REMIX_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"__remixContext|__remixManifest").unwrap()
        });
        if REMIX_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("remix") {
                Self::update_detection(detected, db_name, "html", "remixContext", 90, None);
            }
        }

        // Gatsby: __gatsby or window.___gatsby global
        static GATSBY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"window\.___gatsby|___gatsby|gatsby-chunk-mapping").unwrap()
        });
        if GATSBY_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("gatsby") {
                Self::update_detection(detected, db_name, "html", "gatsby-global", 90, None);
            }
        }

        // ── 5. Next.js / Nuxt.js data blobs ─────────────────────────────────
        // Next.js: <script id="__NEXT_DATA__" type="application/json">
        static NEXT_DATA_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"id=["']__NEXT_DATA__["']"#).unwrap()
        });
        if NEXT_DATA_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("next.js") {
                Self::update_detection(detected, db_name, "html", "__NEXT_DATA__", 95, None);
            }
        }

        // Nuxt.js: window.__NUXT__ SSR payload blob
        if html.contains("window.__NUXT__") || html.contains("__NUXT__=") || html.contains("__NUXT_DATA__") {
            if let Some(db_name) = self.find_tech_name("nuxt.js") {
                Self::update_detection(detected, db_name, "html", "__NUXT__", 90, None);
            }
        }

        // ── 6. Miscellaneous framework globals ───────────────────────────────
        // Alpine.js: x-data attribute pattern
        static ALPINE_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"x-data=["']|x-init=["']|@click\.|x-show=["']"#).unwrap()
        });
        if ALPINE_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("alpine.js") {
                Self::update_detection(detected, db_name, "html", "x-data", 75, None);
            }
        }

        // htmx: hx-get/hx-post/hx-target attributes
        static HTMX_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"hx-get=["']|hx-post=["']|hx-target=["']|hx-swap=["']"#).unwrap()
        });
        if HTMX_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("htmx") {
                Self::update_detection(detected, db_name, "html", "hx-get", 85, None);
            }
        }

        // Inertia.js: data-page attribute (Laravel/Rails SPA bridge)
        static INERTIA_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"data-page=["']\{"component""#).unwrap()
        });
        if INERTIA_RE.is_match(html) {
            if let Some(db_name) = self.find_tech_name("inertia.js") {
                Self::update_detection(detected, db_name, "html", "data-page", 90, None);
            }
        }
    }

    /// Analyze HTML content

    pub(crate) fn analyze_html(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        for (tech_name, patterns) in &self.html_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(html) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    let pat_str = pattern.regex.as_str();
                    Self::update_detection(detected, tech_name, "html", pat_str, pattern.confidence, version);
                }
            }
        }

        // Next.js: attempt to extract version from __NEXT_DATA__ JSON embedded in the HTML.
        //
        // Older Next.js builds (≤9) included a top-level `nextVersion` key:
        //   <script id="__NEXT_DATA__" ...>{"nextVersion":"9.5.3","buildId":...}</script>
        //
        // Modern builds (10+) dropped that field, but some deployments still expose it via
        // custom server configuration or Next.js plugins.  We check both the JSON key format
        // and a raw string match so we don't depend on the JSON being fully parseable.
        static NEXT_DATA_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"["\s]nextVersion\s*:\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        // Some Next.js builds also embed the framework version directly in an inline <script>
        // via `exports.version = "14.2.3"` (UMD build of next/dist/compiled/react-dom) or
        // via a variable assignment like `n.version = "14.2.3"` near `__NEXT_DATA__`.
        static NEXT_INLINE_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?:exports|module\.exports)\.version\s*=\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if html.contains("__NEXT_DATA__") || html.contains("_next/static") || html.contains("/_next/") {
            if let Some(db_name) = self.find_tech_name("next.js") {
                if let Some(cap) = NEXT_DATA_RE.captures(html) {
                    Self::update_detection(detected, db_name, "html", "__NEXT_DATA__ version", 100, Some(cap[1].to_string()));
                } else if let Some(cap) = NEXT_INLINE_VER_RE.captures(html) {
                    Self::update_detection(detected, db_name, "html", "exports.version next.js", 100, Some(cap[1].to_string()));
                }
            }
        }

        // Nuxt.js: extract version from window.__NUXT__ when it's a readable (non-IIFE) object.
        //   window.__NUXT__={config:{...},version:"3.11.0",...}
        // Also handle the __NUXT_VERSION__ constant that Nuxt 3 injects:
        //   <script>window.__NUXT_VERSION__ = "3.11.0";</script>
        static NUXT_HTML_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)(?:window\.__NUXT_VERSION__\s*=\s*|__NUXT__\s*=\s*\{[^}]{0,500}?"version"\s*:\s*)["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        if html.contains("__NUXT__") || html.contains("__nuxt") || html.contains("data-n-head") {
            if let Some(db_name) = self.find_tech_name("nuxt.js") {
                if let Some(cap) = NUXT_HTML_VER_RE.captures(html) {
                    Self::update_detection(detected, db_name, "html", "__NUXT__ version", 100, Some(cap[1].to_string()));
                }
            }
        }

        // Font Awesome: infer major version from class-naming convention when the
        // DB pattern matches presence but the CDN/banner version is unavailable.
        //   v4.x → `class="fa fa-*"`          (two-class syntax, no variant prefix)
        //   v5.x → `class="fas fa-*"` etc.    (solid/regular/brands short prefix)
        //   v6.x → `class="fa-solid"`          (long-form prefix, CE naming)
        static FA_V6_CE_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"class=["'][^"']*\bfa-(?:solid|regular|brands|light|thin|duotone)\b"#).unwrap()
        });
        static FA_V5_V6_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"class=["'][^"']*\b(?:fas|far|fab|fal|fad)\b"#).unwrap()
        });
        static FA_V4_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"class=["'][^"']*\bfa\s+fa-"#).unwrap()
        });
        // FA_CDN_RE: matches Font Awesome CDN hostnames
        static FA_CDN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?:use|kit)\.fontawesome\.com|fontawesome\.com/|cdnjs\.cloudflare\.com/ajax/libs/font-awesome").unwrap()
        });
        if html.contains("fa-") {
            if let Some(db_name) = self.find_tech_name("font awesome") {
                let has_version = detected.get(db_name).and_then(|d| d.version.as_ref()).is_some();
                if !has_version {
                    let fa_count = html.match_indices("fa-").count();
                    let cdn_present = FA_CDN_RE.is_match(html);
                    // Require co-occurrence: at least 2 fa- usages OR a CDN URL
                    if fa_count >= 2 || cdn_present {
                        let inferred = if FA_V6_CE_RE.is_match(html) {
                            Some("6.x")
                        } else if FA_V5_V6_RE.is_match(html) {
                            Some("5.x")
                        } else if FA_V4_RE.is_match(html) {
                            Some("4.x")
                        } else {
                            None
                        };
                        if let Some(v) = inferred {
                            // CDN presence → higher confidence (85); class-only heuristic → 70
                            let conf = if cdn_present { 85u8 } else { 70u8 };
                            Self::update_detection(detected, db_name, "html", "fa-class-inference", conf, Some(v.to_string()));
                        }
                    }
                }
            }
        }
    }
}
