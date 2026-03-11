//! HTTP header and URL analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Analyze URL patterns
    pub(crate) fn analyze_url(&self, url: &str, detected: &mut HashMap<String, TechDetection>) {
        for (tech_name, patterns) in &self.url_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(url) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name, "url", url, pattern.confidence, version);
                }
            }
        }
    }


    /// Targeted header version extraction for technologies whose Wappalyzer DB patterns
    /// either lack version capture groups or have no entry at all.
    pub(crate) fn scan_headers_targeted(&self, headers: &HashMap<String, String>, detected: &mut HashMap<String, TechDetection>) {
        let mut insert = |tech: &str, header: &str, version: Option<String>| {
            if let Some(db_name) = self.find_tech_name(tech) {
                Self::update_detection(detected, db_name, "header", header, 100, version);
            }
        };

        // Envoy: DB pattern is `^envoy$` — captures presence only.
        // Real-world header: "Server: envoy/1.28.0" or "Server: envoy/1.30.1-dev"
        static ENVOY_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)^envoy/(\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?)").unwrap()
        });
        if let Some(server) = headers.get("server") {
            if let Some(cap) = ENVOY_VER_RE.captures(server) {
                insert("envoy", "server", Some(cap[1].to_string()));
            }
        }

        // Varnish: DB pattern covers `Via: varnish (Varnish/7.x)` but many CDNs emit
        // just `Via: 1.1 varnish` with no version. Extract version when present.
        static VARNISH_VIA_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)varnish(?:/| \(Varnish/)?(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if let Some(via) = headers.get("via") {
            if via.to_lowercase().contains("varnish") {
                if let Some(cap) = VARNISH_VIA_RE.captures(via) {
                    insert("varnish", "via", Some(cap[1].to_string()));
                }
                // Presence without version already handled by DB pattern; no else needed.
            }
        }
        // Also check X-Varnish-* headers for version hints (some deployments add these)
        static VARNISH_HDR_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if let Some(xvv) = headers.get("x-varnish-version") {
            if let Some(cap) = VARNISH_HDR_VER_RE.captures(xvv) {
                insert("varnish", "x-varnish-version", Some(cap[1].to_string()));
            }
        }

        // Tengine: Alibaba's Nginx fork. DB pattern is presence-only "Tengine".
        // Real header: "Server: Tengine/2.3.3"
        static TENGINE_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)Tengine/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if let Some(server) = headers.get("server") {
            if let Some(cap) = TENGINE_VER_RE.captures(server) {
                insert("tengine", "server", Some(cap[1].to_string()));
            }
        }

        // Node.js: no DB entry. Some apps expose:
        //   "X-Powered-By: Node.js"          — presence only
        //   "X-Powered-By: Node/v20.11.0"    — with version
        static NODEJS_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)node(?:\.js)?(?:/v?(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        if let Some(xpb) = headers.get("x-powered-by") {
            if let Some(cap) = NODEJS_VER_RE.captures(xpb) {
                insert("node.js", "x-powered-by", cap.get(1).map(|m| m.as_str().to_string()));
            }
        }

        // Express: some deployments expose version in the X-Powered-By header.
        //   "X-Powered-By: Express"          — presence only (version = None)
        //   "X-Powered-By: Express/4.18.2"   — with version
        static EXPRESS_HDR_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)express/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        if let Some(xpb) = headers.get("x-powered-by") {
            if xpb.to_lowercase().contains("express") {
                let version = EXPRESS_HDR_RE.captures(xpb)
                    .map(|cap| cap[1].to_string());
                insert("express", "x-powered-by", version);
            }
        }

        // Zipkin: some Zipkin-instrumented apps or the Zipkin query service expose a
        // custom version header. The Wappalyzer DB only detects presence via `x-b3-sampled`.
        //   "x-zipkin-version: 2.24.3"   (Zipkin query service)
        //   "zipkin-query: 2.24.3"        (older Zipkin deployments)
        static ZIPKIN_HDR_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        for hdr in &["x-zipkin-version", "zipkin-query"] {
            if let Some(val) = headers.get(*hdr) {
                if let Some(cap) = ZIPKIN_HDR_VER_RE.captures(val) {
                    insert("zipkin", hdr, Some(cap[1].to_string()));
                    break;
                }
            }
        }

        // X-Generator: Gatsby, Hugo, Hexo, Jekyll, Nuxt, etc.
        if let Some(xgen) = headers.get("x-generator") {
            let xgen_lower = xgen.to_lowercase();
            static XGEN_VER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap());
            let ver = XGEN_VER_RE.captures(xgen).map(|c| c[1].to_string());
            for candidate in &["gatsby", "hugo", "hexo", "jekyll", "nuxt.js", "next.js", "gridsome", "eleventy"] {
                if xgen_lower.contains(candidate) {
                    insert(candidate, "x-generator", ver.clone());
                    break;
                }
            }
        }

        // X-Runtime: Ruby on Rails emits response time as a float (e.g. "0.234567")
        if let Some(xrt) = headers.get("x-runtime") {
            static XRUNTIME_FLOAT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\d+\.\d+$").unwrap());
            if XRUNTIME_FLOAT_RE.is_match(xrt.trim()) {
                insert("ruby on rails", "x-runtime", None);
            }
        }

        // X-AspNet-Version: explicit .NET version string
        if let Some(xav) = headers.get("x-aspnet-version") {
            static XAV_VER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap());
            if let Some(cap) = XAV_VER_RE.captures(xav) {
                insert("asp.net", "x-aspnet-version", Some(cap[1].to_string()));
            }
        }

        // X-Powered-By: Next.js (with optional version)
        static XPB_NEXTJS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)next(?:\.js)?(?:/(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        if let Some(xpb) = headers.get("x-powered-by") {
            if xpb.to_lowercase().contains("next") {
                let ver = XPB_NEXTJS_RE.captures(xpb).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("next.js", "x-powered-by", ver);
            }
        }

        // X-NextJS-* headers → Next.js
        if headers.keys().any(|k| k.starts_with("x-nextjs-") || k.starts_with("x-next-")) {
            insert("next.js", "x-nextjs-cache", None);
        }

        // X-Nuxt-* headers → Nuxt.js
        if headers.keys().any(|k| k.starts_with("x-nuxt-")) {
            insert("nuxt.js", "x-nuxt-rendered", None);
        }

        // X-Drupal-Cache or X-Drupal-Dynamic-Cache → Drupal
        if headers.contains_key("x-drupal-cache") || headers.contains_key("x-drupal-dynamic-cache") {
            insert("drupal", "x-drupal-cache", None);
        }

        // X-Content-Encoded-By: Joomla
        if let Some(xceb) = headers.get("x-content-encoded-by") {
            if xceb.to_lowercase().contains("joomla") {
                static JOOMLA_VER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(\d+\.\d+(?:\.\d+)?)").unwrap());
                let ver = JOOMLA_VER_RE.captures(xceb).map(|c| c[1].to_string());
                insert("joomla", "x-content-encoded-by", ver);
            }
        }

        // X-Wix-Request-Id → Wix
        if headers.contains_key("x-wix-request-id") {
            insert("wix", "x-wix-request-id", None);
        }

        // X-Shopify-* → Shopify
        if headers.contains_key("x-shopify-stage") || headers.contains_key("x-shopid") || headers.contains_key("x-shopify-request-id") {
            insert("shopify", "x-shopify-stage", None);
        }

        // X-Ghost-Cache-Status → Ghost
        if headers.contains_key("x-ghost-cache-status") || headers.contains_key("x-cache-invalidated") {
            insert("ghost", "x-ghost-cache-status", None);
        }
    }


    /// Generic header-based detection for hosting platforms and servers not reliably
    /// covered by the Wappalyzer DB patterns. Called unconditionally from `analyze()`.
    pub(crate) fn scan_generic_signals(&self, headers: &HashMap<String, String>, detected: &mut HashMap<String, TechDetection>) {
        let mut insert = |tech: &str, header: &str, version: Option<String>| {
            if let Some(db_name) = self.find_tech_name(tech) {
                Self::update_detection(detected, db_name, "header", header, 90, version);
            }
        };

        // ── Hosting / serverless platforms ──────────────────────────────────
        if headers.contains_key("x-vercel-id") || headers.contains_key("x-vercel-cache") {
            insert("vercel", "x-vercel-id", None);
        }
        if headers.contains_key("x-nf-request-id") || headers.get("server").map(|s| s.to_lowercase().contains("netlify")).unwrap_or(false) {
            insert("netlify", "x-nf-request-id", None);
        }
        if headers.contains_key("x-github-request-id") {
            insert("github pages", "x-github-request-id", None);
        }
        if headers.contains_key("fly-request-id") {
            insert("fly.io", "fly-request-id", None);
        }
        if headers.contains_key("x-render-origin-server") {
            insert("render", "x-render-origin-server", None);
        }
        if headers.contains_key("x-railway-request-id") {
            insert("railway", "x-railway-request-id", None);
        }
        // Heroku: its router proxy sets a distinctive Via header value
        if let Some(via) = headers.get("via") {
            if via.to_lowercase().contains("vegur") {
                insert("heroku", "via", None);
            }
        }
        // Fastly CDN
        if headers.contains_key("fastly-io-info") || headers.contains_key("x-fastly-request-id") {
            insert("fastly", "fastly-io-info", None);
        }
        // AWS CloudFront
        if headers.contains_key("x-amz-cf-id") {
            insert("amazon cloudfront", "x-amz-cf-id", None);
        }

        // ── Web server version extraction ────────────────────────────────────
        // These supplement or improve on the Wappalyzer DB entries that often
        // detect presence but do not capture the version from the Server header.
        static SRV_NGINX_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)^nginx/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static SRV_APACHE_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)Apache/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static SRV_IIS_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)Microsoft-IIS/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static SRV_CADDY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)^[Cc]addy(?:/(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        static SRV_GUNICORN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)gunicorn(?:/(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        static SRV_LIGHTTPD_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)lighttpd/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static SRV_LITESPEED_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)LiteSpeed(?:/(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        static SRV_OPENRESTY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)openresty/(\d+\.\d+(?:\.\d+)?\.\d+)").unwrap()
        });
        static SRV_UVICORN_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)uvicorn(?:/(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        static SRV_COWBOY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)^cowboy$").unwrap()
        });
        static SRV_KESTREL_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)^[Kk]estrel$").unwrap()
        });

        if let Some(server) = headers.get("server") {
            if let Some(cap) = SRV_NGINX_RE.captures(server) {
                insert("nginx", "server", Some(cap[1].to_string()));
            }
            if let Some(cap) = SRV_APACHE_RE.captures(server) {
                insert("apache http server", "server", Some(cap[1].to_string()));
            }
            if let Some(cap) = SRV_IIS_RE.captures(server) {
                insert("internet information services", "server", Some(cap[1].to_string()));
            }
            if SRV_CADDY_RE.is_match(server) {
                let ver = SRV_CADDY_RE.captures(server).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("caddy", "server", ver);
            }
            if SRV_GUNICORN_RE.is_match(server) {
                let ver = SRV_GUNICORN_RE.captures(server).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("gunicorn", "server", ver);
            }
            if let Some(cap) = SRV_LIGHTTPD_RE.captures(server) {
                insert("lighttpd", "server", Some(cap[1].to_string()));
            }
            if SRV_LITESPEED_RE.is_match(server) {
                let ver = SRV_LITESPEED_RE.captures(server).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("litespeed", "server", ver);
            }
            if let Some(cap) = SRV_OPENRESTY_RE.captures(server) {
                insert("openresty", "server", Some(cap[1].to_string()));
            }
            if SRV_UVICORN_RE.is_match(server) {
                let ver = SRV_UVICORN_RE.captures(server).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("uvicorn", "server", ver);
            }
            if SRV_COWBOY_RE.is_match(server) {
                insert("cowboy", "server", None);
            }
            if SRV_KESTREL_RE.is_match(server) {
                insert("kestrel", "server", None);
            }
        }

        // ── X-Powered-By version extraction ──────────────────────────────────
        static XPB_PHP_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)^PHP/(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static XPB_ASPNET_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)ASP\.NET").unwrap()
        });
        static XPB_ASPNET_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)ASP\.NET\s+MVC\s+(\d+\.\d+(?:\.\d+)?)").unwrap()
        });
        static XPB_SERVLET_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)Servlet(?:/(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });
        static XPB_PASSENGER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?i)Phusion\s+Passenger(?:\s+(\d+\.\d+(?:\.\d+)?))?").unwrap()
        });

        if let Some(xpb) = headers.get("x-powered-by") {
            if let Some(cap) = XPB_PHP_RE.captures(xpb) {
                insert("php", "x-powered-by", Some(cap[1].to_string()));
            }
            if XPB_ASPNET_RE.is_match(xpb) {
                let ver = XPB_ASPNET_VER_RE.captures(xpb).map(|c| c[1].to_string());
                insert("asp.net", "x-powered-by", ver);
            }
            if XPB_SERVLET_RE.is_match(xpb) {
                let ver = XPB_SERVLET_RE.captures(xpb).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("java servlets", "x-powered-by", ver);
            }
            if XPB_PASSENGER_RE.is_match(xpb) {
                let ver = XPB_PASSENGER_RE.captures(xpb).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
                insert("phusion passenger", "x-powered-by", ver);
            }
        }
    }

    /// Analyze HTTP headers
    pub(crate) fn analyze_headers(&self, headers: &HashMap<String, String>, detected: &mut HashMap<String, TechDetection>) {
        for (tech_name, header_patterns) in &self.header_patterns {
            for (header_name, patterns) in header_patterns {
                if let Some(header_value) = headers.get(header_name) {
                    for pattern in patterns {
                        if let Some(captures) = pattern.regex.captures(header_value) {
                            let version = Self::extract_version(&pattern.version, &captures);
                            Self::update_detection(detected, tech_name, "header", header_name, pattern.confidence, version);
                        }
                    }
                }
            }
        }
    }

}
