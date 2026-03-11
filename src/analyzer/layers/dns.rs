//! DNS lookup, source-map inspection, and favicon fingerprinting for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::analyzer::favicon;
use crate::confidence::compute_noisy_or;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Perform DNS lookups (CNAME, TXT, MX) and match against database `dns` patterns.
    pub async fn detect_from_dns(&self, url: &str, min_confidence: u8) -> Vec<Technology> {
        use hickory_resolver::AsyncResolver;
        use hickory_resolver::config::{ResolverConfig, ResolverOpts};
        use hickory_resolver::proto::rr::RecordType;
        use hickory_resolver::proto::rr::RData;

        let hostname = match url::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| h.to_string())) {
            Some(h) => h,
            None => return Vec::new(),
        };

        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;

        let resolver = AsyncResolver::tokio(ResolverConfig::default(), opts);
        let apex = format!("{}.", hostname.trim_end_matches('.'));

        // Apex A-record lookup: hickory returns the full CNAME chain + final A records.
        // This catches CNAMEs even for domains that don't have a direct CNAME record
        // queryable at root level (most CDN/hosting setups).
        //
        // We also try www.<host> because apex domains often have A records directly
        // while www points to a CNAME (e.g. www.example.com CNAME example.cdn77.org).
        let www = format!("www.{}.", hostname.trim_end_matches('.'));

        let (a_apex, a_www, txt_result, mx_result) = tokio::join!(
            resolver.lookup(apex.as_str(), RecordType::A),
            resolver.lookup(www.as_str(),  RecordType::A),
            resolver.lookup(apex.as_str(), RecordType::TXT),
            resolver.lookup(apex.as_str(), RecordType::MX),
        );

        // Collect CNAME targets from both apex and www A-record resolution chains
        let mut cnames: Vec<String> = Vec::new();
        for result in &[a_apex, a_www] {
            if let Ok(response) = result {
                for record in response.record_iter() {
                    if let Some(RData::CNAME(cname)) = record.data() {
                        let s = cname.to_string().to_lowercase();
                        let s = s.trim_end_matches('.').to_string();
                        if !cnames.contains(&s) {
                            cnames.push(s);
                        }
                    }
                }
            }
        }

        let mut txt_records: Vec<String> = Vec::new();
        match txt_result {
            Ok(response) => {
                for record in response.record_iter() {
                    if let Some(RData::TXT(txt)) = record.data() {
                        for bytes in txt.iter() {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                txt_records.push(s.to_lowercase());
                            }
                        }
                    }
                }
            }
            Err(e) => tracing::debug!("TXT lookup failed for {}: {}", hostname, e),
        }

        let mut mx_records: Vec<String> = Vec::new();
        match mx_result {
            Ok(response) => {
                for record in response.record_iter() {
                    if let Some(RData::MX(mx)) = record.data() {
                        let s = mx.exchange().to_string().to_lowercase();
                        mx_records.push(s.trim_end_matches('.').to_string());
                    }
                }
            }
            Err(e) => tracing::debug!("MX lookup failed for {}: {}", hostname, e),
        }

        if cnames.is_empty() && txt_records.is_empty() && mx_records.is_empty() {
            return Vec::new();
        }

        // Helper: check if any value in `haystack` matches any compiled regex in `pats`
        let matches_any = |haystack: &[String], pats: &[Regex]| -> bool {
            haystack.iter().any(|val| pats.iter().any(|pat| pat.is_match(val)))
        };

        let mut results = Vec::new();
        for (tech_name, dns_map) in &self.dns_patterns {
            let mut matched = false;
            let mut match_signal = String::new();

            // Match each DNS record type.
            // BUG WAS: `if matched || haystack.is_empty() { break; }`
            // `break` on empty CNAME haystack (most apex domains) skipped TXT and MX entirely.
            // Fix: `continue` past empty haystacks, only `break` when already matched.
            for (record_type, haystack) in &[
                ("CNAME", &cnames),
                ("TXT",   &txt_records),
                ("MX",    &mx_records),
            ] {
                if matched { break; }
                if haystack.is_empty() { continue; }
                if let Some(pats) = dns_map.get(&record_type.to_uppercase()) {
                    let pats: &Vec<Regex> = pats;
                    if matches_any(haystack, pats) {
                        matched = true;
                        // Record which DNS value triggered the match for the signal
                        let matched_val = haystack.iter()
                            .find(|v| pats.iter().any(|p| p.is_match(v)))
                            .cloned()
                            .unwrap_or_default();
                        match_signal = format!("{}:{}", record_type.to_lowercase(), matched_val);
                    }
                }
            }

            if matched && 100 >= min_confidence {
                let tech_def = self.database.technologies.get(tech_name);
                results.push(Technology {
                    name: tech_name.clone(),
                    confidence: 100,
                    version: None,
                    categories: self.get_technology_categories(tech_name),
                    website: tech_def.and_then(|d| d.website.clone()),
                    description: tech_def.and_then(|d| d.description.clone()),
                    icon: tech_def.and_then(|d| d.icon.clone()),
                    cpe: tech_def.and_then(|d| d.cpe.clone()),
                    saas: tech_def.and_then(|d| d.saas),
                    pricing: tech_def.and_then(|d| d.pricing.clone()),
                    signals: vec![Signal {
                        signal_type: "dns".to_string(),
                        value: match_signal,
                        weight: 100,
                    }],
                });
            }
        }

        // ── Supplemental CNAME-based detection ──────────────────────────────
        // The Wappalyzer DB `dns` entries are sparse. Many CDNs and platforms
        // are detectable only from CNAME targets, which aren't in the DB.
        // Map CNAME fragment → (tech_name, confidence).
        static CNAME_MAP: &[(&str, &str, u8)] = &[
            // Cloudflare
            ("cdn.cloudflare.net",      "cloudflare",           95),
            ("cloudflare.net",          "cloudflare",           90),
            // AWS CloudFront
            ("cloudfront.net",          "amazon cloudfront",    95),
            // AWS ELB
            ("elb.amazonaws.com",       "amazon web services",  90),
            ("elasticloadbalancing",    "amazon web services",  90),
            // Fastly
            ("fastly.net",              "fastly",               95),
            ("global.ssl.fastly.net",   "fastly",               95),
            // Akamai
            ("akamai.net",              "akamai",               95),
            ("akamaiedge.net",          "akamai",               95),
            ("akamaitechnologies.com",  "akamai",               95),
            ("edgesuite.net",           "akamai",               90),
            ("edgekey.net",             "akamai",               90),
            // Vercel
            ("vercel.app",              "vercel",               95),
            ("vercel-dns.com",          "vercel",               95),
            ("cname.vercel-dns.com",    "vercel",               95),
            // Netlify
            ("netlify.com",             "netlify",              95),
            ("netlify.app",             "netlify",              95),
            // Render
            ("onrender.com",            "render",               95),
            // Fly.io
            ("fly.dev",                 "fly.io",               90),
            // GitHub Pages
            ("github.io",               "github pages",         95),
            // Heroku
            ("herokudns.com",           "heroku",               95),
            ("herokuapp.com",           "heroku",               95),
            // Shopify
            ("myshopify.com",           "shopify",              95),
            ("shopify.com",             "shopify",              90),
            // Squarespace
            ("squarespace.com",         "squarespace",          90),
            // Wix
            ("wix.com",                 "wix",                  90),
            ("parastorage.com",         "wix",                  85),
            // Webflow
            ("proxy.webflow.com",       "webflow",              95),
            ("webflow.io",              "webflow",              95),
            // HubSpot
            ("hubspot.com",             "hubspot",              90),
            ("hs-sites.com",            "hubspot",              90),
            // Ghost
            ("ghost.io",                "ghost",                95),
            // Pantheon
            ("pantheon.io",             "pantheon",             90),
            ("pantheonsite.io",         "pantheon",             90),
            // WP Engine
            ("wpengine.com",            "wp engine",            95),
            // Kinsta
            ("kinsta.cloud",            "kinsta",               95),
            // Cloudways
            ("cloudwaysapps.com",       "cloudways",            90),
            // Azure
            ("azurewebsites.net",       "microsoft azure",      95),
            ("trafficmanager.net",      "microsoft azure",      85),
            ("azureedge.net",           "microsoft azure",      90),
            // Google Cloud
            ("appspot.com",             "google cloud",         90),
            ("run.app",                 "google cloud",         90),
            // Firebase Hosting
            ("web.app",                 "firebase",             85),
            ("firebaseapp.com",         "firebase",             85),
            // Zendesk
            ("zendesk.com",             "zendesk",              85),
            ("zendeskgarden.com",       "zendesk",              85),
            // Intercom
            ("intercom.io",             "intercom",             90),
        ];

        let already_found: std::collections::HashSet<String> = results.iter().map(|t| t.name.to_lowercase()).collect();
        for &(fragment, tech_name, confidence) in CNAME_MAP {
            if already_found.iter().any(|n| n.contains(&tech_name.to_lowercase())) {
                continue; // already detected from DB patterns
            }
            let matched_cname = cnames.iter().find(|c| c.contains(fragment));
            if let Some(cname_val) = matched_cname {
                if confidence >= min_confidence {
                    if let Some(db_name) = self.find_tech_name(tech_name) {
                        let tech_def = self.database.technologies.get(db_name);
                        results.push(Technology {
                            name: db_name.to_string(),
                            confidence,
                            version: None,
                            categories: self.get_technology_categories(db_name),
                            website: tech_def.and_then(|d| d.website.clone()),
                            description: tech_def.and_then(|d| d.description.clone()),
                            icon: tech_def.and_then(|d| d.icon.clone()),
                            cpe: tech_def.and_then(|d| d.cpe.clone()),
                            saas: tech_def.and_then(|d| d.saas),
                            pricing: tech_def.and_then(|d| d.pricing.clone()),
                            signals: vec![Signal {
                                signal_type: "dns".to_string(),
                                value: format!("cname:{}", cname_val),
                                weight: confidence,
                            }],
                        });
                    }
                }
            }
        }

        // ── MX-based email provider detection ────────────────────────────────
        static MX_MAP: &[(&str, &str, u8)] = &[
            ("google.com",              "google workspace",     90),
            ("googlemail.com",          "google workspace",     90),
            ("aspmx.l.google",          "google workspace",     95),
            ("outlook.com",             "microsoft 365",        90),
            ("protection.outlook.com",  "microsoft 365",        90),
            ("mail.protection.outlook", "microsoft 365",        95),
            ("pphosted.com",            "proofpoint",           90),
            ("mimecast.com",            "mimecast",             90),
            ("messagelabs.com",         "symantec email",       90),
            ("mailgun.org",             "mailgun",              90),
            ("sendgrid.net",            "sendgrid",             90),
            ("amazonses.com",           "amazon ses",           90),
        ];

        for &(fragment, tech_name, confidence) in MX_MAP {
            let matched_mx = mx_records.iter().find(|m| m.contains(fragment));
            if let Some(mx_val) = matched_mx {
                if confidence >= min_confidence {
                    if let Some(db_name) = self.find_tech_name(tech_name) {
                        if !results.iter().any(|t| t.name == db_name) {
                            let tech_def = self.database.technologies.get(db_name);
                            results.push(Technology {
                                name: db_name.to_string(),
                                confidence,
                                version: None,
                                categories: self.get_technology_categories(db_name),
                                website: tech_def.and_then(|d| d.website.clone()),
                                description: tech_def.and_then(|d| d.description.clone()),
                                icon: tech_def.and_then(|d| d.icon.clone()),
                                cpe: tech_def.and_then(|d| d.cpe.clone()),
                                saas: tech_def.and_then(|d| d.saas),
                                pricing: tech_def.and_then(|d| d.pricing.clone()),
                                signals: vec![Signal {
                                    signal_type: "dns".to_string(),
                                    value: format!("mx:{}", mx_val),
                                    weight: confidence,
                                }],
                            });
                        }
                    }
                }
            }
        }

        results
    }

    /// Fetch a JS source map file referenced by `//# sourceMappingURL=` and extract
    /// npm package names (and versions when available) from the `sources` array.
    pub(crate) async fn try_source_map(
        &self,
        client: &reqwest::Client,
        js_url: &str,
        js_body: &str,
        detected: &mut HashMap<String, TechDetection>,
        source_map_timeout_secs: u64,
    ) {
        static SOURCE_MAP_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"//# sourceMappingURL=(\S+)").unwrap()
        });
        static NPM_VERSIONED_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"node_modules/(@?[^/]+(?:/[^/]+)?)/(\d+\.\d+\.\d+[^/]*)").unwrap()
        });
        static NPM_UNVERSIONED_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"node_modules/(@?[^/]+(?:/[^/]+)?)").unwrap()
        });

        // 1. Find sourceMappingURL comment
        let map_path = match SOURCE_MAP_RE.captures(js_body).and_then(|c| c.get(1)) {
            Some(m) => m.as_str().to_string(),
            None => return,
        };

        // Skip data: URIs
        if map_path.starts_with("data:") { return; }

        // 2. Resolve URL
        let map_url = if map_path.starts_with("http://") || map_path.starts_with("https://") {
            map_path.clone()
        } else if let Ok(base) = url::Url::parse(js_url) {
            match base.join(&map_path) {
                Ok(u) => u.to_string(),
                Err(_) => return,
            }
        } else {
            return;
        };

        // 3. Fetch .map file (ignore errors)
        let map_body = match client
            .get(&map_url)
            .timeout(std::time::Duration::from_secs(source_map_timeout_secs))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r.text().await {
                Ok(t) => t,
                Err(_) => return,
            },
            _ => return,
        };

        // 4. Parse JSON and extract "sources" array
        let sources: Vec<String> = match serde_json::from_str::<serde_json::Value>(&map_body) {
            Ok(v) => v.get("sources")
                .and_then(|s| s.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default(),
            Err(_) => return,
        };

        // 5. For each source, try versioned then unversioned npm package name
        for source in &sources {
            if let Some(cap) = NPM_VERSIONED_RE.captures(source) {
                let pkg = cap[1].to_lowercase();
                let ver = cap[2].to_string();
                // short name (strip @scope/)
                let short = pkg.split('/').last().unwrap_or(&pkg).to_string();
                if let Some(tech) = self.find_tech_name(&short).or_else(|| self.find_tech_name(&pkg)) {
                    Self::update_detection(detected, tech, "source_map", &source[..source.len().min(100)], 80, Some(ver));
                }
            } else if let Some(cap) = NPM_UNVERSIONED_RE.captures(source) {
                let pkg = cap[1].to_lowercase();
                let short = pkg.split('/').last().unwrap_or(&pkg).to_string();
                if let Some(tech) = self.find_tech_name(&short).or_else(|| self.find_tech_name(&pkg)) {
                    Self::update_detection(detected, tech, "source_map", &source[..source.len().min(100)], 80, None);
                }
            }
        }
    }

    /// Fetch the site's favicon, compute its MurmurHash3 fingerprint, and look it up
    /// in the known-hash database. Adds a "favicon" signal to `technologies` if matched.
    pub(crate) async fn detect_favicon(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        html: &str,
        technologies: &mut Vec<Technology>,
        favicon_timeout_secs: u64,
    ) {
        if self.favicon_hashes.is_empty() { return; }

        // 1. Find favicon URL from HTML <link rel="icon"> / <link rel="shortcut icon">
        static FAVICON_LINK_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<link[^>]+rel=["'][^"']*(?:shortcut\s+)?icon[^"']*["'][^>]+href=["']([^"']+)["']|<link[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*(?:shortcut\s+)?icon"#).unwrap()
        });

        let favicon_path = if let Some(cap) = FAVICON_LINK_RE.captures(html) {
            cap.get(1).or_else(|| cap.get(2))
                .map(|m| m.as_str().to_string())
        } else {
            None
        };

        // 2. Resolve or fallback to /favicon.ico
        let favicon_url = if let Some(path) = favicon_path {
            if path.starts_with("data:") { return; } // skip inline data URIs
            if path.starts_with("http://") || path.starts_with("https://") {
                path
            } else if let Ok(base) = url::Url::parse(base_url) {
                match base.join(&path) {
                    Ok(u) => u.to_string(),
                    Err(_) => return,
                }
            } else {
                return;
            }
        } else {
            // Fallback: /favicon.ico at the origin
            match url::Url::parse(base_url).ok().and_then(|u| {
                let origin = format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""));
                Some(format!("{}/favicon.ico", origin))
            }) {
                Some(u) => u,
                None => return,
            }
        };

        // 3. Fetch favicon bytes
        let bytes = match client
            .get(&favicon_url)
            .timeout(std::time::Duration::from_secs(favicon_timeout_secs))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) => b,
                Err(_) => return,
            },
            _ => return,
        };

        if bytes.is_empty() { return; }

        // 4. Compute hash
        let hash = favicon::hash_favicon(&bytes);

        // 5. Look up in database
        if let Some(tech_name) = self.favicon_hashes.get(&hash) {
            let db_name = self.find_tech_name(tech_name)
                .map(|s| s.to_string())
                .unwrap_or_else(|| tech_name.clone());

            let hash_str = hash.to_string();
            if let Some(t) = technologies.iter_mut().find(|t| t.name == db_name) {
                t.signals.push(Signal {
                    signal_type: "favicon".to_string(),
                    value: hash_str,
                    weight: 100,
                });
                // Re-compute confidence
                t.confidence = compute_noisy_or(&t.signals);
            } else {
                let mut tech = self.build_technology(&db_name, 100, None);
                tech.signals.push(Signal {
                    signal_type: "favicon".to_string(),
                    value: hash_str,
                    weight: 100,
                });
                tech.confidence = 100;
                technologies.push(tech);
            }
        }
    }
}
