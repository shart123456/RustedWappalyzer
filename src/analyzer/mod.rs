//! `TechnologyAnalyzer` — the core pattern-matching engine.
//!
//! Compiles all Wappalyzer regex patterns at startup and exposes
//! the `analyze()` method for detecting technologies in HTTP responses.

use crate::types::*;
use crate::confidence::compute_noisy_or;
use crate::cache;

use std::collections::HashMap;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

pub(crate) mod layers;

pub struct TechnologyAnalyzer {
    pub database: WappalyzerDatabase,
    pub(crate) html_patterns: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) header_patterns: HashMap<String, HashMap<String, Vec<CompiledPattern>>>,
    pub(crate) url_patterns: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) script_patterns: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) inline_script_patterns: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) meta_patterns: HashMap<String, HashMap<String, Vec<CompiledPattern>>>,
    pub(crate) css_patterns: HashMap<String, Vec<CompiledPattern>>,
    pub(crate) cookie_patterns: HashMap<String, HashMap<String, Vec<CompiledPattern>>>,
    /// Lowercase tech name → canonical DB key, for O(1) lookups
    pub(crate) name_index: HashMap<String, String>,
    /// Category id → name, for O(1) lookups
    pub(crate) category_name_map: HashMap<u32, String>,
    /// MurmurHash3 favicon hash → canonical tech name
    pub(crate) favicon_hashes: HashMap<i32, String>,
    /// Pre-compiled DNS patterns: tech_name → record_type → [compiled regexes]
    pub(crate) dns_patterns: HashMap<String, HashMap<String, Vec<Regex>>>,
    /// JS object/property patterns: tech_name → [compiled JS patterns]
    pub(crate) js_patterns: HashMap<String, Vec<CompiledJsPattern>>,
    /// Supplemental CPE overrides: tech name → CPE string, from data/cpe_overrides.json.
    pub(crate) cpe_overrides: HashMap<String, String>,
    /// Version extraction patches: tech name → field name → pattern value.
    /// Added at compile time for Segment C technologies (CPE present, version pattern missing).
    pub(crate) version_patches: HashMap<String, HashMap<String, serde_json::Value>>,
}

impl TechnologyAnalyzer {
    /// Create a new analyzer with the latest Wappalyzer database
    pub async fn new() -> Result<Self, WappalyzerError> {
        let database = cache::load_or_fetch_database().await?;
        let name_index: HashMap<String, String> = database.technologies.keys()
            .map(|k| (k.to_lowercase(), k.clone()))
            .collect();
        let category_name_map: HashMap<u32, String> = database.categories.values()
            .map(|c| (c.id, c.name.clone()))
            .collect();
        let favicon_hashes = cache::load_favicon_hashes();
        let cpe_overrides = cache::load_cpe_overrides();
        let version_patches = cache::load_version_patches();
        let mut analyzer = Self {
            database,
            html_patterns: HashMap::new(),
            header_patterns: HashMap::new(),
            url_patterns: HashMap::new(),
            script_patterns: HashMap::new(),
            inline_script_patterns: HashMap::new(),
            meta_patterns: HashMap::new(),
            css_patterns: HashMap::new(),
            cookie_patterns: HashMap::new(),
            name_index,
            category_name_map,
            favicon_hashes,
            dns_patterns: HashMap::new(),
            js_patterns: HashMap::new(),
            cpe_overrides,
            version_patches,
        };

        analyzer.compile_patterns()?;
        analyzer.compile_version_patches()?;
        Ok(analyzer)
    }

    /// Look up canonical tech name by case-insensitive string
    pub fn find_tech_name(&self, name: &str) -> Option<&str> {
        self.name_index.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Force update the database — delegates to cache module.
    pub async fn update_database() -> Result<WappalyzerDatabase, WappalyzerError> {
        cache::update_database().await
    }

    /// Get database statistics
    pub fn get_stats(&self) -> (usize, usize) {
        (self.database.technologies.len(), self.database.categories.len())
    }

    /// Compile all regex patterns for efficient matching
    fn compile_patterns(&mut self) -> Result<(), WappalyzerError> {
        use std::io::IsTerminal;
        let is_interactive = std::io::stderr().is_terminal();
        let pb = if is_interactive {
            let p = ProgressBar::new(self.database.technologies.len() as u64);
            p.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                .unwrap());
            p.set_message("Compiling patterns");
            Some(p)
        } else {
            None
        };

        for (tech_name, tech_def) in &self.database.technologies {
            // Compile HTML patterns
            if let Some(html_patterns) = &tech_def.html {
                if let Ok(patterns) = Self::compile_pattern_value(html_patterns) {
                    if !patterns.is_empty() {
                        self.html_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile URL patterns
            if let Some(url_patterns) = &tech_def.url {
                if let Ok(patterns) = Self::compile_pattern_value(url_patterns) {
                    if !patterns.is_empty() {
                        self.url_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile script src patterns (both `script` and `scriptSrc` fields map here)
            if let Some(script_patterns) = &tech_def.script {
                if let Ok(patterns) = Self::compile_pattern_value(script_patterns) {
                    if !patterns.is_empty() {
                        self.script_patterns.entry(tech_name.clone()).or_default().extend(patterns);
                    }
                }
            }
            if let Some(script_src_patterns) = &tech_def.script_src {
                if let Ok(patterns) = Self::compile_pattern_value(script_src_patterns) {
                    if !patterns.is_empty() {
                        self.script_patterns.entry(tech_name.clone()).or_default().extend(patterns);
                    }
                }
            }

            // Compile inline script content patterns (`scripts` field)
            if let Some(inline_scripts) = &tech_def.scripts {
                if let Ok(patterns) = Self::compile_pattern_value(inline_scripts) {
                    if !patterns.is_empty() {
                        self.inline_script_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile header patterns
            if let Some(headers) = &tech_def.headers {
                let mut compiled_headers = HashMap::new();
                for (header_name, pattern_value) in headers {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value) {
                        if !patterns.is_empty() {
                            compiled_headers.insert(header_name.to_lowercase(), patterns);
                        }
                    }
                }
                if !compiled_headers.is_empty() {
                    self.header_patterns.insert(tech_name.clone(), compiled_headers);
                }
            }

            // Compile meta patterns
            if let Some(meta) = &tech_def.meta {
                let mut compiled_meta = HashMap::new();
                for (meta_name, pattern_value) in meta {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value) {
                        if !patterns.is_empty() {
                            compiled_meta.insert(meta_name.to_lowercase(), patterns);
                        }
                    }
                }
                if !compiled_meta.is_empty() {
                    self.meta_patterns.insert(tech_name.clone(), compiled_meta);
                }
            }

            // Compile CSS patterns
            if let Some(css_value) = &tech_def.css {
                if let Ok(patterns) = Self::compile_pattern_value(css_value) {
                    if !patterns.is_empty() {
                        self.css_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile cookie patterns
            if let Some(cookies) = &tech_def.cookies {
                let mut compiled_cookies = HashMap::new();
                for (cookie_name, pattern_value) in cookies {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value) {
                        if !patterns.is_empty() {
                            compiled_cookies.insert(cookie_name.to_lowercase(), patterns);
                        }
                    }
                }
                if !compiled_cookies.is_empty() {
                    self.cookie_patterns.insert(tech_name.clone(), compiled_cookies);
                }
            }

            // Compile JS object/property patterns
            if let Some(js_map) = &tech_def.js {
                let mut compiled_js: Vec<CompiledJsPattern> = Vec::new();
                for (path, pattern_value) in js_map {
                    let full_path = format!("window.{}", path);
                    match pattern_value {
                        Value::String(s) if s.is_empty() || s == ".*" => {
                            compiled_js.push(CompiledJsPattern { path: full_path, pattern: None });
                        }
                        Value::String(s) => {
                            if let Ok(Some(cp)) = Self::compile_single_pattern(s) {
                                compiled_js.push(CompiledJsPattern { path: full_path, pattern: Some(cp) });
                            }
                        }
                        _ => {}
                    }
                }
                if !compiled_js.is_empty() {
                    self.js_patterns.insert(tech_name.clone(), compiled_js);
                }
            }

            if let Some(ref p) = pb { p.inc(1); }
        }

        // Compile DNS patterns (pre-compiled regexes for domain-aware matching)
        for (tech_name, tech_def) in &self.database.technologies {
            if let Some(dns_map) = &tech_def.dns {
                let mut compiled = HashMap::new();
                for (record_type, patterns) in dns_map {
                    let pat_strings: Vec<String> = match patterns {
                        Value::String(s) => vec![s.to_lowercase()],
                        Value::Array(arr) => arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| s.to_lowercase())
                            .collect(),
                        _ => continue,
                    };
                    let compiled_regexes: Vec<Regex> = pat_strings.iter().filter_map(|pat_str| {
                        let pattern = if pat_str.contains('.') {
                            format!("(?i){}", regex::escape(pat_str))
                        } else {
                            format!("(?i)(?:^|\\.){}(?:\\.|$)", regex::escape(pat_str))
                        };
                        Regex::new(&pattern).ok()
                    }).collect();
                    if !compiled_regexes.is_empty() {
                        compiled.insert(record_type.to_uppercase(), compiled_regexes);
                    }
                }
                if !compiled.is_empty() {
                    self.dns_patterns.insert(tech_name.clone(), compiled);
                }
            }
        }

        if let Some(p) = pb { p.finish_with_message("Pattern compilation complete"); }
        Ok(())
    }

    /// Merge version extraction patches from `data/version_patches.json` into the compiled
    /// pattern maps. Called after `compile_patterns()` so DB patterns are not overwritten —
    /// patch patterns are appended/merged in alongside the existing ones.
    fn compile_version_patches(&mut self) -> Result<(), WappalyzerError> {
        let patches: Vec<(String, HashMap<String, serde_json::Value>)> = self.version_patches
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (tech_name, fields) in patches {
            for (field_name, value) in &fields {
                match field_name.as_str() {
                    "headers" => {
                        if let Some(obj) = value.as_object() {
                            let entry = self.header_patterns.entry(tech_name.clone()).or_default();
                            for (hname, hpat) in obj {
                                if let Ok(patterns) = Self::compile_pattern_value(hpat) {
                                    entry.insert(hname.to_lowercase(), patterns);
                                }
                            }
                        }
                    }
                    "meta" => {
                        if let Some(obj) = value.as_object() {
                            let entry = self.meta_patterns.entry(tech_name.clone()).or_default();
                            for (mname, mpat) in obj {
                                if let Ok(patterns) = Self::compile_pattern_value(mpat) {
                                    entry.insert(mname.to_lowercase(), patterns);
                                }
                            }
                        }
                    }
                    "html" => {
                        if let Ok(patterns) = Self::compile_pattern_value(value) {
                            self.html_patterns.entry(tech_name.clone()).or_default().extend(patterns);
                        }
                    }
                    "cookies" => {
                        if let Some(obj) = value.as_object() {
                            let entry = self.cookie_patterns.entry(tech_name.clone()).or_default();
                            for (cname, cpat) in obj {
                                if let Ok(patterns) = Self::compile_pattern_value(cpat) {
                                    entry.insert(cname.to_lowercase(), patterns);
                                }
                            }
                        }
                    }
                    "js" => {
                        if let Some(obj) = value.as_object() {
                            let entry = self.js_patterns.entry(tech_name.clone()).or_default();
                            for (path, pat_val) in obj {
                                let full_path = format!("window.{}", path);
                                match pat_val {
                                    serde_json::Value::String(s) if s.is_empty() || s == ".*" => {
                                        entry.push(CompiledJsPattern { path: full_path, pattern: None });
                                    }
                                    serde_json::Value::String(s) => {
                                        if let Ok(Some(cp)) = Self::compile_single_pattern(s) {
                                            entry.push(CompiledJsPattern { path: full_path, pattern: Some(cp) });
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Compile a pattern value (string or array) into CompiledPattern structs
    fn compile_pattern_value(value: &Value) -> Result<Vec<CompiledPattern>, WappalyzerError> {
        let mut patterns = Vec::new();

        match value {
            Value::String(pattern_str) => {
                if let Some(compiled) = Self::compile_single_pattern(pattern_str)? {
                    patterns.push(compiled);
                }
            }
            Value::Array(pattern_array) => {
                for pattern_val in pattern_array {
                    if let Value::String(pattern_str) = pattern_val {
                        if let Some(compiled) = Self::compile_single_pattern(pattern_str)? {
                            patterns.push(compiled);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(patterns)
    }

    /// Compile a single pattern string with confidence and version extraction
    pub fn compile_single_pattern(pattern: &str) -> Result<Option<CompiledPattern>, WappalyzerError> {
        if pattern.is_empty() {
            // Empty pattern = presence-only detection (header/cookie just needs to exist)
            return Ok(Some(CompiledPattern {
                regex: Regex::new(".*").unwrap(),
                confidence: 100,
                version: None,
            }));
        }

        // Parse Wappalyzer pattern format: "pattern\;confidence:100\;version:\1"
        let parts: Vec<&str> = pattern.split("\\;").collect();
        let regex_pattern = parts[0];

        let mut confidence = 100u8;
        let mut version: Option<String> = None;

        // Parse confidence and version from pattern
        for part in parts.iter().skip(1) {
            if let Some(conf_str) = part.strip_prefix("confidence:") {
                if let Ok(conf) = conf_str.parse::<u8>() {
                    confidence = conf;
                }
            } else if let Some(ver_str) = part.strip_prefix("version:") {
                version = Some(ver_str.to_string());
            }
        }

        // Compile regex with case-insensitive flag
        match Regex::new(&format!("(?i){}", regex_pattern)) {
            Ok(regex) => Ok(Some(CompiledPattern {
                regex,
                confidence,
                version,
            })),
            Err(e) => {
                tracing::warn!("Invalid regex pattern in Wappalyzer database (skipping): {}", e);
                Ok(None)
            }
        }
    }

    /// Analyze an HTTP response and detect technologies
    pub fn analyze(&self, response: &HttpResponse, min_confidence: u8) -> Vec<Technology> {
        let mut detected_technologies: HashMap<String, TechDetection> = HashMap::new();

        // Analyze URL
        self.analyze_url(&response.url, &mut detected_technologies);

        // Analyze headers
        self.analyze_headers(&response.headers, &mut detected_technologies);
        self.scan_headers_targeted(&response.headers, &mut detected_technologies);

        // Analyze HTML content
        self.analyze_html(&response.body, &mut detected_technologies);

        // Analyze script tags
        self.analyze_scripts(&response.body, &mut detected_technologies);

        // Analyze meta tags
        self.analyze_meta_tags(&response.body, &mut detected_technologies);

        // Analyze inline CSS
        self.analyze_css(&response.body, &mut detected_technologies);

        // Analyze cookies
        self.analyze_cookies(response, &mut detected_technologies);

        // Analyze inline script content
        self.analyze_inline_scripts(&response.body, &mut detected_technologies);

        // Analyze JS global/property patterns
        self.analyze_js_patterns(&response.body, &mut detected_technologies);

        // Generic fallback signals: hosting platforms, server versions, HTML heuristics
        self.scan_generic_signals(&response.headers, &mut detected_technologies);
        self.scan_html_generic(&response.body, &mut detected_technologies);

        // CSP header mining: detect third-party services from Content-Security-Policy
        self.scan_csp_header(&response.headers, &mut detected_technologies);

        // Generic cookie heuristics: framework/platform cookies not covered by DB
        self.scan_cookie_generic(response, &mut detected_technologies);

        // Apply "implies" logic using a workqueue (O(n) instead of O(n²))
        let mut queue: std::collections::VecDeque<String> =
            detected_technologies.keys().cloned().collect();
        while let Some(tech_name) = queue.pop_front() {
            if let Some(tech_def) = self.database.technologies.get(&tech_name) {
                if let Some(implies) = &tech_def.implies {
                    let implied_list: Vec<String> = match implies {
                        Value::String(s) => vec![s.clone()],
                        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
                        _ => Vec::new(),
                    };
                    for implied in implied_list {
                        let parts: Vec<&str> = implied.split("\\;").collect();
                        let implied_name = parts[0].trim().to_string();
                        let implied_version = parts.iter().skip(1)
                            .find(|p| p.starts_with("version:"))
                            .and_then(|p| p.strip_prefix("version:"))
                            .map(|v| v.to_string())
                            .filter(|v| !v.is_empty());
                        let implied_weight = parts.iter().skip(1)
                            .find(|p| p.starts_with("confidence:"))
                            .and_then(|p| p.strip_prefix("confidence:"))
                            .and_then(|v| v.parse::<u8>().ok())
                            .unwrap_or(100);
                        if !detected_technologies.contains_key(&implied_name) {
                            Self::update_detection(
                                &mut detected_technologies,
                                &implied_name,
                                "implied",
                                &tech_name,
                                implied_weight,
                                implied_version,
                            );
                            queue.push_back(implied_name);
                        }
                    }
                }
            }
        }

        // Apply exclusions and requirements post-processing
        Self::apply_exclusions_and_requirements(&mut detected_technologies, &self.database);

        // Convert to Technology structs — confidence via Noisy-OR, filter by min_confidence
        detected_technologies
            .into_iter()
            .filter_map(|(name, detection)| {
                let confidence = compute_noisy_or(&detection.signals);
                if confidence < min_confidence { return None; }
                let tech_def = self.database.technologies.get(&name);
                let categories = self.get_technology_categories(&name);
                let cpe = tech_def.and_then(|def| def.cpe.clone())
                    .or_else(|| self.cpe_overrides.get(&name).cloned());
                Some(Technology {
                    name,
                    confidence,
                    version: detection.version,
                    signals: detection.signals,
                    categories,
                    website: tech_def.and_then(|def| def.website.clone()),
                    description: tech_def.and_then(|def| def.description.clone()),
                    icon: tech_def.and_then(|def| def.icon.clone()),
                    cpe,
                    saas: tech_def.and_then(|def| def.saas),
                    pricing: tech_def.and_then(|def| def.pricing.clone()),
                })
            })
            .collect()
    }

    /// Extract version from regex captures using version pattern.
    ///
    /// Supports Wappalyzer's full version template syntax:
    /// - `\1`, `\2` … — capture group substitution
    /// - `\1?a:b`     — ternary: use `a` if group 1 matched non-empty, else `b`
    pub fn extract_version(version_pattern: &Option<String>, captures: &regex::Captures) -> Option<String> {
        let pattern = version_pattern.as_ref()?;
        let mut version = pattern.clone();

        // Resolve ternary expressions: \N?true_val:false_val
        // Must run before plain group substitution so \N in branches is replaced next.
        static TERNARY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\\(\d)\?([^:]*):([^\\]*)").unwrap()
        });
        let mut ternary_steps = 0u8;
        loop {
            if ternary_steps >= 10 { break; }
            ternary_steps += 1;
            let snapshot = version.clone();
            if let Some(cap) = TERNARY_RE.captures(&snapshot) {
                let group_num: usize = cap[1].parse().unwrap_or(0);
                let group_val = captures.get(group_num).map(|m| m.as_str()).unwrap_or("");
                let replacement = if !group_val.is_empty() { cap[2].to_string() } else { cap[3].to_string() };
                version = version.replacen(&cap[0], &replacement, 1);
            } else {
                break;
            }
        }

        // Replace capture group references \1 … \9
        for i in 1..captures.len() {
            let placeholder = format!("\\{}", i);
            let capture_val = captures.get(i).map(|m| m.as_str()).unwrap_or("");
            version = version.replace(&placeholder, capture_val);
        }

        // Remove any remaining unreplaced \N tokens (groups that didn't match)
        static LEFTOVER_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\\(\d)").unwrap());
        version = LEFTOVER_RE.replace_all(&version, "").to_string();

        version = version.trim().to_string();
        if version.is_empty() { None } else { Some(version) }
    }

    /// Extract a semver-like version value from `?ver=`, `?v=`, `?version=`, `?rev=`, or `?build=`
    /// query parameters in an asset URL.
    ///
    /// Returns `None` if no matching param is found or the value doesn't look like a version.
    fn extract_query_version(url: &str) -> Option<String> {
        let q_start = url.find('?')?;
        for param in url[q_start + 1..].split('&') {
            let mut kv = param.splitn(2, '=');
            let key = kv.next()?.to_lowercase();
            let val = kv.next().unwrap_or("");
            if matches!(key.as_str(), "ver" | "v" | "version" | "rev" | "build") {
                // Require at least "N.M" pattern and a reasonable length
                if val.len() >= 3
                    && val.len() <= 24
                    && val.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
                    && val.contains('.')
                {
                    return Some(val.to_string());
                }
            }
        }
        None
    }

    /// Record a detection signal and update the version if this is the first version seen.
    /// `value` is truncated to 100 characters to keep signal payloads compact.
    pub(crate) fn update_detection(
        detected: &mut HashMap<String, TechDetection>,
        tech_name: &str,
        signal_type: &str,
        value: &str,
        weight: u8,
        version: Option<String>,
    ) {
        let value_trunc = value.char_indices()
            .nth(100)
            .map(|(i, _)| &value[..i])
            .unwrap_or(value);
        let entry = detected.entry(tech_name.to_string()).or_insert(TechDetection {
            version: None,
            signals: Vec::new(),
        });
        entry.signals.push(Signal {
            signal_type: signal_type.to_string(),
            value: value_trunc.to_string(),
            weight,
        });
        if entry.version.is_none() && version.is_some() {
            entry.version = version;
        }
    }

    /// Get categories for a technology
    fn get_technology_categories(&self, tech_name: &str) -> Vec<String> {
        if let Some(tech_def) = self.database.technologies.get(tech_name) {
            tech_def.categories.iter()
                .filter_map(|cat_id| self.category_name_map.get(cat_id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Build a complete Technology struct from a detected name + confidence + version.
    pub fn build_technology(&self, name: &str, confidence: u8, version: Option<String>) -> Technology {
        let tech_def = self.database.technologies.get(name);
        Technology {
            name: name.to_string(),
            confidence,
            version,
            categories: self.get_technology_categories(name),
            website: tech_def.and_then(|d| d.website.clone()),
            description: tech_def.and_then(|d| d.description.clone()),
            icon: tech_def.and_then(|d| d.icon.clone()),
            cpe: tech_def.and_then(|d| d.cpe.clone())
                .or_else(|| self.cpe_overrides.get(name).cloned()),
            saas: tech_def.and_then(|d| d.saas),
            pricing: tech_def.and_then(|d| d.pricing.clone()),
            signals: Vec::new(),
        }
    }

    /// Post-process detected technologies to enforce `excludes`, `requires`, and
    /// `requires_category` constraints from the Wappalyzer database.
    fn apply_exclusions_and_requirements(
        detected: &mut HashMap<String, TechDetection>,
        database: &WappalyzerDatabase,
    ) {
        // Pass 1: excludes — collect all names that should be removed
        let mut to_remove: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (tech_name, _) in detected.iter() {
            if let Some(tech_def) = database.technologies.get(tech_name) {
                if let Some(excludes) = &tech_def.excludes {
                    let excluded_list: Vec<String> = match excludes {
                        Value::String(s) => vec![s.clone()],
                        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
                        _ => Vec::new(),
                    };
                    for exc in excluded_list {
                        let parts: Vec<&str> = exc.split("\\;").collect();
                        let excluded_name = parts[0].trim().to_string();
                        if detected.contains_key(&excluded_name) {
                            to_remove.insert(excluded_name);
                        }
                    }
                }
            }
        }
        for name in &to_remove {
            detected.remove(name);
        }

        // Pass 2: requires — tech needs another tech to be present
        let current_names: std::collections::HashSet<String> = detected.keys().cloned().collect();
        let mut requires_remove: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (tech_name, _) in detected.iter() {
            if let Some(tech_def) = database.technologies.get(tech_name) {
                if let Some(requires) = &tech_def.requires {
                    let req_list: Vec<String> = match requires {
                        Value::String(s) => vec![s.clone()],
                        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect(),
                        _ => Vec::new(),
                    };
                    for req in req_list {
                        let parts: Vec<&str> = req.split("\\;").collect();
                        let req_name = parts[0].trim().to_string();
                        if !req_name.is_empty() && !current_names.contains(&req_name) {
                            requires_remove.insert(tech_name.clone());
                            break;
                        }
                    }
                }
            }
        }
        for name in &requires_remove {
            detected.remove(name);
        }

        // Pass 3: requires_category — tech needs a tech in a given category
        // Collect all category IDs currently detected
        let mut detected_cat_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for tech_name in detected.keys() {
            if let Some(tech_def) = database.technologies.get(tech_name) {
                for cat_id in &tech_def.categories {
                    detected_cat_ids.insert(*cat_id);
                }
            }
        }
        let mut req_cat_remove: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (tech_name, _) in detected.iter() {
            if let Some(tech_def) = database.technologies.get(tech_name) {
                if let Some(req_cat) = &tech_def.requires_category {
                    let cat_list: Vec<u32> = match req_cat {
                        Value::Number(n) => n.as_u64().map(|v| vec![v as u32]).unwrap_or_default(),
                        Value::Array(arr) => arr.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect(),
                        _ => Vec::new(),
                    };
                    for cat_id in cat_list {
                        if !detected_cat_ids.contains(&cat_id) {
                            req_cat_remove.insert(tech_name.clone());
                            break;
                        }
                    }
                }
            }
        }
        for name in &req_cat_remove {
            detected.remove(name);
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_detection(signals: Vec<Signal>) -> TechDetection {
        TechDetection { version: None, signals }
    }

    fn make_signal(weight: u8) -> Signal {
        Signal { signal_type: "html".to_string(), value: "test".to_string(), weight }
    }

    #[test]
    fn test_excludes_removes_excluded_tech() {
        // Build a minimal in-memory database
        let mut technologies = HashMap::new();
        // "TechA" excludes "TechB"
        technologies.insert("TechA".to_string(), TechnologyDefinition {
            description: None, website: None, categories: vec![], icon: None, cpe: None,
            saas: None, pricing: None, url: None, html: None, css: None, script: None,
            script_src: None, scripts: None, meta: None, headers: None, cookies: None,
            dom: None, js: None, xhr: None, text: None, cert_issuer: None, robots: None,
            dns: None, implies: None,
            excludes: Some(Value::String("TechB".to_string())),
            requires: None, requires_category: None,
        });
        technologies.insert("TechB".to_string(), TechnologyDefinition {
            description: None, website: None, categories: vec![], icon: None, cpe: None,
            saas: None, pricing: None, url: None, html: None, css: None, script: None,
            script_src: None, scripts: None, meta: None, headers: None, cookies: None,
            dom: None, js: None, xhr: None, text: None, cert_issuer: None, robots: None,
            dns: None, implies: None, excludes: None, requires: None, requires_category: None,
        });
        let db = WappalyzerDatabase { technologies, categories: HashMap::new() };

        let mut detected = HashMap::new();
        detected.insert("TechA".to_string(), make_detection(vec![make_signal(100)]));
        detected.insert("TechB".to_string(), make_detection(vec![make_signal(100)]));

        TechnologyAnalyzer::apply_exclusions_and_requirements(&mut detected, &db);

        assert!(detected.contains_key("TechA"), "TechA should remain");
        assert!(!detected.contains_key("TechB"), "TechB should be excluded");
    }

    #[test]
    fn test_requires_removes_tech_without_dependency() {
        let mut technologies = HashMap::new();
        // "TechPlugin" requires "TechCore" to be present
        technologies.insert("TechPlugin".to_string(), TechnologyDefinition {
            description: None, website: None, categories: vec![], icon: None, cpe: None,
            saas: None, pricing: None, url: None, html: None, css: None, script: None,
            script_src: None, scripts: None, meta: None, headers: None, cookies: None,
            dom: None, js: None, xhr: None, text: None, cert_issuer: None, robots: None,
            dns: None, implies: None, excludes: None,
            requires: Some(Value::String("TechCore".to_string())),
            requires_category: None,
        });
        let db = WappalyzerDatabase { technologies, categories: HashMap::new() };

        let mut detected = HashMap::new();
        detected.insert("TechPlugin".to_string(), make_detection(vec![make_signal(100)]));
        // TechCore is NOT in detected

        TechnologyAnalyzer::apply_exclusions_and_requirements(&mut detected, &db);

        assert!(!detected.contains_key("TechPlugin"), "TechPlugin should be removed — TechCore not detected");
    }

    #[test]
    fn test_requires_category_removes_tech_without_category() {
        let mut technologies = HashMap::new();
        // "TechX" requires category 11 (Blog) to be present in detections
        technologies.insert("TechX".to_string(), TechnologyDefinition {
            description: None, website: None, categories: vec![], icon: None, cpe: None,
            saas: None, pricing: None, url: None, html: None, css: None, script: None,
            script_src: None, scripts: None, meta: None, headers: None, cookies: None,
            dom: None, js: None, xhr: None, text: None, cert_issuer: None, robots: None,
            dns: None, implies: None, excludes: None, requires: None,
            requires_category: Some(Value::Number(serde_json::Number::from(11u64))),
        });
        let db = WappalyzerDatabase { technologies, categories: HashMap::new() };

        let mut detected = HashMap::new();
        detected.insert("TechX".to_string(), make_detection(vec![make_signal(100)]));
        // No tech with category 11 detected

        TechnologyAnalyzer::apply_exclusions_and_requirements(&mut detected, &db);

        assert!(!detected.contains_key("TechX"), "TechX should be removed — required category not detected");
    }
}

/// Favicon fingerprinting — MurmurHash3 x86 32-bit, matches Wappalyzer's Python implementation.
mod favicon {
    /// MurmurHash3 x86 32-bit. Matches the output of `mmh3.hash(data, seed)` in Python.
    pub fn mmh3_x86_32(data: &[u8], seed: u32) -> i32 {
        let c1: u32 = 0xcc9e2d51;
        let c2: u32 = 0x1b873593;
        let mut h1 = seed;
        let nblocks = data.len() / 4;
        for i in 0..nblocks {
            let mut k1 = u32::from_le_bytes(data[i*4..i*4+4].try_into().expect("guaranteed 4-byte slice: i < nblocks = data.len()/4"));
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
            h1 = h1.rotate_left(13);
            h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
        }
        let tail = &data[nblocks*4..];
        let mut k1: u32 = 0;
        match tail.len() {
            3 => { k1 ^= (tail[2] as u32) << 16; k1 ^= (tail[1] as u32) << 8; k1 ^= tail[0] as u32; }
            2 => { k1 ^= (tail[1] as u32) << 8; k1 ^= tail[0] as u32; }
            1 => { k1 ^= tail[0] as u32; }
            _ => {}
        }
        if !tail.is_empty() {
            k1 = k1.wrapping_mul(c1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(c2);
            h1 ^= k1;
        }
        h1 ^= data.len() as u32;
        // fmix32
        h1 ^= h1 >> 16;
        h1 = h1.wrapping_mul(0x85ebca6b);
        h1 ^= h1 >> 13;
        h1 = h1.wrapping_mul(0xc2b2ae35);
        h1 ^= h1 >> 16;
        h1 as i32
    }

    /// Encode bytes as base64 with a newline every 76 characters (Python's encodebytes style).
    pub fn base64_encodebytes(data: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let b64 = STANDARD.encode(data);
        let mut out = String::with_capacity(b64.len() + b64.len() / 76 + 2);
        for chunk in b64.as_bytes().chunks(76) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out
    }

    /// Hash favicon bytes using the same algorithm as Wappalyzer's Python implementation.
    pub fn hash_favicon(bytes: &[u8]) -> i32 {
        let encoded = base64_encodebytes(bytes);
        mmh3_x86_32(encoded.as_bytes(), 0)
    }
}
