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

/// Patterns from the Wappalyzer database that the `regex` crate cannot compile,
/// recorded once each so startup does not emit the same warning repeatedly.
///
/// The dominant cause is look-around (`(?!`, `(?=`, `(?<`), which `regex` does not
/// support by design. Each analyzer instance recompiles the whole database, so an
/// unconditional `warn!` per failure produced the same handful of messages many
/// times over and buried the rest of the startup log.
static SKIPPED_PATTERNS: Lazy<std::sync::Mutex<HashMap<String, u32>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

/// Record one pattern that failed to compile. Returns `true` if this is the first
/// time this pattern has been seen (i.e. the caller should log it).
fn record_skipped_pattern(pattern: &str) -> bool {
    let mut guard = match SKIPPED_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let counter = guard.entry(pattern.to_string()).or_insert(0);
    *counter += 1;
    *counter == 1
}

/// Returns `(unique_patterns, total_occurrences)` for patterns skipped so far.
pub fn skipped_pattern_stats() -> (usize, u32) {
    let guard = match SKIPPED_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    (guard.len(), guard.values().sum())
}

/// The distinct patterns skipped so far, sorted for stable output.
pub fn skipped_patterns() -> Vec<String> {
    let guard = match SKIPPED_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut v: Vec<String> = guard.keys().cloned().collect();
    v.sort();
    v
}

/// Emit a single summary of database patterns that could not be compiled.
///
/// Called once after the database is loaded. Without this the gap is invisible:
/// the per-pattern messages were the only signal, and they were both repetitive
/// and easy to scroll past.
pub fn log_skipped_pattern_summary() {
    let (unique, total) = skipped_pattern_stats();
    if unique == 0 {
        return;
    }
    tracing::info!(
        unique_patterns = unique,
        total_occurrences = total,
        "Some database patterns use unsupported regex features (look-around) and were skipped; \
         affected technologies fall back to their remaining patterns"
    );
    for pattern in skipped_patterns() {
        tracing::debug!(pattern = %pattern, "Skipped database pattern");
    }
}

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
    /// Pre-parsed implies graph: tech name → list of implied techs with weight/version.
    /// Built once at startup; used in `analyze()` to avoid repeated string parsing.
    pub(crate) implies_graph: HashMap<String, Vec<ImpliedTech>>,
    /// Compiled DOM rules from the `dom` field: tech name → list of rules.
    /// Each rule carries the selector plus its attribute/text conditions, so a
    /// detection only fires when the conditions actually hold (not on selector
    /// presence alone).
    pub(crate) dom_rules: HashMap<String, Vec<CompiledDomRule>>,
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
            implies_graph: HashMap::new(),
            dom_rules: HashMap::new(),
        };

        analyzer.compile_patterns()?;
        analyzer.compile_version_patches()?;
        analyzer.build_implies_graph();
        Ok(analyzer)
    }

    /// Compile a Wappalyzer `dom` field value into [`CompiledDomRule`]s.
    ///
    /// Handles the three shapes:
    /// - String  `"selector"`            → an exists rule.
    /// - Array   `["s1","s2"]`           → one exists rule per selector.
    /// - Object  `{"sel": {conditions}}` → a rule per selector with its
    ///   `exists` / `attributes` / `text` conditions compiled. `properties`
    ///   (runtime JS object props) are not observable in static HTML, so a rule
    ///   whose only condition is `properties` is dropped — matching it on the
    ///   selector alone is what produced mass false positives.
    fn compile_dom_rules(val: &serde_json::Value) -> Vec<CompiledDomRule> {
        fn exists_rule(selector: &str) -> Option<CompiledDomRule> {
            if selector.is_empty() { return None; }
            Some(CompiledDomRule {
                selector: selector.to_string(),
                attributes: Vec::new(),
                text: None,
                exists: true,
            })
        }

        match val {
            serde_json::Value::String(s) => exists_rule(s).into_iter().collect(),
            serde_json::Value::Array(arr) => arr.iter()
                .filter_map(|v| v.as_str())
                .filter_map(exists_rule)
                .collect(),
            serde_json::Value::Object(map) => {
                let mut rules = Vec::new();
                for (selector, cond) in map {
                    if selector.is_empty() { continue; }
                    // Non-object condition value → treat as bare existence.
                    let Some(cond_obj) = cond.as_object() else {
                        if let Some(r) = exists_rule(selector) { rules.push(r); }
                        continue;
                    };

                    let exists = cond_obj.contains_key("exists");

                    let mut attributes: Vec<(String, Option<CompiledPattern>)> = Vec::new();
                    if let Some(attrs) = cond_obj.get("attributes").and_then(|a| a.as_object()) {
                        for (name, pat) in attrs {
                            let pat_str = pat.as_str().unwrap_or("");
                            let compiled = if pat_str.is_empty() {
                                None // presence-only
                            } else {
                                match Self::compile_single_pattern(pat_str) {
                                    Ok(cp) => cp,
                                    Err(_) => None,
                                }
                            };
                            attributes.push((name.to_ascii_lowercase(), compiled));
                        }
                    }

                    let text = cond_obj.get("text")
                        .and_then(|t| t.as_str())
                        .filter(|s| !s.is_empty())
                        .and_then(|s| Self::compile_single_pattern(s).ok().flatten());

                    // Drop rules with no statically-checkable condition
                    // (e.g. `properties`-only React/Preact rules).
                    if !exists && attributes.is_empty() && text.is_none() {
                        continue;
                    }

                    rules.push(CompiledDomRule { selector: selector.clone(), attributes, text, exists });
                }
                rules
            }
            _ => Vec::new(),
        }
    }

    /// Build the implies graph by parsing all `implies` fields in the database once.
    /// Called after `compile_patterns()` and `compile_version_patches()` in `new()`.
    fn build_implies_graph(&mut self) {
        for (tech_name, tech_def) in &self.database.technologies {
            if let Some(implies) = &tech_def.implies {
                let implied_list: Vec<String> = match implies {
                    Value::String(s) => vec![s.clone()],
                    Value::Array(arr) => arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                    _ => Vec::new(),
                };
                let mut entries: Vec<ImpliedTech> = Vec::new();
                for implied in implied_list {
                    let parts: Vec<&str> = implied.split("\\;").collect();
                    let name = parts[0].trim().to_string();
                    if name.is_empty() { continue; }
                    let version = parts.iter().skip(1)
                        .find(|p| p.starts_with("version:"))
                        .and_then(|p| p.strip_prefix("version:"))
                        .map(|v| v.to_string())
                        .filter(|v| !v.is_empty());
                    let weight = parts.iter().skip(1)
                        .find(|p| p.starts_with("confidence:"))
                        .and_then(|p| p.strip_prefix("confidence:"))
                        .and_then(|v| v.parse::<u8>().ok())
                        .unwrap_or(100);
                    entries.push(ImpliedTech { name, weight, version });
                }
                if !entries.is_empty() {
                    self.implies_graph.insert(tech_name.clone(), entries);
                }
            }
        }
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
                if let Ok(patterns) = Self::compile_pattern_value(html_patterns, "html") {
                    if !patterns.is_empty() {
                        self.html_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile URL patterns
            if let Some(url_patterns) = &tech_def.url {
                if let Ok(patterns) = Self::compile_pattern_value(url_patterns, "url") {
                    if !patterns.is_empty() {
                        self.url_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile script src patterns (both `script` and `scriptSrc` fields map here)
            if let Some(script_patterns) = &tech_def.script {
                if let Ok(patterns) = Self::compile_pattern_value(script_patterns, "script") {
                    if !patterns.is_empty() {
                        self.script_patterns.entry(tech_name.clone()).or_default().extend(patterns);
                    }
                }
            }
            if let Some(script_src_patterns) = &tech_def.script_src {
                if let Ok(patterns) = Self::compile_pattern_value(script_src_patterns, "script_src") {
                    if !patterns.is_empty() {
                        self.script_patterns.entry(tech_name.clone()).or_default().extend(patterns);
                    }
                }
            }

            // Compile inline script content patterns (`scripts` field)
            if let Some(inline_scripts) = &tech_def.scripts {
                if let Ok(patterns) = Self::compile_pattern_value(inline_scripts, "scripts") {
                    if !patterns.is_empty() {
                        self.inline_script_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile header patterns
            if let Some(headers) = &tech_def.headers {
                let mut compiled_headers = HashMap::new();
                for (header_name, pattern_value) in headers {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value, "header") {
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
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value, "meta") {
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
                if let Ok(patterns) = Self::compile_pattern_value(css_value, "css") {
                    if !patterns.is_empty() {
                        self.css_patterns.insert(tech_name.clone(), patterns);
                    }
                }
            }

            // Compile cookie patterns
            if let Some(cookies) = &tech_def.cookies {
                let mut compiled_cookies = HashMap::new();
                for (cookie_name, pattern_value) in cookies {
                    if let Ok(patterns) = Self::compile_pattern_value(pattern_value, "cookie") {
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

        // Compile DOM rules (selector + conditions) from the `dom` field
        for (tech_name, tech_def) in &self.database.technologies {
            if let Some(dom_val) = &tech_def.dom {
                let rules = Self::compile_dom_rules(dom_val);
                if !rules.is_empty() {
                    self.dom_rules.insert(tech_name.clone(), rules);
                }
            }
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
                                if let Ok(patterns) = Self::compile_pattern_value(hpat, "header") {
                                    entry.insert(hname.to_lowercase(), patterns);
                                }
                            }
                        }
                    }
                    "meta" => {
                        if let Some(obj) = value.as_object() {
                            let entry = self.meta_patterns.entry(tech_name.clone()).or_default();
                            for (mname, mpat) in obj {
                                if let Ok(patterns) = Self::compile_pattern_value(mpat, "meta") {
                                    entry.insert(mname.to_lowercase(), patterns);
                                }
                            }
                        }
                    }
                    "html" => {
                        if let Ok(patterns) = Self::compile_pattern_value(value, "html") {
                            self.html_patterns.entry(tech_name.clone()).or_default().extend(patterns);
                        }
                    }
                    "cookies" => {
                        if let Some(obj) = value.as_object() {
                            let entry = self.cookie_patterns.entry(tech_name.clone()).or_default();
                            for (cname, cpat) in obj {
                                if let Ok(patterns) = Self::compile_pattern_value(cpat, "cookie") {
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

    /// Compile a pattern value (string or array) into CompiledPattern structs.
    /// `field_type` controls how empty patterns are handled — see `compile_single_pattern`.
    fn compile_pattern_value(value: &Value, field_type: &str) -> Result<Vec<CompiledPattern>, WappalyzerError> {
        let mut patterns = Vec::new();

        match value {
            Value::String(pattern_str) => {
                if let Some(compiled) = Self::compile_single_pattern_typed(pattern_str, field_type)? {
                    patterns.push(compiled);
                }
            }
            Value::Array(pattern_array) => {
                for pattern_val in pattern_array {
                    if let Value::String(pattern_str) = pattern_val {
                        if let Some(compiled) = Self::compile_single_pattern_typed(pattern_str, field_type)? {
                            patterns.push(compiled);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(patterns)
    }

    /// Field-type-aware wrapper around `compile_single_pattern`.
    ///
    /// For content fields (`html`, `script`, `script_src`, `scripts`, `css`, `url`) an empty
    /// pattern means "no match pattern defined" — return `Ok(None)` so the tech is not added
    /// to the compiled map at all, preventing spurious catch-all detections.
    ///
    /// For presence-only fields (`header`, `cookie`, `meta`) an empty pattern means "match if
    /// the field exists", so we fall through to `compile_single_pattern` which returns `.*`.
    fn compile_single_pattern_typed(pattern: &str, field_type: &str) -> Result<Option<CompiledPattern>, WappalyzerError> {
        if pattern.is_empty() {
            match field_type {
                "html" | "script" | "script_src" | "scripts" | "css" | "url" => {
                    return Ok(None);
                }
                _ => {} // header, cookie, meta — fall through to presence-only `.*`
            }
        }
        Self::compile_single_pattern(pattern)
    }

    /// Compile a single pattern string with confidence and version extraction.
    /// Empty pattern → presence-only catch-all `.*` with confidence 100.
    /// Callers that need field-type-aware behaviour should use `compile_single_pattern_typed`.
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
                // Log each distinct pattern once. Every analyzer instance
                // recompiles the database, so an unconditional warn! here
                // repeated the same messages and drowned the startup log.
                if record_skipped_pattern(regex_pattern) {
                    tracing::warn!(
                        pattern = %regex_pattern,
                        error = %e,
                        "Skipping database pattern that the regex crate cannot compile"
                    );
                }
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

        // DOM selector matching: CSS selectors from the Wappalyzer `dom` field
        self.analyze_dom(&response.body, &mut detected_technologies);

        // Apply "implies" logic using pre-computed graph (avoids repeated string parsing)
        let mut queue: std::collections::VecDeque<String> =
            detected_technologies.keys().cloned().collect();
        while let Some(tech_name) = queue.pop_front() {
            if let Some(implied_list) = self.implies_graph.get(&tech_name) {
                for implied in implied_list {
                    if !detected_technologies.contains_key(&implied.name) {
                        Self::update_detection(
                            &mut detected_technologies,
                            &implied.name,
                            "implied",
                            &tech_name,
                            implied.weight,
                            implied.version.clone(),
                        );
                        queue.push_back(implied.name.clone());
                    }
                }
            }
        }

        // Apply exclusions and requirements post-processing
        Self::apply_exclusions_and_requirements(&mut detected_technologies, &self.database);

        // Convert to Technology structs — confidence via Noisy-OR, filter by min_confidence
        detected_technologies
            .into_iter()
            .filter_map(|(name, mut detection)| {
                Self::dedupe_signals(&mut detection.signals);
                let confidence = compute_noisy_or(&detection.signals);
                if confidence < min_confidence { return None; }
                let tech_def = self.database.technologies.get(&name);
                let categories = self.get_technology_categories(&name);
                let cpe = Self::resolve_cpe(
                    tech_def.and_then(|def| def.cpe.clone()),
                    self.cpe_overrides.get(&name),
                );
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

    /// Pick the CPE for a technology, honouring explicit suppressions.
    ///
    /// Normally the database CPE wins and `data/cpe_overrides.json` only fills gaps.
    /// But several database CPEs point at an unrelated product that merely shares a
    /// name — modern Angular mapped to `angularjs:angular`, the Lightbox JS library
    /// mapped to a `lightbox_photo_gallery` plugin — and a wrong CPE is worse than
    /// none, because it silently produces CVE matches for software that isn't there.
    ///
    /// An override value of `""` means "no trustworthy CPE exists for this name" and
    /// takes precedence over the database. Non-empty overrides keep their original
    /// fill-the-gap behaviour so existing entries are unaffected.
    fn resolve_cpe(db_cpe: Option<String>, override_cpe: Option<&String>) -> Option<String> {
        match override_cpe {
            Some(o) if o.is_empty() => None,
            Some(o) => db_cpe.or_else(|| Some(o.clone())),
            None => db_cpe,
        }
    }

    /// Clean up an extracted version string, or reject it entirely.
    ///
    /// Version patterns capture whatever the page happens to expose, and some sources
    /// are badly behaved. Observed in the wild:
    ///
    /// - WordPress slider plugins stuff their entire marketing description into the
    ///   generator tag: `"6.7.41 - responsive, Mobile-Friendly Slider Plugin for
    ///   WordPress with comfortable drag and drop interface."`
    /// - Asset filenames yield build hashes rather than versions:
    ///   `"70e2b8fbf759cc1d2687"`.
    ///
    /// Both are worse than no version at all: they get written into reports and fed to
    /// CVE lookups as if they were real. Salvage a leading version where one exists,
    /// otherwise return `None`.
    pub(crate) fn sanitize_version(raw: &str) -> Option<String> {
        let mut candidate = raw.trim();

        // "6.7.41 - responsive, Mobile-Friendly ..." => "6.7.41"
        if let Some(idx) = candidate.find(" - ") {
            candidate = candidate[..idx].trim_end();
        }
        // A version never contains whitespace. If prose follows a version-shaped head,
        // keep the head; otherwise the whole value is unusable.
        if let Some(idx) = candidate.find(char::is_whitespace) {
            candidate = candidate[..idx].trim_end();
        }
        candidate = candidate.trim_matches(|c: char| c == ',' || c == ';' || c == '.');

        if candidate.is_empty() || candidate.len() > 32 {
            return None;
        }
        // Only version-ish characters. Rejects quotes, parens, slashes, and unicode prose.
        if !candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '~' | ':'))
        {
            return None;
        }
        // Must contain at least one digit — drops captures like "min" or "latest".
        if !candidate.chars().any(|c| c.is_ascii_digit()) {
            // Keep short non-numeric labels the database uses deliberately (GA4, UA, v2).
            if candidate.len() > 4 {
                return None;
            }
        }
        // A long run of hex with no separator is a build hash, not a version.
        if candidate.len() >= 12
            && !candidate.contains('.')
            && candidate.chars().all(|c| c.is_ascii_hexdigit())
        {
            return None;
        }
        Some(candidate.to_string())
    }

    /// Collapse repeated evidence down to one Signal per `(signal_type, value)`.
    ///
    /// Detection layers append a Signal per regex *hit*, not per distinct pattern, so
    /// a pattern matching 30 page elements produced 30 identical Signals. Two problems
    /// followed: the signal list stopped being readable evidence (Adobe Experience
    /// Manager reported 58 signals of which only ~25 were distinct, and Google Tag
    /// Manager reported 50 that were nearly all the same HTML comment), and because
    /// confidence is Noisy-OR *over the signal list*, re-observing one piece of
    /// evidence inflated confidence as though it were independent corroboration.
    ///
    /// The highest weight seen for a given key wins, so collapsing never weakens a
    /// detection. Note this can lower the computed confidence for technologies that
    /// were previously relying on duplicates to clear `min_confidence` — that is the
    /// intended correction, since one observation should count once.
    fn dedupe_signals(signals: &mut Vec<Signal>) {
        if signals.len() < 2 {
            return;
        }
        let mut max_weight: HashMap<(String, String), u8> = HashMap::new();
        for signal in signals.iter() {
            let key = (signal.signal_type.clone(), signal.value.clone());
            let entry = max_weight.entry(key).or_insert(signal.weight);
            if signal.weight > *entry {
                *entry = signal.weight;
            }
        }
        let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
        signals.retain(|signal| seen.insert((signal.signal_type.clone(), signal.value.clone())));
        for signal in signals.iter_mut() {
            if let Some(weight) = max_weight.get(&(signal.signal_type.clone(), signal.value.clone())) {
                signal.weight = *weight;
            }
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
                .map_or_else(
                    || Self::resolve_cpe(None, self.cpe_overrides.get(name)),
                    |c| Self::resolve_cpe(Some(c), self.cpe_overrides.get(name)),
                ),
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

    /// Re-apply `excludes` / `requires` / `requires_category` gating to a
    /// merged `Vec<Technology>` after late-stage layers (assets, favicon,
    /// probes, DNS) have appended new detections.
    ///
    /// `apply_exclusions_and_requirements` runs inside `analyze()` over the
    /// HTML/header/cookie pass only — without this final pass, late additions
    /// can re-introduce techs whose dependencies were filtered out, e.g.
    /// "Trident AB" (`requires: Shopify`) re-matching `Trident/` inside a
    /// vendor JS UA-sniff block fetched by `inspect_assets`.
    pub fn finalize_gating(&self, technologies: &mut Vec<Technology>) {
        // Late-stage layers (assets, source maps, favicon, probes, DNS) merge their
        // findings with `signals.extend(..)`, which re-appends evidence the initial
        // pass already recorded — one asset scanned per linked file, each re-matching
        // the same handful of patterns. Collapse here, after every layer has merged,
        // so the emitted signal list is distinct evidence rather than a hit counter.
        for tech in technologies.iter_mut() {
            Self::dedupe_signals(&mut tech.signals);
            // Drop or trim versions that aren't versions (plugin blurbs, build hashes).
            if let Some(raw) = tech.version.take() {
                tech.version = Self::sanitize_version(&raw);
            }
        }

        let mut detected: HashMap<String, TechDetection> = technologies
            .iter()
            .map(|t| (
                t.name.clone(),
                TechDetection {
                    version: t.version.clone(),
                    signals: t.signals.clone(),
                },
            ))
            .collect();
        Self::apply_exclusions_and_requirements(&mut detected, &self.database);
        let valid: std::collections::HashSet<String> = detected.into_keys().collect();
        technologies.retain(|t| valid.contains(&t.name));
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
    fn test_sanitize_version_strips_plugin_blurbs() {
        // Slider Revolution / LayerSlider put their whole description in the version.
        assert_eq!(
            TechnologyAnalyzer::sanitize_version(
                "6.7.41 - responsive, Mobile-Friendly Slider Plugin for WordPress with comfortable drag and drop interface."
            ),
            Some("6.7.41".to_string())
        );
        assert_eq!(
            TechnologyAnalyzer::sanitize_version(
                "8.2.0 - Build Heros, Sliders, and Popups. Create Animations and Beautiful, Rich Web Content"
            ),
            Some("8.2.0".to_string())
        );
    }

    #[test]
    fn test_sanitize_version_rejects_build_hashes() {
        // Observed on Bootstrap: an asset filename hash captured as a version.
        assert_eq!(TechnologyAnalyzer::sanitize_version("70e2b8fbf759cc1d2687"), None);
        // A dotted version of similar length is still fine.
        assert_eq!(
            TechnologyAnalyzer::sanitize_version("2016.1.112"),
            Some("2016.1.112".to_string())
        );
    }

    #[test]
    fn test_sanitize_version_keeps_real_versions() {
        for v in ["1.28.0", "5.3.3", "6.x", "3.7.1", "1.1.1k", "2.0.50727", "v2", "GA4", "UA"] {
            assert_eq!(
                TechnologyAnalyzer::sanitize_version(v),
                Some(v.to_string()),
                "should have kept {v}"
            );
        }
    }

    #[test]
    fn test_sanitize_version_rejects_junk() {
        assert_eq!(TechnologyAnalyzer::sanitize_version(""), None);
        assert_eq!(TechnologyAnalyzer::sanitize_version("   "), None);
        assert_eq!(TechnologyAnalyzer::sanitize_version("latest"), None);
        assert_eq!(TechnologyAnalyzer::sanitize_version("minified"), None);
        // over the length cap
        assert_eq!(TechnologyAnalyzer::sanitize_version(&"1".repeat(40)), None);
    }

    #[test]
    fn test_dedupe_signals_collapses_repeats_and_keeps_max_weight() {
        let mut signals = vec![
            Signal { signal_type: "html".into(), value: "aem-Grid".into(), weight: 75 },
            Signal { signal_type: "html".into(), value: "aem-Grid".into(), weight: 100 },
            Signal { signal_type: "html".into(), value: "aem-Grid".into(), weight: 50 },
            Signal { signal_type: "script".into(), value: "aem-Grid".into(), weight: 100 },
        ];
        TechnologyAnalyzer::dedupe_signals(&mut signals);
        assert_eq!(signals.len(), 2, "identical (type,value) pairs should collapse");
        let html = signals.iter().find(|s| s.signal_type == "html").unwrap();
        assert_eq!(html.weight, 100, "the strongest weight should survive");
        // a different signal_type with the same value is distinct evidence
        assert!(signals.iter().any(|s| s.signal_type == "script"));
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
    fn test_requires_array_form_is_enforced() {
        // Regression: the cache stores `requires` as a JSON array (e.g. ["Shopify"])
        // but the original test only covered the Value::String shape. Ensure the
        // Value::Array branch also removes techs whose dependency is missing.
        let mut technologies = HashMap::new();
        technologies.insert("TridentLike".to_string(), TechnologyDefinition {
            description: None, website: None, categories: vec![], icon: None, cpe: None,
            saas: None, pricing: None, url: None, html: None, css: None, script: None,
            script_src: None, scripts: None, meta: None, headers: None, cookies: None,
            dom: None, js: None, xhr: None, text: None, cert_issuer: None, robots: None,
            dns: None, implies: None, excludes: None,
            requires: Some(Value::Array(vec![Value::String("Shopify".to_string())])),
            requires_category: None,
        });
        let db = WappalyzerDatabase { technologies, categories: HashMap::new() };

        let mut detected = HashMap::new();
        detected.insert("TridentLike".to_string(), make_detection(vec![make_signal(100)]));

        TechnologyAnalyzer::apply_exclusions_and_requirements(&mut detected, &db);

        assert!(
            !detected.contains_key("TridentLike"),
            "TridentLike should be removed — Shopify not detected (Value::Array requires path)"
        );
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

#[cfg(test)]
mod skipped_pattern_tests {
    use super::*;

    #[test]
    fn look_around_patterns_are_skipped_not_fatal() {
        // Representative of the shapes actually present in the database.
        for pat in [
            r"^(?!.*player).*aniview\.com/",
            r"<(?!svg)[^>]+\sdata-v(?:ue)?-",
            r"\b(?<!-)UPS\b",
        ] {
            let out = TechnologyAnalyzer::compile_single_pattern(pat);
            assert!(out.is_ok(), "compilation must not error for {pat}");
            assert!(out.unwrap().is_none(), "{pat} should be skipped");
        }
    }

    #[test]
    fn recording_is_deduplicated_per_pattern() {
        let unique_pat = "test-only-pattern-(?!dedupe-probe)";
        assert!(record_skipped_pattern(unique_pat), "first sighting logs");
        assert!(!record_skipped_pattern(unique_pat), "second does not");
        assert!(!record_skipped_pattern(unique_pat), "third does not");
        assert!(skipped_patterns().iter().any(|p| p == unique_pat));
    }

    #[test]
    fn valid_patterns_still_compile() {
        let out = TechnologyAnalyzer::compile_single_pattern(r"nginx/([\d.]+)").unwrap();
        assert!(out.is_some());
    }
}
