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

/// Patterns that needed the backtracking engine, recorded once each. Tracked
/// separately from skipped patterns: these now work, and conflating "we fell back"
/// with "we gave up" is what made the original gap hard to see.
static LOOKAROUND_PATTERNS: Lazy<std::sync::Mutex<HashMap<String, u32>>> =
    Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

fn record_lookaround_pattern(pattern: &str) -> bool {
    let mut guard = match LOOKAROUND_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let counter = guard.entry(pattern.to_string()).or_insert(0);
    *counter += 1;
    *counter == 1
}

/// Returns `(unique_patterns, total_occurrences)` for look-around fallbacks so far.
pub fn lookaround_pattern_stats() -> (usize, u32) {
    let guard = match LOOKAROUND_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    (guard.len(), guard.values().sum())
}

/// Ceiling on the weight of a single `implies` edge, applied in
/// [`TechnologyAnalyzer::expand_implied`].
///
/// The technology database expresses an implication as `"PHP"` or
/// `"PHP\;confidence:50"`, and the overwhelming majority carry no explicit
/// confidence at all. `build_implies_graph` defaults those to 100, so before this
/// ceiling existed every unqualified implication asserted *certainty* — WordPress
/// observed at 55 produced PHP at a flat 100, an inference more confident than the
/// observation it was derived from, and higher than most things we actually saw.
///
/// A database author writing a bare `"implies": ["PHP"]` means "these normally go
/// together", not "this is proof". 90 encodes that: an inference is never quite as
/// good as an observation, and because the ceiling multiplies in at every hop, a
/// chain of implications now loses at least 10% per step instead of holding flat.
/// An edge that DOES carry an explicit `confidence:` below 90 is honoured as
/// written — the ceiling only removes the unearned default.
const IMPLIED_EDGE_CEILING: u8 = 90;

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
    let (fallback_unique, fallback_total) = lookaround_pattern_stats();
    if fallback_unique > 0 {
        tracing::info!(
            unique_patterns = fallback_unique,
            total_occurrences = fallback_total,
            "Patterns using look-around were compiled with the backtracking engine"
        );
    }

    // Patterns we declined to use, as opposed to ones no engine could compile. Reported
    // here so the `text` layer's rejections are visible in the same place as the rest.
    let rejected_text = layers::text::rejected_text_patterns();
    if !rejected_text.is_empty() {
        tracing::info!(
            patterns = rejected_text.len(),
            "Ignored database `text` patterns anchored to the start of the page text"
        );
        for pattern in rejected_text {
            tracing::debug!(pattern = %pattern, "Ignored `text` pattern");
        }
    }

    let (unique, total) = skipped_pattern_stats();
    if unique == 0 {
        return;
    }
    tracing::info!(
        unique_patterns = unique,
        total_occurrences = total,
        "Some database patterns could not be compiled by either regex engine; \
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
    /// Lowercase alias → canonical technology name, from data/tech_aliases.json.
    pub(crate) tech_aliases: HashMap<String, String>,
    /// Version extraction patches: tech name → field name → pattern value.
    /// Added at compile time for Segment C technologies (CPE present, version pattern missing).
    pub(crate) version_patches: HashMap<String, HashMap<String, serde_json::Value>>,
    /// Pre-parsed implies graph: tech name → list of implied techs with weight/version.
    /// Built once at startup; used in `analyze()` to avoid repeated string parsing.
    pub(crate) implies_graph: HashMap<String, Vec<ImpliedTech>>,
    /// Compiled patterns from the `text` field: tech name → patterns matched against
    /// the *visible text* of the page (not the markup). See `layers::text`.
    pub(crate) text_patterns: HashMap<String, Vec<CompiledPattern>>,
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
        let tech_aliases = cache::load_tech_aliases();
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
            tech_aliases,
            version_patches,
            implies_graph: HashMap::new(),
            text_patterns: HashMap::new(),
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

            // Compile visible-page-text patterns (`text` field). Kept in its own map
            // rather than folded into `html_patterns` because the subject is different:
            // these match rendered text, so the layer has to strip markup first.
            if let Some(text_value) = &tech_def.text {
                let patterns = Self::compile_text_patterns(text_value);
                if !patterns.is_empty() {
                    self.text_patterns.insert(tech_name.clone(), patterns);
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
    /// For content fields (`html`, `script`, `script_src`, `scripts`, `css`, `url`, `text`) an
    /// empty pattern means "no match pattern defined" — return `Ok(None)` so the tech is not
    /// added to the compiled map at all, preventing spurious catch-all detections. (`text` has
    /// no such entry in the shipped database, but a `.*` there would tag *every* analysed page
    /// with the technology, so it is classed with the content fields rather than trusted.)
    ///
    /// For presence-only fields (`header`, `cookie`, `meta`) an empty pattern means "match if
    /// the field exists", so we fall through to `compile_single_pattern` which returns `.*`.
    fn compile_single_pattern_typed(pattern: &str, field_type: &str) -> Result<Option<CompiledPattern>, WappalyzerError> {
        if pattern.is_empty() {
            match field_type {
                "html" | "script" | "script_src" | "scripts" | "css" | "url" | "text" => {
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
                regex: PatternRegex::Fast(Regex::new(".*").unwrap()),
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
        let cased = format!("(?i){}", regex_pattern);
        match Regex::new(&cased) {
            Ok(regex) => Ok(Some(CompiledPattern {
                regex: PatternRegex::Fast(regex),
                confidence,
                version,
            })),
            Err(fast_err) => {
                // The `regex` crate rejects look-around by design, and the database uses
                // it. These patterns used to be dropped, silently narrowing detection for
                // the technologies that relied on them. Retry on the backtracking engine,
                // which does support look-around.
                match fancy_regex::Regex::new(&cased) {
                    Ok(fancy) => {
                        if record_lookaround_pattern(regex_pattern) {
                            tracing::debug!(
                                pattern = %regex_pattern,
                                "Pattern needs look-around; compiled with the backtracking engine"
                            );
                        }
                        Ok(Some(CompiledPattern {
                            regex: PatternRegex::Fancy(Box::new(fancy)),
                            confidence,
                            version,
                        }))
                    }
                    Err(fancy_err) => {
                        // Neither engine can compile it. Log each distinct pattern once:
                        // every analyzer instance recompiles the database, so an
                        // unconditional warn! repeated the same messages and drowned
                        // the startup log.
                        if record_skipped_pattern(regex_pattern) {
                            tracing::warn!(
                                pattern = %regex_pattern,
                                regex_error = %fast_err,
                                fancy_error = %fancy_err,
                                "Skipping database pattern that neither regex engine can compile"
                            );
                        }
                        Ok(None)
                    }
                }
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

        // Visible page text: the Wappalyzer `text` field, matched against rendered text
        // only (script/style/noscript/template content excluded). Takes the whole response
        // because it also needs Content-Type. Deliberately weak evidence — see
        // `layers::text::TEXT_SIGNAL_WEIGHT`.
        self.analyze_text(response, &mut detected_technologies);

        // Apply "implies" logic using the pre-computed graph, discounting each implied
        // technology by the confidence of the technology that implied it.
        self.expand_implied(&mut detected_technologies);

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

    /// Expand the `implies` graph over an in-progress detection map, discounting every
    /// implied technology by the confidence of the technology that implied it.
    ///
    /// # Why the confidence has to be computed here
    ///
    /// The implied signal's weight has to be a function of the parent's confidence,
    /// and the parent's confidence is a function of all its signals — so the expansion
    /// cannot run before confidence exists, which is exactly where it used to sit.
    /// `analyze()` computed nothing until the final `filter_map`, so expansion passed
    /// `implied.weight` straight through with no reference to the parent at all.
    ///
    /// So this computes confidence up front, for the seeds, and then keeps it up to
    /// date as the frontier advances. That is only safe because of two properties of
    /// the rest of the pipeline, and it breaks if either changes:
    ///
    /// 1. It is computed the same way the final `filter_map` computes it —
    ///    `dedupe_signals` then [`compute_noisy_or`] — so a technology is never scored
    ///    two different ways. `dedupe_signals` is idempotent, so deduping here and
    ///    again later is a no-op the second time. `compute_noisy_or` is CALLED, never
    ///    re-derived inline, so that the correlated-signal grouping inside it applies
    ///    identically to both.
    /// 2. Nothing adds signals to an already-detected technology after this point.
    ///    The `contains_key` guard below means expansion never touches one, and
    ///    `apply_exclusions_and_requirements` only ever removes entries.
    ///
    /// # Why an implied technology gets exactly one signal
    ///
    /// The `contains_key` guard is load-bearing and is preserved verbatim: a
    /// technology that is already in the map — whether directly observed or implied a
    /// moment ago by someone else — is skipped entirely. So a directly detected
    /// technology never receives an implied signal (its own evidence stands), and an
    /// implied one receives exactly one. That is what stops implication chains from
    /// compounding, and it is also what makes step 1 above hold for implied nodes: a
    /// single-signal technology's noisy-OR is just that signal's weight, so the value
    /// recorded here is exactly what the final `filter_map` will recompute.
    ///
    /// # The arithmetic
    ///
    /// `weight = round(min(edge, IMPLIED_EDGE_CEILING) * parent_confidence / 100)`.
    ///
    /// Multiplying by the parent both DISCOUNTS and BOUNDS: the multiplier is at most
    /// 0.9, so a child is always strictly below its parent, and a child that becomes a
    /// parent at the next level is discounted again from its own already-reduced
    /// figure. Chains therefore decay geometrically — WordPress at 55 implies PHP at
    /// 50, which implies its own children at 45 — instead of every implication in the
    /// graph landing on a flat 100.
    ///
    /// A weight that rounds to 0 is dropped rather than recorded: a zero-weight signal
    /// contributes nothing to noisy-OR, so it would be a technology asserted on no
    /// evidence, and enqueueing it would expand a whole subtree of the graph on the
    /// strength of it. Reaching 0 needs a parent already at 0 or 1, which means the
    /// parent barely exists either.
    fn expand_implied(&self, detected: &mut HashMap<String, TechDetection>) {
        // Confidence of every technology that can act as a parent, seeded with the
        // directly detected ones and extended as the BFS discovers implied ones.
        let mut confidence: HashMap<String, u8> = HashMap::with_capacity(detected.len());
        for (name, detection) in detected.iter_mut() {
            Self::dedupe_signals(&mut detection.signals);
            confidence.insert(name.clone(), compute_noisy_or(&detection.signals));
        }

        // Sorted, not `keys()` order. Which parent claims a shared child is decided by
        // the order the frontier is walked, and now decides that child's WEIGHT as
        // well as its version, so leaving it to `HashMap` iteration order would make
        // the reported confidence vary between runs on identical input. Sorting the
        // seeds is enough to make the whole expansion deterministic: every later
        // enqueue happens in `implies_graph` order, which is fixed.
        let mut seeds: Vec<String> = detected.keys().cloned().collect();
        seeds.sort();
        let mut queue: std::collections::VecDeque<String> = seeds.into_iter().collect();

        while let Some(parent_name) = queue.pop_front() {
            let parent_confidence = match confidence.get(&parent_name) {
                Some(c) => *c,
                // Nothing computes a confidence-free entry into the queue today; if
                // something ever does, implying from an unknown score is worse than
                // not implying at all.
                None => continue,
            };
            if parent_confidence == 0 {
                continue;
            }
            let implied_list = match self.implies_graph.get(&parent_name) {
                Some(list) => list,
                None => continue,
            };
            for implied in implied_list {
                if detected.contains_key(&implied.name) {
                    continue;
                }
                let edge = implied.weight.min(IMPLIED_EDGE_CEILING);
                let weight =
                    ((u32::from(edge) * u32::from(parent_confidence)) as f64 / 100.0).round() as u8;
                if weight == 0 {
                    continue;
                }
                Self::update_detection(
                    detected,
                    &implied.name,
                    "implied",
                    &parent_name,
                    weight,
                    implied.version.clone(),
                );
                // Record the child's confidence so it can discount its own children.
                // Read back through `compute_noisy_or` rather than reusing `weight`
                // directly: the two are equal for a single-signal technology, but
                // going through the function means a change to how signals are
                // combined reaches this path automatically instead of silently
                // diverging from the final score.
                if let Some(child) = detected.get(&implied.name) {
                    confidence.insert(implied.name.clone(), compute_noisy_or(&child.signals));
                }
                queue.push_back(implied.name.clone());
            }
        }
    }

    /// Extract version from regex captures using version pattern.
    ///
    /// Supports Wappalyzer's full version template syntax:
    /// - `\1`, `\2` … — capture group substitution
    /// - `\1?a:b`     — ternary: use `a` if group 1 matched non-empty, else `b`
    pub fn extract_version(version_pattern: &Option<String>, captures: &PatternCaptures) -> Option<String> {
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
                let group_val = captures.group(group_num).unwrap_or("");
                let replacement = if !group_val.is_empty() { cap[2].to_string() } else { cap[3].to_string() };
                version = version.replacen(&cap[0], &replacement, 1);
            } else {
                break;
            }
        }

        // Replace capture group references \1 … \9
        for i in 1..captures.len() {
            let placeholder = format!("\\{}", i);
            let capture_val = captures.group(i).unwrap_or("");
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

    /// How much a version string is worth, given the kind of artifact it was read out of.
    ///
    /// A technology has one version slot and many layers that can fill it, so something
    /// has to arbitrate. Until this function existed the arbiter was arrival order:
    /// `update_detection` wrote a version only when the slot was still empty, and the
    /// layer order in `analyze()` is fixed, so a `?ver=` cache-buster scraped off a
    /// script tag permanently beat an exact version from a source map or from a
    /// `/wp-includes/version.php` probe — both of which run later. That ordering is
    /// almost exactly inverted relative to how reliable the sources are.
    ///
    /// # Where this ranking is applied, and where it is not
    ///
    /// Through exactly ONE predicate — [`Self::version_outranks`] — reached from three
    /// places:
    ///
    /// - [`Self::update_detection`], which every layer funnels through. That covers
    ///   arbitration WITHIN one detection map: the layers of `analyze()` competing with
    ///   each other, the asset/source-map layers competing with each other, and the
    ///   probe layer competing with itself.
    /// - the two folds in `src/lib.rs` (`inspect_assets` and `probe_version_endpoints`,
    ///   both via `merge_version_by_source_rank`) where one of those separate maps is
    ///   merged into the already-built `Vec<Technology>`. That second site is not an
    ///   extra refinement, it is load-bearing: the probe layer and the source-map layer
    ///   fill FRESH maps of their own, so a `probe` or `source_map` version never meets
    ///   the version `analyze()` stored until the fold. Before the fold was ranked, the
    ///   two highest ranks in this function — the only two sources that read a version
    ///   out of the running build itself — were the only ones that could never win.
    ///
    /// Two paths still settle a version collision without consulting this ranking, and
    /// are named so the list above is not read as "everywhere":
    ///
    /// - `Self::merge_aliases` folds two spellings of one product into one entry and
    ///   keeps the canonical entry's version whenever it already has one, i.e. it is
    ///   still first-write-wins between the two spellings.
    /// - `analyze_url`'s DNS append and `detect_favicon` build or extend a `Technology`
    ///   directly rather than through a detection map. Neither supplies a version
    ///   today, so neither has a collision to settle — but neither would be ranked if
    ///   one ever did.
    ///
    /// Sanitisation is untouched by any of this and still happens exactly once, in
    /// `finalize_gating`, over whichever string won: a better-sourced version is no
    /// more exempt from `sanitize_version` than the one it displaced.
    ///
    /// The ranking below is ordered by ONE question: how directly does this string
    /// describe the build that is actually running? Higher wins. The numbers are
    /// ordinal only — nothing multiplies or adds them, they are compared with `>` —
    /// and the gaps are there so a future source can be slotted in without renumbering.
    ///
    /// Nothing here touches confidence. A version's provenance says which *string* to
    /// keep; the signal weight, and only the signal weight, says how sure we are the
    /// technology is present at all.
    ///
    /// `value` is the signal's payload (for `script_src` and `url` layers, the asset
    /// URL) and `version` the candidate string, both needed to tell a version parsed
    /// out of a URL path from one lifted out of a query parameter — see
    /// [`Self::version_is_from_query_string`].
    pub(crate) fn version_source_rank(signal_type: &str, value: &str, version: &str) -> u8 {
        match signal_type {
            // The application answering a question about itself. `/wp-json/`,
            // `/package.json`, `/actuator/info` and friends are fetched by the probe
            // layer precisely because they disclose a version, and what they return is
            // the running build's own statement of what it is. Nothing beats that.
            "probe" => 100,

            // A JavaScript source map's `sources` array carries literal
            // `node_modules/<pkg>/<version>/...` paths emitted by the bundler at build
            // time. Exact and unspoofable in practice — but one step below a probe
            // because it names the version of a *dependency inside the bundle*, which
            // for a vendored or transitively pinned package need not be the version of
            // the product we are attributing it to.
            "source_map" => 95,

            // `<meta name="generator" content="WordPress 6.8.1">`. The application
            // declaring its own version in its own markup: deliberate, usually right,
            // and below a probe only because generator tags are routinely left stale
            // by upgrades that do not rewrite the template, and are trivially edited
            // or faked by hardening plugins.
            "meta" => 80,

            // `Server:`, `X-Powered-By:`, `X-Generator:`. Also a self-report, but one
            // that is very often about the web server or language runtime in front of
            // the application rather than the application, and that operators
            // routinely truncate or blank.
            "header" => 70,

            // TXT records and the like. Published by the domain's operator, so it has
            // real authority — but it describes an account or a zone configuration,
            // not the build serving this particular response, and it goes stale
            // silently. Every spelling in the tree is matched; see the same note in
            // `confidence::independence_class`.
            //
            // Mostly precautionary: src/analyzer/layers/dns.rs builds its `Technology`
            // values with `version: None` and never calls `update_detection`, so no DNS
            // signal ever arrives here as a CANDIDATE. It can still be read here as
            // part of an incumbent's evidence — `version_rank_from_signals` ranks every
            // signal a technology carries — so the number is not unreachable, and the
            // arm also means a DNS layer that one day does extract a version is ranked
            // on purpose rather than falling into the unknown default below.
            "dns" | "dns_txt" | "dns_mx" | "dns_cname" => 65,

            // Cookie names and values. Version-bearing cookies exist (a few frameworks
            // stamp a build id) but the convention is weak and the value is as often a
            // session artifact as a version.
            "cookie" => 60,

            // A DOM rule reads a named attribute off a specific selector, e.g.
            // `[data-version]` on a known root element. More targeted than a regex
            // over the whole document, which is the only reason it sits above `html`.
            "dom" => 55,

            // Regexes over the response body: whole-document (`html`), inline script
            // text (`script`), inline CSS (`css`), JS globals (`js`). This tier is
            // wide: it holds both the best body evidence there is (a minifier-preserved
            // `/*! jQuery v3.7.1 */` banner) and some of the loosest patterns in the
            // database. They share a rank because the signal type does not distinguish
            // the two, and inventing a finer split here would be guesswork.
            "html" | "script" | "css" | "js" => 50,

            // A version sitting in a URL *path* segment —
            // `/ajax/libs/jquery/3.7.1/jquery.min.js`. Structured and conventional, so
            // better than a query string, but it is a claim made by whoever chose the
            // path, and CDN mirrors and rewrite rules are free to serve something else
            // from it.
            //
            // A version lifted out of a *query parameter* is the weakest structured
            // source there is. `?ver=` is a cache-buster: CMSs stamp their own core
            // version onto every asset they enqueue, including third-party libraries
            // that have nothing to do with that number, and themes stamp the theme
            // version. `Self::extract_query_version` feeds exactly these into this
            // function.
            "script_src" | "url" => {
                if Self::version_is_from_query_string(value, version) { 20 } else { 40 }
            }

            // Rendered page text. Prose that happens to contain something version
            // shaped ("Powered by Foo 2.1") is the least controlled source we read:
            // it is content, written by whoever writes the content. See
            // `layers::text::TEXT_SIGNAL_WEIGHT` for the matching view of its weight.
            "page-text" => 10,

            // Not an observation at all. `ImpliedTech::version` is a constant written
            // into the technology database's `implies` string, so it describes what
            // the database author expected, not what this host is running. Anything
            // actually observed should displace it.
            "implied" => 5,

            // Unrecognised or newly added signal type. Deliberately low but non-zero:
            // a new layer can still fill an empty version slot (the `None` case in
            // `update_detection` does not consult this function at all), and can still
            // beat page text and an implication, but cannot silently displace a source
            // whose trustworthiness someone has actually thought about. A new layer
            // that deserves better gets an explicit arm above.
            //
            // `favicon` deliberately has no arm. The favicon layer maps a content hash
            // to a technology *name*, never to a version, and it pushes its Signal
            // straight onto the `Technology` rather than through `update_detection`
            // (src/analyzer/layers/dns.rs), so it never offers a candidate. It does
            // land in this default when an incumbent's rank is estimated from its
            // signal list — the favicon layer runs before the probe layer, so a
            // `favicon` signal is routinely present at the probe fold — and 15 is the
            // right answer there: an identifier that carries no version must not raise
            // the bar a real version source has to clear.
            _ => 15,
        }
    }

    /// True when `version` appears in `value`'s query string and NOT in its path.
    ///
    /// Used only to separate the two very different qualities of version that the
    /// `script_src` and `url` layers both report: `/jquery/3.7.1/jquery.min.js` (path)
    /// versus `/jquery.min.js?ver=6.5.3` (cache-buster).
    ///
    /// Note the deliberate asymmetry: if the string occurs on BOTH sides we treat it
    /// as a path version, because a path that contains the number is corroboration,
    /// not a cache-buster coincidence.
    ///
    /// When this is called to re-rank an ALREADY STORED signal the `value` it sees has
    /// been truncated to 100 characters by `update_detection`, so a long URL may have
    /// lost its `?` or its parameters. That degrades to `false`, i.e. to the higher
    /// path rank, which makes the stored version harder to displace — the same
    /// direction as the old first-write-wins behaviour, so truncation can never cause
    /// a version to be replaced that would otherwise have been kept.
    fn version_is_from_query_string(value: &str, version: &str) -> bool {
        match value.find('?') {
            None => false,
            Some(q) => value[q + 1..].contains(version) && !value[..q].contains(version),
        }
    }

    /// Best rank any signal in `signals` could have given to the version string
    /// `version`.
    ///
    /// Neither `TechDetection` nor `Technology` records WHICH signal supplied the
    /// string sitting in its single `version` field — both structs are defined in
    /// src/types.rs and carry no provenance — so the rank of an already-stored version
    /// cannot be looked up. It has to be recovered from the evidence list, and since
    /// we cannot tell which entry produced it, this takes the maximum over all of
    /// them. This is an approximation, not a measurement, and the two callers sit on
    /// opposite sides of it, so the direction of the error matters in each:
    ///
    /// **Ranking the INCUMBENT** (both callers do this). The max over-estimates
    /// whenever the entry also holds a higher-ranked signal that carried no version.
    /// Over-estimating here is the safe direction: it can only make the stored version
    /// HARDER to displace, so it never causes a replacement an exact tracker would not
    /// also make. The worst case is declining an upgrade and keeping the old string —
    /// exactly what the code did before any of this existed.
    ///
    /// **Ranking the CANDIDATE** (only the `src/lib.rs` folds do this; inside
    /// `update_detection` the candidate's rank is computed exactly, from the
    /// signal_type and value of the very call supplying it). Here the max is NOT
    /// conservative: an inflated candidate rank can displace a version it should have
    /// lost to. The exposure is one specific shape, and it is worth stating rather
    /// than hiding:
    ///
    /// - The probe fold cannot hit it. Every signal `parse_probe_responses` emits has
    ///   signal_type `probe`, so the max is taken over a single rank and equals it.
    /// - The asset fold can. `inspect_assets` fills one map from two layers, so a
    ///   technology may hold a `script_src` banner version (rank 40) alongside a
    ///   versionless `source_map` signal (rank 95) — `try_source_map` emits exactly
    ///   that when a `node_modules/<pkg>/` path names a package but no version could
    ///   be parsed out of it. The rank-40 string is then judged at 95 and could
    ///   displace a `meta` or `header` version that should have outranked it.
    ///
    /// Closing that gap properly means giving the detection a provenance field, which
    /// means editing src/types.rs; it is deliberately left open rather than papered
    /// over with a comment claiming the ranks are exact.
    pub(crate) fn version_rank_from_signals(signals: &[Signal], version: &str) -> u8 {
        signals
            .iter()
            .map(|signal| Self::version_source_rank(&signal.signal_type, &signal.value, version))
            .max()
            .unwrap_or(0)
    }

    /// THE version-precedence rule. Every place that has to choose between two
    /// candidate version strings for one technology asks this and nothing else.
    ///
    /// It lives alone because it used to live in more than one place: the fold sites
    /// in `src/lib.rs` carried their own `if t.version.is_none()` copy of the rule and
    /// were simply never updated when ranking arrived, which is how `"probe" => 100`
    /// came to be inert while the ranking table read as though it governed everything.
    /// A precedence rule with three implementations has three behaviours.
    ///
    /// `candidate_rank` is supplied by the caller rather than computed here because
    /// the callers know different amounts: `update_detection` has the exact
    /// signal_type and value behind its candidate, while a fold site can only
    /// approximate via [`Self::version_rank_from_signals`]. The comparison itself must
    /// not differ between them, so only the comparison is here.
    ///
    /// A candidate must rank STRICTLY higher to win. Ties keep the incumbent, so among
    /// equally trustworthy sources the first to arrive still wins: with one slot and
    /// no way to tell two same-rank sources apart any other rule is just a different
    /// arbitrary choice, and this one leaves the pre-existing behaviour untouched for
    /// the common case where every candidate comes from the same tier.
    pub(crate) fn version_outranks(
        candidate_rank: u8,
        incumbent: Option<&str>,
        incumbent_signals: &[Signal],
    ) -> bool {
        match incumbent {
            // Nothing to displace: any candidate at all beats an empty slot. Note that
            // this arm never consults the ranking, which is why a layer with no arm in
            // `version_source_rank` can still fill a version.
            None => true,
            Some(incumbent) => {
                candidate_rank > Self::version_rank_from_signals(incumbent_signals, incumbent)
            }
        }
    }

    /// Record a detection signal, and keep the BEST-SOURCED version rather than the
    /// first one to arrive.
    ///
    /// Every detection layer funnels through here, which is what makes it the right
    /// place to arbitrate between version candidates: the layers stay pure evidence
    /// producers and none of them has to know what any other layer found.
    ///
    /// A candidate replaces the stored version only if [`Self::version_outranks`] says
    /// so — the same predicate the `src/lib.rs` folds use, so a version that loses here
    /// loses there too. This function arbitrates only within ONE detection map; a probe
    /// or source-map version competes with what `analyze()` found at the fold, not here.
    ///
    /// `value` is truncated to 100 characters to keep signal payloads compact. The
    /// ranking above is computed from the UNTRUNCATED value, so the candidate is
    /// judged on the whole URL even when only a prefix is retained as evidence.
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

        // Resolved BEFORE this call's signal is appended, so that
        // `version_rank_from_signals` sees only prior evidence. Appending first would let
        // the candidate's own signal set the bar it then has to clear, and no candidate
        // could ever win.
        if let Some(candidate) = version {
            // Exact candidate rank: this call knows the signal_type and the untruncated
            // value that produced `candidate`, which the fold sites in src/lib.rs do not.
            let candidate_rank = Self::version_source_rank(signal_type, value, &candidate);
            if Self::version_outranks(candidate_rank, entry.version.as_deref(), &entry.signals) {
                entry.version = Some(candidate);
            }
        }

        entry.signals.push(Signal {
            signal_type: signal_type.to_string(),
            value: value_trunc.to_string(),
            weight,
        });
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
    /// Fold technologies that are the same product under different names into one.
    ///
    /// The Wappalyzer database lists some products more than once — "All in One SEO"
    /// and "All in One SEO Pack" are one plugin renamed — so a single installation was
    /// reported as two or three separate technologies, each with its own signals.
    ///
    /// Signals are concatenated (deduped immediately afterwards by the caller), the
    /// highest confidence wins, and a version is taken from the alias only when the
    /// canonical entry does not already have one.
    fn merge_aliases(&self, technologies: &mut Vec<Technology>) {
        if self.tech_aliases.is_empty() {
            return;
        }
        // alias name -> canonical name, for the entries actually present
        let mut to_merge: Vec<(usize, String)> = Vec::new();
        for (idx, tech) in technologies.iter().enumerate() {
            if let Some(canonical) = self.tech_aliases.get(&tech.name.to_lowercase()) {
                to_merge.push((idx, canonical.clone()));
            }
        }
        if to_merge.is_empty() {
            return;
        }

        // Drain highest index first so the remaining indices stay valid.
        for (idx, canonical) in to_merge.into_iter().rev() {
            let alias = technologies.remove(idx);
            match technologies.iter_mut().find(|t| t.name.eq_ignore_ascii_case(&canonical)) {
                Some(target) => {
                    target.signals.extend(alias.signals);
                    target.confidence = target.confidence.max(alias.confidence);
                    if target.version.is_none() {
                        target.version = alias.version;
                    }
                }
                None => {
                    // Canonical entry absent: rename in place rather than dropping the
                    // detection, and rebuild the metadata so categories/CPE match the
                    // canonical name instead of the alias.
                    let mut renamed = self.build_technology(&canonical, alias.confidence, alias.version);
                    renamed.signals = alias.signals;
                    technologies.push(renamed);
                }
            }
        }
    }

    pub fn finalize_gating(&self, technologies: &mut Vec<Technology>) {
        // Fold duplicate names for one product into a single entry before anything else,
        // so signal dedup and gating see one technology rather than two or three.
        self.merge_aliases(technologies);

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

/// A TechnologyAnalyzer with everything empty, for testing instance methods that
    /// only touch one field. Cheaper and more predictable than loading the database.
    fn empty_analyzer() -> TechnologyAnalyzer {
        TechnologyAnalyzer {
            database: WappalyzerDatabase {
                technologies: HashMap::new(),
                categories: HashMap::new(),
            },
            html_patterns: HashMap::new(),
            header_patterns: HashMap::new(),
            url_patterns: HashMap::new(),
            script_patterns: HashMap::new(),
            inline_script_patterns: HashMap::new(),
            meta_patterns: HashMap::new(),
            css_patterns: HashMap::new(),
            cookie_patterns: HashMap::new(),
            name_index: HashMap::new(),
            category_name_map: HashMap::new(),
            favicon_hashes: HashMap::new(),
            dns_patterns: HashMap::new(),
            js_patterns: HashMap::new(),
            cpe_overrides: HashMap::new(),
            tech_aliases: HashMap::new(),
            version_patches: HashMap::new(),
            implies_graph: HashMap::new(),
            dom_rules: HashMap::new(),
            text_patterns: HashMap::new(),
        }
    }

    fn make_tech(name: &str) -> Technology {
        Technology {
            name: name.to_string(),
            confidence: 100,
            version: None,
            categories: vec![],
            website: None,
            description: None,
            icon: None,
            cpe: None,
            saas: None,
            pricing: None,
            signals: vec![],
        }
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
    fn test_merge_aliases_folds_duplicates_into_one_entry() {
        // "All in One SEO" and "All in One SEO Pack" are one plugin under its old and
        // new database names, so one installation was reported as two technologies.
        let mut analyzer = empty_analyzer();
        analyzer
            .tech_aliases
            .insert("all in one seo pack".to_string(), "All in One SEO".to_string());

        let mut techs = vec![
            Technology {
                name: "All in One SEO".into(),
                confidence: 90,
                version: None,
                categories: vec![],
                website: None,
                description: None,
                icon: None,
                cpe: None,
                saas: None,
                pricing: None,
                signals: vec![Signal { signal_type: "html".into(), value: "a".into(), weight: 90 }],
            },
            Technology {
                name: "All in One SEO Pack".into(),
                confidence: 100,
                version: Some("5.0.0.1".into()),
                categories: vec![],
                website: None,
                description: None,
                icon: None,
                cpe: None,
                saas: None,
                pricing: None,
                signals: vec![Signal { signal_type: "script".into(), value: "b".into(), weight: 100 }],
            },
        ];

        analyzer.merge_aliases(&mut techs);

        assert_eq!(techs.len(), 1, "the alias should have folded into the canonical entry");
        let merged = &techs[0];
        assert_eq!(merged.name, "All in One SEO");
        assert_eq!(merged.confidence, 100, "the higher confidence should win");
        assert_eq!(merged.version.as_deref(), Some("5.0.0.1"), "version taken from the alias");
        assert_eq!(merged.signals.len(), 2, "signals from both entries should survive");
    }

    #[test]
    fn test_merge_aliases_renames_when_canonical_is_absent() {
        // Only the alias was detected: rename rather than drop the detection.
        let mut analyzer = empty_analyzer();
        analyzer
            .tech_aliases
            .insert("aioseo".to_string(), "All in One SEO".to_string());

        let mut techs = vec![Technology {
            name: "AIOSEO".into(),
            confidence: 75,
            version: Some("5.0".into()),
            categories: vec![],
            website: None,
            description: None,
            icon: None,
            cpe: None,
            saas: None,
            pricing: None,
            signals: vec![Signal { signal_type: "html".into(), value: "x".into(), weight: 75 }],
        }];

        analyzer.merge_aliases(&mut techs);
        assert_eq!(techs.len(), 1);
        assert_eq!(techs[0].name, "All in One SEO");
        assert_eq!(techs[0].version.as_deref(), Some("5.0"));
        assert_eq!(techs[0].signals.len(), 1, "the detection must not be lost");
    }

    #[test]
    fn test_merge_aliases_leaves_unrelated_names_alone() {
        // "HashThemes Total" and "Total WordPress Theme" share a word but are different
        // products. Merging them would be worse than reporting both.
        let analyzer = empty_analyzer();
        let mut techs = vec![
            make_tech("HashThemes Total"),
            make_tech("Total WordPress Theme"),
        ];
        analyzer.merge_aliases(&mut techs);
        assert_eq!(techs.len(), 2, "distinct products must not be merged");
    }

    #[test]
    fn test_react_marker_is_required_for_generic_exports_version() {
        // Regression: `exports.version=` is generic — every UMD package sets it. A
        // vendor bundle contains many packages, and whichever one set it was reported
        // as React's version, producing "React 5.53.3" (never a real React release).
        // The guard is that the bundle must actually contain React internals.
        let marker = regex::Regex::new(
            r"react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__|ReactCurrentOwner|ReactCurrentDispatcher|react\.element|react\.fragment"
        ).unwrap();

        // A vendor bundle whose version belongs to some unrelated package.
        let unrelated = r#"var x={};exports.version="5.53.3";module.exports=x;"#;
        assert!(
            !marker.is_match(unrelated),
            "an unrelated bundle must not satisfy the React marker"
        );

        // A genuine React bundle.
        let real_react = r#"var ReactCurrentOwner={current:null};exports.version="18.3.1";"#;
        assert!(marker.is_match(real_react), "a real React bundle must satisfy the marker");
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

    // ── version precedence (source quality, not arrival order) ───────────────

    /// One `update_detection` call, so the tests below read as a sequence of layers
    /// reporting what they found.
    fn feed(
        detected: &mut HashMap<String, TechDetection>,
        signal_type: &str,
        value: &str,
        version: &str,
    ) {
        TechnologyAnalyzer::update_detection(
            detected,
            "WordPress",
            signal_type,
            value,
            80,
            Some(version.to_string()),
        );
    }

    /// The whole point of ranking version sources: the better source must win no
    /// matter which layer happened to run first.
    ///
    /// Both orderings are asserted deliberately. Under the old first-write-wins rule
    /// the `(meta, then query param)` ordering already produced the right answer by
    /// accident, so a test that only checked that ordering would pass against the bug
    /// it is supposed to catch. It is the `(query param, then meta)` ordering that
    /// bites — that is the real-world one, since `analyze_scripts` runs before
    /// `analyze_meta_tags`.
    ///
    /// The scenario is the common WordPress one: every asset WordPress enqueues is
    /// stamped with `?ver=<core version>` as a cache-buster, and that number goes
    /// stale or gets frozen by caching plugins, while the generator meta tag is the
    /// installation stating its own version.
    #[test]
    fn test_better_version_source_wins_in_either_arrival_order() {
        let query_param = (
            "script_src",
            "https://example.com/wp-includes/js/wp-emoji-release.min.js?ver=6.5.3",
            "6.5.3",
        );
        let meta_generator = ("meta", "generator: WordPress 6.8.1", "6.8.1");

        for (first, second) in [(query_param, meta_generator), (meta_generator, query_param)] {
            let mut detected: HashMap<String, TechDetection> = HashMap::new();
            feed(&mut detected, first.0, first.1, first.2);
            feed(&mut detected, second.0, second.1, second.2);

            assert_eq!(
                detected["WordPress"].version.as_deref(),
                Some("6.8.1"),
                "meta generator must beat a ?ver= cache-buster; order was {} then {}",
                first.0,
                second.0,
            );
            // Losing the version arbitration must not lose the evidence: both layers
            // still observed WordPress, and confidence is computed from signals.
            assert_eq!(detected["WordPress"].signals.len(), 2);
        }
    }

    /// Within one signal type, a version in the URL path outranks one in the query
    /// string — the distinction `version_is_from_query_string` exists to make. Both
    /// of these arrive from `analyze_scripts` as `script_src`, so signal type alone
    /// cannot separate them.
    #[test]
    fn test_path_version_outranks_query_version_within_script_src() {
        let cdn_path = (
            "script_src",
            "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js",
            "3.7.1",
        );
        let cache_buster = ("script_src", "https://example.com/js/jquery.min.js?ver=1.2.3", "1.2.3");

        for (first, second) in [(cdn_path, cache_buster), (cache_buster, cdn_path)] {
            let mut detected: HashMap<String, TechDetection> = HashMap::new();
            feed(&mut detected, first.0, first.1, first.2);
            feed(&mut detected, second.0, second.1, second.2);
            assert_eq!(
                detected["WordPress"].version.as_deref(),
                Some("3.7.1"),
                "CDN path version must beat a query parameter; first was {}",
                first.1,
            );
        }
    }

    /// Equal-rank candidates keep the incumbent — the documented tie rule.
    #[test]
    fn test_equal_rank_version_sources_keep_the_first() {
        let mut detected: HashMap<String, TechDetection> = HashMap::new();
        feed(&mut detected, "html", "<!-- built with 1.0.0 -->", "1.0.0");
        feed(&mut detected, "html", "<!-- and also 2.0.0 -->", "2.0.0");
        assert_eq!(detected["WordPress"].version.as_deref(), Some("1.0.0"));
    }

    /// An empty version slot is filled by whatever turns up, however poorly ranked.
    /// Ranking arbitrates between candidates; it must never suppress the only one.
    #[test]
    fn test_weakest_source_still_fills_an_empty_version() {
        let mut detected: HashMap<String, TechDetection> = HashMap::new();
        TechnologyAnalyzer::update_detection(
            &mut detected,
            "WordPress",
            "header",
            "x-powered-by: wordpress",
            90,
            None,
        );
        feed(&mut detected, "page-text", "Proudly powered by WordPress 6.8.1", "6.8.1");
        assert_eq!(detected["WordPress"].version.as_deref(), Some("6.8.1"));
    }

    // ── implied technologies are bounded by their parent ─────────────────────

    fn implies(name: &str, weight: u8) -> ImpliedTech {
        ImpliedTech { name: name.to_string(), weight, version: None }
    }

    /// An inference must never be more confident than the observation behind it, and
    /// a chain of inferences must decay rather than hold flat.
    ///
    /// The graph here is the motivating real one, with the database's usual bare
    /// `"implies"` entries that `build_implies_graph` defaults to weight 100: observe
    /// WordPress weakly, and both PHP and (transitively) MySQL used to land at a flat
    /// 100 — more confident than the only thing actually seen.
    #[test]
    fn test_implied_confidence_is_bounded_by_and_decays_from_its_parent() {
        let mut analyzer = empty_analyzer();
        analyzer.implies_graph.insert("WordPress".to_string(), vec![implies("PHP", 100)]);
        analyzer.implies_graph.insert("PHP".to_string(), vec![implies("MySQL", 100)]);

        let mut detected: HashMap<String, TechDetection> = HashMap::new();
        TechnologyAnalyzer::update_detection(
            &mut detected,
            "WordPress",
            "html",
            "/wp-content/themes/x/style.css",
            55,
            None,
        );

        analyzer.expand_implied(&mut detected);

        let score = |name: &str| compute_noisy_or(&detected[name].signals);
        let parent = score("WordPress");
        let child = score("PHP");
        let grandchild = score("MySQL");

        assert_eq!(parent, 55, "the only observation is a single weight-55 signal");
        // round(90 * 55 / 100) = 50, round(90 * 50 / 100) = 45.
        assert_eq!(child, 50);
        assert_eq!(grandchild, 45);
        assert!(child < parent, "an inference cannot beat its evidence");
        assert!(grandchild < child, "a two-hop chain must decay, not hold flat");

        // One implied signal each — the guard that stops chains compounding.
        assert_eq!(detected["PHP"].signals.len(), 1);
        assert_eq!(detected["MySQL"].signals.len(), 1);
        assert_eq!(detected["PHP"].signals[0].signal_type, "implied");
        assert_eq!(detected["PHP"].signals[0].value, "WordPress");
        assert_eq!(detected["MySQL"].signals[0].value, "PHP");
    }

    /// An explicit `confidence:` below the ceiling is honoured as written, and still
    /// scaled by the parent. The ceiling only removes the unearned default of 100.
    #[test]
    fn test_explicit_edge_confidence_is_scaled_not_replaced() {
        let mut analyzer = empty_analyzer();
        analyzer.implies_graph.insert("Parent".to_string(), vec![implies("Child", 50)]);

        let mut detected: HashMap<String, TechDetection> = HashMap::new();
        TechnologyAnalyzer::update_detection(&mut detected, "Parent", "html", "marker", 80, None);
        analyzer.expand_implied(&mut detected);

        // round(50 * 80 / 100) = 40 — the edge's own 50, discounted by the parent.
        assert_eq!(compute_noisy_or(&detected["Child"].signals), 40);
    }

    /// A technology we actually observed keeps its own evidence and gains no implied
    /// signal, however strongly something else implies it. Preserving this is what
    /// stops a weak parent from dragging down a well-evidenced child.
    #[test]
    fn test_directly_detected_technology_receives_no_implied_signal() {
        let mut analyzer = empty_analyzer();
        analyzer.implies_graph.insert("WordPress".to_string(), vec![implies("PHP", 100)]);

        let mut detected: HashMap<String, TechDetection> = HashMap::new();
        TechnologyAnalyzer::update_detection(&mut detected, "WordPress", "html", "wp", 40, None);
        TechnologyAnalyzer::update_detection(
            &mut detected,
            "PHP",
            "header",
            "x-powered-by: PHP/8.2.1",
            100,
            Some("8.2.1".to_string()),
        );

        analyzer.expand_implied(&mut detected);

        assert_eq!(detected["PHP"].signals.len(), 1);
        assert_eq!(detected["PHP"].signals[0].signal_type, "header");
        assert_eq!(compute_noisy_or(&detected["PHP"].signals), 100);
    }

    /// A cycle in the graph must terminate. The `contains_key` guard is what does it:
    /// the second time round, the technology is already present and is skipped.
    #[test]
    fn test_implies_cycle_terminates() {
        let mut analyzer = empty_analyzer();
        analyzer.implies_graph.insert("A".to_string(), vec![implies("B", 100)]);
        analyzer.implies_graph.insert("B".to_string(), vec![implies("A", 100)]);

        let mut detected: HashMap<String, TechDetection> = HashMap::new();
        TechnologyAnalyzer::update_detection(&mut detected, "A", "html", "marker", 100, None);
        analyzer.expand_implied(&mut detected);

        assert_eq!(detected.len(), 2);
        assert_eq!(detected["A"].signals.len(), 1);
        assert_eq!(detected["B"].signals.len(), 1);
        assert_eq!(compute_noisy_or(&detected["B"].signals), 90);
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
    fn look_around_patterns_now_compile_on_the_fallback_engine() {
        // These used to be dropped at startup, silently narrowing detection for the
        // technologies that relied on them. Every shape below is taken verbatim from
        // the database.
        for pat in [
            r"^(?!.*player).*aniview\.com/",
            r"<(?!svg)[^>]+\sdata-v(?:ue)?-",
            r"\b(?<!-)UPS\b",
            r"^(?:(?!psecn).)*$",
            r"/sites/(?!(?:default|all)/).*/(?:files|themes|modules)/",
            r"leaflet.{0,32}\.js(?!.+shopify)",
            r"(?<!elo\.io)/cargo\.",
            r"\.acquire\.io/(?!cobrowse)",
        ] {
            let out = TechnologyAnalyzer::compile_single_pattern(pat)
                .unwrap_or_else(|e| panic!("compilation errored for {pat}: {e}"));
            let compiled = out.unwrap_or_else(|| panic!("{pat} should compile, not be skipped"));
            assert!(
                matches!(compiled.regex, PatternRegex::Fancy(_)),
                "{pat} should land on the backtracking engine"
            );
        }
    }

    #[test]
    fn look_around_semantics_are_actually_honoured() {
        // Compiling is not enough — the assertion has to work, or we would have traded
        // a missing pattern for a wrong one.
        let neg = TechnologyAnalyzer::compile_single_pattern(r"^(?:(?!psecn).)*$")
            .unwrap()
            .expect("compiles");
        assert!(neg.regex.is_match("harmless string"));
        assert!(!neg.regex.is_match("contains psecn here"));

        let drupal = TechnologyAnalyzer::compile_single_pattern(
            r"/sites/(?!(?:default|all)/).*/(?:files|themes|modules)/",
        )
        .unwrap()
        .expect("compiles");
        assert!(drupal.regex.is_match("/sites/example.com/files/"));
        assert!(!drupal.regex.is_match("/sites/default/files/"));
        assert!(!drupal.regex.is_match("/sites/all/modules/"));

        let leaflet = TechnologyAnalyzer::compile_single_pattern(r"leaflet.{0,32}\.js(?!.+shopify)")
            .unwrap()
            .expect("compiles");
        assert!(leaflet.regex.is_match("/js/leaflet.js"));
        assert!(!leaflet.regex.is_match("/js/leaflet.js?from=shopify"));

        let lookbehind = TechnologyAnalyzer::compile_single_pattern(r"(?<!elo\.io)/cargo\.")
            .unwrap()
            .expect("compiles");
        assert!(lookbehind.regex.is_match("https://example.com/cargo."));
        assert!(!lookbehind.regex.is_match("https://elo.io/cargo."));
    }

    #[test]
    fn fallback_still_extracts_capture_groups() {
        // Version extraction must work through the fallback engine too.
        let p = TechnologyAnalyzer::compile_single_pattern(
            r"leaflet-((?:\d+\.)+\d+)\.js(?!.+shopify)\;version:\1",
        )
        .unwrap()
        .expect("compiles");
        let caps = p.regex.captures("/js/leaflet-1.9.4.js").expect("should match");
        assert_eq!(
            TechnologyAnalyzer::extract_version(&p.version, &caps).as_deref(),
            Some("1.9.4")
        );
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
