//! CSS and inline script analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Analyze inline CSS (<style> blocks) for technology patterns
    pub(crate) fn analyze_css(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        static STYLE_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?is)<style[^>]*>(.*?)</style>").unwrap()
        });

        let mut css_content = String::new();
        for cap in STYLE_REGEX.captures_iter(html) {
            if let Some(content) = cap.get(1) {
                css_content.push_str(content.as_str());
                css_content.push('\n');
            }
        }

        if css_content.is_empty() {
            return;
        }

        for (tech_name, patterns) in &self.css_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(&css_content) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name, "css", pattern.regex.as_str(), pattern.confidence, version);
                }
            }
        }
    }

    /// Analyze inline <script> block content against `scripts` field patterns

    pub(crate) fn analyze_inline_scripts(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        static INLINE_SCRIPT_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"(?is)<script(?:\s[^>]*)?>(.+?)</script>").unwrap()
        });

        let mut content = String::new();
        for cap in INLINE_SCRIPT_REGEX.captures_iter(html) {
            if let Some(body) = cap.get(1) {
                content.push_str(body.as_str());
                content.push('\n');
            }
        }

        if content.is_empty() {
            return;
        }

        for (tech_name, patterns) in &self.inline_script_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(&content) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name, "script", pattern.regex.as_str(), pattern.confidence, version);
                }
            }
        }

        // Generic heuristic pass over all concatenated inline script content
        self.scan_js_version_heuristics(&content, detected);
    }

    /// Heuristic scanner for generic JS version variable patterns in inline script content.
    ///
    /// Looks for common patterns like:
    ///   - `jQuery.version = "3.7.1"`
    ///   - `REACT_VERSION = "18.2.0"`
    ///   - `window.__APP_VER__ = "2.0.0"`
    ///
    /// Matches the extracted name against the technology database (case-insensitive).
    /// Detected with confidence 75 to distinguish from authoritative pattern matches.

    pub(crate) fn scan_js_version_heuristics(&self, content: &str, detected: &mut HashMap<String, TechDetection>) {
        // `SomeName.version = "x.y.z"` or `SomeName.version: "x.y.z"`
        static OBJ_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)\b([A-Za-z][A-Za-z0-9_$]{1,30})\.version\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });
        // `LIB_VERSION = "x.y.z"` or `__LIB_VERSION__ = "x.y.z"`
        static CONST_VER_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)\b([A-Za-z_][A-Za-z0-9_]{2,30})_version\s*[=:]\s*["'](\d+\.\d+(?:\.\d+)?)["']"#).unwrap()
        });

        for cap in OBJ_VER_RE.captures_iter(content) {
            let raw = cap[1].to_lowercase();
            let ver = cap[2].to_string();
            if let Some(tech) = self.find_tech_name(&raw) {
                Self::update_detection(detected, tech, "script", "js-heuristic", 75, Some(ver));
            }
        }

        for cap in CONST_VER_RE.captures_iter(content) {
            let raw = cap[1].to_lowercase();
            let ver = cap[2].to_string();
            if let Some(tech) = self.find_tech_name(&raw) {
                Self::update_detection(detected, tech, "script", "js-heuristic", 75, Some(ver));
            }
        }
    }

    /// Analyze cookies from response headers for technology patterns

    pub(crate) fn match_inline_script_patterns(&self, content: &str, detected: &mut HashMap<String, TechDetection>) {
        for (tech_name, patterns) in &self.inline_script_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(content) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name, "script", pattern.regex.as_str(), pattern.confidence, version);
                }
            }
        }
    }

    /// Match css_patterns against raw CSS text.

    pub(crate) fn match_css_patterns(&self, content: &str, detected: &mut HashMap<String, TechDetection>) {
        for (tech_name, patterns) in &self.css_patterns {
            for pattern in patterns {
                if let Some(captures) = pattern.regex.captures(content) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    Self::update_detection(detected, tech_name, "css", pattern.regex.as_str(), pattern.confidence, version);
                }
            }
        }
    }
}
