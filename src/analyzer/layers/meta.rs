//! Meta tag analysis methods for [`TechnologyAnalyzer`].

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::HashMap;
use once_cell::sync::Lazy;
use regex::Regex;

impl TechnologyAnalyzer {
    /// Analyze meta tags in HTML
    pub(crate) fn analyze_meta_tags(&self, html: &str, detected: &mut HashMap<String, TechDetection>) {
        static META_REGEX: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r#"(?i)<meta[^>]*name=['"]([^'"]*)['"]*[^>]*content=['"]([^'"]*)['"]*[^>]*>"#).unwrap()
        });

        for meta_match in META_REGEX.captures_iter(html) {
            if let (Some(meta_name), Some(meta_content)) = (meta_match.get(1), meta_match.get(2)) {
                let meta_name_lower = meta_name.as_str().to_lowercase();

                for (tech_name, meta_patterns) in &self.meta_patterns {
                    if let Some(patterns) = meta_patterns.get(&meta_name_lower) {
                        for pattern in patterns {
                            if let Some(captures) = pattern.regex.captures(meta_content.as_str()) {
                                let version = Self::extract_version(&pattern.version, &captures);
                                Self::update_detection(detected, tech_name, "meta", &meta_name_lower, pattern.confidence, version);
                            }
                        }
                    }
                }
            }
        }
    }

}
