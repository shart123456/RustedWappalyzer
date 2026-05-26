use crate::types::*;
use crate::analyzer::TechnologyAnalyzer;
use std::collections::HashMap;

impl TechnologyAnalyzer {
    /// Match CSS selectors from the Wappalyzer `dom` field against the HTML body.
    /// Uses `scraper` for real CSS selector parsing. Presence of a matching element
    /// gives confidence 75.
    pub(crate) fn analyze_dom(
        &self,
        html: &str,
        detected: &mut HashMap<String, TechDetection>,
    ) {
        let document = scraper::Html::parse_document(html);

        for (tech_name, selectors) in &self.dom_selectors {
            for selector_str in selectors {
                if let Ok(selector) = scraper::Selector::parse(selector_str) {
                    if document.select(&selector).next().is_some() {
                        Self::update_detection(
                            detected,
                            tech_name,
                            "dom",
                            selector_str,
                            75,
                            None,
                        );
                        break; // one match per tech is enough
                    }
                }
            }
        }
    }
}
