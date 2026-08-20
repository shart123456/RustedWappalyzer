use crate::types::*;
use crate::analyzer::TechnologyAnalyzer;
use std::collections::HashMap;

impl TechnologyAnalyzer {
    /// Match compiled Wappalyzer `dom` rules against the HTML body.
    ///
    /// A rule fires only when an element matching its selector *also* satisfies
    /// every attribute condition and the text condition (if any). Bare-selector
    /// (exists) rules fire on presence. This condition enforcement is what stops
    /// generic selectors (`div`, `*`, `body > div`, `a,body`) from matching every
    /// page. Weight is a conservative 75; version is extracted from a matching
    /// attribute/text pattern when the rule carries one.
    pub(crate) fn analyze_dom(
        &self,
        html: &str,
        detected: &mut HashMap<String, TechDetection>,
    ) {
        let document = scraper::Html::parse_document(html);

        for (tech_name, rules) in &self.dom_rules {
            'rules: for rule in rules {
                let Ok(selector) = scraper::Selector::parse(&rule.selector) else {
                    continue;
                };
                for element in document.select(&selector) {
                    if let Some(version) = Self::dom_rule_matches(rule, element) {
                        Self::update_detection(detected, tech_name, "dom", &rule.selector, 75, version);
                        break 'rules; // one match per tech is enough
                    }
                }
            }
        }
    }

    /// Evaluate a rule's conditions against a single candidate element.
    ///
    /// Returns `None` if the element fails any condition, or `Some(version)` if
    /// it satisfies all of them (`version` is the first version extracted from a
    /// matching attribute/text pattern, or `None`).
    fn dom_rule_matches(rule: &CompiledDomRule, element: scraper::ElementRef) -> Option<Option<String>> {
        let mut version: Option<String> = None;

        // Attribute conditions — all must hold on this element.
        for (attr_name, pattern) in &rule.attributes {
            let value = element
                .value()
                .attrs()
                .find(|(k, _)| k.eq_ignore_ascii_case(attr_name))
                .map(|(_, v)| v)?; // attribute absent → no match
            if let Some(cp) = pattern {
                let caps = cp.regex.captures(value)?; // value doesn't match → no match
                if version.is_none() {
                    version = Self::extract_version(&cp.version, &caps);
                }
            }
            // else: presence-only attribute — already satisfied by being found.
        }

        // Text condition — the element's combined text must match.
        if let Some(cp) = &rule.text {
            let text: String = element.text().collect::<Vec<_>>().join("");
            let caps = cp.regex.captures(text.trim())?;
            if version.is_none() {
                version = Self::extract_version(&cp.version, &caps);
            }
        }

        Some(version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CompiledDomRule;

    fn el<'a>(doc: &'a scraper::Html, sel: &str) -> scraper::ElementRef<'a> {
        doc.select(&scraper::Selector::parse(sel).unwrap()).next().unwrap()
    }

    #[test]
    fn attribute_condition_gates_generic_selector() {
        // SvelteKit-style: the broad `a,body` selector is gated by a specific
        // attribute — the bug was matching on the selector alone.
        let rule = CompiledDomRule {
            selector: "a,body".into(),
            attributes: vec![("data-sveltekit-preload-data".into(), None)],
            text: None,
            exists: false,
        };
        let plain = scraper::Html::parse_document("<html><body><a>x</a></body></html>");
        assert!(TechnologyAnalyzer::dom_rule_matches(&rule, el(&plain, "body")).is_none());

        let real = scraper::Html::parse_document(
            "<html><body data-sveltekit-preload-data='hover'>x</body></html>");
        assert!(TechnologyAnalyzer::dom_rule_matches(&rule, el(&real, "body")).is_some());
    }

    #[test]
    fn text_condition_gates_generic_selector() {
        // Apereo CAS-style: any `title` element used to match; now the text must.
        let cp = TechnologyAnalyzer::compile_single_pattern("Central Authentication Service")
            .unwrap().unwrap();
        let rule = CompiledDomRule { selector: "title".into(), attributes: vec![], text: Some(cp), exists: false };
        let other = scraper::Html::parse_document("<html><head><title>My Blog</title></head></html>");
        assert!(TechnologyAnalyzer::dom_rule_matches(&rule, el(&other, "title")).is_none());
        let cas = scraper::Html::parse_document(
            "<html><head><title>CAS Central Authentication Service</title></head></html>");
        assert!(TechnologyAnalyzer::dom_rule_matches(&rule, el(&cas, "title")).is_some());
    }

    #[test]
    fn attribute_pattern_extracts_version() {
        // Qwik-style: `*` with a q:version attribute pattern yields a version.
        let cp = TechnologyAnalyzer::compile_single_pattern(r"^([\d\.]+)\;version:\1")
            .unwrap().unwrap();
        let rule = CompiledDomRule { selector: "*".into(), attributes: vec![("q:version".into(), Some(cp))], text: None, exists: false };
        let doc = scraper::Html::parse_document("<html q:version='1.5.0'><body></body></html>");
        assert_eq!(TechnologyAnalyzer::dom_rule_matches(&rule, el(&doc, "html")),
                   Some(Some("1.5.0".to_string())));
    }

    #[test]
    fn exists_rule_matches_on_presence() {
        // Vite-style specific exists selector still fires on presence.
        let rule = CompiledDomRule { selector: "script#vite-legacy-polyfill".into(), attributes: vec![], text: None, exists: true };
        let doc = scraper::Html::parse_document(
            "<html><body><script id='vite-legacy-polyfill'></script></body></html>");
        assert!(TechnologyAnalyzer::dom_rule_matches(&rule, el(&doc, "script")).is_some());
    }

    #[test]
    fn properties_only_rules_are_dropped_at_compile() {
        // React/Preact `properties` rules (runtime JS) aren't statically checkable
        // and must not become exists rules on a generic selector.
        let dom = serde_json::json!({
            "body > div": { "properties": { "_reactRootContainer": "" } },
            "div[id*='react-root']": { "exists": "" }
        });
        let rules = TechnologyAnalyzer::compile_dom_rules(&dom);
        assert_eq!(rules.len(), 1, "properties-only rule should be dropped");
        assert_eq!(rules[0].selector, "div[id*='react-root']");
    }
}
