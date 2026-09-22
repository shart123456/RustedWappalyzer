//! Visible page-text analysis (the Wappalyzer `text` field) for [`TechnologyAnalyzer`].
//!
//! `TechnologyDefinition` has always deserialized `text`, but nothing compiled or
//! matched it, so the field was dead data: in the shipped database 60 technologies
//! carry `text` patterns and 56 of those have no other detection field at all, which
//! means they could never be detected by any code path.
//!
//! `text` is not `html`. It matches what a reader *sees* on the page, not the markup:
//! a carrier name inside a minified inline script, a CSS selector or an HTML comment
//! is not page text and must not fire here. That distinction is the whole reason this
//! layer parses the document instead of running the regexes over `response.body`.
//!
//! Read [`TEXT_SIGNAL_WEIGHT`] before assuming this layer improved recall. It did not,
//! at the threshold anyone uses by default: the evidence it produces is deliberately
//! weighted below every caller's default `min_confidence`, because the patterns it
//! matches are carrier names in prose. It makes the field reachable *on request*, and
//! makes a text mention visible in the signal list of a technology found some other
//! way. Both of those are worth having; neither is "56 technologies now detected".

use crate::analyzer::TechnologyAnalyzer;
use crate::types::*;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use once_cell::sync::Lazy;
use serde_json::Value;

/// Weight of a single `page-text` signal — and the reason this layer is opt-in.
///
/// All but one of the 66 `text` patterns in the shipped database is a shipping carrier's
/// name (the exception is Elcom's `Web CMS by Elcom`), and most are matched with nothing
/// more than a word boundary: `\bUPS\b`, `\bDPD\b`, `\bGLS\b`, `\bDX\b`, `\bHermes\b`.
/// The intended evidence is a carrier logo row on a checkout page, but the same regex
/// fires on a news article about UPS, on a page that mentions Hermès the fashion house,
/// or on any page that happens to use one of those two- and three-letter strings as an
/// ordinary word or acronym. Giving these the database's nominal confidence (all 66 parse
/// to 100; not one carries an explicit `\;confidence:` suffix) would put a dozen couriers
/// on unrelated pages at full confidence, which is strictly worse than the zero recall it
/// replaced.
///
/// # What 45 actually buys, stated without optimism
///
/// `page-text` is classified into the `PageDocument` independence class — see the
/// `"page-text"` arm of `explicit_class` in `src/confidence.rs`, where that placement is
/// argued at length. Within a class only the strongest signal counts, so **a page-text
/// signal never raises the confidence of any technology in the shipped database**:
///
/// * 56 of the 60 `text` technologies have no other detection field at all, so a
///   page-text signal is their only signal and their score is exactly this weight. Two
///   of those 56 — APC and Asendia — carry nothing but the start-anchored typo that
///   `compile_text_patterns` rejects below, leaving 54 this layer can actually reach.
/// * The other four — Elcom (`meta`), Cubyn (`scriptSrc`, `scripts`), PostNL and DHL
///   (`dom`) — corroborate through fields that are themselves page-document signals and
///   that all outweigh 45. When one of those fires, this layer adds a visible entry to
///   the signal list and nothing to the number.
///
/// So this is **evidence a caller can inspect, not a recall improvement at the default
/// threshold**. 45 sits below the `min_confidence` of 50 that every entry point defaults
/// to — `body.confidence.unwrap_or(50)` in `src/server/handlers.rs`,
/// `min_confidence.unwrap_or(50)` in `src/python.rs`, `default_value = "50"` on the CLI's
/// `analyze`, `batch` and `wayback` — so a carrier named on a page reaches nobody who did
/// not ask for it. The caller this serves is one doing e-commerce or logistics
/// fingerprinting who passes `confidence: 45` or lower and knowingly accepts the weaker
/// claim being made: *this page says DPD*, not *this site integrates DPD*.
///
/// Raising the weight past 50 is the one change that would make those 54 technologies
/// visible by default, and it is the change this constant exists to refuse. `\bDX\b` and
/// `\bBRT\b` firing on ordinary English prose at 55 would be a worse product than not
/// shipping the layer, and no arrangement of the confidence model can rescue a pattern
/// that weak — only a better pattern could.
///
/// Nor can this layer contribute a version: no shipped `text` pattern carries a
/// `\;version:` group, so the `"page-text" => 10` arm in `version_source_rank`
/// (`src/analyzer/mod.rs`) is defensive against a future database, not something that
/// fires today.
pub(crate) const TEXT_SIGNAL_WEIGHT: u8 = 45;

/// Elements whose character data is not page text.
///
/// `script`/`style` hold code, `template` holds inert markup that is never rendered
/// until cloned by JS, and `noscript` content is parsed by html5ever as a raw text node
/// (scripting is enabled by default) so without this it would leak the whole fallback
/// markup into the extracted text. Comments need no entry: they are `Node::Comment`,
/// not `Node::Text`, so they never reach the collector.
const NON_TEXT_ELEMENTS: [&str; 4] = ["script", "style", "noscript", "template"];

/// Database `text` patterns rejected at compile time, recorded so each is reported once.
///
/// Mirrors the `SKIPPED_PATTERNS` registry in `analyzer/mod.rs` but is kept separate on
/// purpose: those patterns are ones no regex engine can compile, these are ones that
/// compile fine and that we decline to use. Conflating the two would make the startup
/// summary's claim ("could not be compiled by either regex engine") untrue.
static REJECTED_TEXT_PATTERNS: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

/// Record one rejected pattern. Returns `true` the first time it is seen, i.e. when the
/// caller should log it. Every analyzer instance recompiles the whole database, so an
/// unconditional warning repeats the same handful of lines on every construction.
fn record_rejected_text_pattern(pattern: &str) -> bool {
    let mut guard = match REJECTED_TEXT_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.insert(pattern.to_string())
}

/// The distinct `text` patterns rejected so far, sorted for stable output.
pub fn rejected_text_patterns() -> Vec<String> {
    let guard = match REJECTED_TEXT_PATTERNS.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let mut v: Vec<String> = guard.iter().cloned().collect();
    v.sort();
    v
}

impl TechnologyAnalyzer {
    /// Match compiled `text` patterns against the visible text of the page.
    ///
    /// Called from `analyze()` like every other layer; it only ever appends Signals via
    /// `update_detection` and never decides a technology's confidence itself.
    ///
    /// This parses the response body a second time — `analyze_dom` already built a
    /// `scraper::Html` from the same bytes. Sharing one parse would mean either handing
    /// the parsed document to every layer (a change to every layer signature, i.e. a
    /// different and much larger refactor) or folding text matching into the DOM layer,
    /// which would bury an unrelated detection inside `analyze_dom`. The cost is one
    /// extra html5ever parse per analysis, paid only on the HTML path; both parses are
    /// linear in body size.
    pub(crate) fn analyze_text(&self, response: &HttpResponse, detected: &mut HashMap<String, TechDetection>) {
        if self.text_patterns.is_empty() || !Self::body_has_visible_text(&response.headers) {
            return;
        }
        let document = scraper::Html::parse_document(&response.body);
        let text = Self::visible_text(&document);
        if text.is_empty() {
            return;
        }
        Self::match_text_patterns(&self.text_patterns, &text, detected);
    }

    /// Does this response have a rendered form at all?
    ///
    /// Only an HTML document has "visible text". `analyze()` runs over whatever body came
    /// back, which for these targets is regularly JSON, plain text or an XML feed, and
    /// feeding such a body through an HTML parser yields one enormous text node holding
    /// the raw payload — at which point a courier name in any JSON string field, or in an
    /// error message, becomes "page text". Content types that do not claim to be HTML are
    /// therefore skipped here. `text/html` and `application/xhtml+xml` both contain
    /// "html", which is why the check is a substring rather than an equality test.
    ///
    /// A *missing* Content-Type counts as HTML: servers omit it, and the rest of the HTML
    /// layers already run unconditionally on the same body, so refusing to look would lose
    /// real evidence for no gain.
    fn body_has_visible_text(headers: &HashMap<String, String>) -> bool {
        match headers.get("content-type") {
            Some(content_type) => content_type.to_ascii_lowercase().contains("html"),
            None => true,
        }
    }

    /// Match a compiled text-pattern map against already-extracted page text.
    ///
    /// Split out from `analyze_text` so it can be tested without constructing an
    /// analyzer (which would load and compile the whole technology database).
    ///
    /// At most one signal is emitted per technology (the `break` below). The database
    /// lists a technology's text patterns as alternative spellings of the same claim —
    /// Australia Post is `["\bAusPost\b", "\bAustralia Post\b"]` — so matching two of
    /// them is one fact observed twice, not two independent observations, and the signal
    /// list a caller reads should say so.
    ///
    /// Today that is a statement about the *output*, not about the score: `page-text`
    /// signals share one independence class, so `compute_noisy_or` already takes the
    /// strongest and two 45s would combine to 45, not to anything higher. The `break` is
    /// what keeps that true of this layer on its own terms rather than by borrowing a
    /// guarantee from the confidence model — so that how many synonyms the database
    /// happens to list for a carrier can never become the thing that decides whether it
    /// is reported.
    pub(crate) fn match_text_patterns(
        patterns: &HashMap<String, Vec<CompiledPattern>>,
        text: &str,
        detected: &mut HashMap<String, TechDetection>,
    ) {
        for (tech_name, tech_patterns) in patterns {
            for pattern in tech_patterns {
                if let Some(captures) = pattern.regex.captures(text) {
                    let version = Self::extract_version(&pattern.version, &captures);
                    // `min` rather than a flat constant: no shipped `text` pattern carries
                    // an explicit confidence today, but if one ever does and it is *lower*
                    // than our cap, the database's more cautious value should win.
                    let weight = pattern.confidence.min(TEXT_SIGNAL_WEIGHT);
                    Self::update_detection(
                        detected,
                        tech_name,
                        "page-text",
                        pattern.regex.as_str(),
                        weight,
                        version,
                    );
                    break;
                }
            }
        }
    }

    /// Extract the rendered text of a parsed document, whitespace-normalised.
    ///
    /// Walks every node in document order and keeps the character data of text nodes
    /// that have no [`NON_TEXT_ELEMENTS`] ancestor. Document order matters: patterns
    /// like `\bAustralia Post\b` span inline elements, so emitting a subtree's text out
    /// of order would break multi-word matches.
    ///
    /// Two normalisations make those multi-word patterns work the way a reader would
    /// expect:
    ///
    /// * Every run of whitespace — including the line breaks and indentation that HTML
    ///   authors scatter through markup, and NBSP, which `char::is_whitespace` covers —
    ///   collapses to a single space, so `"Australia\n      Post"` matches.
    /// * Adjacent text nodes are separated by a space. Without it `<li>DHL</li>
    ///   <li>UPS</li>` would yield `DHLUPS` and neither word-boundary pattern would
    ///   match. The reverse case (`<span>D</span><span>PD</span>`, which a browser
    ///   renders as `DPD`) is then missed, and that is the right side to err on here:
    ///   it loses a contrived match instead of inventing one.
    pub(crate) fn visible_text(document: &scraper::Html) -> String {
        let mut collected = String::new();
        for node in document.tree.root().descendants() {
            let Some(text) = node.value().as_text() else {
                continue;
            };
            let inside_non_text = node.ancestors().any(|ancestor| {
                ancestor
                    .value()
                    .as_element()
                    .is_some_and(|element| NON_TEXT_ELEMENTS.contains(&element.name()))
            });
            if inside_non_text {
                continue;
            }
            collected.push_str(text);
            // Node separator; collapsed away below if the text already ended in space.
            collected.push(' ');
        }

        let mut normalised = String::with_capacity(collected.len());
        let mut pending_space = false;
        for ch in collected.chars() {
            if ch.is_whitespace() {
                // Never leads with a space, and a trailing run is simply dropped.
                pending_space = !normalised.is_empty();
                continue;
            }
            if pending_space {
                normalised.push(' ');
                pending_space = false;
            }
            normalised.push(ch);
        }
        normalised
    }

    /// Compile a technology's `text` field into matchable patterns.
    ///
    /// Uses the shared compilation path, so a pattern needing look-around
    /// (`\b(?<!-)UPS\b`, the only one in the database today) falls back to the
    /// backtracking engine exactly as it does for every other field.
    ///
    /// One class of pattern is rejected rather than compiled: anything anchored to the
    /// start of the subject. Two database entries are anchored — `\APC\b` (APC) and
    /// `\Asendia\b` (Asendia) — and both are plainly typos for `\bAPC\b` and
    /// `\bAsendia\b`, with the `b` of `\b` lost. `\A` is a real anchor to the `regex`
    /// crate, so `\APC\b` compiles to "the subject begins with PC", which against a whole
    /// page's text means any page whose first visible word is `PC…` is reported as
    /// running APC. Nothing a `text` pattern could legitimately want is expressible as
    /// an anchor to the very start of a page's text, so treating the whole class as
    /// unusable costs no real detection. Rejections are recorded and logged once each
    /// rather than dropped silently.
    pub(crate) fn compile_text_patterns(value: &Value) -> Vec<CompiledPattern> {
        let compiled = match Self::compile_pattern_value(value, "text") {
            Ok(patterns) => patterns,
            Err(_) => return Vec::new(),
        };

        compiled
            .into_iter()
            .filter(|pattern| {
                let source = pattern.regex.as_str();
                if !Self::text_pattern_is_start_anchored(source) {
                    return true;
                }
                if record_rejected_text_pattern(source) {
                    tracing::warn!(
                        pattern = %source,
                        "Ignoring `text` pattern anchored to the start of the page text; \
                         it would match on position rather than on the technology's name"
                    );
                }
                false
            })
            .collect()
    }

    /// Does this compiled pattern anchor at the start of the subject?
    ///
    /// Operates on the compiled source, which `compile_single_pattern` has already
    /// prefixed with `(?i)` and stripped of any `\;confidence:`/`\;version:` suffix.
    fn text_pattern_is_start_anchored(source: &str) -> bool {
        let body = source.strip_prefix("(?i)").unwrap_or(source);
        body.starts_with('^') || body.starts_with(r"\A")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns(tech: &str, json: Value) -> HashMap<String, Vec<CompiledPattern>> {
        let compiled = TechnologyAnalyzer::compile_text_patterns(&json);
        let mut map = HashMap::new();
        map.insert(tech.to_string(), compiled);
        map
    }

    fn detect(tech: &str, json: Value, html: &str) -> HashMap<String, TechDetection> {
        let document = scraper::Html::parse_document(html);
        let text = TechnologyAnalyzer::visible_text(&document);
        let mut detected = HashMap::new();
        TechnologyAnalyzer::match_text_patterns(&patterns(tech, json), &text, &mut detected);
        detected
    }

    #[test]
    fn carrier_named_in_visible_text_is_detected() {
        let detected = detect(
            "DPD",
            serde_json::json!([r"\bDPD\b"]),
            "<html><body><p>We ship with DPD and others.</p></body></html>",
        );
        let detection = detected.get("DPD").expect("visible carrier name should be detected");
        assert_eq!(detection.signals.len(), 1);
        assert_eq!(detection.signals[0].signal_type, "page-text");
        assert_eq!(detection.signals[0].weight, TEXT_SIGNAL_WEIGHT);
    }

    #[test]
    fn carrier_named_only_inside_script_is_not_detected() {
        // The precision guard: `text` means rendered page text. A carrier name that
        // appears only in a minified inline script (or a style block, or a comment) is
        // markup, not something a reader sees, and must not produce a detection.
        let detected = detect(
            "DPD",
            serde_json::json!([r"\bDPD\b"]),
            r#"<html><head><style>.DPD{color:red}</style></head>
               <body><!-- DPD tracking -->
               <script>var carriers=["DPD","GLS"];</script>
               <noscript>DPD fallback</noscript>
               <template><span>DPD</span></template>
               <p>Nothing to see here.</p></body></html>"#,
        );
        assert!(
            detected.is_empty(),
            "script/style/comment/noscript/template content is not page text: {:?}",
            detected.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn multi_word_pattern_matches_across_whitespace_and_inline_elements() {
        // Markup wraps and indents freely; the rendered text does not.
        let detected = detect(
            "Australia Post",
            serde_json::json!([r"\bAusPost\b", r"\bAustralia Post\b"]),
            "<html><body><p>Delivered by Australia\n          <b>Post</b> tomorrow.</p></body></html>",
        );
        let detection = detected
            .get("Australia Post")
            .expect("whitespace between the words should be normalised away");
        // Both patterns are alternative spellings of one fact, and only the second
        // matches here anyway — either way a technology yields a single text signal.
        assert_eq!(detection.signals.len(), 1);
    }

    #[test]
    fn several_matching_patterns_yield_one_signal() {
        let detected = detect(
            "Australia Post",
            serde_json::json!([r"\bAusPost\b", r"\bAustralia Post\b"]),
            "<html><body><p>AusPost, trading as Australia Post, delivers it.</p></body></html>",
        );
        let detection = detected.get("Australia Post").expect("should be detected");
        assert_eq!(
            detection.signals.len(),
            1,
            "alternative spellings of one name must not corroborate each other"
        );
        assert_eq!(detection.signals[0].weight, TEXT_SIGNAL_WEIGHT);
    }

    #[test]
    fn lookaround_pattern_compiles_and_matches() {
        // `\b(?<!-)UPS\b` is the one database text pattern the fast engine rejects;
        // it must reach the backtracking fallback instead of being dropped.
        let compiled = TechnologyAnalyzer::compile_text_patterns(&serde_json::json!([r"\b(?<!-)UPS\b"]));
        assert_eq!(compiled.len(), 1, "look-around pattern should compile via fancy-regex");

        let detected = detect("UPS", serde_json::json!([r"\b(?<!-)UPS\b"]), "<p>Ships via UPS.</p>");
        assert!(detected.contains_key("UPS"));

        let hyphenated = detect("UPS", serde_json::json!([r"\b(?<!-)UPS\b"]), "<p>A 400VA mini-UPS.</p>");
        assert!(hyphenated.is_empty(), "the look-behind must still exclude `-UPS`");
    }

    #[test]
    fn start_anchored_patterns_are_rejected() {
        // `\APC\b` is the database's typo for `\bAPC\b`; compiled as written it means
        // "the page's text begins with PC", which is a position, not a technology.
        assert!(TechnologyAnalyzer::compile_text_patterns(&serde_json::json!([r"\APC\b"])).is_empty());
        assert!(TechnologyAnalyzer::compile_text_patterns(&serde_json::json!([r"^Acme\b"])).is_empty());
        assert!(rejected_text_patterns().iter().any(|p| p.contains(r"\APC")));

        // A page that would have matched the anchored pattern detects nothing.
        let detected = detect("APC", serde_json::json!([r"\APC\b"]), "<p>PC builds and parts.</p>");
        assert!(detected.is_empty());
    }

    #[test]
    fn empty_pattern_is_not_a_catch_all() {
        // `text` is a content field: an empty pattern means "nothing to match", not
        // "matches anything". Compiling it to `.*` would tag every page analysed.
        assert!(TechnologyAnalyzer::compile_text_patterns(&serde_json::json!([""])).is_empty());
        assert!(TechnologyAnalyzer::compile_text_patterns(&serde_json::json!("")).is_empty());
    }

    #[test]
    fn only_html_bodies_are_treated_as_page_text() {
        let mut headers = HashMap::new();
        assert!(TechnologyAnalyzer::body_has_visible_text(&headers), "absent Content-Type");

        for html_ct in ["text/html; charset=utf-8", "application/xhtml+xml", "TEXT/HTML"] {
            headers.insert("content-type".to_string(), html_ct.to_string());
            assert!(TechnologyAnalyzer::body_has_visible_text(&headers), "{html_ct}");
        }
        // A JSON payload has no rendered text; its raw contents must not become evidence.
        for other_ct in ["application/json", "text/plain", "application/rss+xml"] {
            headers.insert("content-type".to_string(), other_ct.to_string());
            assert!(!TechnologyAnalyzer::body_has_visible_text(&headers), "{other_ct}");
        }
    }

    /// The `min_confidence` every entry point applies when the caller names none:
    /// `unwrap_or(50)` in the server handlers and the Python binding, `default_value =
    /// "50"` on the CLI. Duplicated as a literal here on purpose — there is no shared
    /// constant to import, and the whole point of this weight is its relationship to
    /// that number, so the test should fail loudly if someone changes one of them.
    const CALLER_DEFAULT_MIN_CONFIDENCE: u8 = 50;

    #[test]
    fn a_page_text_only_detection_is_filtered_out_at_the_default_threshold() {
        // The contract this layer actually ships under, pinned end to end: a carrier
        // named in prose and nowhere else scores exactly TEXT_SIGNAL_WEIGHT, which is
        // below what every caller asks for unless they lower the bar deliberately.
        // If someone raises the weight to "make the layer work", this test is where
        // they have to come and argue with `\bDX\b`.
        let detected = detect(
            "DPD",
            serde_json::json!([r"\bDPD\b"]),
            "<html><body><p>Yesterday DPD lost a parcel, writes our correspondent.</p></body></html>",
        );
        let detection = detected.get("DPD").expect("the text layer should still fire");
        let confidence = crate::confidence::compute_noisy_or(&detection.signals);

        assert_eq!(confidence, TEXT_SIGNAL_WEIGHT, "a lone signal scores its own weight");
        assert!(
            confidence < CALLER_DEFAULT_MIN_CONFIDENCE,
            "page text alone must not reach a caller who did not ask for it"
        );
        // It is a real, non-zero score, though — a caller passing `confidence: 45`
        // gets this detection, which is what makes the layer opt-in rather than dead.
        assert!(confidence > 0);
    }

    #[test]
    fn page_text_does_not_raise_a_technology_found_in_the_markup() {
        // The other half of the shipped contract, and the part most likely to be
        // misremembered as an improvement. PostNL and DHL carry `dom` patterns
        // alongside their `text` ones; `dom` and `page-text` are the same independence
        // class (one response body, read twice), so the text match contributes a
        // visible signal and no confidence. Byte-identical output plus one entry.
        let detected = detect(
            "DHL",
            serde_json::json!([r"\bDHL\b"]),
            "<html><body><p>Shipped with DHL.</p></body></html>",
        );
        let text_signal = detected["DHL"].signals[0].clone();

        let dom_only = [Signal { signal_type: "dom".into(), value: "#dhl".into(), weight: 70 }];
        let dom_plus_text = [dom_only[0].clone(), text_signal];

        assert_eq!(
            crate::confidence::compute_noisy_or(&dom_plus_text),
            crate::confidence::compute_noisy_or(&dom_only),
            "a page-text match must not corroborate markup from the same response"
        );
    }

    #[test]
    fn visible_text_is_normalised_and_ordered() {
        let document = scraper::Html::parse_document(
            "<html><head><title>Shop</title></head><body>\n  <ul><li>DHL</li><li>UPS</li></ul>\n\
             <p>Total:\u{a0}10</p></body></html>",
        );
        // Text nodes keep document order, runs of whitespace collapse to one space, and
        // adjacent nodes stay separated so `DHL` and `UPS` remain distinct words.
        assert_eq!(TechnologyAnalyzer::visible_text(&document), "Shop DHL UPS Total: 10");
    }
}
