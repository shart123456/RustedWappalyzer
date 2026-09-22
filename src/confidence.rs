use crate::types::Signal;

/// An *independence class*: the artifact a signal was read out of.
///
/// Noisy-OR is only a sound way to combine evidence when the pieces of evidence are
/// conditionally independent given the technology — i.e. when each one is a separate
/// noisy sensor pointed at the world. Several of this engine's detection layers are not
/// separate sensors: they read the *same bytes* through different regexes and report
/// what they find under different `signal_type` labels.
///
/// `dedupe_signals` (src/analyzer/mod.rs) already collapses repeats of an identical
/// `(signal_type, value)` pair, which catches a single layer firing on 30 page elements.
/// It cannot catch the cross-layer case: a WordPress plugin path that appears in the
/// response body is matched by `analyze_html` as `html` and by `analyze_scripts` as
/// `script_src`, producing two Signals with different values that then multiplied up as
/// though two independent sensors had agreed. Two 70s became 91 and a third became 97.
///
/// So signals are grouped by the artifact they came from, the strongest signal wins
/// *within* a group (they are views of one observation, so the best view is what that
/// observation is worth), and the group maxima are combined with noisy-OR *across*
/// groups (those really are separate observations of separate artifacts).
///
/// The boundaries below follow one rule: **one class per artifact fetched**. Every
/// placement is justified at its match arm, including the ones that are arguable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IndependenceClass {
    /// The page document we fetched: its body bytes and its final URL.
    PageDocument,
    /// The response header block of that same fetch, including `Set-Cookie`.
    ResponseHeaders,
    /// DNS records for the host — a separate set of network lookups.
    Dns,
    /// The site's favicon — a separate HTTP GET, matched by content hash.
    Favicon,
    /// A JavaScript source map — a separate HTTP GET of a separate file.
    SourceMap,
    /// Well-known endpoints probed after the main fetch.
    Probe,
    /// Not an observation at all: inferred from another technology's detection.
    Implied,
}

/// Number of variants in `IndependenceClass`. Used to size the per-class tally array.
///
/// There is no compile-time check tying this to the enum, so a new variant means
/// bumping this constant. It is deliberately a plain array rather than a `HashMap`:
/// `compute_noisy_or` runs once per detected technology per analysed URL, the class
/// count is tiny and fixed, and an array keeps the hot path allocation-free.
const CLASS_COUNT: usize = 7;

impl IndependenceClass {
    /// Dense index into the tally array. Kept next to `CLASS_COUNT` so the two are
    /// read together; every arm must be `< CLASS_COUNT`.
    fn index(self) -> usize {
        match self {
            IndependenceClass::PageDocument => 0,
            IndependenceClass::ResponseHeaders => 1,
            IndependenceClass::Dns => 2,
            IndependenceClass::Favicon => 3,
            IndependenceClass::SourceMap => 4,
            IndependenceClass::Probe => 5,
            IndependenceClass::Implied => 6,
        }
    }
}

/// Map a `Signal::signal_type` string onto the artifact it was read out of — for the
/// types this module has an opinion about. Returns `None` for anything else.
///
/// The class has to be derived from the type string here rather than carried on the
/// Signal itself: `Signal` is built by struct literal in several places outside this
/// module (src/analyzer/layers/dns.rs and a number of test modules) and adding a field
/// would break every one of them.
///
/// The `Option` is not decoration. Production never sees the `None` — `independence_class`
/// applies the documented default to it — but it is what lets a test assert that every
/// signal type this tree actually emits was classified *on purpose*. That mattered:
/// `page-text` shipped as a whole detection layer that fell through the default and
/// changed no output anywhere, and nothing failed to say so. See the default's own
/// rationale on `independence_class`.
fn explicit_class(signal_type: &str) -> Option<IndependenceClass> {
    Some(match signal_type {
        // ── The page document ────────────────────────────────────────────────────
        // All of these layers are handed `response.body` and differ only in which
        // slice of it they look at: `analyze_html` scans the whole document,
        // `analyze_scripts` the `src` attributes, `analyze_inline_scripts` and
        // `analyze_css` the text inside <script> and <style>, `analyze_meta_tags` the
        // meta tags, `analyze_dom` the DOM selectors, `analyze_js_patterns` the
        // JS globals. One fetch, one artifact, many readings of it.
        "html" | "script" | "script_src" | "meta" | "css" | "dom" | "js" => {
            IndependenceClass::PageDocument
        }

        // Arguable placement #1. `url` does not come from the body: `analyze_url`
        // matches the Wappalyzer DB's `url` patterns against `response.url`, the
        // address we ended up at. It is grouped with the body anyway because the two
        // are not independent — the path we requested is what *selected* the body we
        // got back, so `/wp-content/...` in the URL and WordPress markers in the body
        // are one fact, not two. URL patterns are also among the loosest in the
        // database (bare substring matches on a path), so letting them add
        // independent probability mass on top of body evidence is precisely the
        // inflation this function exists to stop.
        "url" => IndependenceClass::PageDocument,

        // Arguable placement #3, and the one that decides whether the page-text layer
        // is worth anything. `page-text` (src/analyzer/layers/text.rs) matches the
        // Wappalyzer `text` field against the *rendered* text of the document, with
        // script, style, noscript and template content stripped out. That really is a
        // different reading from the markup layers, and it was tempting to call it a
        // different observation and give it a class of its own — which is also the
        // only placement under which the layer would ever change a score.
        //
        // It is not a different observation, for a reason that has nothing to do with
        // which bytes were read and everything to do with the failure mode:
        // conditional independence has to hold for the *false* positives too, and here
        // it demonstrably does not. All but one of the `text` patterns in the shipped
        // database is a shipping carrier's name (`\bUPS\b`, `\bRoyal Mail\b`,
        // `\bHermes\b`), and the page that trips one wrongly — an article or a product
        // review *about* a carrier — carries that same name in its <title>, in its
        // og:description and in its prose at once. Those are not three sensors
        // agreeing; they are one editorial decision seen three times. Giving page text
        // its own class would have let the markup match and the prose match multiply,
        // which turns exactly the false-positive case into the confident one.
        //
        // The cost is real and is not hidden here: every field that could corroborate
        // one of these technologies is also a body field (`meta`, `dom`, `scriptSrc`,
        // `scripts`), so a page-text signal never raises any technology's score in the
        // shipped database. It is attributable evidence in the signal list, and it is
        // the *only* signal — scoring its own weight, 45 — for the technologies that
        // have no other detection field, which surfaces them solely to a caller who
        // asks for a threshold at or below 45. `TEXT_SIGNAL_WEIGHT` in
        // src/analyzer/layers/text.rs carries the other half of this argument,
        // including why raising that weight past the default 50 is not an option.
        "page-text" => IndependenceClass::PageDocument,

        // ── The response header block ────────────────────────────────────────────
        // `analyze_headers`, `scan_headers_targeted`, `scan_generic_signals` and
        // `scan_csp_header` all iterate the same `response.headers` map, so the same
        // `X-Powered-By` line can surface more than once under different values.
        //
        // Arguable placement #2, and the one most likely to cost recall: cookies.
        // A cookie *is* a response header (`Set-Cookie`), and both `analyze_cookies`
        // and `scan_cookie_generic` read that same header, so keeping them apart would
        // leave the same double-count open that this change closes elsewhere. The cost
        // is that a technology evidenced by a framework cookie *and* a distinct
        // server header — arguably two different things the server told us — now
        // scores the stronger of the two instead of their noisy-OR.
        "header" | "cookie" => IndependenceClass::ResponseHeaders,

        // ── Separate network observations ────────────────────────────────────────
        // DNS is one class covering every record type. A CNAME, a TXT record and an
        // MX record are separate queries, but they are all reads of one zone file
        // published by one operator, and `detect_from_dns` walks the CNAME chain plus
        // `www.<host>` so the same delegation is routinely seen more than once.
        // `dns` is what src/analyzer/layers/dns.rs actually emits today; the
        // `dns_txt` / `dns_mx` spellings documented on `Signal` are matched too so
        // that splitting them out later needs no change here.
        "dns" | "dns_txt" | "dns_mx" | "dns_cname" => IndependenceClass::Dns,

        // A hash of the bytes at /favicon.ico. A separate GET of a separate file,
        // genuinely independent of what the HTML said.
        "favicon" => IndependenceClass::Favicon,

        // A separate GET of a .map file. Its `sources` array names npm packages that
        // the page body never mentions, so it is real extra information — but ONE
        // fetched map yields many signals (a package appears under both its versioned
        // and unversioned path), which is exactly the within-class repeat this
        // grouping is for.
        "source_map" => IndependenceClass::SourceMap,

        // Every probed endpoint collapses into one class. Strictly, /wp-json and
        // /readme.html are two artifacts and would deserve two classes; they are
        // merged because the Signal carries no per-probe provenance we can trust —
        // `value` is a hand-written label, several probes share one label, and a
        // single fetched document (package.json, /actuator/info) emits a whole run of
        // signals from the same bytes. With 94 probe call sites, guessing wrong in the
        // permissive direction is the expensive mistake, so this takes the strongest
        // probe and stops. In practice this costs almost nothing: probe weights are
        // high (90–100), so a genuinely probe-confirmed technology still lands at or
        // near 100.
        "probe" => IndependenceClass::Probe,

        // `implied` gets its own class because it is not an observation — it is an
        // inference from another technology already detected, so it can never be
        // "the same bytes read twice" as any real signal, and folding it into the
        // page-document or header class would arbitrarily suppress either it or the
        // real evidence depending on which weight happened to be larger.
        //
        // The correlation it *does* carry — being wholly derivative of its parent —
        // is not something this function can see, and is handled where it belongs, by
        // bounding an implied technology's confidence by its parent's in
        // src/analyzer/mod.rs. Note also that `analyze()` only adds an implied signal
        // when the technology is not already in the detection map, so on a single pass
        // an implied signal is usually the *only* signal on its technology and the
        // grouping is a no-op; it coexists with real evidence only after detections
        // from different passes are merged.
        "implied" => IndependenceClass::Implied,

        // Unknown or newly added signal type: no opinion. `independence_class` decides
        // what to do with it, and documents why.
        _ => return None,
    })
}

/// The artifact a signal was read out of, with the default applied for types
/// [`explicit_class`] has never heard of.
///
/// # Why the default is still `PageDocument`
///
/// A new signal type falling silently into this class is precisely how the `page-text`
/// layer came to ship inert: it was added by one change, the classification was added
/// by nobody, and every text match landed in the same class as the markup layers, where
/// only the strongest signal counts.
///
/// Flipping the default to "a class of its own" would *not* have surfaced that. It
/// trades a silent loss of recall for a silent loss of precision. New detection layers
/// overwhelmingly read the response body — it is the artifact already in hand — so an
/// unclassified type is most often a body reading, and under a permissive default it
/// would start multiplying against the existing body signals. That is the inflation bug
/// this whole module was written to fix (two 70s became 91, a third made 97), and it
/// announces itself no more loudly than a lost detection does; it just fails in the
/// direction that produces confident wrong answers instead of missing right ones.
/// Between two silent failures, the conservative one is the one to keep.
///
/// So the default is unchanged and the *silence* is what got fixed. `explicit_class`
/// reports whether a type was classified deliberately, and
/// `every_signal_type_this_tree_emits_is_classified_on_purpose` in this file's tests
/// holds the list of types the tree emits and fails on any that is not in this match.
/// That list is a checklist, not a proof — it cannot notice a type introduced in
/// another file by someone who never opens this one — but it is the only one of the
/// three options considered that turns this particular mistake into a red test rather
/// than a quiet change in output. A signal type that really is a separate observation
/// still needs an explicit arm above; so, now, does one that is not.
fn independence_class(signal_type: &str) -> IndependenceClass {
    explicit_class(signal_type).unwrap_or(IndependenceClass::PageDocument)
}

/// Compute the combined confidence score from a set of detection signals.
///
/// Signals are first grouped into independence classes by the artifact they were read
/// out of (see [`IndependenceClass`]). Within a class only the strongest signal counts,
/// because the members are different readings of one observation. The class maxima are
/// then combined with Noisy-OR, which treats each class as an independent noisy sensor:
/// the probability that *none* of them fire is the product of their individual "miss"
/// probabilities (`1 - weight/100`), and the score is `1 - P(none fire)` on [0, 100].
///
/// # Examples
/// - A `header` signal of weight 70 and a `dns` signal of weight 60 are two separate
///   observations → P(none) = 0.30 × 0.40 = 0.12 → score = 88.
/// - An `html` signal of 70 and a `script_src` signal of 70 are two readings of one
///   response body → score = 70, not 91.
pub(crate) fn compute_noisy_or(signals: &[Signal]) -> u8 {
    if signals.is_empty() { return 0; }

    // Strongest weight seen per class. A class with no signals stays at 0, which is
    // exactly right: it contributes a miss probability of `1 - 0/100 == 1.0`, the
    // multiplicative identity, so absent classes drop out of the product on their own
    // and need no separate "was this class present" bookkeeping.
    let mut strongest = [0u8; CLASS_COUNT];
    for signal in signals {
        let slot = &mut strongest[independence_class(&signal.signal_type).index()];
        if signal.weight > *slot {
            *slot = signal.weight;
        }
    }

    let p_none: f64 = strongest
        .iter()
        .fold(1.0, |acc, &weight| acc * (1.0 - weight as f64 / 100.0));
    (((1.0 - p_none) * 100.0).round() as u8).min(100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Signal;

    /// Build one signal.
    ///
    /// This helper used to take only a weight and hard-code `signal_type: "test"`.
    /// It now takes the type because the type is what decides how signals combine —
    /// and because two `sig(w)` calls produced two Signals with an identical
    /// `(signal_type, value)` pair, an input `dedupe_signals` guarantees can never
    /// reach this function in production. The assertions in the four original tests
    /// below are unchanged; only the inputs are now spelled out.
    fn sig(signal_type: &str, weight: u8) -> Signal {
        Signal { signal_type: signal_type.into(), value: "v".into(), weight }
    }

    // ── Original four: empty, single, the documented example, and the cap ────────

    #[test]
    fn empty_signals_zero() {
        assert_eq!(compute_noisy_or(&[]), 0);
    }

    #[test]
    fn single_signal_equals_weight() {
        assert_eq!(compute_noisy_or(&[sig("html", 80)]), 80);
    }

    #[test]
    fn two_signals_noisy_or() {
        // This pins the example in the doc comment: two signals from two different
        // artifacts (a response header and a DNS record) still corroborate.
        // P(none) = 0.30 * 0.40 = 0.12 → score = 88
        assert_eq!(compute_noisy_or(&[sig("header", 70), sig("dns", 60)]), 88);
    }

    #[test]
    fn hundred_weight_caps_at_100() {
        assert_eq!(compute_noisy_or(&[sig("html", 100)]), 100);
    }

    // ── The inflation this change exists to stop ────────────────────────────────

    #[test]
    fn correlated_body_signals_no_longer_multiply() {
        // The motivating case: one plugin path in the response body seen by the HTML
        // layer, the script-src layer and the inline-CSS layer. Under plain noisy-OR
        // this scored 1 - 0.3^3 = 97; it is one observation and must score 70.
        let signals = [
            sig("html", 70),
            sig("script_src", 70),
            sig("css", 70),
        ];
        assert_eq!(compute_noisy_or(&signals), 70);
    }

    #[test]
    fn url_match_does_not_reinforce_the_body_it_selected() {
        // `url` is folded into the page-document class, so a loose URL-path match on
        // top of body evidence adds nothing.
        assert_eq!(compute_noisy_or(&[sig("html", 70), sig("url", 70)]), 70);
    }

    #[test]
    fn strongest_within_a_class_wins_regardless_of_order() {
        // Ordering must not matter, and the weaker reading must never drag the class
        // down: collapsing a class can only ever keep its best view.
        assert_eq!(compute_noisy_or(&[sig("html", 40), sig("meta", 90)]), 90);
        assert_eq!(compute_noisy_or(&[sig("meta", 90), sig("html", 40)]), 90);
    }

    #[test]
    fn cookies_group_with_response_headers() {
        // A Set-Cookie *is* a response header, and two layers read that same header.
        assert_eq!(compute_noisy_or(&[sig("header", 70), sig("cookie", 70)]), 70);
    }

    #[test]
    fn dns_record_types_share_one_class() {
        // CNAME, TXT and MX are separate queries against one zone published by one
        // operator, so they are one observation of that zone.
        let signals = [sig("dns", 70), sig("dns_txt", 60), sig("dns_mx", 50)];
        assert_eq!(compute_noisy_or(&signals), 70);
    }

    #[test]
    fn repeated_probes_share_one_class() {
        // Several probe hits collapse to the strongest, so a run of endpoint probes
        // cannot ratchet a weak detection up to certainty.
        assert_eq!(compute_noisy_or(&[sig("probe", 70), sig("probe", 60)]), 70);
    }

    #[test]
    fn unknown_signal_type_defaults_into_the_page_document_class() {
        // A signal type this function has never heard of — including the ones future
        // body-reading layers will add — must not act as independent corroboration of
        // the body it was almost certainly read from.
        assert_eq!(explicit_class("some_future_body_layer"), None);
        assert_eq!(
            compute_noisy_or(&[sig("html", 70), sig("some_future_body_layer", 70)]),
            70
        );
    }

    // ── The page-text layer's placement, pinned on purpose ──────────────────────

    #[test]
    fn page_text_is_deliberately_in_the_page_document_class() {
        // This is the assertion the `page-text` layer shipped without. It is written
        // against `explicit_class`, not against a score, so that it fails if someone
        // deletes the arm and lets the type fall through again — a behavioural test
        // alone would keep passing, because the default lands in the same class and
        // the arithmetic would be identical. The classification is the thing being
        // pinned; the score below is the consequence.
        assert_eq!(explicit_class("page-text"), Some(IndependenceClass::PageDocument));
    }

    #[test]
    fn page_text_cannot_corroborate_markup_from_the_same_page() {
        // A carrier's name in the rendered text and the same name in the markup are
        // one editorial fact seen twice — most sharply when both are wrong, as on a
        // news article about a courier. The stronger reading is what the page is
        // worth; the text match adds a visible signal and no probability mass.
        assert_eq!(compute_noisy_or(&[sig("dom", 70), sig("page-text", 45)]), 70);
        assert_eq!(compute_noisy_or(&[sig("meta", 70), sig("page-text", 45)]), 70);
    }

    #[test]
    fn a_lone_page_text_signal_scores_its_own_weight() {
        // The invariant a single signal always has, and the one that makes the layer
        // opt-in rather than inert: 45 is a real score, it is simply below the 50 that
        // every caller defaults to. A caller asking for 45 gets these detections.
        assert_eq!(compute_noisy_or(&[sig("page-text", 45)]), 45);
    }

    #[test]
    fn every_signal_type_this_tree_emits_is_classified_on_purpose() {
        // The guard that `page-text` needed and did not have. Every string this tree
        // passes as a `signal_type` — the 14 literal third arguments to
        // `update_detection` plus the two `Signal` struct literals in
        // src/analyzer/layers/dns.rs — must reach an explicit arm above, so that a new
        // layer's author has to decide what its evidence is independent *of* rather
        // than inheriting the body class by omission.
        //
        // Adding a layer? Add its signal type here, and give it an arm in
        // `explicit_class`. This list is maintained by hand: nothing can derive it
        // from the source at test time, so it catches the author who came here and
        // forgot, not the one who never came here at all.
        const EMITTED: [&str; 16] = [
            // `update_detection` call sites (src/analyzer/**)
            "cookie", "css", "dom", "header", "html", "implied", "js", "meta",
            "page-text", "probe", "script", "script_src", "source_map", "url",
            // `Signal` struct literals (src/analyzer/layers/dns.rs)
            "dns", "favicon",
        ];
        for signal_type in EMITTED {
            assert!(
                explicit_class(signal_type).is_some(),
                "signal type `{signal_type}` is emitted by this tree but has no explicit \
                 arm in `explicit_class`; it is silently being treated as page-document \
                 evidence, which suppresses it against any other body signal"
            );
        }
    }

    // ── Corroboration that must keep working ────────────────────────────────────

    #[test]
    fn independent_observations_still_reinforce_each_other() {
        // A response header, a DNS record and a favicon hash are three genuinely
        // separate observations: a page fetch, a set of DNS lookups and a fetch of
        // /favicon.ico. P(none) = 0.30 * 0.40 * 0.50 = 0.06 → score = 94.
        let signals = [sig("header", 70), sig("dns", 60), sig("favicon", 50)];
        assert_eq!(compute_noisy_or(&signals), 94);
    }

    #[test]
    fn body_evidence_and_a_probe_still_corroborate() {
        // The common well-corroborated shape — markers in the page plus a confirmed
        // well-known endpoint — must stay comfortably above the default
        // min_confidence of 50 rather than being flattened by the grouping.
        let signals = [
            sig("html", 60),
            sig("script_src", 60),
            sig("probe", 60),
        ];
        assert_eq!(compute_noisy_or(&signals), 84);
    }

    #[test]
    fn source_map_is_independent_of_the_page_body() {
        // A .map file is a separate GET whose `sources` array names packages the page
        // body never mentions, so it genuinely adds information.
        assert_eq!(compute_noisy_or(&[sig("html", 60), sig("source_map", 80)]), 92);
    }

    #[test]
    fn implied_forms_its_own_class() {
        // An implied signal is an inference, not a reading of the page, so it neither
        // suppresses nor is suppressed by the page-document class here. Bounding it by
        // its parent's confidence is a separate concern handled in the analyzer.
        assert_eq!(compute_noisy_or(&[sig("html", 70), sig("implied", 60)]), 88);
    }

    #[test]
    fn many_repeated_source_map_entries_do_not_inflate() {
        // One fetched map lists a package under both its versioned and unversioned
        // path, emitting several 80-weight signals from the same bytes.
        let signals = [sig("source_map", 80), sig("source_map", 80), sig("source_map", 80)];
        assert_eq!(compute_noisy_or(&signals), 80);
    }

    #[test]
    fn zero_weight_signal_scores_zero() {
        // A weight of 0 means "this sensor never fires"; grouping must not turn that
        // into a non-zero score.
        assert_eq!(compute_noisy_or(&[sig("html", 0)]), 0);
    }
}
