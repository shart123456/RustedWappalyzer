//! Ground-truth detection corpus — the scoreboard for the analyzer.
//!
//! # Why this file exists
//!
//! Detection changes in this repository have historically been justified
//! anecdotally: somebody looked at one site, saw a wrong answer, changed a
//! pattern, looked at the same site again and called it fixed. With 7,586
//! technologies and roughly fifteen detection layers, nobody can reason their way
//! to "did that help?", and until this file there was no way to measure it. The
//! `dedupe_signals` comment in `src/analyzer/mod.rs` says as much out loud: it
//! concedes that the change lowered confidence for some technologies without
//! knowing which ones. This harness is the answer to that class of question.
//!
//! # Where the ground truth comes from
//!
//! From Docker image tags, not from this program. `docker run nginx:1.25.3` is
//! Nginx 1.25.3 — that is what the tag *means*, and it is true whether or not our
//! analyzer can see it. `fixtures/capture_corpus.sh` starts each container, curls
//! its homepage, and writes the captured response next to the expectations derived
//! from the tag (plus, for things like the bundled Apache and PHP in the WordPress
//! image, versions read out of the running container with `apache2 -v` / `php -v`).
//!
//! The one thing this harness must never do is record the current analyzer's output
//! as "expected". That would measure self-consistency instead of correctness and
//! would freeze today's bugs into the spec. If a fixture's expectation looks wrong,
//! check it against the image — do not check it against us.
//!
//! # Why capture and replay are separate
//!
//! You cannot point rustywap at a local container: every target goes through
//! `is_safe_url()`, which refuses loopback and private addresses, so
//! `rustywap analyze http://localhost:38501` fails by design. That guard is SSRF
//! protection and weakening it to make a test suite more convenient would be a poor
//! trade. So capture happens by hand with curl and Docker, and this test replays the
//! saved bytes through the library. Consequently **the replay performs no network I/O
//! and needs no Docker**, which is what lets it run in CI. The one thing that can
//! still reach the network is loading the pattern database itself, because
//! `wappalyzer_cache.json` is gitignored — see the comment in `wappalyzer()`; that is
//! shared with every other test in this repo and is not something this file invents.
//!
//! # What this number does and does not mean
//!
//! It replays through [`StandaloneWappalyzer::analyze_prefetched`], which — per its
//! own doc comment in `src/lib.rs` — runs the analyzer core and the final gate and
//! nothing else. No DNS records, no linked JS/CSS inspection, no favicon hashing, no
//! well-known endpoint probes. A great many real version strings live in linked
//! JavaScript, so the score below is deliberately a **lower bound on the core
//! layers**, not end-to-end recall. Do not quote it as "rustywap detects N% of
//! technologies"; it is "the header/HTML/meta/cookie/script-tag layers recover N% of
//! what is provably there".

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rusty_wappalyzer::{HttpResponse, StandaloneWappalyzer, Technology};
use serde::Deserialize;

// ── Ratchets ────────────────────────────────────────────────────────────────
//
// These are FLOORS, and they are a RATCHET: raise them when detection improves,
// never lower them. Lowering a floor so that a change can land is the single thing
// that destroys the value of this file — it converts a regression detector into a
// rubber stamp, and the next person has no way to know the number ever meant
// anything. If a change you believe in pushes the score below the floor, the honest
// options are to fix the change, or to fix the ground truth *with evidence from the
// image* that the expectation was wrong in the first place.
//
// ## What the two metrics count
//
// The corpus is fixed and can be counted by hand from `fixtures/corpus/*.json`:
// **22 expectations**, of which **21 carry a truth version**. The one that does not
// is the Jetty bundled inside the Jenkins image, whose version the `jenkins:2.440`
// tag does not pin.
//
//   recall        = technologies detected            / 22
//   version exact = exact version matches            / 21
//
// Both denominators are properties of the *fixtures*, not of the analyzer's output,
// and that is deliberate — see `Tally::version_score` for why the version denominator
// must never be "expectations that happened to be detected".
//
// ## Provenance of the numbers, stated plainly so nobody has to guess
//
// **Recall: 19/22 = 0.8636.** Measured by replaying every fixture through the
// `/analyze-response` endpoint of an already-running build, because the working tree
// was mid-edit by several parallel changes and could not be compiled at the time. It
// is therefore a measurement of *a* build of this analyzer, not necessarily of the
// exact commit you are reading.
//
// **Version exact: 13 of the 21.** The last time this test itself ran it printed
// `version exact 13/18` — 18 because the denominator was, at that time, the buggy
// "detected *and* versioned" count. That reconciles with the 19/22 above: of 19
// detected technologies exactly one, Jetty, carries no truth version, which leaves
// 18. The numerator is the honest part of that measurement and is
// unaffected by the fix; scored against the corrected denominator the same 13 exact
// matches give **13/21 = 0.6190**.
//
// Two other version figures circulated while this file was being reviewed — 14/21 =
// 0.6667 (an earlier draft of this very comment) and 14/18 = 0.7778 (a reviewer
// recomputing by hand down a different path). Both use a numerator of 14 that this
// test has never actually printed, and neither uses the corrected denominator. They
// are superseded and recorded here only so that nobody rediscovers them and assumes
// the current number is a regression. If the next real run prints a numerator other
// than 13, update this paragraph — not the code.
//
// ## How the floors below were derived
//
// The gap between measurement and floor is sized in whole expectations rather than in
// decimals, because "two expectations may regress before CI goes red" is a statement a
// human can act on and "0.55" is not.
//
//   recall  : measured 19/22. Two expectations of slack means 17/22 = 0.7727 must
//             still pass and 16/22 = 0.7273 must not. 0.75 sits between them.
//   version : measured 13/21. Two expectations of slack means 11/21 = 0.5238 must
//             still pass and 10/21 = 0.4762 must not. 0.52 sits between them.
//
// Two is the slack a floor gets when it was never confirmed green against this exact
// tree — enough that an unrelated in-flight change cannot turn CI red on this file's
// first run, not so much that a real regression slips through unnoticed.
//
// One honest note on the ratchet, because `VERSION_FLOOR` used to read 0.55 and now
// reads 0.52, and that must not be mistaken for a floor being lowered to let a change
// land. The *definition* of the version metric changed: its denominator went from a
// number the analyzer could shrink (18) to a fixed property of the fixtures (21), so
// the two floors are not measurements of the same quantity and are not comparable.
// 0.55 under the new definition would leave only one expectation of slack (12/21 =
// 0.5714 passes, 11/21 does not) on a floor that has never once been confirmed green
// here. 0.52 restates the same two-expectation policy against the new denominator.
// This is a one-time recalibration of a redefined metric; from here the ratchet rule
// applies without exception — raise only.
//
// The floors were confirmed green on 2026-09-21: recall 19/22 = 0.8636 (margin +0.1136),
// version exact 13/21 = 0.6190 (margin +0.0990). The "Provenance" section above records
// how they were first derived and is kept for that history.
//
// **Do NOT ratchet these to the printed values.** An earlier draft of this note said to,
// and that would be a mistake, for a reason that is not obvious: these scores are not a
// pure function of this repo. They depend on the *content of the technology database*,
// which is `wappalyzer_cache.json` — gitignored, so on a fresh CI checkout it is
// downloaded from the upstream GitHub mirror at test time (see `wappalyzer()` below).
// Upstream adds, removes and edits patterns continuously, so two runs of an identical
// tree can legitimately score differently. Zero-margin floors would turn that upstream
// drift into a red build with no local cause, and the usual response to a test that
// fails for reasons nobody changed is to delete it.
//
// So the slack is deliberate and is sized in whole expectations: each floor tolerates
// two regressions and trips on the third. Raise a floor only when the *structural* level
// changes — a new layer that genuinely lifts the score — and keep roughly two
// expectations of headroom when you do. The ratchet still only moves up.
const RECALL_FLOOR: f64 = 0.75;
const VERSION_FLOOR: f64 = 0.52;

/// Minimum confidence used when replaying, matching the API's default so that the
/// score describes what a caller of this service would actually receive. Measured
/// at capture time, 0 and 50 produced identical scores on this corpus — every
/// expected technology that was found at all was found with high confidence.
const MIN_CONFIDENCE: u8 = 50;

// ── Fixture format ──────────────────────────────────────────────────────────

/// One expectation: a technology the image provably contains.
#[derive(Debug, Deserialize)]
struct Expectation {
    /// Must be a key in the shipped database. An expectation naming a technology
    /// the database does not define can never pass — it can only drag the score
    /// down for no reason — so `expectations_name_real_technologies` fails on it
    /// rather than letting it quietly rot.
    technology: String,
    /// `None` when the image tag does not pin a version (the Jetty bundled inside
    /// the Jenkins image, for example). Absent versions are not scored.
    version: Option<String>,
    /// How the value above was established: an image tag, or an `exec_probe`.
    /// Printed on a miss so the reader can immediately judge whether to trust it.
    source: String,
}

/// A captured response plus the ground truth that came with it.
#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    image: String,
    captured_at: String,
    notes: String,
    body_truncated: bool,
    body_original_bytes: usize,
    expect: Vec<Expectation>,
    /// Deserialises straight into the crate's own `HttpResponse`, which is the
    /// whole reason the fixture format looks the way it does: there is no
    /// translation layer between what was captured and what the analyzer sees, so
    /// there is nothing for a translation layer to get subtly wrong.
    response: HttpResponse,
}

// ── Shared analyzer ─────────────────────────────────────────────────────────

static WAPPALYZER: OnceLock<StandaloneWappalyzer> = OnceLock::new();

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Build the analyzer once per test binary.
///
/// Follows the pattern in `tests/detection_tests.rs`: `StandaloneWappalyzer` is not
/// `Sync`-friendly to construct from inside an existing runtime, so a dedicated
/// current-thread runtime is spun up inside the `OnceLock` initialiser, which runs
/// exactly once even if several tests race for it.
fn wappalyzer() -> &'static StandaloneWappalyzer {
    WAPPALYZER.get_or_init(|| {
        // Database bootstrap, and the one honest caveat about this suite's
        // offline-ness.
        //
        // The REPLAY is offline — every byte the analyzer looks at comes out of
        // fixtures/corpus. Loading the pattern database is a separate matter:
        // `cache::load_or_fetch_database()` reads WAPPALYZER_CACHE if it is set,
        // otherwise a file beside the binary, and *downloads* the 7,586-technology
        // database from GitHub if neither is there. wappalyzer_cache.json is in
        // .gitignore, so on a fresh CI checkout that download is what happens — for
        // this suite exactly as it already does for tests/detection_tests.rs. This
        // file does not fix that (it is a property of every test in the repo and
        // fixing it means deciding whether to vendor a 6.8 MB database), but it does
        // two things about it: it prefers the checked-out copy when one exists, so a
        // developer machine never goes online for it, and it says so out loud when
        // one does not, so a surprising hang during test startup has a visible cause.
        if std::env::var_os("WAPPALYZER_CACHE").is_none() {
            let cache = repo_root().join("wappalyzer_cache.json");
            if cache.is_file() {
                std::env::set_var("WAPPALYZER_CACHE", cache);
            } else {
                eprintln!(
                    "detection_corpus: no wappalyzer_cache.json at {} and WAPPALYZER_CACHE \
                     is unset — the analyzer will fetch the technology database over the \
                     network before the (offline) replay begins. Set WAPPALYZER_CACHE to \
                     avoid that.",
                    cache.display()
                );
            }
        }

        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(async {
                StandaloneWappalyzer::new(false)
                    .await
                    .expect("StandaloneWappalyzer::new() failed — is wappalyzer_cache.json present?")
            })
    })
}

// ── Loading ─────────────────────────────────────────────────────────────────

fn corpus_dir() -> PathBuf {
    repo_root().join("fixtures").join("corpus")
}

/// Load every fixture, sorted by name so the printed report is stable between runs
/// and a diff of two reports shows only what actually changed.
fn load_corpus() -> Vec<Fixture> {
    let dir = corpus_dir();

    // A harness that passes with zero fixtures reads as coverage while providing
    // none, which is strictly worse than having no harness at all. Both "the
    // directory vanished" and "the directory is empty" are hard failures.
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!(
            "fixtures/corpus is missing or unreadable ({}): {e}. \
             Regenerate it with ./fixtures/capture_corpus.sh (needs Docker).",
            dir.display()
        )
    });

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();

    assert!(
        !paths.is_empty(),
        "fixtures/corpus ({}) contains no .json fixtures. \
         Regenerate it with ./fixtures/capture_corpus.sh (needs Docker). \
         Passing with an empty corpus would be a lie.",
        dir.display()
    );

    paths.iter().map(|p| load_fixture(p)).collect()
}

fn load_fixture(path: &Path) -> Fixture {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()));
    let fixture: Fixture = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("fixture {} is not valid: {e}", path.display()));
    assert!(
        !fixture.expect.is_empty(),
        "fixture {} has no expectations — it scores nothing and only costs bytes",
        path.display()
    );
    fixture
}

// ── Scoring ─────────────────────────────────────────────────────────────────

/// How a detected version compares to the version the image pins.
#[derive(Debug, PartialEq, Eq)]
enum VersionVerdict {
    /// Exactly what the image says.
    Exact,
    /// A dot-boundary prefix of the truth: Drupal's meta generator only ever emits
    /// `Drupal 10`, so "10" against a ground truth of "10.2.1" is genuinely correct
    /// information, just coarse. Scoring it as a failure would pressure someone into
    /// inventing precision the page does not contain, which is a worse outcome than
    /// an honest partial.
    Partial,
    /// A version was extracted and it disagrees with the image.
    Wrong,
    /// The technology was found but no version came with it.
    Missing,
}

fn judge_version(expected: &str, detected: Option<&str>) -> VersionVerdict {
    match detected {
        None => VersionVerdict::Missing,
        Some(v) if v == expected => VersionVerdict::Exact,
        // `starts_with(v + ".")` rather than a bare prefix test, so that "1.2"
        // matches "1.2.3" but "1.2" does not match "1.24.0".
        Some(v) if expected.starts_with(&format!("{v}.")) => VersionVerdict::Partial,
        Some(_) => VersionVerdict::Wrong,
    }
}

/// What happened to one expectation. Kept as a value rather than being folded
/// straight into counters so that the report and the score are computed from the
/// *same* decision — a report that disagrees with the number it is explaining is
/// worse than no report.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The technology was not detected at all. `had_truth_version` is carried
    /// because such an expectation is a recall failure *and*, when the image pinned
    /// a version, a version failure: you did not get the version.
    Undetected { had_truth_version: bool },
    /// Detected, and the image pins no version to check it against. Scores recall
    /// only and touches neither side of the version fraction.
    DetectedUnversioned,
    /// Detected, and the image pins a version. Scores recall and one version slot.
    DetectedVersioned(VersionVerdict),
}

/// Score one expectation. Pure: `truth` is the version the image pins (if any) and
/// `hit` is what the analyzer reported for that technology name — `None` for "not
/// detected", `Some(None)` for "detected, no version", `Some(Some(v))` for
/// "detected as v".
fn score_expectation(truth: Option<&str>, hit: Option<Option<&str>>) -> Outcome {
    match (hit, truth) {
        (None, truth) => Outcome::Undetected {
            had_truth_version: truth.is_some(),
        },
        (Some(_), None) => Outcome::DetectedUnversioned,
        (Some(detected), Some(truth)) => Outcome::DetectedVersioned(judge_version(truth, detected)),
    }
}

/// Running totals over a set of [`Outcome`]s.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tally {
    expected_total: usize,
    detected_total: usize,
    /// Every expectation that carries a truth version, **whether or not the
    /// technology was detected**. See [`Tally::version_score`].
    versioned_total: usize,
    version_exact: usize,
    version_partial: usize,
    version_wrong: usize,
    /// Detected, but no version came with it.
    version_absent: usize,
    /// Not detected at all, and the image pinned a version.
    version_undetected: usize,
}

impl Tally {
    fn add(&mut self, outcome: &Outcome) {
        self.expected_total += 1;
        match outcome {
            Outcome::Undetected { had_truth_version } => {
                if *had_truth_version {
                    self.versioned_total += 1;
                    self.version_undetected += 1;
                }
            }
            Outcome::DetectedUnversioned => {
                self.detected_total += 1;
            }
            Outcome::DetectedVersioned(verdict) => {
                self.detected_total += 1;
                self.versioned_total += 1;
                match verdict {
                    VersionVerdict::Exact => self.version_exact += 1,
                    VersionVerdict::Partial => self.version_partial += 1,
                    VersionVerdict::Wrong => self.version_wrong += 1,
                    VersionVerdict::Missing => self.version_absent += 1,
                }
            }
        }
    }

    fn recall(&self) -> f64 {
        if self.expected_total == 0 {
            1.0
        } else {
            self.detected_total as f64 / self.expected_total as f64
        }
    }

    /// Exact version matches over **every expectation that carries a truth version**.
    ///
    /// The denominator deliberately does not depend on what the analyzer found, and
    /// that is the whole point. An earlier version of this file counted only
    /// expectations that were both detected *and* versioned, which made the metric
    /// reward regressions: if a technology fell out of detection entirely it left the
    /// denominator, so the fraction went *up*. Work the arithmetic on this corpus at
    /// the measurement recorded at the top of this file (19 of 22 detected, 13 exact
    /// versions, old denominator 18). Take any one expectation that is detected
    /// without a version — Gitea is the candidate the reviewer used — and suppose it
    /// regresses to not being detected at all. Recall falls 19/22 = 0.864 → 18/22 =
    /// 0.818, still clear of its 0.75 floor, so CI stays green. Meanwhile the old
    /// version score *rises*, 13/18 = 0.722 → 13/17 = 0.765, because the lost
    /// detection took its own failure out of the denominator with it — and the report
    /// then cheerfully advises ratcheting the version floor up, to a number reachable
    /// only because detection got worse. A harness that can be improved by breaking
    /// detection is worse than no harness, so a miss now counts as a version failure,
    /// because it is one: you did not get the version.
    ///
    /// Both counters move in the same direction now, which also means a single lost
    /// detection costs *both* scores. That is intended, not double-counting: losing a
    /// technology really does cost you both the technology and its version.
    fn version_score(&self) -> f64 {
        if self.versioned_total == 0 {
            1.0
        } else {
            self.version_exact as f64 / self.versioned_total as f64
        }
    }
}

/// Index detections by name. The analyzer does not emit duplicate names after
/// gating, but building a map rather than scanning a `Vec` per expectation keeps
/// the scoring O(n) and, more usefully, makes "was it detected twice?" impossible
/// to express by accident.
fn index(technologies: &[Technology]) -> BTreeMap<&str, Option<&str>> {
    technologies
        .iter()
        .map(|t| (t.name.as_str(), t.version.as_deref()))
        .collect()
}

// ── The tests ───────────────────────────────────────────────────────────────

/// Guards the ground truth itself.
///
/// An expectation that names a technology the database has never heard of is
/// unfalsifiable: it can only ever be a miss, and it silently lowers the score
/// forever while looking like a detection bug. Catching it here, with a message that
/// says what to do, keeps that failure mode from being mistaken for a regression.
#[test]
fn expectations_name_real_technologies() {
    let analyzer = wappalyzer().shared_analyzer();
    let mut bad = Vec::new();
    for fixture in load_corpus() {
        for expectation in &fixture.expect {
            if analyzer.find_tech_name(&expectation.technology).is_none() {
                bad.push(format!(
                    "  {}: '{}' is not in the shipped database (source: {})",
                    fixture.name, expectation.technology, expectation.source
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "these expectations name technologies the database does not define, so they \
         can never pass:\n{}\nFix the name in fixtures/ground_truth.json (and re-run \
         fixtures/capture_corpus.sh), or drop the expectation.",
        bad.join("\n")
    );
}

/// The regression guard for the metric itself, and the reason [`Tally`] and
/// [`score_expectation`] are separate from the replay at all.
///
/// This runs entirely on synthetic inputs — no fixtures, no analyzer, no database,
/// no network — so it still fails loudly on a machine where the corpus replay cannot
/// run. It pins the one property that makes the version score trustworthy: **a
/// technology that stops being detected must never raise the version score.**
///
/// Under the old "detected and versioned" denominator the `after` case below scored
/// 2/2 = 1.000 against the `before` case's 2/3 = 0.667, i.e. deleting a detection was
/// worth +0.33 on the scoreboard. Delete the `had_truth_version` arm in `Tally::add`
/// (or restore the old denominator) and this test goes red on exactly that.
#[test]
fn losing_a_detection_never_raises_the_version_score() {
    fn tally_of(cases: &[(Option<&str>, Option<Option<&str>>)]) -> Tally {
        let mut tally = Tally::default();
        for (truth, hit) in cases {
            tally.add(&score_expectation(*truth, *hit));
        }
        tally
    }

    // Three expectations, all with a pinned truth version. Two are detected with the
    // right version; the third is detected but yields no version.
    let before = tally_of(&[
        (Some("1.0"), Some(Some("1.0"))),
        (Some("2.0"), Some(Some("2.0"))),
        (Some("3.0"), Some(None)),
    ]);

    // The regression: that third technology is now not detected at all. Strictly
    // worse in every way a user would care about.
    let after = tally_of(&[
        (Some("1.0"), Some(Some("1.0"))),
        (Some("2.0"), Some(Some("2.0"))),
        (Some("3.0"), None),
    ]);

    // The denominator is a property of the ground truth, so it does not move.
    assert_eq!(before.versioned_total, 3, "version denominator before");
    assert_eq!(after.versioned_total, 3, "version denominator after");

    // Recall notices the regression...
    assert!(
        after.recall() < before.recall(),
        "recall should fall when a technology stops being detected: {} -> {}",
        before.recall(),
        after.recall()
    );

    // ...and the version score, crucially, does not reward it.
    assert!(
        after.version_score() <= before.version_score(),
        "losing a detection raised the version score {} -> {} — the metric is \
         non-monotonic again and can be gamed by breaking detection",
        before.version_score(),
        after.version_score()
    );
    assert_eq!(after.version_score(), before.version_score());
    assert!((before.version_score() - 2.0 / 3.0).abs() < 1e-12);

    // The miss is accounted for as a version failure rather than vanishing.
    assert_eq!(before.version_absent, 1);
    assert_eq!(after.version_undetected, 1);

    // And an expectation with no pinned truth version stays out of the version
    // fraction entirely, detected or not — that is the Jenkins/Jetty case.
    let unversioned = tally_of(&[(None, None), (None, Some(None))]);
    assert_eq!(unversioned.versioned_total, 0);
    assert_eq!(unversioned.version_score(), 1.0);
}

/// Replay the whole corpus, print a per-fixture report, and enforce the ratchets.
///
/// Run with `cargo test --test detection_corpus -- --nocapture` to see the report; a
/// bare pass/fail number would defeat the point of building the corpus, because the
/// value is in seeing *which* technology stopped being detected.
#[test]
fn corpus_recall_meets_floor() {
    let wap = wappalyzer();
    let corpus = load_corpus();

    let mut tally = Tally::default();
    let mut misses: Vec<String> = Vec::new();

    println!();
    println!("=== detection corpus ({} fixtures) ===", corpus.len());
    println!("core layers only: no DNS, no linked assets, no favicon, no probes");
    println!();

    for fixture in &corpus {
        let detected = wap.analyze_prefetched(&fixture.response, MIN_CONFIDENCE);
        let found = index(&detected);

        println!(
            "--- {}  [{}]  captured {}",
            fixture.name, fixture.image, fixture.captured_at
        );
        println!(
            "    HTTP {} · {} body bytes{} · {} detections total",
            fixture.response.status_code,
            fixture.body_original_bytes,
            if fixture.body_truncated {
                " (TRUNCATED at capture)"
            } else {
                ""
            },
            detected.len()
        );
        if !fixture.notes.is_empty() {
            println!("    note: {}", fixture.notes);
        }

        for expectation in &fixture.expect {
            let hit = found.get(expectation.technology.as_str()).copied();
            let outcome = score_expectation(expectation.version.as_deref(), hit);
            tally.add(&outcome);

            // `hit.flatten()` is the version the analyzer reported, if any; it is
            // needed only for the report lines, which is why printing reads it
            // separately instead of the Outcome carrying it around.
            let detected_version = hit.flatten();
            match &outcome {
                Outcome::Undetected { had_truth_version } => {
                    println!(
                        "    MISS      {}  (truth: {}, from {}){}",
                        expectation.technology,
                        expectation.version.as_deref().unwrap_or("<no version>"),
                        expectation.source,
                        if *had_truth_version {
                            "  — counts against BOTH recall and version"
                        } else {
                            ""
                        }
                    );
                    misses.push(format!("{}/{}", fixture.name, expectation.technology));
                }
                Outcome::DetectedUnversioned => {
                    println!(
                        "    ok        {}{}  (no version claimed by the image)",
                        expectation.technology,
                        detected_version
                            .map(|v| format!(" v{v}"))
                            .unwrap_or_default()
                    );
                }
                Outcome::DetectedVersioned(verdict) => {
                    let truth = expectation.version.as_deref().unwrap_or("?");
                    match verdict {
                        VersionVerdict::Exact => {
                            println!("    ok        {} v{truth}", expectation.technology);
                        }
                        VersionVerdict::Partial => {
                            println!(
                                "    PARTIAL   {} v{}  (truth {truth} — coarser, not wrong)",
                                expectation.technology,
                                detected_version.unwrap_or("?")
                            );
                        }
                        VersionVerdict::Wrong => {
                            println!(
                                "    BAD VER   {} v{}  (truth {truth})",
                                expectation.technology,
                                detected_version.unwrap_or("?")
                            );
                        }
                        VersionVerdict::Missing => {
                            println!(
                                "    NO VER    {}  (truth {truth}, from {})",
                                expectation.technology, expectation.source
                            );
                        }
                    }
                }
            }
        }

        // Everything the analyzer reported that the ground truth does not mention.
        // These are NOT scored as false positives: the corpus records what an image
        // provably contains, never the complete set of what it contains, so a page
        // that genuinely ships jQuery would be punished for being honest. They are
        // printed because an implausible extra ("Shopify" on an nginx welcome page)
        // is a precision bug worth a human's attention, and there is nowhere else it
        // would ever show up.
        let extras: Vec<&str> = found
            .keys()
            .copied()
            .filter(|name| !fixture.expect.iter().any(|e| e.technology == *name))
            .collect();
        if !extras.is_empty() {
            println!("    also saw: {}", extras.join(", "));
        }
        println!();
    }

    let recall = tally.recall();
    let version_score = tally.version_score();
    let (detected_total, expected_total) = (tally.detected_total, tally.expected_total);
    let (version_exact, versioned_total) = (tally.version_exact, tally.versioned_total);

    println!("=== score ===");
    println!(
        "recall          {detected_total}/{expected_total} = {recall:.4}   \
         (floor {RECALL_FLOOR:.4}, margin {:+.4})",
        recall - RECALL_FLOOR
    );
    println!(
        "version exact   {version_exact}/{versioned_total} = {version_score:.4}   \
         (floor {VERSION_FLOOR:.4}, margin {:+.4})",
        version_score - VERSION_FLOOR
    );
    // The denominator here is every expectation with a truth version, so these five
    // buckets add up to it exactly. If they ever do not, the tally is wrong.
    println!(
        "version detail  exact {} · partial {} · wrong {} · none {} · undetected {}",
        tally.version_exact,
        tally.version_partial,
        tally.version_wrong,
        tally.version_absent,
        tally.version_undetected
    );
    if !misses.is_empty() {
        println!("undetected      {}", misses.join(", "));
    }
    println!();
    println!(
        "If both margins are positive, RAISE the floors in tests/detection_corpus.rs \
         to the measured values. That is what makes this a ratchet. Raising a floor is \
         only ever justified by a score that went up because detection got better — \
         the version denominator is fixed at the number of expectations carrying a \
         truth version, so it cannot be inflated by losing a detection."
    );
    println!();

    assert!(
        recall >= RECALL_FLOOR,
        "technology recall {recall:.4} fell below the floor {RECALL_FLOOR:.4}. \
         Undetected: {}. Read the report above before touching this floor — lowering \
         it is the one change that makes this file worthless.",
        misses.join(", ")
    );
    assert!(
        version_score >= VERSION_FLOOR,
        "exact-version accuracy {version_score:.4} fell below the floor \
         {VERSION_FLOOR:.4} ({version_exact}/{versioned_total}). Read the report above \
         before touching this floor. Note that an undetected technology counts here \
         too ({} of them), so a recall regression shows up in this number as well.",
        tally.version_undetected
    );
}
