# Detection corpus

A set of real HTTP responses from software whose identity and version are known for
certain, plus the answers the analyzer is supposed to give for them. It is the
scoreboard that `tests/detection_corpus.rs` runs against.

```
fixtures/
  ground_truth.json    # the spec: which image, which port, what it provably runs
  capture_corpus.sh    # rebuilds corpus/ from Docker (manual, needs Docker + network)
  corpus/*.json        # captured responses + expectations  (11 fixtures, 180 KB)
```

## Why it exists

Before this, every detection change in the repository was argued anecdotally — "I
looked at one site and it seemed better". With 7,586 technologies and around fifteen
detection layers, nobody can hold that in their head, and there was no way to answer
"did that change help or hurt?". The `dedupe_signals` comment in
`src/analyzer/mod.rs` admits the problem in writing: the change lowered confidence
for some technologies and the author could not say which. This corpus is how that
question gets answered from now on.

## Where the answers come from

From the Docker image tag, never from the analyzer. `docker run nginx:1.25.3` is
Nginx 1.25.3 — that is what the tag means, and it stays true whether or not we can
detect it. Some expectations (the Apache and PHP inside `wordpress:6.4.2-apache`,
say) come from running `apache2 -v` / `php -v` *inside the container*, which is the
same kind of evidence: the image tells us about itself, directly, not through our
own pattern matching.

**Never record the current analyzer's output as the expectation.** That would
measure self-consistency rather than correctness and would freeze today's bugs into
the spec — the corpus would then agree with every regression it was built to catch.
Every technology name in `ground_truth.json` was checked against
`wappalyzer_cache.json` before it was written down, because an expectation naming a
technology the database does not define can never pass; it can only lower the score
forever while looking like a detection bug. `expectations_name_real_technologies`
in the test re-checks that on every run.

## Why capture and replay are two different things

You cannot point rustywap at a local container:

```
$ rustywap analyze http://localhost:38501
Error: ... resolves to a private/internal IP address and is not allowed
```

That is `is_safe_url()` doing its job — SSRF protection, and not something to weaken
for the convenience of a test suite. So:

* **capture** (this directory's shell script) runs by hand, needs Docker, and uses
  `curl` to record what the container actually sent;
* **replay** (`tests/detection_corpus.rs`) needs neither Docker nor a network, and
  feeds the saved bytes to `StandaloneWappalyzer::analyze_prefetched()`.

## Running the test

```bash
cargo test --test detection_corpus -- --nocapture
```

`--nocapture` matters. The pass/fail bit is the least interesting output; the report
tells you *which* technology stopped being detected and which version went stale.

## Regenerating the corpus

Needs Docker and the ability to pull images. It is re-runnable: containers are torn
down before and after each fixture, and corpus files are overwritten in place.

```bash
./fixtures/capture_corpus.sh                      # everything in ground_truth.json
./fixtures/capture_corpus.sh nginx-1.25.3         # just one
KEEP_CONTAINERS=1 ./fixtures/capture_corpus.sh nginx-1.25.3   # leave it up to poke at
```

Housekeeping the script already observes, and you should too if you edit it:
containers are named `rwfix-<fixture>` and always removed; host ports live in
38500–38600 and are assigned in `ground_truth.json`; readiness is polled rather than
slept for (nginx answers in milliseconds, SonarQube takes minutes); and a container
that never becomes ready is **skipped and reported**, never captured. An error page
recorded as a fixture is worse than a missing fixture, because it silently becomes
the spec.

If something goes wrong mid-run:

```bash
docker rm -f $(docker ps -aq --filter name=rwfix-)
```

## Adding a fixture

1. Add an entry to `ground_truth.json`: name, image, container port, a free host port
   in 38500–38600, and the `expect` list derived from the tag.
2. Confirm each `technology` value exists in `wappalyzer_cache.json` (it is 6.8 MB —
   use `python3 -c "import json; print('Grafana' in json.load(open('wappalyzer_cache.json'))['technologies'])"`,
   do not `cat` it).
3. Run `./fixtures/capture_corpus.sh <name>`.
4. Re-run the test. If recall went **up**, raise the floor (see below).

If the app needs coaxing to serve a page, `run_args` (docker flags) and `cmd` (the
command after the image) are both available; `joomla-5.0.2` uses them to skip an
entrypoint that otherwise refuses to start without a MySQL server. Write down in
`notes` exactly what you bypassed and why. For a version you can only learn from
inside the container, add an `exec_probes` entry instead of typing a number in by
hand.

## The floors are a ratchet

`tests/detection_corpus.rs` asserts a floor on technology recall (0.75) and on exact-version
accuracy (0.55). They may be **raised, never lowered**. Lowering a floor so that a change can
land is the one edit that destroys the point of this corpus: it turns a regression
detector into a rubber stamp and leaves the next reader no way to know the number ever
meant anything. If a change you believe in drops the score, either fix the change, or
fix the ground truth — with evidence from the image — and say so in the commit.

## What the score does and does not measure

`analyze_prefetched()` runs the analyzer core and the final exclude/require gate,
and nothing else: no DNS records, no linked JS/CSS inspection, no favicon hashing, no
well-known endpoint probes (its doc comment in `src/lib.rs` spells this out). Plenty
of real version strings live in linked JavaScript, so this score is a lower bound on
the **core layers**, not end-to-end recall. Do not quote it as "rustywap detects N%
of technologies".

Two further caveats worth knowing before you read a miss as a bug:

* **Several fixtures are installer pages.** WordPress, Drupal, Joomla, Nextcloud,
  MediaWiki and Gitea all serve a first-run setup screen when they have no database.
  Those pages carry strong fingerprints and are legitimate captures, but they are not
  running sites, and a real deployment exposes more. Each such fixture says so in its
  `notes`.
* **Extra detections are printed but not penalised.** The corpus records what an
  image *provably* contains, never everything it contains, so a page that genuinely
  ships jQuery must not be scored down for it. The report lists anything detected
  beyond the ground truth under `also saw:` purely so a human can notice an
  implausible one — "Shopify" on an nginx welcome page would be a precision bug, and
  this is the only place it would ever surface.

## Images deliberately not in the corpus

`traefik:v3.0`, `prom/prometheus:v2.49.1`, `hashicorp/consul:1.17.1` and
`hashicorp/vault:1.15.4` were pulled and then left out. The shipped database has no
entry for Traefik, Prometheus, Consul or Vault at all, so there is no expectation
that could be written for them which the engine is even capable of satisfying —
capturing them would add bytes and noise without adding signal. Add them back the day
those technologies land in the database.
