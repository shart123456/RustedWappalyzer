#!/usr/bin/env bash
#
# capture_corpus.sh -- rebuild fixtures/corpus/ from Docker images.
#
# WHAT THIS IS FOR
# ----------------
# tests/detection_corpus.rs scores the analyzer against known-correct answers. The
# hard part of such a harness is not the scoring, it is getting answers you can
# trust. Docker solves that: `docker run nginx:1.25.3` is, definitionally, Nginx
# 1.25.3. So the ground truth comes from the image tag (see fixtures/ground_truth.json),
# this script only records what the server actually sent back.
#
# WHY CAPTURE AND REPLAY ARE SPLIT
# --------------------------------
# You cannot point rustywap at a local container. Both the CLI and the server run
# every target through is_safe_url(), which refuses private and loopback addresses:
#
#     $ rustywap analyze http://localhost:38501
#     Error: ... resolves to a private/internal IP address and is not allowed
#
# That guard is SSRF protection and it is doing its job -- it is not to be weakened
# or bypassed so a test suite can be more convenient. Hence: curl captures the
# response here (this script, run by hand, needs Docker and a network), and the Rust
# test replays the saved bytes through the library (offline, runs in CI).
#
# HOW TO RUN
# ----------
#     ./fixtures/capture_corpus.sh              # every fixture in ground_truth.json
#     ./fixtures/capture_corpus.sh nginx-1.25.3 grafana-10.2.3   # only these
#     KEEP_CONTAINERS=1 ./fixtures/capture_corpus.sh nginx-1.25.3   # leave it up to poke at
#
# It is re-runnable: each fixture's container is torn down before it is started and
# again after it is captured, and each corpus file is overwritten in place.
#
# OPERATIONAL RULES (please keep them)
#   * every container is named rwfix-<fixture>, so `docker rm -f $(docker ps -aq
#     --filter name=rwfix-)` always cleans up after a botched run;
#   * ports live in 38500-38600 and are assigned in ground_truth.json;
#   * readiness is POLLED, never slept for -- sonarqube and jenkins take minutes,
#     nginx takes milliseconds, and a fixed sleep is wrong for both;
#   * a container that never becomes ready is SKIPPED and reported. An error page
#     recorded as though it were a fixture is worse than a missing fixture, because
#     it silently becomes the spec.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROUND_TRUTH="$HERE/ground_truth.json"
CORPUS_DIR="$HERE/corpus"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Bodies are capped so the repository does not grow a megabyte every time someone
# adds a fixture. 256 KiB is far above any of the pages captured here (the largest
# is a few tens of KiB) while still being small enough that the whole corpus stays
# reviewable in a diff. The cap is recorded per fixture in `body_truncated` so a
# future reader can tell "the analyzer saw the whole page" from "the analyzer saw
# the first 256 KiB of the page".
MAX_BODY_BYTES=$((256 * 1024))

mkdir -p "$CORPUS_DIR"

command -v docker >/dev/null || { echo "docker not found -- this script needs it; the TEST does not." >&2; exit 1; }
command -v curl   >/dev/null || { echo "curl not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

SELECTED=("$@")

mapfile -t NAMES < <(python3 -c '
import json, sys
gt = json.load(open(sys.argv[1]))
for f in gt["fixtures"]:
    print(f["name"])
' "$GROUND_TRUTH")

want() {
    [ ${#SELECTED[@]} -eq 0 ] && return 0
    local n="$1" s
    for s in "${SELECTED[@]}"; do [ "$s" = "$n" ] && return 0; done
    return 1
}

CAPTURED=(); SKIPPED=()

for name in "${NAMES[@]}"; do
    want "$name" || continue

    # Pull this fixture's spec out of the ground-truth file as shell-safe lines.
    eval "$(python3 -c '
import json, shlex, sys
gt = json.load(open(sys.argv[1]))
f = next(x for x in gt["fixtures"] if x["name"] == sys.argv[2])
print("IMAGE=" + shlex.quote(f["image"]))
print("CPORT=" + shlex.quote(str(f["container_port"])))
print("HPORT=" + shlex.quote(str(f["host_port"])))
print("PATH_=" + shlex.quote(f.get("path", "/")))
print("READY=" + shlex.quote(str(f.get("ready_timeout_secs", 90))))
print("RUN_ARGS=(" + " ".join(shlex.quote(a) for a in f.get("run_args", [])) + ")")
print("CMD=(" + " ".join(shlex.quote(a) for a in f.get("cmd", [])) + ")")
print("PROBES=" + shlex.quote(json.dumps(f.get("exec_probes", []))))
' "$GROUND_TRUTH" "$name")"

    container="rwfix-${name}"
    url="http://127.0.0.1:${HPORT}${PATH_}"

    echo "=== ${name}  (${IMAGE})  ->  ${url}"

    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "    SKIP: image not present locally. Run: docker pull ${IMAGE}"
        SKIPPED+=("${name}: image ${IMAGE} not pulled")
        continue
    fi

    docker rm -f "$container" >/dev/null 2>&1

    if ! docker run -d --name "$container" -p "127.0.0.1:${HPORT}:${CPORT}" \
            "${RUN_ARGS[@]}" "$IMAGE" "${CMD[@]}" >/dev/null 2>"$WORK/runerr"; then
        echo "    SKIP: docker run failed: $(head -c 300 "$WORK/runerr")"
        SKIPPED+=("${name}: docker run failed")
        docker rm -f "$container" >/dev/null 2>&1
        continue
    fi

    # Poll for readiness. "Ready" means the port answered with a complete HTTP
    # response -- any status, because several of these apps answer their unconfigured
    # root with a 302 to an installer, and a 302 is a perfectly good fingerprint.
    # It deliberately does NOT mean "200", which would hang forever on those.
    deadline=$(( $(date +%s) + READY ))
    ready=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        if curl -s -o /dev/null --max-time 5 "$url"; then ready=1; break; fi
        if ! docker ps --format '{{.Names}}' | grep -qx "$container"; then
            echo "    container exited early; logs:"
            docker logs --tail 15 "$container" 2>&1 | sed 's/^/      /'
            break
        fi
        sleep 2
    done

    if [ "$ready" -ne 1 ]; then
        echo "    SKIP: never became ready within ${READY}s -- NOT writing a fixture."
        SKIPPED+=("${name}: not ready within ${READY}s")
        docker rm -f "$container" >/dev/null 2>&1
        continue
    fi

    # Capture. -L follows redirects because that is what the real client does
    # (reqwest::redirect::Policy::limited(5) in src/http_client.rs), and because the
    # interesting page for half this corpus is behind a 302 to an installer. -D
    # writes one header block per hop; the fixture builder keeps the LAST block,
    # which is what reqwest hands the analyzer. Set-Cookie is NOT folded here --
    # curl emits one line per header, and keeping them separate is the whole reason
    # HttpResponse.set_cookie_headers is a Vec.
    if ! curl -sS -L --max-time 30 \
            -D "$WORK/headers.txt" -o "$WORK/body.bin" \
            -w '%{time_total}\n%{url_effective}\n' \
            "$url" > "$WORK/meta.txt" 2>"$WORK/curlerr"; then
        echo "    SKIP: curl failed: $(head -c 300 "$WORK/curlerr")"
        SKIPPED+=("${name}: curl failed")
        docker rm -f "$container" >/dev/null 2>&1
        continue
    fi

    # Run the in-container version probes (apache2 -v, php -v, ...). These exist so
    # that an expectation like "this WordPress image also serves PHP 8.2.14" is a
    # fact read out of the running image rather than something a human remembered.
    : > "$WORK/probes.json"
    python3 - "$PROBES" "$container" > "$WORK/probes.json" <<'PYPROBE'
import json, re, subprocess, sys
probes = json.loads(sys.argv[1])
container = sys.argv[2]
out = {}
for p in probes:
    try:
        r = subprocess.run(["docker", "exec", container] + p["cmd"],
                           capture_output=True, text=True, timeout=30)
        text = (r.stdout or "") + (r.stderr or "")
        m = re.search(p["regex"], text, re.M)
        if m:
            out[p["id"]] = m.group(1)
        else:
            sys.stderr.write("    probe %s: no version in output\n" % p["id"])
    except Exception as e:  # a probe failing must never fail the capture
        sys.stderr.write("    probe %s failed: %s\n" % (p["id"], e))
print(json.dumps(out))
PYPROBE

    python3 - "$GROUND_TRUTH" "$name" "$url" "$WORK/headers.txt" "$WORK/body.bin" \
               "$WORK/meta.txt" "$WORK/probes.json" "$CORPUS_DIR" "$MAX_BODY_BYTES" <<'PYBUILD'
import datetime, json, sys, os

gt_path, name, url, hdr_path, body_path, meta_path, probes_path, corpus_dir, maxb = sys.argv[1:10]
maxb = int(maxb)

spec = next(f for f in json.load(open(gt_path))["fixtures"] if f["name"] == name)
probes = json.load(open(probes_path)) if os.path.getsize(probes_path) else {}

# --- headers: keep the LAST block, which is the response reqwest would hand us ---
raw = open(hdr_path, "rb").read().decode("iso-8859-1")
blocks, cur = [], []
for line in raw.splitlines():
    if line.startswith("HTTP/"):
        if cur:
            blocks.append(cur)
        cur = [line]
    elif line.strip() == "":
        continue
    elif cur:
        cur.append(line)
if cur:
    blocks.append(cur)
last = blocks[-1] if blocks else []

status = int(last[0].split()[1]) if last else 0
headers, set_cookies = {}, []
for line in last[1:]:
    if ":" not in line:
        continue
    k, v = line.split(":", 1)
    k, v = k.strip().lower(), v.strip()
    if k == "set-cookie":
        set_cookies.append(v)
    else:
        # Last-wins for ordinary headers, matching fetch_with_client() in
        # src/http_client.rs. Do not "improve" this into a list: the analyzer
        # reads a HashMap<String, String> and a fixture that disagrees with the
        # real client is measuring a code path nobody runs.
        headers[k] = v
if set_cookies:
    # fetch_with_client() also exposes the cookies joined by newlines under the
    # "set-cookie" key, because some layers read the flat header map. Reproduce
    # that exactly rather than approximating it.
    headers["set-cookie"] = "\n".join(set_cookies)

body_bytes = open(body_path, "rb").read()
original_len = len(body_bytes)
truncated = original_len > maxb
if truncated:
    body_bytes = body_bytes[:maxb]
body = body_bytes.decode("utf-8", errors="replace")

meta = open(meta_path).read().split()
try:
    time_total_ms = int(float(meta[0]) * 1000)
except Exception:
    time_total_ms = 0
effective = meta[1] if len(meta) > 1 else url

expect = []
for e in spec["expect"]:
    version = e.get("version")
    src = e.get("source", "")
    if src.startswith("exec_probe:"):
        version = probes.get(src.split(":", 1)[1])
        if version is None:
            # No probe result => no version claim. Recording a made-up version
            # would poison the scoreboard in the one direction that matters.
            src = src + " (probe returned nothing; no version asserted)"
    expect.append({"technology": e["technology"], "version": version, "source": src})

fixture = {
    "name": name,
    "image": spec["image"],
    "captured_at": datetime.datetime.now(datetime.timezone.utc)
                     .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "captured_by": "fixtures/capture_corpus.sh",
    "capture_url": url,
    "effective_url": effective,
    "notes": spec.get("notes", ""),
    "body_truncated": truncated,
    "body_original_bytes": original_len,
    "expect": expect,
    "response": {
        "url": url,
        "headers": headers,
        "body": body,
        "status_code": status,
        "response_time_ms": time_total_ms,
        "set_cookie_headers": set_cookies,
    },
}

out = os.path.join(corpus_dir, name + ".json")
with open(out, "w") as fh:
    json.dump(fixture, fh, indent=2, sort_keys=False)
    fh.write("\n")
print("    wrote %s  (status %s, %d body bytes%s, %d cookies)" % (
    os.path.relpath(out), status, original_len,
    ", TRUNCATED" if truncated else "", len(set_cookies)))
PYBUILD
    rc=$?
    if [ $rc -ne 0 ]; then
        SKIPPED+=("${name}: fixture build failed")
    else
        CAPTURED+=("$name")
    fi

    if [ "${KEEP_CONTAINERS:-0}" = "1" ]; then
        echo "    KEEP_CONTAINERS=1 -- leaving ${container} running on ${HPORT}"
    else
        docker rm -f "$container" >/dev/null 2>&1
    fi
done

echo
echo "captured: ${#CAPTURED[@]}  ${CAPTURED[*]:-}"
if [ ${#SKIPPED[@]} -gt 0 ]; then
    echo "skipped:  ${#SKIPPED[@]}"
    for s in "${SKIPPED[@]}"; do echo "  - $s"; done
fi
echo "corpus on disk: $(du -sh "$CORPUS_DIR" 2>/dev/null | cut -f1)"
