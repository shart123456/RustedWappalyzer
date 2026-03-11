# RustedWappalyzer

Web technology fingerprinting tool built in Rust. Detects 3,900+ technologies — frameworks, CDNs, analytics, infrastructure — with version extraction and optional CVE/PoC enrichment.

## Quick Start

```bash
git clone https://github.com/shart123456/RustedWappalyzer
cd RustedWappalyzer
docker build -t wappalyzer .
docker run -d -p 3000:3000 --name wappalyzer wappalyzer
```

The API is now running at `http://localhost:3000`.

---

## API

### Analyze a URL

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

```json
[
  { "technology": "Nginx",      "version": "1.24.0", "confidence": 100, "categories": ["Web Servers"] },
  { "technology": "React",      "version": "18.3.1", "confidence": 100, "categories": ["JavaScript Frameworks"] },
  { "technology": "Tailwind CSS","version": "3.4.1",  "confidence": 100, "categories": ["UI Frameworks"] }
]
```

**Request options:**

| Field | Default | Description |
|---|---|---|
| `url` | required | Target URL |
| `confidence` | `50` | Minimum confidence threshold (0–100) |
| `insecure` | `false` | Skip SSL certificate verification |
| `full_scan` | `false` | Probe well-known endpoints for extra version info |
| `auto_escalate` | `false` | Re-run with `full_scan` automatically if any detected tech is missing a version |

---

### Batch Analyze

```bash
curl -X POST http://localhost:3000/batch \
  -H "Content-Type: application/json" \
  -d '{
    "urls": ["https://example.com", "https://another.com"],
    "concurrency": 5
  }'
```

| Field | Default | Description |
|---|---|---|
| `urls` | required | Array of target URLs (max 100) |
| `concurrency` | `5` | Parallel requests |
| `confidence` | `50` | Minimum confidence threshold |
| `full_scan` | `false` | Probe extra endpoints |

> **Note:** TLS mode for batch requests is controlled by the server's startup configuration (`--insecure` flag on `serve`), not a per-request field. SSRF validation for all URLs runs concurrently before any analysis begins.

---

### Wayback Comparison

Compare the current tech stack against historical Wayback Machine snapshots (~1 year and ~2 years ago).

```bash
curl -X POST http://localhost:3000/wayback \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Returns current technologies plus two historical snapshots, showing added/removed technologies and version changes over time.

---

### Other Endpoints

```bash
# Health check
curl http://localhost:3000/health

# Database info (technology count, categories)
curl http://localhost:3000/info
```

---

### API Authentication

Set the `API_KEY` environment variable to require bearer token authentication on all endpoints:

```bash
docker run -d -p 3000:3000 -e API_KEY=mysecretkey wappalyzer
```

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Authorization: Bearer mysecretkey" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

### Rate Limiting

The server enforces **60 requests per minute per IP**. Requests exceeding the limit receive `HTTP 429`.

---

### Response Caching

Responses are cached in-memory (1,000 entries, 60-second TTL) keyed on URL + options. Repeated requests for the same URL return instantly.

---

## CLI

```bash
# Prerequisites: Rust toolchain, libssl-dev, pkg-config
cargo build --release

# Analyze a single URL (table output)
./target/release/wappalyzer analyze https://example.com

# JSON output
./target/release/wappalyzer analyze https://example.com --format json

# Simple one-per-line output
./target/release/wappalyzer analyze https://example.com --format simple

# Verbose output
./target/release/wappalyzer analyze https://example.com --verbose

# Full scan — probes extra endpoints for version info
./target/release/wappalyzer analyze https://example.com --full-scan

# Skip SSL verification
./target/release/wappalyzer analyze https://example.com --insecure

# Batch from file (one URL per line)
./target/release/wappalyzer batch urls.txt --concurrency 10 --output results.json

# Historical comparison via Wayback Machine
./target/release/wappalyzer wayback https://example.com

# Start the API server
./target/release/wappalyzer serve --port 3000

# Update the technology database
./target/release/wappalyzer update

# Force re-fetch (ignore cached database)
./target/release/wappalyzer update --force

# Show database stats
./target/release/wappalyzer info

# Run performance benchmark
./target/release/wappalyzer benchmark --count 100 --threads 5
```

---

## Detection Layers

Detection is performed across nine independent layers, then merged with noisy-OR confidence aggregation.

| Layer | What it analyzes |
|---|---|
| **Headers** | HTTP response headers; targeted version extraction for Nginx, Rails, Next.js, Nuxt, Drupal, Joomla, Wix, Shopify, Ghost, Gatsby, Hugo |
| **HTML** | Meta tags, SPA globals (`__NEXT_DATA__`, `window.__NUXT__`), Alpine.js, htmx, Inertia.js, meta[name=generator] |
| **Scripts** | Script/CSS URL patterns; CDN path versions (`@5.3.3`), banner comments (`/*! Bootstrap v5.3.3 */`), JS globals |
| **Meta tags** | Database meta tag pattern matching |
| **CSS** | Inline CSS content scanning |
| **Cookies** | Generic cookie detection: Express (`connect.sid`), Django (`csrftoken`), Laravel, Shopify, Google Analytics, Hotjar, HubSpot |
| **CSP** | Content-Security-Policy domain parsing; 60+ SaaS/service mappings (Sentry, Intercom, Hotjar, Datadog, Stripe, Rollbar, Mixpanel, Zendesk, HubSpot, Cloudinary, etc.) |
| **DNS** | CNAME chain analysis (40+ CDN/hosting patterns), MX records (12 email providers), TXT records; includes `www.` variant and A-record resolution |
| **Probes** (`full_scan`) | `/package.json`, `/wp-json/`, `/actuator/info`, `/healthz`, `/readyz`, `/livez`, `/_health`, `/metrics` |

### How Version Detection Works

| Method | Example |
|---|---|
| HTTP response header | `Server: nginx/1.24.0` |
| CDN URL path | `jquery@3.7.1/dist/jquery.min.js` |
| Banner comment in JS/CSS | `/*! Bootstrap v5.3.3 */` |
| JavaScript global | `exports.version = "18.3.1"` |
| Script URL pattern | `pubads_impl_20240304.js` → GPT date version |
| Meta generator tag | `<meta name="generator" content="WordPress 6.4.2">` |
| SPA global object | `window.__NEXT_DATA__.buildId` |
| Endpoint probing (`full_scan`) | `GET /package.json` → `{"dependencies": {...}}` |

---

## Optional: CVE & PoC Enrichment

When a MongoDB instance is available, detected technologies are automatically enriched with CVE data and proof-of-concept references.

```bash
docker run -d -p 3000:3000 \
  -e MONGODB_URI=mongodb://localhost:27017 \
  wappalyzer
```

The server connects to two optional databases:
- **VulnVault** — CVE records indexed by technology name + version + CPE
- **PocVault** — Proof-of-concept references indexed by CVE ID and CPE

Enriched response fields:

```json
{
  "technology": "WordPress",
  "version": "6.4.2",
  "confidence": 95,
  "cpe": "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*",
  "cves": ["CVE-2024-1234"],
  "pocs": ["https://github.com/..."]
}
```

---

## Security

**SSRF Protection (dual-layer)** — Requests to internal infrastructure are blocked at two independent points:

1. **Pre-flight check** — `is_safe_url()` resolves the hostname via async DNS before the request is dispatched, providing a fast rejection with a human-readable error message.
2. **DNS resolver hook** — In server mode, a custom `SsrfDnsResolver` is installed on the HTTP client and re-validates every resolved IP at TCP-connect time. This mitigates DNS rebinding attacks where a hostname resolves to a public IP during the pre-flight but rebinds to a private IP by the time the connection is made.

Blocked address ranges:
- Loopback (`127.0.0.0/8`, `::1`)
- Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local (`169.254.0.0/16`, `fe80::/10`)
- Unique local IPv6 (`fc00::/7`)
- IPv4-mapped IPv6 (`::ffff:x.x.x.x`) for all of the above

**Response body cap** — Fetched pages are truncated at 10 MB to prevent memory exhaustion from abnormally large responses.

**Rate limiting** — 60 requests/minute per IP (sliding window), enforced server-side. Excess requests receive `HTTP 429`.

**API key auth** — Optional bearer token via `API_KEY` env var. Comparison is constant-time to prevent timing attacks.

**Request body limit** — JSON request bodies are capped at 64 KB by the Actix-web layer.

---

## Python Bindings

A Python package (`rusty_wappalyzer`) is available via [maturin](https://github.com/PyO3/maturin).

```bash
pip install maturin
maturin develop --features python
```

```python
import rusty_wappalyzer

analyzer = rusty_wappalyzer.PyWappalyzer()
results = analyzer.analyze("https://example.com")
for tech in results:
    print(tech.name, tech.version, tech.confidence)
```

---

## Logging

When running in server mode, logs are written to `logs/wappalyzer.log` with daily rotation, and to stderr. Log level defaults to `info`.

---

## Architecture

```
src/
  main.rs          — CLI entry point (clap commands: analyze, batch, wayback, serve, update, info, benchmark)
  lib.rs           — Public library API (StandaloneWappalyzer, analyze_url, analyze_urls_batch)
  types.rs         — All shared data structures (Technology, Signal, WappalyzerConfig, …)
  cache.rs         — Technology database fetch, load, and write; SHA-256 integrity check; favicon hash embedding
  http_client.rs   — Shared fetch_with_client(); reqwest builder + SSRF DNS resolver; 10 MB body cap
  confidence.rs    — Noisy-OR confidence aggregation
  middleware.rs    — Per-IP sliding-window rate limiter (moka-backed)
  output.rs        — CLI output formatting (table, json, simple)
  benchmark.rs     — Performance benchmarking
  wayback.rs       — Wayback Machine CDX API integration
  vuln.rs          — VulnVault MongoDB CVE lookup
  poc.rs           — PocVault MongoDB PoC lookup
  alert.rs         — AlertVault KEV/GHSA advisory lookup
  python.rs        — PyO3 bindings (feature-gated: --features python)
  analyzer/
    mod.rs         — TechnologyAnalyzer struct + pattern compilation (regex, JS, DNS)
    layers/
      headers.rs   — HTTP header detection + targeted version extraction
      html.rs      — HTML heuristics, SPA globals, meta[name=generator]
      scripts.rs   — Script/CSS URL analysis, banner comments, CDN path versions
      meta.rs      — Database meta tag pattern matching
      css.rs       — Inline CSS content scanning
      cookies.rs   — Generic cookie detection (Express, Django, Laravel, …)
      csp.rs       — Content-Security-Policy domain parsing (60+ SaaS mappings)
      dns.rs       — CNAME/TXT/MX record analysis (40+ CDN patterns)
      probes.rs    — Well-known endpoint probing (/package.json, /wp-json/, /healthz, …)
  server/
    mod.rs         — Actix-web server setup, app_data wiring, background cache refresh
    handlers.rs    — /analyze, /batch, /wayback, /health, /info endpoints
    cache.rs       — Hot-URL tracker; background auto-refresh loop (moka, 60s TTL)
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `API_KEY` | _(none)_ | Bearer token required on all endpoints when set |
| `MONGODB_URI` | _(none)_ | MongoDB connection string for CVE/PoC/KEV enrichment |
| `WAPPALYZER_CACHE` | next to binary | Path to the cached technology database JSON file |
| `WAPPALYZER_DB_URL` | `https://raw.githubusercontent.com/enthec/webappanalyzer/main/src` | Base URL for fetching the technology database. Override to use a corporate proxy or private mirror — the server will append `/technologies/{letter}.json` and `/categories.json` automatically. |
| `RUST_LOG` | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |

### Request/Concurrency Limits

Default timeouts and limits (in `WappalyzerConfig`):

| Setting | Default |
|---|---|
| HTTP request timeout | 30s |
| Connect timeout | 10s |
| Asset fetch timeout | 8s |
| Probe timeout | 8s |
| Favicon timeout | 8s |
| Source map timeout | 10s |
| Asset concurrency | 10 |
| Probe concurrency | 8 |
| Max batch size | 100 URLs |
| Max response body | 10 MB (truncated with a warning log) |
| User-Agent | Chrome 122 on Linux |
