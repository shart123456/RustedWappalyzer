# Stage 1: Build
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./

# Create dummy targets to pre-build dependencies. Cargo.toml declares both a
# [lib] at src/lib.rs and a [[bin]] at src/main.rs, so both must exist or cargo
# aborts with "can't find lib `rusty_wappalyzer` at path /app/src/lib.rs".
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && touch src/lib.rs
RUN cargo build --release
RUN rm src/main.rs src/lib.rs

# Copy real source and build
# src/cache.rs embeds data/favicon_hashes.json, data/cpe_overrides.json and
# data/version_patches.json via include_str!, so data/ must be in the builder
# context or the real build fails with "couldn't read src/../data/...".
COPY src ./src
COPY data ./data
# Touch both targets: cargo fingerprints by mtime, and COPY can leave lib.rs
# older than the empty dummy artifact built above, in which case cargo reuses
# the empty lib and every rusty_wappalyzer:: import fails to resolve.
RUN touch src/main.rs src/lib.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root system user to run the service.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

# Copy binary
COPY --from=builder /app/target/release/rustywap /usr/local/bin/rustywap

# Seed the writable cache directory with the baked technology DB, then hand
# ownership to the non-root user so the cache module can refresh it at runtime.
# WAPPALYZER_CACHE points here so the binary never writes next to itself in the
# read-only /usr/local/bin/.
RUN mkdir -p /data
COPY wappalyzer_cache.json /data/wappalyzer_cache.json
# /app/logs must exist and be writable: server mode initialises a daily rolling
# file appender at the relative path "logs", which resolves under WORKDIR
# (/app). Without this the process panics on startup as the non-root user:
#   "initializing rolling file appender failed: ... PermissionDenied"
RUN mkdir -p /app/logs && chown -R app:app /data /app/logs
ENV WAPPALYZER_CACHE=/data/wappalyzer_cache.json

EXPOSE 3000

# Run as the unprivileged user (uid 10001). Matches the runAsNonRoot/runAsUser
# security context in deploy/k8s/wappalyzer.yaml.
USER app

CMD ["rustywap", "serve"]
