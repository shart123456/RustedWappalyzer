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

# Create dummy main.rs to pre-build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm src/main.rs

# Copy real source and build
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary and cache
COPY --from=builder /app/target/release/wappalyzer /usr/local/bin/wappalyzer
COPY wappalyzer_cache.json /app/wappalyzer_cache.json

# Create writable data directory for the cache
RUN mkdir -p /data

# Point the cache module at the writable /data directory so the binary
# does not attempt to write next to itself in the read-only /usr/local/bin/
ENV WAPPALYZER_CACHE=/data/wappalyzer_cache.json

# Declare /data as a volume so the cache survives container restarts
VOLUME ["/data"]

EXPOSE 3000

CMD ["wappalyzer", "serve"]
