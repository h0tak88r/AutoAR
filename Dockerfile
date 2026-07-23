# --- Builder stage: install Go-based security tools and build AutoAR bot ---
FROM golang:1.25-bookworm AS builder

WORKDIR /app

# Install system packages required for building tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev ca-certificates \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install external tools used by AutoAR that are called as subprocess binaries.
# NOTE: httpx and nuclei are used as Go packages (go.mod), no binary needed.
# NOTE: interlace was removed — replaced by native Go concurrency.
# TruffleHog is called as a CLI binary by githubscan.go, so it must be installed here.
RUN git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog && \
    cd /tmp/trufflehog && \
    go build -o /go/bin/trufflehog . && \
    cd /app && \
    rm -rf /tmp/trufflehog && \
    go install -v github.com/d3mondev/puredns/v2@latest

# Build AutoAR main CLI and entrypoint
WORKDIR /app

# Copy go.mod and go.sum first
COPY go.mod go.sum ./

# Download dependencies (module graph only)
RUN go mod download

# Copy application source
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Fetch katana and all its sub-packages into go.sum.
# replace directives in go.mod prevent katana from upgrading the
# gitea/gitlab SDKs that nuclei v3.7.1 depends on.
RUN go get github.com/projectdiscovery/katana@v1.6.1 && \
    go get github.com/projectdiscovery/katana/pkg/utils@v1.6.1 && \
    go get github.com/projectdiscovery/katana/pkg/output@v1.6.1 && \
    go get github.com/projectdiscovery/katana/pkg/types@v1.6.1 && \
    go get github.com/projectdiscovery/katana/pkg/engine/standard@v1.6.1

# Build main autoar binary from cmd/autoar (CGO enabled for naabu/libpcap)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/autoar ./cmd/autoar

# Build entrypoint binary (replaces docker-entrypoint.sh)
WORKDIR /app/internal/scanner/entrypoint
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/autoar-entrypoint .
WORKDIR /app

# --- Runtime stage: minimal Debian image ---
FROM debian:bookworm-slim

ENV AUTOAR_SCRIPT_PATH=/usr/local/bin/autoar \
    AUTOAR_CONFIG_FILE=/app/autoar.yaml \
    AUTOAR_RESULTS_DIR=/app/new-results

WORKDIR /app

# System deps for runtime and common tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates tini jq dnsutils libpcap0.8 \
    postgresql-client docker.io \
    python3 sqlmap nmap \
    unzip zip \
    && rm -rf /var/lib/apt/lists/*

# Copy minimal application configuration and assets (source not required at runtime)
COPY regexes/ ./regexes/
COPY templates/ ./templates/
COPY web/static/data/ ./web/static/data/
COPY autoar.sample.yaml ./
COPY env.example ./

# Clone submodules directly
RUN cd /app && \
    rm -rf nuclei_templates Wordlists && \
    git clone --depth 1 https://github.com/h0tak88r/nuclei_templates.git nuclei_templates && \
    git clone --depth 1 https://github.com/h0tak88r/Wordlists.git Wordlists

# Copy Go tools from builder stage
COPY --from=builder /go/bin/ /usr/local/bin/
# Copy main autoar binary
COPY --from=builder /app/autoar /usr/local/bin/autoar
# Copy entrypoint binary
COPY --from=builder /app/autoar-entrypoint /usr/local/bin/autoar-entrypoint
# Create main.sh symlink to autoar for backward compatibility
RUN ln -sf /usr/local/bin/autoar /app/main.sh && \
    chmod +x /usr/local/bin/autoar 2>/dev/null || true

# Ensure directories exist
RUN mkdir -p /app/new-results /app/nuclei_templates || true

# Permissions
RUN chmod +x /usr/local/bin/autoar-entrypoint \
    && echo "All modules are now Go-based - pure Go implementation" || true

# Add a non-root user.
# `ulimit -n 1024` first: some libc/useradd versions loop over every possible file
# descriptor up to the (build container's) nofile limit, which can busy-spin for
# minutes when that limit is huge. Capping it keeps this step fast.
RUN ulimit -n 1024 2>/dev/null || true; \
    useradd -m -u 10001 autoar && \
    chown -R autoar:autoar /app && \
    chown autoar:autoar /usr/local/bin/autoar-entrypoint
USER autoar

EXPOSE 8000

# Use tini as init for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/autoar-entrypoint"]

# Basic healthcheck: verify the API server responds, not just that the process exists (#18)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -sf http://localhost:${API_PORT:-8000}/health || exit 1
