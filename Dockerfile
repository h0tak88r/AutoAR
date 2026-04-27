# --- Builder stage: install Go-based security tools and build AutoAR bot ---
FROM golang:1.26-bookworm AS builder

WORKDIR /app

# Install system packages required for building tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev ca-certificates \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install external Go-based CLI tools used by AutoAR (only those requested explicitly by subshells)
RUN GOBIN=/go/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    GOBIN=/go/bin go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/go/bin go install -v github.com/codingo/interlace@latest || true

# Install TruffleHog (binary handled via custom build)
RUN git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog && \
    cd /tmp/trufflehog && go build -o /go/bin/trufflehog . && \
    rm -rf /tmp/trufflehog
# Build AutoAR main CLI and entrypoint
WORKDIR /app

# Copy go.mod and go.sum first
COPY go.mod go.sum ./

# Download dependencies (module graph only)
RUN go mod download

# Copy application source
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build main autoar binary from cmd/autoar (CGO enabled for naabu/libpcap)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /app/autoar ./cmd/autoar

# Build entrypoint binary (replaces docker-entrypoint.sh)
WORKDIR /app/internal/modules/entrypoint
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
    python3 python3-pip sqlmap nmap \
    default-jre-headless unzip zip \
    && rm -rf /var/lib/apt/lists/*

# Install Apktool and Uber-APK-Signer for MITM patching
RUN curl -L https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -o /usr/local/bin/apktool && \
    chmod +x /usr/local/bin/apktool && \
    curl -L https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar -o /usr/local/bin/apktool.jar && \
    curl -L https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar -o /usr/local/bin/uber-apk-signer.jar && \
    curl -L https://github.com/EFForg/apkeep/releases/download/0.18.0/apkeep-x86_64-unknown-linux-gnu -o /usr/local/bin/apkeep && \
    chmod +x /usr/local/bin/apkeep

# Copy minimal application configuration and assets (source not required at runtime)
COPY regexes/ ./regexes/
COPY templates/ ./templates/
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

# Install Nuclei templates to a known location
RUN nuclei -update-templates -ud /app/nuclei-templates || true


# Ensure directories exist
RUN mkdir -p /app/new-results /app/nuclei_templates || true

# Permissions
RUN chmod +x /app/generate_config.sh 2>/dev/null || true \
    && chmod +x /app/main.sh 2>/dev/null || true \
    && chmod +x /usr/local/bin/autoar-entrypoint \
    && echo "All modules are now Go-based - pure Go implementation" || true

# Add a non-root user
RUN useradd -m -u 10001 autoar && \
    chown -R autoar:autoar /app && \
    chown autoar:autoar /usr/local/bin/autoar-entrypoint
USER autoar

# Use tini as init for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/autoar-entrypoint"]

# Basic healthcheck: verify the API server responds, not just that the process exists (#18)
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -sf http://localhost:${API_PORT:-8000}/health || exit 1
