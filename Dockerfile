# syntax=docker/dockerfile:1.7

# --- Builder stage: install Go-based security tools and build AutoAR bot ---
FROM golang:1.26-bullseye AS builder

WORKDIR /app

# Install system packages required for building tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev ca-certificates \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install external Go-based CLI tools used by AutoAR
RUN GOBIN=/go/bin go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    GOBIN=/go/bin go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    GOBIN=/go/bin go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    GOBIN=/go/bin go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    GOBIN=/go/bin go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    GOBIN=/go/bin go install -v github.com/ffuf/ffuf/v2@latest && \
    GOBIN=/go/bin go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    GOBIN=/go/bin go install -v github.com/tomnomnom/waybackurls@latest && \
    GOBIN=/go/bin go install -v github.com/hahwul/dalfox/v2@latest && \
    GOBIN=/go/bin go install -v github.com/tomnomnom/anew@latest && \
    GOBIN=/go/bin go install -v github.com/codingo/interlace@latest && \
    GOBIN=/go/bin go install -v github.com/deletescape/goop@latest && \
    GOBIN=/go/bin go install -v github.com/h0tak88r/misconfig-mapper@latest || true

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
FROM debian:bullseye-slim

ENV AUTOAR_SCRIPT_PATH=/usr/local/bin/autoar \
    AUTOAR_CONFIG_FILE=/app/autoar.yaml \
    AUTOAR_RESULTS_DIR=/app/new-results

WORKDIR /app

# System deps for runtime and common tools (including Java + unzip for jadx and apktool)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates tini jq dnsutils libpcap0.8 \
    postgresql-client docker.io \
    openjdk-17-jre-headless unzip \
    python3 python3-pip sqlmap nmap \
    && rm -rf /var/lib/apt/lists/*

# Install jadx decompiler for apkX analysis
RUN set -eux; \
    JADX_VERSION="1.4.7"; \
    curl -L "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip; \
    mkdir -p /opt/jadx; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx; \
    ln -sf /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui || true; \
    rm /tmp/jadx.zip

# Install apktool for MITM patching (decode/encode APKs)
RUN set -eux; \
    APKTOOL_VERSION="2.9.3"; \
    curl -L "https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_${APKTOOL_VERSION}.jar" -o /usr/local/bin/apktool.jar; \
    echo '#!/bin/sh\njava -jar /usr/local/bin/apktool.jar "$@"' > /usr/local/bin/apktool; \
    chmod +x /usr/local/bin/apktool

# Install uber-apk-signer for signing patched APKs (optional, but recommended)
RUN set -eux; \
    curl -L "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar" -o /usr/local/bin/uber-apk-signer.jar; \
    echo '#!/bin/sh\njava -jar /usr/local/bin/uber-apk-signer.jar "$@"' > /usr/local/bin/uber-apk-signer; \
    chmod +x /usr/local/bin/uber-apk-signer || true

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

# Update misconfig-mapper templates
RUN misconfig-mapper -update-templates || true

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
