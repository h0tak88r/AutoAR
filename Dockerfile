# syntax=docker/dockerfile:1.7

# --- Builder stage: install Go-based security tools and build AutoAR bot ---
FROM golang:1.24-bullseye AS builder

WORKDIR /app

# Install system packages required for building tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev ca-certificates \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

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
RUN CGO_ENABLED=1 GOOS=linux go build -o /app/autoar ./cmd/autoar

# Build entrypoint binary (replaces docker-entrypoint.sh)
WORKDIR /app/internal/modules/entrypoint
RUN CGO_ENABLED=1 GOOS=linux go build -o /app/autoar-entrypoint .
WORKDIR /app

# --- Runtime stage: minimal Debian image ---
FROM debian:bullseye-slim

ENV AUTOAR_SCRIPT_PATH=/usr/local/bin/autoar \
    AUTOAR_CONFIG_FILE=/app/autoar.yaml \
    AUTOAR_RESULTS_DIR=/app/new-results

WORKDIR /app

# System deps for runtime and common tools (including Java + unzip for jadx)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates tini jq dnsutils libpcap0.8 \
    postgresql-client docker.io \
    openjdk-17-jre-headless unzip \
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

# Copy minimal application configuration and assets (source not required at runtime)
COPY regexes/ ./regexes/
COPY templates/ ./templates/
COPY autoar.sample.yaml ./
COPY env.example ./

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

# Basic healthcheck: ensure process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD pgrep -f autoar || exit 1
