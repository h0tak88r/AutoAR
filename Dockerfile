# syntax=docker/dockerfile:1.7

# --- Builder stage: install Go-based security tools and build AutoAR bot ---
FROM golang:1.24-bullseye AS builder

WORKDIR /app

# Install system packages required for building tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev ca-certificates \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust using rustup (newer version required for jwt-hack)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    rustup default stable && \
    rustc --version && \
    cargo --version

# Install next88 (React2Shell scanner) from GitHub
RUN go install github.com/h0tak88r/next88@latest && \
    chmod +x /go/bin/next88

WORKDIR /app

# Install Go-based security tools directly
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/ffuf/ffuf@latest && \
    go install -v github.com/Emoe/kxss@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/tomnomnom/gf@latest && \
    go install -v github.com/hakluke/hakrawler@latest && \
    go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/channyein1337/jsleak@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/tomnomnom/anew@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/mikefarah/yq/v4@latest && \
    go install -v github.com/kacakb/jsfinder@latest && \
    go install -v github.com/musana/fuzzuli@latest && \
    go install -v github.com/h0tak88r/confused2/cmd/confused2@latest && \
    go install -v github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest

# Install TruffleHog using the official install script
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /go/bin || \
    (echo "TruffleHog installation failed, continuing without it..." && echo "#!/bin/sh" > /go/bin/trufflehog && chmod +x /go/bin/trufflehog)

# Install jwt-hack (Rust-based JWT toolkit)
# Use rustup-installed Rust (ensure PATH is set)
ENV PATH="/root/.cargo/bin:${PATH}"
RUN set -e && \
    echo "Installing jwt-hack..." && \
    rustc --version && \
    cargo --version && \
    cargo install jwt-hack --locked --root /usr/local --verbose 2>&1 | tee /tmp/jwt-hack-install.log && \
    if [ ! -f /usr/local/bin/jwt-hack ] || [ ! -s /usr/local/bin/jwt-hack ]; then \
        echo "[ERROR] jwt-hack binary not found or empty after installation" && \
        cat /tmp/jwt-hack-install.log && \
        exit 1; \
    fi && \
    chmod +x /usr/local/bin/jwt-hack && \
    /usr/local/bin/jwt-hack --version && \
    echo "jwt-hack installed successfully"

# Build AutoAR main CLI and modules
WORKDIR /app

# Copy go.mod and go.sum first
COPY go.mod go.sum ./

# Copy gomodules directory (needed for go mod download with replace directives)
COPY gomodules/ ./gomodules/

# Download dependencies
RUN go mod download

# Build db-cli helper binary
RUN cd gomodules/db/cmd && CGO_ENABLED=0 GOOS=linux go build -o /app/db-cli .

# Copy main.go
COPY main.go ./

# Build main autoar binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/autoar .

# --- Runtime stage: minimal Debian image ---
FROM debian:bullseye-slim

ENV AUTOAR_SCRIPT_PATH=/usr/local/bin/autoar \
    AUTOAR_CONFIG_FILE=/app/autoar.yaml \
    AUTOAR_RESULTS_DIR=/app/new-results

WORKDIR /app

# System deps for runtime and common tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates tini jq dnsutils libpcap0.8 \
    postgresql-client awscli docker.io \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . /app

# Clone submodules directly
RUN cd /app && \
    rm -rf nuclei_templates Wordlists && \
    git clone --depth 1 https://github.com/h0tak88r/nuclei_templates.git nuclei_templates && \
    git clone --depth 1 https://github.com/h0tak88r/Wordlists.git Wordlists

# Copy Go tools from builder stage (including next88)
COPY --from=builder /go/bin/ /usr/local/bin/
# Copy main autoar binary
COPY --from=builder /app/autoar /usr/local/bin/autoar
# Copy db-cli helper binary
COPY --from=builder /app/db-cli /usr/local/bin/db-cli
# Copy jwt-hack from builder stage (installed to /usr/local/bin)
COPY --from=builder /usr/local/bin/jwt-hack /usr/local/bin/jwt-hack
# Create react2shell symlink for backward compatibility
# Also create main.sh symlink to autoar for backward compatibility
RUN ln -sf /usr/local/bin/next88 /usr/local/bin/react2shell && \
    ln -sf /usr/local/bin/autoar /app/main.sh && \
    chmod +x /usr/local/bin/next88 /usr/local/bin/react2shell /usr/local/bin/autoar /usr/local/bin/jwt-hack 2>/dev/null || true

# Install Nuclei templates to a known location
RUN nuclei -update-templates -ud /app/nuclei-templates || true

# Update misconfig-mapper templates
RUN misconfig-mapper -update-templates || true

# Ensure directories exist
RUN mkdir -p /app/new-results /app/nuclei_templates || true

# Permissions and executables
RUN chmod +x /app/generate_config.sh || true \
    && chmod +x /app/main.sh || true \
    && chmod +x /app/python/db_handler.py || true \
    && chmod +x /app/lib/db_wrapper.sh || true \
    && find /app/modules -type f -name '*.sh' -exec chmod +x {} + || true \
    && find /app/lib -type f -name '*.sh' -exec chmod +x {} + || true

# Add a non-root user
RUN useradd -m -u 10001 autoar && chown -R autoar:autoar /app
USER autoar

# Entrypoint script that generates config and starts the bot
COPY --chown=autoar:autoar docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Use tini as init for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker-entrypoint.sh"]

# Basic healthcheck: ensure process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD pgrep -f autoar || exit 1
