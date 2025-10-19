# syntax=docker/dockerfile:1.7

# --- Builder stage: install Go-based security tools ---
FROM golang:1.24-bullseye AS builder

WORKDIR /app

# Install system packages required for building tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /go/bin

# --- Runtime stage: minimal Python image to run the Discord bot ---
FROM python:3.11-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AUTOAR_SCRIPT_PATH=/app/main.sh \
    AUTOAR_CONFIG_FILE=/app/autoar.yaml \
    AUTOAR_RESULTS_DIR=/app/new-results

WORKDIR /app

# System deps for runtime and common tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates tini jq dnsutils python3-dev gcc \
    postgresql-client libpq-dev awscli docker.io \
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . /app

# Copy Go tools from builder stage
COPY --from=builder /go/bin/ /usr/local/bin/

# Install Nuclei templates
RUN nuclei -update-templates || true

# Ensure directories exist
RUN mkdir -p /app/new-results /app/nuclei_templates || true

# Python dependencies
# Prefer existing requirements.txt; append discord.py if missing
RUN set -e; \
    if ! grep -iq '^discord\.py' requirements.txt 2>/dev/null; then \
      printf "\ndiscord.py>=2.4.0\n" >> requirements.txt; \
    fi; \
    if ! grep -iq '^pyyaml' requirements.txt 2>/dev/null; then \
      printf "pyyaml>=6.0.1\n" >> requirements.txt; \
    fi; \
    pip install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir git+https://github.com/codingo/Interlace.git

# Permissions and executables
RUN chmod +x /app/generate_config.sh || true \
    && chmod +x /app/main.sh || true \
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

# Basic healthcheck: ensure process is running by checking python import
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD python -c "import sys,importlib; importlib.import_module('discord'); sys.exit(0)" || exit 1


