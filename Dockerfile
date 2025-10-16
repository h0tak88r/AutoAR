# syntax=docker/dockerfile:1.7

# --- Builder stage: optional tool installation (Go-based and system tools) ---
FROM golang:1.24-bullseye AS builder

WORKDIR /app

# Install system packages required by setup.sh and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl build-essential cmake libpcap-dev python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy only the scripts that may be needed for tool install caching
COPY setup.sh /app/setup.sh
COPY fastlook-setup.sh /app/fastlook-setup.sh

# Allow opting-in to run setup at build time to bake tools into image
ARG RUN_SETUP_AT_BUILD=false
ARG RUN_FASTLOOK_SETUP=false
RUN chmod +x /app/setup.sh /app/fastlook-setup.sh \
    && if [ "$RUN_FASTLOOK_SETUP" = "true" ]; then /app/fastlook-setup.sh; fi \
    && if [ "$RUN_SETUP_AT_BUILD" = "true" ]; then /app/setup.sh; fi


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
    && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY . /app

# If we built tools in builder (fastlook or full), copy Go bin into PATH
COPY --from=builder /go/bin/ /usr/local/bin/

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
    && chmod +x /app/setup.sh || true \
    && chmod +x /app/autoAr.sh || true \
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


