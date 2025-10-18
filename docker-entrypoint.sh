#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] AutoAR Discord bot starting..."

# Load configuration (will generate autoar.yaml if needed)
echo "[entrypoint] Loading configuration..."
source /app/lib/config.sh
echo "[entrypoint] Configuration loaded successfully"

# Initialize database schema
echo "[entrypoint] Initializing database schema"
source /app/lib/db.sh && db_init_schema || echo "[entrypoint] Database schema initialization completed with warnings"

# Optionally run tool check/installation at container start
if [[ "${RUN_SETUP:-false}" == "true" ]]; then
  echo "[entrypoint] RUN_SETUP=true -> executing modules/check_tools.sh"
  /app/modules/check_tools.sh run || echo "[entrypoint] check_tools finished with warnings"
fi

# Create results dir and set permissions
mkdir -p "${AUTOAR_RESULTS_DIR:-/app/new-results}"

# Validate mandatory envs and files
if [[ -z "${DISCORD_BOT_TOKEN:-}" ]]; then
  echo "[entrypoint] Error: DISCORD_BOT_TOKEN is not set" >&2
  exit 1
fi

if [[ ! -f "${AUTOAR_SCRIPT_PATH:-/app/main.sh}" ]]; then
  echo "[entrypoint] Error: AutoAR script not found at ${AUTOAR_SCRIPT_PATH:-/app/main.sh}" >&2
  exit 1
fi

echo "[entrypoint] Launching discord_bot.py"
exec python /app/discord_bot.py


