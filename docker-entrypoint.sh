#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] AutoAR starting..."

# Get the mode from environment variable (default: discord)
AUTOAR_MODE="${AUTOAR_MODE:-discord}"

echo "[entrypoint] Mode: ${AUTOAR_MODE}"

# Load configuration (will generate autoar.yaml if needed)
echo "[entrypoint] Loading configuration..."
source /app/lib/config.sh
echo "[entrypoint] Configuration loaded successfully"

# Initialize database schema (only if database is configured)
if [[ -n "${DB_HOST:-}" && -n "${DB_USER:-}" ]]; then
  echo "[entrypoint] Initializing database schema"
  source /app/lib/db.sh && db_init_schema || echo "[entrypoint] Database schema initialization completed with warnings"
  
  # KeyHack templates are already in the database - no import needed
  # Templates can be added via 'keyhack add' command or Discord /keyhack_add
else
  echo "[entrypoint] Database not configured, skipping schema initialization"
fi

# Optionally run tool check/installation at container start
if [[ "${RUN_SETUP:-false}" == "true" ]]; then
  echo "[entrypoint] RUN_SETUP=true -> executing modules/check_tools.sh"
  /app/modules/check_tools.sh run || echo "[entrypoint] check_tools finished with warnings"
fi

# Create results dir and set permissions
mkdir -p "${AUTOAR_RESULTS_DIR:-/app/new-results}"

# Validate mandatory envs and files based on mode
if [[ "${AUTOAR_MODE}" == "discord" || "${AUTOAR_MODE}" == "both" ]]; then
  if [[ -z "${DISCORD_BOT_TOKEN:-}" ]]; then
    echo "[entrypoint] Error: DISCORD_BOT_TOKEN is not set (required for discord/both mode)" >&2
    exit 1
  fi
fi

if [[ ! -f "${AUTOAR_SCRIPT_PATH:-/app/main.sh}" ]]; then
  echo "[entrypoint] Error: AutoAR script not found at ${AUTOAR_SCRIPT_PATH:-/app/main.sh}" >&2
  exit 1
fi

# Launch based on mode
case "${AUTOAR_MODE}" in
  discord)
    echo "[entrypoint] Launching Discord Bot only (Go)..."
    exec /usr/local/bin/autoar bot
    ;;
  api)
    echo "[entrypoint] Launching API Server only (Go)..."
    exec /usr/local/bin/autoar api
    ;;
  both)
    echo "[entrypoint] Launching both Discord Bot and API Server (Go)..."
    exec /usr/local/bin/autoar both
    ;;
  *)
    echo "[entrypoint] Error: Invalid AUTOAR_MODE '${AUTOAR_MODE}'" >&2
    echo "[entrypoint] Valid modes: discord, api, both" >&2
    exit 1
    ;;
esac
