#!/usr/bin/env bash
set -euo pipefail

echo "[entrypoint] AutoAR Discord bot starting..."

# Generate config if missing or forced
if [[ ! -f "/app/autoar.yaml" ]] || [[ "${REGENERATE_CONFIG:-false}" == "true" ]]; then
  echo "[entrypoint] Generating /app/autoar.yaml from environment variables"
  /app/generate_config.sh || { echo "[entrypoint] Failed to generate config"; exit 1; }
fi

# Optionally run setup.sh at container start (tool installation)
if [[ "${RUN_SETUP:-false}" == "true" ]]; then
  echo "[entrypoint] RUN_SETUP=true -> executing /app/setup.sh"
  /app/setup.sh || { echo "[entrypoint] setup.sh failed"; exit 1; }
fi

# Create results dir and set permissions
mkdir -p "${AUTOAR_RESULTS_DIR:-/app/new-results}"

# Validate mandatory envs and files
if [[ -z "${DISCORD_BOT_TOKEN:-}" ]]; then
  echo "[entrypoint] Error: DISCORD_BOT_TOKEN is not set" >&2
  exit 1
fi

if [[ ! -f "${AUTOAR_SCRIPT_PATH:-/app/autoAr.sh}" ]]; then
  echo "[entrypoint] Error: AutoAR script not found at ${AUTOAR_SCRIPT_PATH:-/app/autoAr.sh}" >&2
  exit 1
fi

echo "[entrypoint] Launching discord_bot.py"
exec python /app/discord_bot.py


