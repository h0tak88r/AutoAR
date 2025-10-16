#!/usr/bin/env bash
set -euo pipefail

AUTOAR_CONFIG_FILE=${AUTOAR_CONFIG_FILE:-/app/autoar.yaml}

yaml_get() {
  local key="$1"
  if command -v yq >/dev/null 2>&1 && [[ -f "$AUTOAR_CONFIG_FILE" ]]; then
    yq -r "$key" "$AUTOAR_CONFIG_FILE" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

load_config() {
  DISCORD_WEBHOOK=${DISCORD_WEBHOOK:-$(yaml_get '.DISCORD_WEBHOOK')}
}

load_config


