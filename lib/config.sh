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
  
  # Database configuration
  DB_TYPE=${DB_TYPE:-$(yaml_get '.DB_TYPE')}
  DB_HOST=${DB_HOST:-$(yaml_get '.DB_HOST')}
  DB_PORT=${DB_PORT:-$(yaml_get '.DB_PORT')}
  DB_USER=${DB_USER:-$(yaml_get '.DB_USER')}
  DB_PASSWORD=${DB_PASSWORD:-$(yaml_get '.DB_PASSWORD')}
  DB_NAME=${DB_NAME:-$(yaml_get '.DB_NAME')}
  AUTOAR_DB=${AUTOAR_DB:-$(yaml_get '.AUTOAR_DB')}
  
  # Set defaults if not configured
  DB_TYPE=${DB_TYPE:-sqlite}
  DB_HOST=${DB_HOST:-localhost}
  DB_PORT=${DB_PORT:-5432}
  DB_USER=${DB_USER:-autoar}
  DB_PASSWORD=${DB_PASSWORD:-}
  DB_NAME=${DB_NAME:-autoar}
  AUTOAR_DB=${AUTOAR_DB:-/app/autoar.db}
}

load_config


