#!/usr/bin/env bash
set -euo pipefail

discord_send() {
  local content="$1"
  [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
  curl -sS -H "Content-Type: application/json" -X POST -d "{\"content\": \"${content//\"/\\\"}\"}" "$DISCORD_WEBHOOK" >/dev/null || true
}

discord_file() {
  local file="$1" desc="$2"
  [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
  [[ -f "$file" ]] || return 0
  curl -sS -F "file=@$file" -F "payload_json={\"content\": \"${desc//\"/\\\"}\"}" "$DISCORD_WEBHOOK" >/dev/null || true
}


