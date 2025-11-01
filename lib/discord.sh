#!/usr/bin/env bash
set -euo pipefail

discord_send() {
  local content="$1"
  if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
    return 0
  fi
  local response
  response=$(curl -sS -w "\n%{http_code}" -H "Content-Type: application/json" -X POST -d "{\"content\": \"${content//\"/\\\"}\"}" "$DISCORD_WEBHOOK" 2>&1)
  local http_code
  http_code=$(echo "$response" | tail -n1)
  if [[ "$http_code" =~ ^[2][0-9]{2}$ ]]; then
    return 0
  else
    echo "Discord send failed: HTTP $http_code" >&2
    return 1
  fi
}

discord_file() {
  local file="$1" desc="$2"
  if [[ -z "${DISCORD_WEBHOOK:-}" ]]; then
    return 0
  fi
  if [[ ! -f "$file" ]]; then
    echo "Discord file error: File not found: $file" >&2
    return 1
  fi
  local response
  response=$(curl -sS -w "\n%{http_code}" -F "file=@$file" -F "payload_json={\"content\": \"${desc//\"/\\\"}\"}" "$DISCORD_WEBHOOK" 2>&1)
  local http_code
  http_code=$(echo "$response" | tail -n1)
  if [[ "$http_code" =~ ^[2][0-9]{2}$ ]]; then
    return 0
  else
    echo "Discord file send failed: HTTP $http_code" >&2
    return 1
  fi
}


