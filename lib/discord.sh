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

# Send file via Discord bot (if available) or webhook (fallback)
# This function sends final results via bot, while webhook is used for logging
discord_send_file_via_bot() {
  local file="$1"
  local desc="$2"
  local scan_id="${3:-}"
  
  [[ -f "$file" ]] || return 0
  
  # Try to send via Discord bot API if available
  if [[ -n "${DISCORD_BOT_TOKEN:-}" ]] && [[ "${AUTOAR_MODE:-}" == "discord" || "${AUTOAR_MODE:-}" == "both" ]]; then
    local api_host="${API_HOST:-localhost}"
    local api_port="${API_PORT:-8000}"
    local api_url="http://${api_host}:${api_port}/internal/send-file"
    
    # Get scan_id and channel_id from environment (set by Go bot)
    local channel_id="${AUTOAR_CURRENT_CHANNEL_ID:-}"
    if [[ -z "$scan_id" ]]; then
      scan_id="${AUTOAR_CURRENT_SCAN_ID:-}"
    fi
    
    # Build JSON payload
    local payload="{\"file_path\": \"$file\", \"description\": \"${desc//\"/\\\"}\""
    if [[ -n "$scan_id" ]]; then
      payload="${payload}, \"scan_id\": \"$scan_id\""
    fi
    if [[ -n "$channel_id" ]]; then
      payload="${payload}, \"channel_id\": \"$channel_id\""
    fi
    payload="${payload}}"
    
    # Send file via bot API
    local curl_output
    curl_output=$(curl -sS -w "\n%{http_code}" -X POST "$api_url" \
      -H "Content-Type: application/json" \
      -d "$payload" 2>&1)
    local http_code=$(echo "$curl_output" | tail -n1)
    local response=$(echo "$curl_output" | sed '$d')
    
    if [[ "$http_code" == "200" ]]; then
      log_info "File sent via Discord bot: $desc"
      return 0
    else
      log_warn "Failed to send file via bot API (HTTP $http_code): $response"
      log_warn "Falling back to webhook"
    fi
  fi
  
  # Fallback to webhook
  if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    discord_file "$file" "$desc"
  fi
}


