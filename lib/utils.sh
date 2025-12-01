#!/usr/bin/env bash
set -euo pipefail

# Source config first to get cross-platform paths
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/config.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/logging.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/db.sh" 2>/dev/null || true

ensure_dir() { mkdir -p "$1"; }

results_dir() {
  local d="$1"
  echo "${AUTOAR_RESULTS_DIR}/$d"
}

# ----- Phase timeout helpers -----

phase_timeout_enabled() {
  [[ -n "${AUTOAR_PHASE_TIMEOUT:-}" ]] || return 1
  [[ -n "${AUTOAR_PHASE_START_TS:-}" ]] || return 1
  [[ "${AUTOAR_PHASE_TIMEOUT:-0}" -gt 0 ]] || return 1
  return 0
}

phase_time_remaining() {
  if ! phase_timeout_enabled; then
    echo ""
    return 1
  fi

  local now
  now=$(date +%s)
  local elapsed=$((now - AUTOAR_PHASE_START_TS))
  local remaining=$((AUTOAR_PHASE_TIMEOUT - elapsed))
  if (( remaining < 0 )); then
    remaining=0
  fi
  echo "$remaining"
  return 0
}

run_with_phase_timeout() {
  local description="$1"
  shift

  local remaining
  remaining=$(phase_time_remaining)

  if [[ -n "$remaining" ]]; then
    if (( remaining <= 0 )); then
      log_warn "Phase timeout reached before ${description:-command}; skipping."
      return 124
    fi

    if command -v timeout >/dev/null 2>&1; then
      timeout --preserve-status --signal TERM --kill-after=30 "$remaining" "$@"
      return $?
    else
      log_warn "Phase timeout requested for ${description:-command} but 'timeout' command is unavailable; running without enforcement."
    fi
  fi

  "$@"
}

# Check if Discord bot is available (running in Docker with bot)
is_discord_bot_available() {
  # Check if we're in Docker and Discord bot token is set
  if [[ "${AUTOAR_ENV:-}" == "docker" && -n "${DISCORD_BOT_TOKEN:-}" ]]; then
    return 0
  fi
  return 1
}

# Send file via Discord (bot or webhook)
discord_send_file() {
  local file_path="$1"
  local description="$2"
  
  if is_discord_bot_available; then
    # For Discord bot, we'll use webhook for immediate sending
    # This provides better user experience with progressive updates
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
      discord_file "$file_path" "$description"
    else
      log_info "File will be sent via Discord bot: $description"
    fi
  elif [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    # Fallback to webhook
    discord_file "$file_path" "$description"
  else
    log_info "No Discord integration available for: $description"
  fi
}

# Send immediate Discord notification for scan progress
discord_send_progress() {
  local message="$1"
  
  if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    curl -H "Content-Type: application/json" \
         -d "{\"content\": \"$message\"}" \
         "${DISCORD_WEBHOOK}" >/dev/null 2>&1 || true
  fi
}

domain_dir_init() {
  local domain="$1"
  local dir
  dir="$(results_dir "$domain")"
  mkdir -p "$dir"/subs "$dir"/urls "$dir"/vulnerabilities/js
  echo "$dir"
}

# Prerequisite helper functions
ensure_subdomains() {
  local domain="$1"
  local subs_file="$2"  # e.g., /app/new-results/example.com/subs/all-subs.txt
  
  # Check if file exists and is not empty
  if [[ -s "$subs_file" ]]; then
    log_info "Using existing subdomains from $subs_file"
    return 0
  fi
  
  # Try to pull from database (if database is available)
  if [[ -n "${DB_HOST:-}" && -n "${DB_USER:-}" ]]; then
    log_info "Attempting to pull subdomains from database"
    local count
    count=$(db_get_subdomains "$domain" > "$subs_file" 2>/dev/null && wc -l < "$subs_file" || echo 0)
    
    if [[ $count -gt 0 ]]; then
      log_success "Loaded $count subdomains from database"
      return 0
    fi
  else
    log_info "Database not configured, skipping database lookup"
  fi
  
  # Run subdomain enumeration
  log_info "No subdomains in DB, running enumeration"
  "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" || return 1
}

ensure_live_hosts() {
  local domain="$1"
  local live_file="$2"
  
  if [[ -s "$live_file" ]]; then
    return 0
  fi
  
  # Try DB first (if database is available)
  if [[ -n "${DB_HOST:-}" && -n "${DB_USER:-}" ]]; then
    local count
    count=$(db_get_live_subdomains "$domain" > "$live_file" 2>/dev/null && wc -l < "$live_file" || echo 0)
    
    if [[ $count -gt 0 ]]; then
      log_success "Loaded $count live hosts from database"
      return 0
    fi
  else
    log_info "Database not configured, skipping database lookup"
  fi
  
  # Ensure subdomains exist
  local subs_file="$(dirname "$live_file")/all-subs.txt"
  ensure_subdomains "$domain" "$subs_file" || return 1
  
  # Run live host check
  "$ROOT_DIR/modules/livehosts.sh" get -d "$domain" || return 1
}

ensure_urls() {
  local domain="$1"
  local urls_file="$2"
  
  if [[ -s "$urls_file" ]]; then
    return 0
  fi
  
  # Ensure live hosts exist first
  local dir="$(dirname "$(dirname "$urls_file")")"
  local live_file="$dir/subs/live-subs.txt"
  ensure_live_hosts "$domain" "$live_file" || return 1
  
  # Run URL collection
  "$ROOT_DIR/modules/urls.sh" collect -d "$domain" || return 1
}


