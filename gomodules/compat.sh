#!/usr/bin/env bash
# Compatibility layer for lib/ functions (migrated to gomodules/)
# This provides minimal bash function replacements for modules

# Logging functions
log_info()    { printf "[INFO] %s\n" "$*"; }
log_warn()    { printf "[WARN] %s\n" "$*"; }
log_error()   { printf "[ERROR] %s\n" "$*" 1>&2; }
log_success() { printf "[OK] %s\n" "$*"; }

# Utility functions
ensure_dir() { mkdir -p "$1"; }
results_dir() {
  local d="$1"
  echo "${AUTOAR_RESULTS_DIR:-new-results}/$d"
}

domain_dir_init() {
  local domain="$1"
  local dir; dir="$(results_dir "$domain")"
  mkdir -p "$dir"/subs "$dir"/urls "$dir"/vulnerabilities/js
  echo "$dir"
}

# Config variables (set defaults if not already set)
AUTOAR_ENV="${AUTOAR_ENV:-local}"
AUTOAR_RESULTS_DIR="${AUTOAR_RESULTS_DIR:-new-results}"
AUTOAR_CONFIG_FILE="${AUTOAR_CONFIG_FILE:-autoar.yaml}"

# Discord file sending (bot handles it in Discord mode)
discord_send_file() {
  local file_path="$1" desc="$2"
  # In Discord bot mode, files are sent by bot after scan completes
  if [[ "${AUTOAR_MODE:-}" == "discord" || "${AUTOAR_MODE:-}" == "both" ]]; then
    log_info "File will be sent by Discord bot: $desc"
    return 0
  elif [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    # Fallback to webhook if bot not available
    curl -sS -F "file=@$file_path" -F "payload_json={\"content\": \"${desc//\"/\\\"}\"}" "$DISCORD_WEBHOOK" >/dev/null || true
  fi
}

discord_send() {
  local content="$1"
  [[ -z "${DISCORD_WEBHOOK:-}" ]] && return 0
  curl -sS -H "Content-Type: application/json" -X POST -d "{\"content\": \"${content//\"/\\\"}\"}" "$DISCORD_WEBHOOK" >/dev/null || true
}

discord_send_progress() {
  local message="$1"
  discord_send "$message"
}

# Phase timeout helpers
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
  local now; now=$(date +%s)
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
  if [[ -n "$remaining" ]] && [[ "$remaining" =~ ^[0-9]+$ ]]; then
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

# ensure_subdomains - Ensure subdomains file exists (from DB or enumeration)
ensure_subdomains() {
  local domain="$1"
  local subs_file="$2"
  local silent="${3:-false}"
  local force_refresh="${4:-false}"
  
  # If force_refresh is true, remove existing file
  if [[ "$force_refresh" == "true" && -f "$subs_file" ]]; then
    log_info "Force refresh requested, removing existing subdomains file"
    rm -f "$subs_file"
  fi
  
  # Check if file exists and is not empty
  if [[ -s "$subs_file" ]]; then
    local count=$(wc -l < "$subs_file" 2>/dev/null || echo 0)
    log_info "Using existing subdomains from $subs_file ($count subdomains)"
    if [[ $count -lt 5 ]]; then
      log_warn "Very few subdomains found ($count), might be stale. Re-enumerating..."
      rm -f "$subs_file"
    else
      return 0
    fi
  fi
  
  # Try to pull from database (if database is available)
  if [[ -n "${DB_HOST:-}" && -n "${DB_USER:-}" ]]; then
    log_info "Attempting to pull subdomains from database"
    # Database lookup would go here if we add that function
  fi
  
  # Run subdomain enumeration
  log_info "No subdomains in DB, running enumeration"
  
  # Ensure directory exists
  local dir=$(dirname "$subs_file")
  mkdir -p "$dir"
  
  if command -v autoar >/dev/null 2>&1; then
    # Try Go subdomains module first
    if autoar subdomains get -d "$domain" -t 100 ${silent:+-s} 2>&1; then
      # Check if file was created
      if [[ -f "$subs_file" ]]; then
        return 0
      fi
    fi
  fi
  
  # Fallback to bash module
  # Try to find ROOT_DIR from calling script's context
  local root_dir="${ROOT_DIR:-}"
  if [[ -z "$root_dir" ]]; then
    # Try common locations
    if [[ -d "/app/modules" ]]; then
      root_dir="/app"
    elif [[ -d "$(pwd)/modules" ]]; then
      root_dir="$(pwd)"
    else
      root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
  fi
  
  if [[ "$silent" == "true" ]]; then
    "$root_dir/modules/subdomains.sh" get -d "$domain" --silent || return 1
  else
    "$root_dir/modules/subdomains.sh" get -d "$domain" || return 1
  fi
}

# ensure_live_hosts - Ensure live hosts file exists
ensure_live_hosts() {
  local domain="$1"
  local live_file="$2"
  
  if [[ -s "$live_file" ]]; then
    return 0
  fi
  
  # Try DB first (if database is available)
  if [[ -n "${DB_HOST:-}" && -n "${DB_USER:-}" ]]; then
    local count
    # Database lookup would go here if we add that function
  fi
  
  # Ensure subdomains exist first
  local dir=$(dirname "$(dirname "$live_file")")
  local subs_file="$dir/subs/all-subs.txt"
  ensure_subdomains "$domain" "$subs_file" || return 1
  
  # Run live host check
  local root_dir="${ROOT_DIR:-}"
  if [[ -z "$root_dir" ]]; then
    if [[ -d "/app/modules" ]]; then
      root_dir="/app"
    elif [[ -d "$(pwd)/modules" ]]; then
      root_dir="$(pwd)"
    else
      root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
  fi
  
  "$root_dir/modules/livehosts.sh" get -d "$domain" || return 1
}
