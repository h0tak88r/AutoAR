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

# Prerequisite helper functions
ensure_subdomains() {
  local domain="$1"
  local subs_file="$2"  # e.g., /app/new-results/example.com/subs/all-subs.txt
  local silent="${3:-false}"  # Optional silent flag
  local force_refresh="${4:-false}"  # Optional force refresh flag
  
  # Get ROOT_DIR if not set
  local ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || echo .)}"
  
  # If force_refresh is true, remove existing file to force re-enumeration
  if [[ "$force_refresh" == "true" && -f "$subs_file" ]]; then
    log_info "Force refresh requested, removing existing subdomains file"
    rm -f "$subs_file"
  fi
  
  # Check if file exists and is not empty
  if [[ -s "$subs_file" ]]; then
    local count=$(wc -l < "$subs_file" 2>/dev/null || echo 0)
    log_info "Using existing subdomains from $subs_file ($count subdomains)"
    # If file has very few subdomains (< 5), it might be stale - re-enumerate
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
    local count
    if command -v autoar >/dev/null 2>&1; then
      # Use autoar db commands to get subdomains (if implemented)
      # For now, skip DB lookup as it requires db query implementation
      count=0
    fi
    
    if [[ $count -gt 0 ]]; then
      log_success "Loaded $count subdomains from database"
      return 0
    fi
  else
    log_info "Database not configured, skipping database lookup"
  fi
  
  # Run subdomain enumeration
  log_info "No subdomains in DB, running enumeration"
  local subs_dir="$(dirname "$subs_file")"
  mkdir -p "$subs_dir"
  
  if [[ "$silent" == "true" ]]; then
    if command -v autoar >/dev/null 2>&1; then
      autoar subdomains get -d "$domain" -s 2>&1 || return 1
    else
      "${ROOT_DIR}/modules/subdomains.sh" get -d "$domain" --silent || return 1
    fi
  else
    if command -v autoar >/dev/null 2>&1; then
      autoar subdomains get -d "$domain" 2>&1 || return 1
    else
      "${ROOT_DIR}/modules/subdomains.sh" get -d "$domain" || return 1
    fi
  fi
}

ensure_live_hosts() {
  local domain="$1"
  local live_file="$2"
  
  if [[ -s "$live_file" ]]; then
    return 0
  fi
  
  # Try DB first (if database is available)
  if [[ -n "${DB_HOST:-}" && -n "${DB_USER:-}" ]]; then
    local count=0
    # DB lookup would go here if implemented
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
  
  # Run live host check via Go-powered CLI
  if command -v autoar >/dev/null 2>&1; then
    autoar livehosts get -d "$domain" || return 1
  else
    log_error "autoar binary not found; cannot run livehosts module"
    return 1
  fi
}

ensure_urls() {
  local domain="$1"
  local urls_file="$2"
  local ROOT_DIR="${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." 2>/dev/null && pwd || echo .)}"
  
  if [[ -s "$urls_file" ]]; then
    return 0
  fi
  
  # Ensure live hosts exist first
  local dir="$(dirname "$(dirname "$urls_file")")"
  local live_file="$dir/subs/live-subs.txt"
  ensure_live_hosts "$domain" "$live_file" || return 1
  
  # Run URL collection
  if command -v autoar >/dev/null 2>&1; then
    autoar urls collect -d "$domain" || return 1
  else
    log_error "autoar binary not found; cannot run urls module"
    return 1
  fi
}
