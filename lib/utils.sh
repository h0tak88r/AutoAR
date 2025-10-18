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
  
  # Try to pull from database
  log_info "Attempting to pull subdomains from database"
  local count
  count=$(db_get_subdomains "$domain" > "$subs_file" 2>/dev/null && wc -l < "$subs_file" || echo 0)
  
  if [[ $count -gt 0 ]]; then
    log_success "Loaded $count subdomains from database"
    return 0
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
  
  # Try DB first
  local count
  count=$(db_get_live_subdomains "$domain" > "$live_file" 2>/dev/null && wc -l < "$live_file" || echo 0)
  
  if [[ $count -gt 0 ]]; then
    log_success "Loaded $count live hosts from database"
    return 0
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


