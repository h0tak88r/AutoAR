#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"
source "$ROOT_DIR/lib/db.sh"

usage() { 
  echo "Usage: livehosts get -d <domain> [-t <threads>] [-s|--silent]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for httpx (default: 100)"
  echo "  -s, --silent     Silent mode: don't send Discord notifications"
}

livehosts_get() {
  local domain="" threads="100" silent=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      -s|--silent) silent=true; shift;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "$domain")"
  local subs_dir="$dir/subs"
  ensure_dir "$subs_dir"
  
  # Ensure subdomains exist (from DB or enumeration)
  # Pass silent flag to ensure_subdomains to prevent Discord notifications
  ensure_subdomains "$domain" "$subs_dir/all-subs.txt" "$silent" || { log_warn "Failed to get subdomains for $domain"; exit 1; }

  log_info "Filtering live hosts via httpx with $threads threads"
  if command -v httpx >/dev/null 2>&1; then
    cat "$subs_dir/all-subs.txt" | httpx -silent -nc -threads "$threads" -o "$subs_dir/live-subs.txt" >/dev/null 2>&1 || true
  else
    : > "$subs_dir/live-subs.txt"
  fi
  local total=$(wc -l < "$subs_dir/all-subs.txt" 2>/dev/null || echo 0)
  local live=$(wc -l < "$subs_dir/live-subs.txt" 2>/dev/null || echo 0)
  log_success "Found $live live subdomains out of $total"
  
  # Update database with live host information
  if [[ $live -gt 0 ]]; then
    log_info "Updating database with live host information"
    if db_ensure_connection; then
      # Initialize schema if needed
      db_init_schema 2>/dev/null || true
      while IFS= read -r subdomain; do
        if [[ -n "$subdomain" ]]; then
          # Extract protocol and status from httpx output if available
          local http_url="http://$subdomain"
          local https_url="https://$subdomain"
          db_insert_subdomain "$domain" "$subdomain" true "$http_url" "$https_url" 200 200
        fi
      done < "$subs_dir/live-subs.txt"
    else
      log_warn "Database connection failed, skipping database update"
    fi
  fi
  
  # Send final results via bot only if not in silent mode
  # COMMENTED OUT: Force silent mode for react2shell_scan
  if [[ "$silent" != "true" ]]; then
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-livehosts_$(date +%s)}"
    discord_send_file "$subs_dir/live-subs.txt" "Live subdomains ($live/$total) for $domain" "$scan_id"
  fi
}

case "${1:-}" in
  get) shift; livehosts_get "$@" ;;
  *) usage; exit 1;;
esac


