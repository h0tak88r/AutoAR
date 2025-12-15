#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load compatibility functions
if [[ -f "$ROOT_DIR/gomodules/compat.sh" ]]; then
  source "$ROOT_DIR/gomodules/compat.sh"
else
  # Minimal fallback functions
  log_info()    { printf "[INFO] %s\n" "$*"; }
  log_warn()    { printf "[WARN] %s\n" "$*"; }
  log_error()   { printf "[ERROR] %s\n" "$*" 1>&2; }
  log_success() { printf "[OK] %s\n" "$*"; }
  ensure_dir() { mkdir -p "$1"; }
  results_dir() { echo "${AUTOAR_RESULTS_DIR:-new-results}/$1"; }
  discord_send_file() { log_info "File will be sent by Discord bot: $2"; return 0; }
fi

# Load database functions
if [[ -f "$ROOT_DIR/gomodules/db/wrapper.sh" ]]; then
  source "$ROOT_DIR/gomodules/db/wrapper.sh"
fi

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
    if command -v autoar >/dev/null 2>&1; then
      # Use Go module to get subdomains from DB (if we add that function)
      # For now, just try enumeration
    fi
  fi
  
  # Run subdomain enumeration
  log_info "No subdomains in DB, running enumeration"
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
  if [[ "$silent" == "true" ]]; then
    "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" --silent || return 1
  else
    "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" || return 1
  fi
}

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


