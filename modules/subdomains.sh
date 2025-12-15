#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load environment variables first
if [[ -f "$ROOT_DIR/.env" ]]; then
  source "$ROOT_DIR/.env"
fi

# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/
# lib/config.sh functionality in gomodules/ - functionality in gomodules/
# lib/discord.sh functionality in gomodules/ - functionality in gomodules/
# lib/db.sh functionality in gomodules/ - functionality in gomodules/

usage() { 
  echo "Usage: subdomains get -d <domain> [-t <threads>] [-s|--silent]"
  echo "  -d, --domain     Target domain to enumerate"
  echo "  -t, --threads    Number of threads for subfinder (default: 100)"
  echo "  -s, --silent     Silent mode: don't send Discord notifications"
}

subdomains_get() {
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

  local dir; dir="$(domain_dir_init "$domain")"
  local subs_dir="$dir/subs"
  ensure_dir "$subs_dir"

  log_info "Collecting subdomains for $domain"

  # Try Go subdomains module first (uses subfinder library)
  if command -v autoar >/dev/null 2>&1; then
    log_info "Using Go subdomains module (subfinder library)"
    if autoar subdomains get -d "$domain" -t "$threads" ${silent:+-s} 2>&1; then
      # Go module handles everything including database saving
      if [[ -f "$subs_dir/all-subs.txt" ]]; then
        local total; total=$(wc -l < "$subs_dir/all-subs.txt" 2>/dev/null || echo 0)
        log_success "Found $total unique subdomains"
        return 0
      fi
    fi
    log_warn "Go subdomains module failed, falling back to bash implementation"
  fi

  # Fallback: API sources (lightweight)
  tmp_file="$subs_dir/tmp_subs.txt"
  : > "$tmp_file"
  curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" || true
  curl -s "https://crt.sh/?q=%.$domain&output=json" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" || true

  if command -v subfinder >/dev/null 2>&1; then
    log_info "Running subfinder binary with $threads threads"
    subfinder -d "$domain" -silent -o "$subs_dir/subfinder-subs.txt" -pc "${AUTOAR_CONFIG_FILE}" -t "$threads" >/dev/null 2>&1 || true
  else
    : > "$subs_dir/subfinder-subs.txt"
  fi

  cat "$tmp_file" "$subs_dir/subfinder-subs.txt" 2>/dev/null | grep -v "\*" | sort -u > "$subs_dir/all-subs.txt"
  rm -f "$tmp_file"

  local total; total=$(wc -l < "$subs_dir/all-subs.txt" 2>/dev/null || echo 0)
  log_success "Found $total unique subdomains"
  
  # Save subdomains to database (batch insert for performance)
  if [[ $total -gt 0 ]]; then
    log_info "Saving subdomains to database"
    if command -v autoar >/dev/null 2>&1; then
      # Use Go database module via autoar
      if autoar db check-connection >/dev/null 2>&1; then
        autoar db init-schema >/dev/null 2>&1 || true
        if ! autoar db batch-insert-subdomains "$domain" "$subs_dir/all-subs.txt" false; then
          log_warn "Failed to save subdomains to database"
        fi
      else
        log_warn "Database connection failed, skipping database save"
      fi
    elif [[ -f "$ROOT_DIR/gomodules/db/wrapper.sh" ]]; then
      # Use Go wrapper script
      source "$ROOT_DIR/gomodules/db/wrapper.sh"
      if db_ensure_connection; then
        db_init_schema 2>/dev/null || true
        db_batch_insert_subdomains "$domain" "$subs_dir/all-subs.txt" false || log_warn "Failed to save subdomains to database"
      else
        log_warn "Database connection failed, skipping database save"
      fi
    else
      log_warn "Database tools not available, skipping database save"
    fi
  fi
  
  # Send final results via bot only if not in silent mode
  if [[ "$silent" != "true" ]]; then
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-subdomains_$(date +%s)}"
    discord_send_file "$subs_dir/all-subs.txt" "Subdomains for $domain" "$scan_id"
  fi
}

case "${1:-}" in
  get) shift; subdomains_get "$@" ;;
  *) usage; exit 1;;
esac


