#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load environment variables first
if [[ -f "$ROOT_DIR/.env" ]]; then
  source "$ROOT_DIR/.env"
fi

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"
source "$ROOT_DIR/lib/db.sh"

usage() { 
  echo "Usage: subdomains get -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to enumerate"
  echo "  -t, --threads    Number of threads for subfinder (default: 100)"
}

subdomains_get() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(domain_dir_init "$domain")"
  local subs_dir="$dir/subs"
  ensure_dir "$subs_dir"

  log_info "Collecting subdomains for $domain"

  # API sources (lightweight)
  tmp_file="$subs_dir/tmp_subs.txt"
  : > "$tmp_file"
  curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" || true
  curl -s "https://crt.sh/?q=%.$domain&output=json" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" || true

  if command -v subfinder >/dev/null 2>&1; then
    log_info "Running subfinder with $threads threads"
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
    if db_ensure_connection; then
      # Initialize schema if needed
      db_init_schema 2>/dev/null || true
      # Batch insert subdomains
      db_batch_insert_subdomains "$domain" "$subs_dir/all-subs.txt" false
    else
      log_warn "Database connection failed, skipping database save"
    fi
  fi
  
  discord_send_file "$subs_dir/all-subs.txt" "Subdomains for $domain"
}

case "${1:-}" in
  get) shift; subdomains_get "$@" ;;
  *) usage; exit 1;;
esac


