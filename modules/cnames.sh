#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load compatibility functions
if [[ -f "$ROOT_DIR/gomodules/compat.sh" ]]; then
  source "$ROOT_DIR/gomodules/compat.sh"
fi

usage() { echo "Usage: cnames get -d <domain>"; }

cnames_get() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "$domain")"
  local subs_dir="$dir/subs"
  ensure_dir "$subs_dir"
  
  # Ensure subdomains exist (from DB or enumeration)
  ensure_subdomains "$domain" "$subs_dir/all-subs.txt" || { log_warn "Failed to get subdomains for $domain"; exit 1; }

  local out="$subs_dir/cname-records.txt"
  if command -v dnsx >/dev/null 2>&1; then
    log_info "Collecting CNAME records via dnsx"
    cat "$subs_dir/all-subs.txt" | dnsx -cname -silent -resp -nc -o "$out" >/dev/null 2>&1 || true
  else
    : > "$out"
  fi

  local count=$(wc -l < "$out" 2>/dev/null || echo 0)
  log_success "Found $count CNAME records"
  
  # Send final results via bot (webhook still used for logging via discord_send_progress)
  local scan_id="${AUTOAR_CURRENT_SCAN_ID:-cnames_$(date +%s)}"
  discord_send_file "$out" "CNAME records for $domain ($count)" "$scan_id"
}

case "${1:-}" in
  get) shift; cnames_get "$@" ;;
  *) usage; exit 1;;
esac


