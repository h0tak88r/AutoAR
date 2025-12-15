#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load compatibility functions (replaces lib/ functions)
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
  discord_send_file() { log_info "File will be sent by Discord bot: $2"; }
fi

usage() { echo "Usage: reflection scan -d <domain>"; }

reflection_scan() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir urls_file out_file
  dir="$(results_dir "$domain")"
  urls_file="$dir/urls/all-urls.txt"
  out_file="$dir/vulnerabilities/kxss-results.txt"
  ensure_dir "$(dirname "$out_file")"
  
  # Ensure URLs exist (from DB or URL collection)
  ensure_urls "$domain" "$urls_file" || { log_warn "Failed to get URLs for $domain"; exit 1; }

  if command -v kxss >/dev/null 2>&1; then
    kxss < "$urls_file" | grep -v "Unfiltered: \[\]" > "$out_file" 2>/dev/null || true
  else
    : > "$out_file"
  fi

  if [[ -s "$out_file" ]]; then
    local count=$(wc -l < "$out_file")
    log_success "Found reflection points: $count"
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-reflection_$(date +%s)}"
    discord_send_file "$out_file" "Reflection points for $domain ($count)" "$scan_id"
  else
    log_info "No reflection points found"
  fi
}

case "${1:-}" in
  scan) shift; reflection_scan "$@" ;;
  *) usage; exit 1;;
esac


