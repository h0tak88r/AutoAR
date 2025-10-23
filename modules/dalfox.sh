#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: dalfox run -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for dalfox (default: 100)"
}

dalfox_run() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir="$(results_dir "$domain")"
  local in_file="$dir/vulnerabilities/xss/gf-results.txt"
  local out_file="$dir/dalfox-results.txt"
  ensure_dir "$(dirname "$out_file")"
  
  # Ensure GF results exist (run GF scan first)
  if [[ ! -s "$in_file" ]]; then
    log_info "No XSS candidates found, running GF scan first"
    discord_send_progress "🔄 **No XSS candidates found, running GF scan first for $domain**"
    "$ROOT_DIR/modules/gf_scan.sh" scan -d "$domain" || { log_warn "Failed to run GF scan for $domain"; exit 1; }
  fi
  
  [[ -s "$in_file" ]] || { log_warn "No XSS candidate file at $in_file after GF scan"; exit 0; }

  if command -v dalfox >/dev/null 2>&1; then
    log_info "Running dalfox with $threads threads"
    dalfox file "$in_file" --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -b "0x88.xss.cl" -w "$threads" -o "$out_file" 2>/dev/null || true
  fi
  [[ -s "$out_file" ]] && discord_send_file "$out_file" "Dalfox results for $domain"
}

case "${1:-}" in
  run) shift; dalfox_run "$@" ;;
  *) usage; exit 1;;
esac


