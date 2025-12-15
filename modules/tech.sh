#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load compatibility functions
if [[ -f "$ROOT_DIR/gomodules/compat.sh" ]]; then
  source "$ROOT_DIR/gomodules/compat.sh"
fi

usage() { 
  echo "Usage: tech detect -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for httpx (default: 100)"
}

tech_detect() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "$domain")"
  local subs="$dir/subs/live-subs.txt"
  local out="$dir/subs/tech-detect.txt"
  ensure_dir "$(dirname "$subs")"
  
  # Ensure live hosts exist (from DB or live host check)
  ensure_live_hosts "$domain" "$subs" || { log_warn "Failed to get live hosts for $domain"; exit 1; }
  if command -v httpx >/dev/null 2>&1; then
    log_info "Running technology detection with $threads threads"
    httpx -l "$subs" -tech-detect -title -status-code -server -nc -silent -threads "$threads" -o "$out" >/dev/null 2>&1 || true
    local count=$(wc -l < "$out" 2>/dev/null || echo 0)
    log_success "Technology detection completed for $count hosts"
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-tech_$(date +%s)}"
    discord_send_file "$out" "Technology detection results ($count)" "$scan_id"
  fi
}

case "${1:-}" in
  detect) shift; tech_detect "$@" ;;
  *) usage; exit 1;;
esac


