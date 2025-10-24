#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: nuclei run -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for nuclei (default: 100)"
}

nuclei_run() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir subs_dir out1 out2
  dir="$(results_dir "$domain")"
  subs_dir="$dir/subs"
  out1="$dir/vulnerabilities/nuclei_templates-results.txt"
  out2="$dir/vulnerabilities/nuclei-templates-results.txt"
  ensure_dir "$(dirname "$out1")"
  
  # Ensure live hosts exist (from DB or live host check)
  ensure_live_hosts "$domain" "$subs_dir/live-subs.txt" || { log_warn "Failed to get live hosts for $domain"; exit 1; }

  if command -v nuclei >/dev/null 2>&1; then
    log_info "Running nuclei with $threads threads"
    [[ -s "$subs_dir/live-subs.txt" ]] && nuclei -l "$subs_dir/live-subs.txt" -t nuclei_templates/Others -c "$threads" -o "$out1" >/dev/null 2>&1 || true
    [[ -s "$subs_dir/live-subs.txt" ]] && nuclei -l "$subs_dir/live-subs.txt" -t nuclei-templates/http -c "$threads" -o "$out2" >/dev/null 2>&1 || true
  fi

  [[ -s "$out1" ]] && discord_send_file "$out1" "Nuclei custom template results"
  [[ -s "$out2" ]] && discord_send_file "$out2" "Nuclei public template results"
}

case "${1:-}" in
  run) shift; nuclei_run "$@" ;;
  *) usage; exit 1;;
esac


