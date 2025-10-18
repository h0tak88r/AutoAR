#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: nuclei run -d <domain>"; }

nuclei_run() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
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
    [[ -s "$subs_dir/live-subs.txt" ]] && nuclei -l "$subs_dir/live-subs.txt" -t nuclei_templates/Others -o "$out1" >/dev/null 2>&1 || true
    [[ -s "$subs_dir/live-subs.txt" ]] && nuclei -l "$subs_dir/live-subs.txt" -t nuclei-templates/http -o "$out2" >/dev/null 2>&1 || true
  fi

  [[ -s "$out1" ]] && discord_send_file "$out1" "Nuclei custom template results"
  [[ -s "$out2" ]] && discord_send_file "$out2" "Nuclei public template results"
}

case "${1:-}" in
  run) shift; nuclei_run "$@" ;;
  *) usage; exit 1;;
esac


