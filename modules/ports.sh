#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: ports scan -d <domain>"; }

ports_scan() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir="$ROOT_DIR/$(results_dir "$domain")"
  dir="$(results_dir "$domain")"
  local subs="$dir/subs/live-subs.txt"
  local out="$dir/ports/ports.txt"
  ensure_dir "$(dirname "$out")"
  [[ -s "$subs" ]] || { log_warn "No live subdomains to scan at $subs"; exit 0; }

  if command -v naabu >/dev/null 2>&1; then
    naabu -l "$subs" -tp 10000 -ec -c 500 -Pn --silent -rate 1000 -o "$out" >/dev/null 2>&1 || true
  fi
  [[ -s "$out" ]] && discord_file "$out" "Port scan results for $domain"
}

case "${1:-}" in
  scan) shift; ports_scan "$@" ;;
  *) usage; exit 1;;
esac


