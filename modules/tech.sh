#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: tech detect -d <domain>"; }

tech_detect() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "$domain")"
  local subs="$dir/subs/live-subs.txt"
  local out="$dir/subs/tech-detect.txt"
  [[ -s "$subs" ]] || { log_warn "No live subdomains found at $subs"; exit 0; }
  if command -v httpx >/dev/null 2>&1; then
    httpx -l "$subs" -tech-detect -title -status-code -server -nc -silent -o "$out" >/dev/null 2>&1 || true
    local count=$(wc -l < "$out" 2>/dev/null || echo 0)
    log_success "Technology detection completed for $count hosts"
    discord_file "$out" "Technology detection results ($count)"
  fi
}

case "${1:-}" in
  detect) shift; tech_detect "$@" ;;
  *) usage; exit 1;;
esac


