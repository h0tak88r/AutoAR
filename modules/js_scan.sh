#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: js scan -d <domain> [-s <subdomain>]"; }

js_scan() {
  local domain="" sub=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -s|--subdomain) sub="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" && -z "$sub" ]] && { usage; exit 1; }

  local target_dir; target_dir="$(results_dir "${sub:-$domain}")"
  local urls_file="$target_dir/urls/js-urls.txt"
  [[ -s "$urls_file" ]] || { log_warn "No JS URLs present at $urls_file"; exit 0; }

  local out_dir="$target_dir/vulnerabilities/js"; ensure_dir "$out_dir"

  if command -v jsleak >/dev/null 2>&1; then
    jsleak -t "$ROOT_DIR/regexes/trufflehog-v3.yaml" -s -c 20 < "$urls_file" > "$out_dir/trufflehog.txt" 2>/dev/null || true
  fi
  if [[ -d "$ROOT_DIR/regexes" ]]; then
    for f in "$ROOT_DIR"/regexes/*.yaml; do
      [[ -f "$f" ]] || continue
      base="$(basename "$f" .yaml)"
      jsleak -t "$f" -s -c 20 < "$urls_file" > "$out_dir/$base.txt" 2>/dev/null || true
    done
  fi

  if [[ -s "$out_dir/trufflehog.txt" ]]; then
    discord_file "$out_dir/trufflehog.txt" "JS scan matches (trufflehog)"
  fi
}

case "${1:-}" in
  scan) shift; js_scan "$@" ;;
  *) usage; exit 1;;
esac


