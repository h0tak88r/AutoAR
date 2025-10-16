#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: gf scan -d <domain>"; }

gf_scan() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir="$ROOT_DIR/$(results_dir "$domain")"
  dir="$(results_dir "$domain")"
  local urls="$dir/urls/all-urls.txt"
  local base="$dir/vulnerabilities"
  ensure_dir "$base"
  [[ -s "$urls" ]] || { log_warn "No URLs to scan at $urls"; exit 0; }

  if command -v gf >/dev/null 2>&1; then
    for pattern in debug_logic idor iext img-traversal iparams isubs jsvar lfi rce redirect sqli ssrf ssti xss; do
      local out="$base/$pattern/gf-results.txt"
      ensure_dir "$(dirname "$out")"
      cat "$urls" | gf "$pattern" > "$out" 2>/dev/null || true
      [[ -s "$out" ]] && discord_file "$out" "GF $pattern matches"
    done
  fi
}

case "${1:-}" in
  scan) shift; gf_scan "$@" ;;
  *) usage; exit 1;;
esac


