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

  local dir="$(results_dir "$domain")"
  local urls="$dir/urls/all-urls.txt"
  local base="$dir/vulnerabilities"
  ensure_dir "$base"
  
  # Ensure URLs exist (from DB or URL collection)
  if ! ensure_urls "$domain" "$urls"; then
    log_info "No URLs found for $domain, running fastlook first"
    discord_send_progress "🔄 **No URLs found for $domain, running fastlook first**"
    "$ROOT_DIR/modules/fastlook.sh" run -d "$domain" || { log_warn "Failed to run fastlook for $domain"; exit 1; }
    
    # Try to get URLs again after fastlook
    if ! ensure_urls "$domain" "$urls"; then
      log_warn "Still no URLs found for $domain after fastlook"; exit 1;
    fi
  fi

  if command -v gf >/dev/null 2>&1; then
    for pattern in debug_logic idor iext img-traversal iparams isubs jsvar lfi rce redirect sqli ssrf ssti xss; do
      local out="$base/$pattern/gf-results.txt"
      ensure_dir "$(dirname "$out")"
      cat "$urls" | gf "$pattern" > "$out" 2>/dev/null || true
      [[ -s "$out" ]] && discord_send_file "$out" "GF $pattern matches"
    done
  fi
}

case "${1:-}" in
  scan) shift; gf_scan "$@" ;;
  *) usage; exit 1;;
esac


