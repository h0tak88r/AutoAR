#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: urls collect -d <domain>"; }

urls_collect() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir subs_dir urls_dir
  dir="$(results_dir "$domain")"
  subs_dir="$dir/subs"; urls_dir="$dir/urls"
  ensure_dir "$urls_dir"

  : > "$urls_dir/all-urls.txt"
  : > "$urls_dir/js-urls.txt"

  if command -v urlfinder >/dev/null 2>&1; then
    log_info "Collecting URLs with urlfinder"
    urlfinder -d "$domain" -all -silent -o "$urls_dir/all-urls.txt" -pc "${AUTOAR_CONFIG_FILE:-/app/autoar.yaml}" >/dev/null 2>&1 || true
  fi

  if [[ -s "$subs_dir/live-subs.txt" && -x "$(command -v jsfinder || echo /bin/false)" ]]; then
    log_info "Running JSFinder on live subdomains"
    jsfinder -l "$subs_dir/live-subs.txt" -c 50 -s -o "$urls_dir/js-urls.txt" >/dev/null 2>&1 || true
  fi

  if [[ -s "$urls_dir/all-urls.txt" ]]; then
    grep -i ".js" "$urls_dir/all-urls.txt" >> "$urls_dir/js-urls.txt" || true
    sort -u -o "$urls_dir/js-urls.txt" "$urls_dir/js-urls.txt"
    cat "$urls_dir/js-urls.txt" >> "$urls_dir/all-urls.txt" || true
    sort -u -o "$urls_dir/all-urls.txt" "$urls_dir/all-urls.txt"
  fi

  local total=$(wc -l < "$urls_dir/all-urls.txt" 2>/dev/null || echo 0)
  local js=$(wc -l < "$urls_dir/js-urls.txt" 2>/dev/null || echo 0)
  log_success "Found $total total URLs; $js JavaScript URLs"
  discord_file "$urls_dir/all-urls.txt" "All URLs for $domain ($total)"
  [[ $js -gt 0 ]] && discord_file "$urls_dir/js-urls.txt" "JS URLs for $domain ($js)"
}

case "${1:-}" in
  collect) shift; urls_collect "$@" ;;
  *) usage; exit 1;;
esac


