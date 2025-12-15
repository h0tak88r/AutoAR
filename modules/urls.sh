#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/
# lib/config.sh functionality in gomodules/ - functionality in gomodules/
# lib/discord.sh functionality in gomodules/ - functionality in gomodules/

usage() { 
  echo "Usage: urls collect -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for urlfinder and jsfinder (default: 100)"
}

urls_collect() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir subs_dir urls_dir
  dir="$(results_dir "$domain")"
  subs_dir="$dir/subs"; urls_dir="$dir/urls"
  ensure_dir "$urls_dir"
  
  # Ensure live hosts exist (from DB or live host check)
  ensure_live_hosts "$domain" "$subs_dir/live-subs.txt" || { log_warn "Failed to get live hosts for $domain"; exit 1; }

  : > "$urls_dir/all-urls.txt"
  : > "$urls_dir/js-urls.txt"

  if command -v urlfinder >/dev/null 2>&1; then
    log_info "Collecting URLs with urlfinder"
    # urlfinder doesn't support -t flag, so we don't pass it
    urlfinder -d "$domain" -all -silent -pc "${AUTOAR_CONFIG_FILE}" > "$urls_dir/all-urls.txt" 2>/dev/null || true
  fi

  if [[ -s "$subs_dir/live-subs.txt" && -x "$(command -v jsfinder || echo /bin/false)" ]]; then
    log_info "Running JSFinder on live subdomains with $threads threads"
    jsfinder -l "$subs_dir/live-subs.txt" -c "$threads" -s -o "$urls_dir/js-urls.txt" >/dev/null 2>&1 || true
  fi

  if [[ -s "$urls_dir/all-urls.txt" ]]; then
    grep -i ".js" "$urls_dir/all-urls.txt" 2>/dev/null >> "$urls_dir/js-urls.txt" || true
    sort -u -o "$urls_dir/js-urls.txt" "$urls_dir/js-urls.txt"
    cat "$urls_dir/js-urls.txt" >> "$urls_dir/all-urls.txt" || true
    sort -u -o "$urls_dir/all-urls.txt" "$urls_dir/all-urls.txt"
  fi

  local total=$(wc -l < "$urls_dir/all-urls.txt" 2>/dev/null || echo 0)
  local js=$(wc -l < "$urls_dir/js-urls.txt" 2>/dev/null || echo 0)
  log_success "Found $total total URLs; $js JavaScript URLs"
  # Send final results via bot (webhook used for logging)
  local scan_id="${AUTOAR_CURRENT_SCAN_ID:-urls_$(date +%s)}"
  discord_send_file "$urls_dir/all-urls.txt" "All URLs for $domain ($total)" "$scan_id"
  [[ $js -gt 0 ]] && discord_send_file "$urls_dir/js-urls.txt" "JS URLs for $domain ($js)" "$scan_id"
}

case "${1:-}" in
  collect) shift; urls_collect "$@" ;;
  *) usage; exit 1;;
esac


