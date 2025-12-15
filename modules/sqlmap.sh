#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/
# lib/discord.sh functionality in gomodules/ - functionality in gomodules/

usage() { 
  echo "Usage: sqlmap run -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for sqlmap (default: 100)"
}

sqlmap_run() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "$domain")"
  local in_file="$dir/vulnerabilities/sqli/gf-results.txt"
  local out_file="$dir/vulnerabilities/sqli/sqlmap-results.txt"
  ensure_dir "$(dirname "$out_file")"
  
  # Ensure GF results exist (run GF scan first)
  if [[ ! -s "$in_file" ]]; then
    log_info "No SQLi candidates found, running GF scan first"
    discord_send_progress "🔄 **No SQLi candidates found, running GF scan first for $domain**"
    "$ROOT_DIR/modules/gf_scan.sh" scan -d "$domain" || { log_warn "Failed to run GF scan for $domain"; exit 1; }
  fi
  
  [[ -s "$in_file" ]] || { log_warn "No SQLi candidate file at $in_file after GF scan"; exit 0; }

  local temp_urls="$dir/vulnerabilities/sqli/clean_urls.txt"
  : > "$temp_urls"
  while IFS= read -r url; do
    cleaned_url=$(echo "$url" | tr -cd '[:print:]' | grep -E '^https?://') || true
    [[ -n "$cleaned_url" ]] && echo "$cleaned_url" >> "$temp_urls"
  done < "$in_file"
  [[ -s "$temp_urls" ]] || { log_warn "No valid URLs for sqlmap"; exit 0; }

  if command -v interlace >/dev/null 2>&1; then
    log_info "Running sqlmap with $threads threads using interlace"
    interlace -tL "$temp_urls" -threads "$threads" -c "sqlmap -u _target_ --batch --dbs --random-agent" -o "$out_file" 2>/dev/null || true
  else
    # fallback single-thread
    log_info "Running sqlmap in single-thread mode (interlace not found)"
    while IFS= read -r u; do
      sqlmap -u "$u" --batch --random-agent --dbs >> "$out_file" 2>/dev/null || true
    done < "$temp_urls"
  fi

  if [[ -s "$out_file" ]]; then
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-sqlmap_$(date +%s)}"
    discord_send_file "$out_file" "SQLMap results for $domain" "$scan_id"
  fi
  rm -f "$temp_urls"
}

case "${1:-}" in
  run) shift; sqlmap_run "$@" ;;
  *) usage; exit 1;;
esac


