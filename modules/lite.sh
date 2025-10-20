#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: lite run -d <domain>"; }

lite_run() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  # Send initial progress notification
  discord_send_progress "🚀 **Starting Lite Scan for $domain**"
  
  # Compose of modular steps with progress updates
  log_info "Step 1/5: Subdomain enumeration"
  discord_send_progress "📡 **Step 1/5:** Enumerating subdomains for $domain"
  "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" || log_warn "Subdomain enumeration failed, continuing..."
  
  log_info "Step 2/5: CNAME record collection"
  discord_send_progress "🔗 **Step 2/5:** Collecting CNAME records for $domain"
  "$ROOT_DIR/modules/cnames.sh" get -d "$domain" || log_warn "CNAME collection failed, continuing..."
  
  log_info "Step 3/5: Live host filtering"
  discord_send_progress "🌐 **Step 3/5:** Filtering live hosts for $domain"
  "$ROOT_DIR/modules/livehosts.sh" get -d "$domain" || log_warn "Live host filtering failed, continuing..."
  
  log_info "Step 4/5: URL collection"
  discord_send_progress "🔍 **Step 4/5:** Collecting URLs for $domain"
  "$ROOT_DIR/modules/urls.sh" collect -d "$domain" || log_warn "URL collection failed, continuing..."
  
  log_info "Step 5/5: JavaScript scanning"
  discord_send_progress "📜 **Step 5/5:** Scanning JavaScript files for $domain"
  "$ROOT_DIR/modules/js_scan.sh" scan -d "$domain" || log_warn "JavaScript scanning failed, continuing..."
  
  # Send all JS scan results to Discord if they exist
  local js_results_dir="$(results_dir "$domain")/vulnerabilities/js"
  for findings_file in "$js_results_dir"/*.txt; do
    if [[ -s "$findings_file" ]]; then
      base="$(basename "$findings_file" .txt)"
      discord_file "$findings_file" "JS scan matches ($base) for $domain"
    fi
  done
  
  # Send completion notification
  discord_send_progress "✅ **Lite Scan completed for $domain** - All results sent above"
}

case "${1:-}" in
  run) shift; lite_run "$@" ;;
  *) usage; exit 1;;
esac


