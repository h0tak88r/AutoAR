#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: fastlook run -d <domain>"; }

fastlook_run() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  # Send initial progress notification
  discord_send_progress "🚀 **Starting Fast Look for $domain**"
  
  # Step 1: Subdomain enumeration
  log_info "Step 1/4: Subdomain enumeration"
  discord_send_progress "📡 **Step 1/4:** Enumerating subdomains for $domain"
  "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" || log_warn "Subdomain enumeration failed, continuing..."
  
  # Step 2: Live host filtering
  log_info "Step 2/4: Live host filtering"
  discord_send_progress "🌐 **Step 2/4:** Filtering live hosts for $domain"
  "$ROOT_DIR/modules/livehosts.sh" get -d "$domain" || log_warn "Live host filtering failed, continuing..."
  
  # Step 3: URL collection (including JS URLs)
  log_info "Step 3/4: URL collection"
  discord_send_progress "🔍 **Step 3/4:** Collecting URLs and JS files for $domain"
  "$ROOT_DIR/modules/urls.sh" collect -d "$domain" || log_warn "URL collection failed, continuing..."
  
  # Step 4: CNAME record collection
  log_info "Step 4/4: CNAME record collection"
  discord_send_progress "🔗 **Step 4/4:** Collecting CNAME records for $domain"
  "$ROOT_DIR/modules/cnames.sh" get -d "$domain" || log_warn "CNAME collection failed, continuing..."
  
  # Send completion notification
  discord_send_progress "✅ **Fast Look completed for $domain** - All results sent above"
}

case "${1:-}" in
  run) shift; fastlook_run "$@" ;;
  *) usage; exit 1;;
esac
