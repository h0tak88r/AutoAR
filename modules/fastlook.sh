#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load compatibility functions (replaces lib/ functions)
if [[ -f "$ROOT_DIR/gomodules/compat.sh" ]]; then
  source "$ROOT_DIR/gomodules/compat.sh"
else
  # Minimal fallback functions
  log_info()    { printf "[INFO] %s\n" "$*"; }
  log_warn()    { printf "[WARN] %s\n" "$*"; }
  log_error()   { printf "[ERROR] %s\n" "$*" 1>&2; }
  log_success() { printf "[OK] %s\n" "$*"; }
  ensure_dir() { mkdir -p "$1"; }
  results_dir() { echo "${AUTOAR_RESULTS_DIR:-new-results}/$1"; }
  discord_send_file() { log_info "File will be sent by Discord bot: $2"; }
fi

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
  log_info "Step 1/3: Subdomain enumeration"
  discord_send_progress "📡 **Step 1/3:** Enumerating subdomains for $domain"
  "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" || log_warn "Subdomain enumeration failed, continuing..."
  
  # Step 2: Live host filtering
  log_info "Step 2/3: Live host filtering"
  discord_send_progress "🌐 **Step 2/3:** Filtering live hosts for $domain"
  autoar livehosts get -d "$domain" -s || log_warn "Live host filtering failed, continuing..."
  
  # Step 3: URL collection (including JS URLs)
  log_info "Step 3/3: URL collection"
  discord_send_progress "🔍 **Step 3/3:** Collecting URLs and JS files for $domain"
  autoar urls collect -d "$domain" || log_warn "URL collection failed, continuing..."
  
  # Send completion notification
  discord_send_progress "✅ **Fast Look completed for $domain** - All results sent above"
}

case "${1:-}" in
  run) shift; fastlook_run "$@" ;;
  *) usage; exit 1;;
esac
