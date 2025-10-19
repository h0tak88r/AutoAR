#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: ports scan -d <domain>"; }

ports_scan() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  log_info "Starting ports scan for domain: $domain"
  
  local dir="$(results_dir "$domain")"
  local subs="$dir/subs/live-subs.txt"
  local out="$dir/ports/ports.txt"
  
  log_info "Results directory: $dir"
  log_info "Subdomains file: $subs"
  log_info "Output file: $out"
  
  ensure_dir "$(dirname "$out")"
  log_info "Created output directory: $(dirname "$out")"
  
  # Ensure live hosts exist (from DB or live host check)
  log_info "Ensuring live hosts exist..."
  if ! ensure_live_hosts "$domain" "$subs"; then
    log_error "Failed to get live hosts for $domain"
    exit 1
  fi
  log_info "Live hosts check completed"

  if command -v naabu >/dev/null 2>&1; then
    log_info "Running naabu port scan..."
    if naabu -l "$subs" -tp 1000 -ec -c 500 -Pn --silent -rate 1000 -o "$out"; then
      log_success "Naabu scan completed successfully"
    else
      log_warn "Naabu scan completed with warnings"
    fi
  else
    log_error "naabu not found, skipping port scan"
  fi
  
  if [[ -s "$out" ]]; then
    log_success "Port scan results saved to: $out"
    discord_send_file "$out" "Port scan results for $domain"
  else
    log_warn "No port scan results generated"
  fi
}

case "${1:-}" in
  scan) shift; ports_scan "$@" ;;
  *) usage; exit 1;;
esac


