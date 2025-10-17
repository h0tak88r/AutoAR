#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"

usage() { echo "Usage: cleanup run --domain <domain> [--keep] | cleanup run --dir <path> [--keep]"; }

cleanup_run() {
  local domain_dir="" keep=false domain=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) domain="$2"; shift 2;;
      --dir|--domain-dir) domain_dir="$2"; shift 2;;
      --keep) keep=true; shift;;
      *) usage; exit 1;;
    esac
  done
  if [[ -n "$domain" ]]; then domain_dir="$(results_dir "$domain")"; fi
  [[ -z "$domain_dir" ]] && { usage; exit 1; }

  if [[ "$keep" == true ]]; then
    log_info "Keep requested; skipping cleanup for $domain_dir"
    exit 0
  fi

  if [[ -d "$domain_dir" ]]; then
    log_info "Cleaning $domain_dir"
    rm -rf "$domain_dir" 2>/dev/null || true
    log_success "Cleanup completed"
  else
    log_warn "Directory not found: $domain_dir"
  fi
}

case "${1:-}" in
  run) shift; cleanup_run "$@" ;;
  *) usage; exit 1;;
esac


