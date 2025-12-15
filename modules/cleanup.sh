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


