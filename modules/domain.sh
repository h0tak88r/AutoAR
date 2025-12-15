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

usage() { echo "Usage: domain run -d <domain>"; }

domain_run() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  # Stepwise pipeline with soft-fail behavior
  "$ROOT_DIR/modules/subdomains.sh" get -d "$domain" || true
  "$ROOT_DIR/modules/cnames.sh" get -d "$domain" || true
  autoar livehosts get -d "$domain" -s || true
  "$ROOT_DIR/modules/tech.sh" detect -d "$domain" || true
  autoar urls collect -d "$domain" || true
  "$ROOT_DIR/modules/js_scan.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/reflection.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/gf_scan.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/sqlmap.sh" run -d "$domain" || true
  "$ROOT_DIR/modules/dalfox.sh" run -d "$domain" || true
  "$ROOT_DIR/modules/ports.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/nuclei.sh" run -d "$domain" || true
  autoar dns takeover -d "$domain" || true
}

case "${1:-}" in
  run) shift; domain_run "$@" ;;
  *) usage; exit 1;;
esac


