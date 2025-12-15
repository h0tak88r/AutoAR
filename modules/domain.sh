#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/

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
  "$ROOT_DIR/modules/livehosts.sh" get -d "$domain" || true
  "$ROOT_DIR/modules/tech.sh" detect -d "$domain" || true
  "$ROOT_DIR/modules/urls.sh" collect -d "$domain" || true
  "$ROOT_DIR/modules/js_scan.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/reflection.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/gf_scan.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/sqlmap.sh" run -d "$domain" || true
  "$ROOT_DIR/modules/dalfox.sh" run -d "$domain" || true
  "$ROOT_DIR/modules/ports.sh" scan -d "$domain" || true
  "$ROOT_DIR/modules/nuclei.sh" run -d "$domain" || true
  "$ROOT_DIR/modules/dns_takeover.sh" takeover -d "$domain" || true
}

case "${1:-}" in
  run) shift; domain_run "$@" ;;
  *) usage; exit 1;;
esac


