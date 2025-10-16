#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"

usage() { echo "Usage: lite run -d <domain>"; }

lite_run() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  # Compose of modular steps
  "$ROOT_DIR/modules/subdomains.sh" get -d "$domain"
  "$ROOT_DIR/modules/cnames.sh" get -d "$domain"
  "$ROOT_DIR/modules/livehosts.sh" get -d "$domain"
  "$ROOT_DIR/modules/urls.sh" collect -d "$domain"
  "$ROOT_DIR/modules/js_scan.sh" scan -d "$domain"
}

case "${1:-}" in
  run) shift; lite_run "$@" ;;
  *) usage; exit 1;;
esac


