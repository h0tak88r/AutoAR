#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: cnames get -d <domain>"; }

cnames_get() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "$domain")"
  local subs_dir="$dir/subs"
  [[ -s "$subs_dir/all-subs.txt" ]] || { log_warn "No subdomains file at $subs_dir/all-subs.txt"; exit 0; }

  local out="$subs_dir/cname-records.txt"
  if command -v dnsx >/dev/null 2>&1; then
    log_info "Collecting CNAME records via dnsx"
    cat "$subs_dir/all-subs.txt" | dnsx -cname -silent -resp -nc -o "$out" >/dev/null 2>&1 || true
  else
    : > "$out"
  fi

  local count=$(wc -l < "$out" 2>/dev/null || echo 0)
  log_success "Found $count CNAME records"
  discord_file "$out" "CNAME records for $domain ($count)"
}

case "${1:-}" in
  get) shift; cnames_get "$@" ;;
  *) usage; exit 1;;
esac


