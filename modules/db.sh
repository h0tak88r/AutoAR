#!/usr/bin/env bash
# Database CLI module for AutoAR (PostgreSQL + SQLite)
# Provides read/list/export helpers using lib/db.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/utils.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/db.sh" 2>/dev/null || true

die() { echo "$1" >&2; exit 1; }

db_domains_list() {
  db_list_domains
}

db_subdomains_list() {
  local domain=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  db_get_subdomains "$domain"
}

db_subdomains_export() {
  local domain="" out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -o|--out) out="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  [[ -z "$out" ]] && out="$ROOT_DIR/new-results/$domain/subs/db-subdomains.txt"
  db_export_subdomains "$domain" "$out"
}

db_js_list() {
  local domain=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  db_get_js_files "$domain"
}

usage() {
  cat <<EOF
Usage: db <resource> <action> [options]

Resources & actions:
  domains list                             List distinct domains in DB
  subdomains list   -d <domain>            List subdomains for a domain
  subdomains export -d <domain> [-o file]  Export subdomains to file (and Discord if configured)
  js list          -d <domain>             List JS files for a domain

Options:
  --db <path>       Override DB path (default: $AUTOAR_DB)
EOF
}

# Entry
main() {
  [[ $# -lt 2 ]] && { usage; exit 1; }
  local resource="$1"; shift
  local action="$1"; shift

  # Allow overriding DB path
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --db) AUTOAR_DB="$2"; shift 2;;
      *) break;;
    esac
  done

  case "$resource:$action" in
    domains:list)      db_domains_list "$@" ;;
    subdomains:list)   db_subdomains_list "$@" ;;
    subdomains:export) db_subdomains_export "$@" ;;
    js:list)           db_js_list "$@" ;;
    *) usage; exit 1;;
  esac
}

main "$@"


