#!/usr/bin/env bash
# Database module for AutoAR (SQLite)
# Provides read/list/export helpers without the Python helper

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/utils.sh" 2>/dev/null || true

AUTOAR_DB=${AUTOAR_DB:-/app/autoar.db}

die() { echo "$1" >&2; exit 1; }

require_sqlite() {
  command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is not installed in the container"
}

require_db() {
  [[ -f "$AUTOAR_DB" ]] || die "Database not found at $AUTOAR_DB (set AUTOAR_DB or create DB)"
}

# Detect table/column names for subdomains
# Sets: SUBDOMAINS_TABLE, COL_DOMAIN, COL_SUBDOMAIN
detect_subdomains_schema() {
  local tbl
  SUBDOMAINS_TABLE=""
  COL_DOMAIN=""
  COL_SUBDOMAIN=""

  # Find a table that likely stores subdomains
  for tbl in subdomains Subdomains SUBDOMAINS discovered_subdomains subs; do
    if sqlite3 "$AUTOAR_DB" "SELECT name FROM sqlite_master WHERE type='table' AND name='$tbl';" | grep -q "^$tbl$"; then
      SUBDOMAINS_TABLE="$tbl"; break
    fi
  done

  if [[ -z "$SUBDOMAINS_TABLE" ]]; then
    # Fallback: first table with columns like subdomain
    SUBDOMAINS_TABLE=$(sqlite3 "$AUTOAR_DB" "SELECT name FROM sqlite_master WHERE type='table'" | while read -r t; do
      if sqlite3 "$AUTOAR_DB" "PRAGMA table_info($t);" | awk -F'|' '{print $2}' | grep -Eq "(^|\n)(subdomain|host|fqdn)(\n|$)"; then echo "$t"; fi
    done | head -n1)
  fi

  [[ -z "$SUBDOMAINS_TABLE" ]] && die "Could not detect subdomains table in $AUTOAR_DB"

  # Detect domain column
  if sqlite3 "$AUTOAR_DB" "PRAGMA table_info($SUBDOMAINS_TABLE);" | awk -F'|' '{print $2}' | grep -qx domain; then
    COL_DOMAIN=domain
  elif sqlite3 "$AUTOAR_DB" "PRAGMA table_info($SUBDOMAINS_TABLE);" | awk -F'|' '{print $2}' | grep -qx root_domain; then
    COL_DOMAIN=root_domain
  elif sqlite3 "$AUTOAR_DB" "PRAGMA table_info($SUBDOMAINS_TABLE);" | awk -F'|' '{print $2}' | grep -qx base_domain; then
    COL_DOMAIN=base_domain
  else
    # As a last resort, derive from subdomain FQDN suffix
    COL_DOMAIN=""
  fi

  # Detect subdomain column
  if sqlite3 "$AUTOAR_DB" "PRAGMA table_info($SUBDOMAINS_TABLE);" | awk -F'|' '{print $2}' | grep -qx subdomain; then
    COL_SUBDOMAIN=subdomain
  elif sqlite3 "$AUTOAR_DB" "PRAGMA table_info($SUBDOMAINS_TABLE);" | awk -F'|' '{print $2}' | grep -qx host; then
    COL_SUBDOMAIN=host
  elif sqlite3 "$AUTOAR_DB" "PRAGMA table_info($SUBDOMAINS_TABLE);" | awk -F'|' '{print $2}' | grep -qx fqdn; then
    COL_SUBDOMAIN=fqdn
  else
    die "Could not detect subdomain column in $SUBDOMAINS_TABLE"
  fi
}

db_domains_list() {
  require_sqlite; require_db; detect_subdomains_schema
  if [[ -n "$COL_DOMAIN" ]]; then
    sqlite3 -noheader -list "$AUTOAR_DB" "SELECT DISTINCT $COL_DOMAIN FROM $SUBDOMAINS_TABLE ORDER BY $COL_DOMAIN;"
  else
    # Derive base domains from FQDNs
    sqlite3 -noheader -list "$AUTOAR_DB" "SELECT DISTINCT
      substr($COL_SUBDOMAIN, instr($COL_SUBDOMAIN, '.')+1)
      FROM $SUBDOMAINS_TABLE WHERE instr($COL_SUBDOMAIN,'.')>0
      ORDER BY 1;"
  fi
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
  require_sqlite; require_db; detect_subdomains_schema
  if [[ -n "$COL_DOMAIN" ]]; then
    sqlite3 -noheader -list "$AUTOAR_DB" "SELECT $COL_SUBDOMAIN FROM $SUBDOMAINS_TABLE WHERE $COL_DOMAIN = '$domain' ORDER BY $COL_SUBDOMAIN;"
  else
    sqlite3 -noheader -list "$AUTOAR_DB" "SELECT $COL_SUBDOMAIN FROM $SUBDOMAINS_TABLE WHERE $COL_SUBDOMAIN LIKE '%.' || '$domain' ORDER BY $COL_SUBDOMAIN;"
  fi
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
  mkdir -p "$(dirname "$out")"
  db_subdomains_list --domain "$domain" > "$out" || true
  if [[ -s "$out" ]]; then
    log_success "Exported $(wc -l < "$out") subdomains to $out"
    # If available, send to Discord
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
      source "$ROOT_DIR/lib/discord.sh" 2>/dev/null || true
      command -v send_file_to_discord >/dev/null 2>&1 && send_file_to_discord "$out" "DB subdomains for $domain"
    fi
  else
    log_warn "No subdomains found for $domain"
  fi
}

usage() {
  cat <<EOF
Usage: db <resource> <action> [options]

Resources & actions:
  domains list                             List distinct domains in DB
  subdomains list   -d <domain>            List subdomains for a domain
  subdomains export -d <domain> [-o file]  Export subdomains to file (and Discord if configured)

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
    *) usage; exit 1;;
  esac
}

main "$@"


