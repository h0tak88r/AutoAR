#!/usr/bin/env bash
# Database CLI module for AutoAR (PostgreSQL + SQLite)
# Provides read/list/export helpers using lib/db.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/utils.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/db.sh" 2>/dev/null || { echo "ERROR: Failed to load lib/db.sh" >&2; exit 1; }
source "$ROOT_DIR/lib/discord.sh" 2>/dev/null || true

die() { echo "$1" >&2; exit 1; }

# Send database results to Discord
send_db_result_to_discord() {
  local command="$1"
  local result="$2"
  local domain="${3:-}"
  
  if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    local message="**Database Command:** \`$command\`"
    if [[ -n "$domain" ]]; then
      message="$message
**Domain:** \`$domain\`"
    fi
    message="$message
**Result:**
\`\`\`
$result
\`\`\`"
    
    discord_send "$message" >/dev/null 2>&1 || true
  fi
}

db_domains_list() {
  db_ensure_connection
  local result=$(db_list_domains)
  echo "$result"
  
  # Send domains list to Discord
  send_db_result_to_discord "db domains list" "$result"
  
  # Also send all subdomains for each domain to Discord
  if [[ -n "$result" ]]; then
    local temp_file="/tmp/domains_subdomains.txt"
    echo "# AutoAR Database - All Subdomains by Domain" > "$temp_file"
    echo "# Generated: $(date)" >> "$temp_file"
    echo "" >> "$temp_file"
    
    while IFS= read -r domain; do
      if [[ -n "$domain" ]]; then
        echo "## Domain: $domain" >> "$temp_file"
        local subdomains=$(db_get_subdomains "$domain")
        if [[ -n "$subdomains" ]]; then
          echo "$subdomains" >> "$temp_file"
        else
          echo "No subdomains found" >> "$temp_file"
        fi
        echo "" >> "$temp_file"
      fi
    done <<< "$result"
    
    # Move temp file to results directory for bot to pick up
    if [[ -f "$temp_file" && -s "$temp_file" ]]; then
      local results_dir="${AUTOAR_RESULTS_DIR}/db_export_$(date +%Y%m%d_%H%M%S)"
      mkdir -p "$results_dir"
      mv "$temp_file" "$results_dir/domains_subdomains.txt"
      echo "Subdomains exported to: $results_dir/domains_subdomains.txt"
    fi
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
  db_ensure_connection
  local result=$(db_get_subdomains "$domain")
  echo "$result"
  send_db_result_to_discord "db subdomains list" "$result" "$domain"
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
  db_ensure_connection
  local result=$(db_get_js_files "$domain")
  echo "$result"
  send_db_result_to_discord "db js list" "$result" "$domain"
}

db_domain_delete() {
  local domain=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  
  db_ensure_connection
  
  log_info "Deleting domain: $domain"
  
  # Delete subdomains first (foreign key constraint)
  local subdomain_count=$(db_query "SELECT COUNT(*) FROM subdomains WHERE domain = '$domain';")
  if [[ "$subdomain_count" -gt 0 ]]; then
    log_info "Deleting $subdomain_count subdomains for $domain"
    db_exec "DELETE FROM subdomains WHERE domain = '$domain';"
  fi
  
  # Delete JS files
  local js_count=$(db_query "SELECT COUNT(*) FROM js_files WHERE domain = '$domain';")
  if [[ "$js_count" -gt 0 ]]; then
    log_info "Deleting $js_count JS files for $domain"
    db_exec "DELETE FROM js_files WHERE domain = '$domain';"
  fi
  
  # Delete domain
  local domain_count=$(db_query "SELECT COUNT(*) FROM domains WHERE domain = '$domain';")
  if [[ "$domain_count" -gt 0 ]]; then
    log_info "Deleting domain: $domain"
    db_exec "DELETE FROM domains WHERE domain = '$domain';"
    log_success "Successfully deleted domain '$domain' and all related data"
    
    # Send result to Discord
    local result="Successfully deleted domain '$domain' and all related data:\n- Subdomains: $subdomain_count\n- JS files: $js_count"
    send_db_result_to_discord "db domains delete" "$result" "$domain"
  else
    log_warn "Domain '$domain' not found in database"
    send_db_result_to_discord "db domains delete" "Domain '$domain' not found in database" "$domain"
  fi
}

usage() {
  cat <<EOF
Usage: db <resource> <action> [options]

Resources & actions:
  domains list                             List distinct domains in DB
  domains delete   -d <domain>             Delete domain and all related data
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
    domains:delete)    db_domain_delete "$@" ;;
    subdomains:list)   db_subdomains_list "$@" ;;
    subdomains:export) db_subdomains_export "$@" ;;
    js:list)           db_js_list "$@" ;;
    *) usage; exit 1;;
  esac
}

main "$@"


