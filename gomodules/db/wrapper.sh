#!/usr/bin/env bash
# Wrapper script to call Go database functions from bash modules
# This allows bash modules to use Go database functions without rewriting everything

DB_CLI="${DB_CLI:-/usr/local/bin/db-cli}"

# db_insert_domain - Insert or get domain ID
db_insert_domain() {
  local domain="$1"
  if [[ -z "$domain" ]]; then
    echo "" >&2
    return 1
  fi
  
  "$DB_CLI" insert-domain "$domain" 2>/dev/null || echo ""
}

# db_batch_insert_subdomains - Batch insert subdomains
db_batch_insert_subdomains() {
  local domain="$1"
  local subdomains_file="$2"
  local is_live="${3:-false}"
  
  if [[ ! -f "$subdomains_file" ]]; then
    return 1
  fi
  
  "$DB_CLI" batch-insert-subdomains "$domain" "$subdomains_file" "$is_live"
}

# db_insert_subdomain - Insert or update a single subdomain
db_insert_subdomain() {
  local domain="$1"
  local subdomain="$2"
  local is_live="${3:-false}"
  local http_url="${4:-}"
  local https_url="${5:-}"
  local http_status="${6:-0}"
  local https_status="${7:-0}"
  
  "$DB_CLI" insert-subdomain "$domain" "$subdomain" "$is_live" "$http_url" "$https_url" "$http_status" "$https_status"
}

# db_init_schema - Initialize database schema
db_init_schema() {
  "$DB_CLI" init-schema >/dev/null 2>&1
}

# db_ensure_connection - Check database connection
db_ensure_connection() {
  "$DB_CLI" check-connection >/dev/null 2>&1
}
