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

# db_insert_js_file - Insert or update a JS file (subdomain extracted from URL automatically)
db_insert_js_file() {
  local domain="$1"
  local js_url="$2"
  local content_hash="${3:-}"
  
  "$DB_CLI" insert-js-file "$domain" "$js_url" "$content_hash"
}

# db_insert_keyhack_template - Insert or update a KeyHack template
db_insert_keyhack_template() {
  local keyname="$1"
  local command_template="$2"
  local method="${3:-GET}"
  local url="$4"
  local header="${5:-}"
  local body="${6:-}"
  local notes="${7:-}"
  local description="${8:-}"
  
  "$DB_CLI" insert-keyhack-template "$keyname" "$command_template" "$method" "$url" "$header" "$body" "$notes" "$description"
}

# db_ensure_connection - Check database connection
db_ensure_connection() {
  "$DB_CLI" check-connection >/dev/null 2>&1
}
