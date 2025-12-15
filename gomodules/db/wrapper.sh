#!/usr/bin/env bash
# Wrapper script to call Go database functions from bash modules
# Uses autoar db commands instead of separate db-cli binary

AUTOAR_BIN="${AUTOAR_BIN:-/usr/local/bin/autoar}"

# db_insert_domain - Insert or get domain ID
db_insert_domain() {
  local domain="$1"
  if [[ -z "$domain" ]]; then
    echo "" >&2
    return 1
  fi
  
  "$AUTOAR_BIN" db insert-domain "$domain" 2>/dev/null || echo ""
}

# db_batch_insert_subdomains - Batch insert subdomains
db_batch_insert_subdomains() {
  local domain="$1"
  local subdomains_file="$2"
  local is_live="${3:-false}"
  
  if [[ ! -f "$subdomains_file" ]]; then
    return 1
  fi
  
  "$AUTOAR_BIN" db batch-insert-subdomains "$domain" "$subdomains_file" "$is_live"
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
  
  "$AUTOAR_BIN" db insert-subdomain "$domain" "$subdomain" "$is_live" "$http_url" "$https_url" "$http_status" "$https_status"
}

# db_insert_js_file - Insert or update a JS file (subdomain extracted from URL automatically)
db_insert_js_file() {
  local domain="$1"
  local js_url="$2"
  local content_hash="${3:-}"
  
  "$AUTOAR_BIN" db insert-js-file "$domain" "$js_url" "$content_hash"
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
  
  "$AUTOAR_BIN" db insert-keyhack-template "$keyname" "$command_template" "$method" "$url" "$header" "$body" "$notes" "$description"
}

# db_init_schema - Initialize database schema
db_init_schema() {
  "$AUTOAR_BIN" db init-schema >/dev/null 2>&1
}

# db_ensure_connection - Check database connection
db_ensure_connection() {
  "$AUTOAR_BIN" db check-connection >/dev/null 2>&1
}
