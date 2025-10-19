#!/usr/bin/env bash
# Database wrapper script for AutoAR
# This script provides shell-compatible functions that call the Python DB handler

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_DB="$ROOT_DIR/db_handler.py"

# Load environment variables
if [[ -f "$ROOT_DIR/.env" ]]; then
  source "$ROOT_DIR/.env"
fi

# Database functions that call the Python script
db_insert_domain() {
  local domain="$1"
  "$PYTHON_DB" insert-domain "$domain"
}

db_batch_insert_subdomains() {
  local domain="$1"
  local file="$2"
  local is_live="${3:-false}"
  
  if [[ "$is_live" == "true" ]]; then
    "$PYTHON_DB" batch-insert-subdomains "$domain" "$file" --live
  else
    "$PYTHON_DB" batch-insert-subdomains "$domain" "$file"
  fi
}

db_insert_js_file() {
  local domain="$1"
  local js_url="$2"
  local content_hash="${3:-}"
  
  if [[ -n "$content_hash" ]]; then
    "$PYTHON_DB" insert-js-file "$domain" "$js_url" --hash "$content_hash"
  else
    "$PYTHON_DB" insert-js-file "$domain" "$js_url"
  fi
}

db_get_domains() {
  "$PYTHON_DB" get-domains
}

db_get_subdomains() {
  local domain="$1"
  "$PYTHON_DB" get-subdomains "$domain"
}

db_get_all_subdomains() {
  "$PYTHON_DB" get-all-subdomains
}

db_delete_domain() {
  local domain="$1"
  local force="${2:-false}"
  
  if [[ "$force" == "true" ]]; then
    "$PYTHON_DB" delete-domain "$domain" --force
  else
    "$PYTHON_DB" delete-domain "$domain"
  fi
}

# If this script is called directly, pass arguments to Python script
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  "$PYTHON_DB" "$@"
fi
