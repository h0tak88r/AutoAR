#!/usr/bin/env bash
set -euo pipefail

# Cross-platform path detection
detect_environment() {
  if [[ -d "/app" && -f "/app/main.sh" ]]; then
    # Docker environment
    echo "docker"
  else
    # Local/bash environment
    echo "local"
  fi
}

# Set paths based on environment
AUTOAR_ENV=$(detect_environment)
if [[ "$AUTOAR_ENV" == "docker" ]]; then
  AUTOAR_ROOT="/app"
  AUTOAR_RESULTS_DIR="/app/new-results"
  AUTOAR_CONFIG_FILE="/app/autoar.yaml"
else
  AUTOAR_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  AUTOAR_RESULTS_DIR="${AUTOAR_ROOT}/new-results"
  AUTOAR_CONFIG_FILE="${AUTOAR_ROOT}/autoar.yaml"
fi

# Export for other scripts
export AUTOAR_ROOT AUTOAR_RESULTS_DIR AUTOAR_CONFIG_FILE AUTOAR_ENV

# Function to get value from YAML or environment variable
get_config_value() {
  local key="$1"
  local default_value="${2:-}"
  
  # First try environment variable
  local env_value="${!key:-}"
  if [[ -n "$env_value" ]]; then
    echo "$env_value"
    return
  fi
  
  # Then try YAML file
  if command -v yq >/dev/null 2>&1 && [[ -f "$AUTOAR_CONFIG_FILE" ]]; then
    local yaml_value=$(yq -r "$key" "$AUTOAR_CONFIG_FILE" 2>/dev/null || echo "")
    if [[ -n "$yaml_value" && "$yaml_value" != "null" ]]; then
      echo "$yaml_value"
      return
    fi
  fi
  
  # Return default value
  echo "$default_value"
}

# Function to generate YAML config from environment variables
generate_yaml_config() {
  local config_file="$1"
  
  # Create directory if it doesn't exist
  local config_dir=$(dirname "$config_file")
  if [[ ! -d "$config_dir" ]]; then
    mkdir -p "$config_dir"
  fi
  
  cat > "$config_file" << 'EOF'
# AutoAR Configuration
# Generated automatically from environment variables

# API Keys for various services
EOF

  # API Keys section
  local api_keys=(
    "GITHUB_TOKEN"
    "SECURITYTRAILS_API_KEY"
    "SHODAN_API_KEY"
    "VIRUSTOTAL_API_KEY"
    "WORDPRESS_API_KEY"
    "BEVIGIL_API_KEY"
    "BINARYEDGE_API_KEY"
    "URLSCAN_API_KEY"
    "CENSYS_API_ID"
    "CENSYS_API_SECRET"
    "CERTSPOTTER_API_KEY"
    "CHAOS_API_KEY"
    "FOFA_EMAIL"
    "FOFA_KEY"
    "FULLHUNT_API_KEY"
    "INTELX_API_KEY"
    "PASSIVETOTAL_USERNAME"
    "PASSIVETOTAL_API_KEY"
    "QUAKE_USERNAME"
    "QUAKE_PASSWORD"
    "THREATBOOK_API_KEY"
    "WHOISXMLAPI_API_KEY"
    "ZOOMEYE_USERNAME"
    "ZOOMEYE_PASSWORD"
    "ZOOMEYEAPI_API_KEY"
    "H1_API_KEY"
    "INTEGRITI_API_KEY"
    "OPENROUTER_API_KEY"
  )

  for api_key in "${api_keys[@]}"; do
    local value="${!api_key:-}"
    if [[ -n "$value" ]]; then
      local yaml_key=$(echo "$api_key" | tr '[:upper:]' '[:lower:]' | sed 's/_api_key$//' | sed 's/_username$//' | sed 's/_password$//' | sed 's/_email$//' | sed 's/_key$//')
      echo "$yaml_key: [\"$value\"]" >> "$config_file"
    fi
  done

  # Additional configuration
  cat >> "$config_file" << EOF

# Additional configuration
DISCORD_WEBHOOK: "${DISCORD_WEBHOOK:-}"

# Database Configuration
SAVE_TO_DB: ${SAVE_TO_DB:-true}
VERBOSE: ${VERBOSE:-false}
DB_TYPE: "${DB_TYPE:-postgresql}"
DB_HOST: "${DB_HOST:-}"
DB_NAME: "${DB_NAME:-autoar}"
DOMAINS_COLLECTION: "${DOMAINS_COLLECTION:-domains}"
SUBDOMAINS_COLLECTION: "${SUBDOMAINS_COLLECTION:-subdomains}"

# Tool configuration
tools:
  nuclei:
    templates_path: "${NUCLEI_TEMPLATES_PATH:-./nuclei_templates}"
    rate_limit: ${NUCLEI_RATE_LIMIT:-150}
    concurrency: ${NUCLEI_CONCURRENCY:-25}
  
  ffuf:
    wordlist_path: "${FFUF_WORDLIST_PATH:-./Wordlists/quick_fuzz.txt}"
    threads: ${FFUF_THREADS:-50}
  
  subfinder:
    config_path: "./autoar.yaml"
    threads: ${SUBFINDER_THREADS:-10}
  
  github_scan:
    max_repos: ${GITHUB_MAX_REPOS:-50}
    parallel_jobs: ${GITHUB_PARALLEL_JOBS:-3}
    html_reports: ${GITHUB_HTML_REPORTS:-true}
    scan_types: ["${GITHUB_SCAN_TYPES:-github_org_scan}"]

# Storage configuration
storage:
  type: "local"
  local_path: "./new-results"
EOF
}

load_config() {
  # Generate config file if it doesn't exist or if forced
  if [[ ! -f "$AUTOAR_CONFIG_FILE" ]] || [[ "${REGENERATE_CONFIG:-false}" == "true" ]]; then
    generate_yaml_config "$AUTOAR_CONFIG_FILE"
  fi
  
  # Load configuration values
  DISCORD_WEBHOOK=$(get_config_value "DISCORD_WEBHOOK" "")
  
  # Database configuration - preserve environment variables if set
  DB_TYPE=${DB_TYPE:-$(get_config_value "DB_TYPE" "postgresql")}
  DB_HOST=${DB_HOST:-$(get_config_value "DB_HOST" "")}
  DB_PORT=${DB_PORT:-$(get_config_value "DB_PORT" "5432")}
  DB_USER=${DB_USER:-$(get_config_value "DB_USER" "autoar")}
  DB_PASSWORD=${DB_PASSWORD:-$(get_config_value "DB_PASSWORD" "")}
  DB_NAME=${DB_NAME:-$(get_config_value "DB_NAME" "autoar")}
  AUTOAR_DB=${AUTOAR_DB:-$(get_config_value "AUTOAR_DB" "/app/autoar.db")}
  
  # Additional config
  SAVE_TO_DB=$(get_config_value "SAVE_TO_DB" "true")
  VERBOSE=$(get_config_value "VERBOSE" "false")
}

load_config


