#!/bin/bash
# AutoAR Configuration Generator
# Generates autoar.yaml from environment variables if it doesn't exist

# set -euo pipefail

# Source required libraries
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Load logging functions
if [[ -f "$ROOT_DIR/lib/logging.sh" ]]; then
    source "$ROOT_DIR/lib/logging.sh"
else
    # Fallback logging functions if lib/logging.sh is not available
    log_info() { echo "[INFO] $*"; }
    log_success() { echo "[SUCCESS] $*"; }
    log_warning() { echo "[WARNING] $*"; }
    log_error() { echo "[ERROR] $*"; }
fi

# Configuration file paths
CONFIG_FILE="${AUTOAR_CONFIG_FILE:-./autoar.yaml}"
SAMPLE_CONFIG="$ROOT_DIR/autoar.sample.yaml"

# Function to get environment variable with fallback
get_env_var() {
    local var_name="$1"
    local default_value="${2:-}"
    local value="${!var_name:-$default_value}"
    echo "$value"
}

# Function to convert environment variable name to YAML key
env_to_yaml_key() {
    local env_name="$1"
    # Convert to lowercase and handle special cases
    case "$env_name" in
        "GITHUB_TOKEN") echo "github" ;;
        "SECURITYTRAILS_API_KEY") echo "securitytrails" ;;
        "SHODAN_API_KEY") echo "shodan" ;;
        "VIRUSTOTAL_API_KEY") echo "virustotal" ;;
        "WORDPRESS_API_KEY") echo "wordpress" ;;
        "BEVIGIL_API_KEY") echo "bevigil" ;;
        "BINARYEDGE_API_KEY") echo "binaryedge" ;;
        "URLSCAN_API_KEY") echo "urlscan" ;;
        "CENSYS_API_ID") echo "censys" ;;
        "CENSYS_API_SECRET") echo "censys" ;;
        "CERTSPOTTER_API_KEY") echo "certspotter" ;;
        "CHAOS_API_KEY") echo "chaos" ;;
        "FOFA_EMAIL") echo "fofa" ;;
        "FOFA_KEY") echo "fofa" ;;
        "FULLHUNT_API_KEY") echo "fullhunt" ;;
        "INTELX_API_KEY") echo "intelx" ;;
        "PASSIVETOTAL_USERNAME") echo "passivetotal" ;;
        "PASSIVETOTAL_API_KEY") echo "passivetotal" ;;
        "QUAKE_USERNAME") echo "quake" ;;
        "QUAKE_PASSWORD") echo "quake" ;;
        "THREATBOOK_API_KEY") echo "threatbook" ;;
        "WHOISXMLAPI_API_KEY") echo "whoisxmlapi" ;;
        "ZOOMEYE_USERNAME") echo "zoomeye" ;;
        "ZOOMEYE_PASSWORD") echo "zoomeye" ;;
        "ZOOMEYEAPI_API_KEY") echo "zoomeyeapi" ;;
        "H1_API_KEY") echo "h1" ;;
        "INTEGRITI_API_KEY") echo "integriti" ;;
        "OPENROUTER_API_KEY") echo "openrouter_api" ;;
        *) echo "$(echo "$env_name" | tr '[:upper:]' '[:lower:]')" ;;
    esac
}

# Function to generate YAML content
generate_yaml_config() {
    local config_file="$1"
    
    log_info "Generating configuration file: $config_file"
    
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
        local value=$(get_env_var "$api_key")
        if [[ -n "$value" ]]; then
            local yaml_key=$(env_to_yaml_key "$api_key")
            echo "$yaml_key: [\"$value\"]" >> "$config_file"
        fi
    done

    # Additional API Keys section
    cat >> "$config_file" << 'EOF'

# Additional API Keys
EOF

    local additional_keys=(
        "DISCORD_WEBHOOK"
    )

    for key in "${additional_keys[@]}"; do
        local value=$(get_env_var "$key")
        if [[ -n "$value" ]]; then
            echo "$key: \"$value\"" >> "$config_file"
        fi
    done

    # Database Configuration
    cat >> "$config_file" << 'EOF'

# Database Configuration
EOF

    local db_save=$(get_env_var "SAVE_TO_DB" "true")
    local db_verbose=$(get_env_var "VERBOSE" "false")
    local db_name=$(get_env_var "DB_NAME" "autoar")
    local db_type=$(get_env_var "DB_TYPE" "postgresql")
    local db_host=$(get_env_var "DB_HOST" "")
    local domains_collection=$(get_env_var "DOMAINS_COLLECTION" "domains")
    local subdomains_collection=$(get_env_var "SUBDOMAINS_COLLECTION" "subdomains")

    cat >> "$config_file" << EOF
SAVE_TO_DB: $db_save
VERBOSE: $db_verbose
DB_TYPE: "$db_type"
DB_HOST: "$db_host"
DB_NAME: "$db_name"
DOMAINS_COLLECTION: "$domains_collection"
SUBDOMAINS_COLLECTION: "$subdomains_collection"
EOF


    # Tool configuration with environment variable overrides
    local nuclei_templates=$(get_env_var "NUCLEI_TEMPLATES_PATH" "./nuclei_templates")
    local nuclei_rate_limit=$(get_env_var "NUCLEI_RATE_LIMIT" "150")
    local nuclei_concurrency=$(get_env_var "NUCLEI_CONCURRENCY" "25")
    local ffuf_wordlist=$(get_env_var "FFUF_WORDLIST_PATH" "./Wordlists/quick_fuzz.txt")
    local ffuf_threads=$(get_env_var "FFUF_THREADS" "50")
    local subfinder_threads=$(get_env_var "SUBFINDER_THREADS" "10")
    local github_max_repos=$(get_env_var "GITHUB_MAX_REPOS" "50")
    local github_parallel=$(get_env_var "GITHUB_PARALLEL_JOBS" "3")
    local github_html=$(get_env_var "GITHUB_HTML_REPORTS" "true")
    local github_scan_types=$(get_env_var "GITHUB_SCAN_TYPES" "github_org_scan")

    cat >> "$config_file" << EOF

# Tool configuration
tools:
  nuclei:
    templates_path: "$nuclei_templates"
    rate_limit: $nuclei_rate_limit
    concurrency: $nuclei_concurrency
  
  ffuf:
    wordlist_path: "$ffuf_wordlist"
    threads: $ffuf_threads
  
  subfinder:
    config_path: "./autoar.yaml"
    threads: $subfinder_threads
  
  github_scan:
    max_repos: $github_max_repos
    parallel_jobs: $github_parallel
    html_reports: $github_html
    scan_types: ["$github_scan_types"]
EOF

    # Storage configuration
    cat >> "$config_file" << 'EOF'

# Storage configuration
storage:
  type: "local"
  local_path: "./new-results"
EOF

    log_success "Configuration file generated successfully: $config_file"
}

# Function to validate configuration
validate_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        log_error "Configuration file not found: $config_file"
        return 1
    fi

    # Validate YAML using Python (most reliable)
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import yaml; yaml.safe_load(open('$config_file'))" >/dev/null 2>&1; then
            log_success "Configuration file is valid YAML"
        else
            log_error "Configuration file contains invalid YAML"
            return 1
        fi
    else
        log_warning "Python3 not available, skipping YAML validation"
    fi

    return 0
}

# Main function
main() {
    local force_regenerate="${REGENERATE_CONFIG:-false}"
    
    # Check if config file already exists
    if [[ -f "$CONFIG_FILE" && "$force_regenerate" != "true" ]]; then
        log_info "Configuration file already exists: $CONFIG_FILE"
        log_info "Set REGENERATE_CONFIG=true to force regeneration"
        return 0
    fi

    # Check if sample config exists
    if [[ ! -f "$SAMPLE_CONFIG" ]]; then
        log_warning "Sample configuration file not found: $SAMPLE_CONFIG"
        log_info "Proceeding with environment-based generation"
    fi

    # Create directory if it doesn't exist
    local config_dir=$(dirname "$CONFIG_FILE")
    if [[ ! -d "$config_dir" ]]; then
        log_info "Creating configuration directory: $config_dir"
        mkdir -p "$config_dir"
    fi

    # Generate configuration
    generate_yaml_config "$CONFIG_FILE"

    # Validate configuration
    if validate_config "$CONFIG_FILE"; then
        log_success "Configuration generation completed successfully"
        
        # Show summary of configured values
        log_info "Configuration summary:"
        echo "  - Config file: $CONFIG_FILE"
        echo "  - Database: $(get_env_var "DB_TYPE" "sqlite")"
        echo "  - Save to DB: $(get_env_var "SAVE_TO_DB" "true")"
        echo "  - Verbose: $(get_env_var "VERBOSE" "false")"
        echo "  - Discord webhook: $(if [[ -n "$(get_env_var "DISCORD_WEBHOOK")" ]]; then echo "configured"; else echo "not configured"; fi)"
        
        # Count configured API keys
        local api_count=0
        for api_key in GITHUB_TOKEN SECURITYTRAILS_API_KEY SHODAN_API_KEY VIRUSTOTAL_API_KEY; do
            if [[ -n "$(get_env_var "$api_key")" ]]; then
                ((api_count++))
            fi
        done
        echo "  - API keys configured: $api_count"
        
    else
        log_error "Configuration validation failed"
        exit 1
    fi
    
    # Explicitly exit with success
    exit 0
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi