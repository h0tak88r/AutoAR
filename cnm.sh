#!/bin/bash

# ======================
# Configuration Section
# ======================

# Default configuration values
declare -A CONFIG
CONFIG=(
    [DB_NAME]=""
    [DISCORD_WEBHOOK]=""
    [SAVE_TO_DB]="false"
    [VERBOSE]="false"
    [RESULTS_DIR]="cnm_results"
    [SUBDOMAINS_FILE]="subdomains.txt"
    [MATCHES_FILE]="cnm_matches.txt"
)

# Global variables
DEBUG=false
SEND_INDIVIDUAL=false
BATCH_DELAY_ENABLED=true
TARGET=""
DOMAIN_FILE=""
CNAME_FILTERS=()
SUBDOMAINS_INPUT_FILE=""

# ======================
# Utility Functions
# ======================

log() {
    local message="$1"
    printf "%s\n" "$message"
}

debug() {
    if [[ "$DEBUG" == "true" ]]; then
        local message="[DEBUG] $1"
        printf "%s\n" "$message"
    fi
}

error() {
    printf "\e[31m[ERROR] %s\e[0m\n" "$1" >&2
    return 1
}

# ======================
# Configuration Functions
# ======================

load_config() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then
        error "Configuration file not found: $config_file"
        return 1
    fi

    # Load YAML configuration using yq
    CONFIG[DB_NAME]=$(yq -r '.DB_NAME // empty' "$config_file")
    CONFIG[DISCORD_WEBHOOK]=$(yq -r '.DISCORD_WEBHOOK // empty' "$config_file")
    CONFIG[SAVE_TO_DB]=$(yq -r '.SAVE_TO_DB // "false"' "$config_file")
    CONFIG[VERBOSE]=$(yq -r '.VERBOSE // "false"' "$config_file")

    # Validate required configuration
    if [[ -z "${CONFIG[DB_NAME]}" ]]; then
        error "DB_NAME not set in configuration"
        return 1
    fi
}

print_config() {
    local show_sensitive="${1:-false}"
    
    printf "\n=== Current Configuration ===\n"
    printf "%-20s: %s\n" "Results Directory" "${CONFIG[RESULTS_DIR]}"
    printf "%-20s: %s\n" "Database Name" "${CONFIG[DB_NAME]}"
    printf "%-20s: %s\n" "Save to Database" "${CONFIG[SAVE_TO_DB]}"
    printf "%-20s: %s\n" "Verbose Mode" "${CONFIG[VERBOSE]}"
    printf "%-20s: %s\n" "Subdomains File" "${CONFIG[SUBDOMAINS_FILE]}"
    printf "%-20s: %s\n" "Matches File" "${CONFIG[MATCHES_FILE]}"
    
    # Only show sensitive information if explicitly requested
    if [[ "$show_sensitive" == "true" ]]; then
        printf "%-20s: %s\n" "Discord Webhook" "${CONFIG[DISCORD_WEBHOOK]}"
    else
        printf "%-20s: %s\n" "Discord Webhook" "[HIDDEN]"
    fi
    printf "==============================\n\n"
}

# ======================
# Validation Functions
# ======================

validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        error "Invalid domain format: $domain"
        return 1
    fi
    return 0
}

validate_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        error "File not found: $file"
        return 1
    fi
    if [[ ! -r "$file" ]]; then
        error "File not readable: $file"
        return 1
    fi
    return 0
}

# ======================
# Directory Management
# ======================

setup_results_dir() {
    local target="$1"
    if [[ -z "$target" ]]; then
        error "Target domain not specified for directory setup"
        return 1
    fi
    
    local dir="${CONFIG[RESULTS_DIR]}/$target"
    
    # Ensure base results directory exists
    if ! mkdir -p "${CONFIG[RESULTS_DIR]}"; then
        error "Failed to create base results directory: ${CONFIG[RESULTS_DIR]}"
        return 1
    fi
    
    # Remove previous results if they exist
    if [[ -d "$dir" ]]; then
        log "[+] Removing previous results for $target"
        if ! rm -rf "$dir"; then
            error "Failed to remove previous results directory: $dir"
            return 1
        fi
    fi
    
    # Create new directory structure
    if ! mkdir -p "$dir/subs"; then
        error "Failed to create subdirectory structure: $dir/subs"
        return 1
    fi
    
    log "[+] Created fresh directory structure at $dir"
    return 0
}

# ======================
# Subdomain Collection
# ======================

collect_subdomains() {
    local target="$1"
    local dir="${CONFIG[RESULTS_DIR]}/$target"
    
    debug "Starting subdomain collection for: $target"
    log "[+] Collecting subdomains for $target using multiple sources"
    
    local tmp_file="$dir/subs/tmp_subs.txt"
    collect_from_sources "$target" "$tmp_file"
    process_collected_subdomains "$target" "$tmp_file" "$dir"
}

collect_from_sources() {
    local target="$1"
    local output_file="$2"
    
    # HackerTarget
    if ${CONFIG[VERBOSE]}; then log "[*] Querying hackertarget"; fi
    curl -s "https://api.hackertarget.com/hostsearch/?q=$target" | cut -d',' -f1 >> "$output_file"
    
    # Certificate Transparency
    if ${CONFIG[VERBOSE]}; then log "[*] Querying crt.sh"; fi
    curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | grep -o '"name_value":"[^"]*' | cut -d':' -f2 | sed 's/"//g' >> "$output_file"
    
    # Add common subdomains
    add_common_subdomains "$target" "$output_file"
}

add_common_subdomains() {
    local target="$1"
    local output_file="$2"
    
    local common_prefixes=(
        "www" "admin" "mail" "support" "help" "desk" "portal" "api"
        "app" "blog" "dev" "stage" "test" "qa" "uat" "helpdesk"
        "feedback" "assistance"
    )
    
    for prefix in "${common_prefixes[@]}"; do
        echo "$prefix.$target" >> "$output_file"
    done
    
    # Add base entries
    echo "$target" >> "$output_file"
    echo "www.$target" >> "$output_file"
}

process_collected_subdomains() {
    local target="$1"
    local tmp_file="$2"
    local dir="$3"
    
    if [[ -f "$tmp_file" ]]; then
        # Clean and sort unique subdomains
        sed 's/\\n/\n/g' "$tmp_file" | sed 's/\*//g' | sed 's/^\.//g' | sed 's/\.$//g' | sort -u | grep -v '^\s*$' | grep -v '\\.' > "$dir/subs/all-subs.txt"
        
        local total_subs=$(wc -l < "$dir/subs/all-subs.txt" | tr -d ' ')
        log "[+] Found $total_subs unique subdomains for $target"
        
        # Save to central file and SQLite if enabled
        if [[ -s "$dir/subs/all-subs.txt" ]]; then
            cat "$dir/subs/all-subs.txt" >> "${CONFIG[RESULTS_DIR]}/${CONFIG[SUBDOMAINS_FILE]}"
            if [[ "${CONFIG[SAVE_TO_DB]}" == "true" ]]; then
                ./sqlite_db_handler.py add_subdomains_file "$target" "$dir/subs/all-subs.txt"
            fi
        fi
    fi
    
    rm -f "$tmp_file" 2>/dev/null
}

# ======================
# File Management
# ======================

ensure_matches_file() {
    # Create central matches file if it doesn't exist
    if [[ ! -f "${CONFIG[RESULTS_DIR]}/${CONFIG[MATCHES_FILE]}" ]]; then
        mkdir -p "${CONFIG[RESULTS_DIR]}"
        touch "${CONFIG[RESULTS_DIR]}/${CONFIG[MATCHES_FILE]}"
    fi
}

# ======================
# CNAME Processing
# ======================

check_cname() {
    local target="$1"
    local dir="${CONFIG[RESULTS_DIR]}/$target"
    local subdomains_file="$SUBDOMAINS_INPUT_FILE"
    
    log "[+] Checking CNAME records for specified entries"
    
    # Initialize results file
    > "$dir/cname_results.txt"
    ensure_matches_file
    
    # Determine which subdomains file to use
    if [[ -n "$SUBDOMAINS_INPUT_FILE" ]]; then
        if [[ ! -f "$SUBDOMAINS_INPUT_FILE" ]]; then
            error "Subdomains file not found: $SUBDOMAINS_INPUT_FILE"
            return 1
        fi
        subdomains_file="$SUBDOMAINS_INPUT_FILE"
    else
        subdomains_file="$dir/subs/all-subs.txt"
    fi
    
    # Check if we have any subdomains to process
    if [[ ! -s "$subdomains_file" ]]; then
        log "[-] No subdomains found to check in $subdomains_file"
        return 1
    fi
    
    local total_subdomains=$(wc -l < "$subdomains_file" | tr -d ' ')
    local cname_count=0
    local total=0
    local count=0
    
    log "[+] Processing $total_subdomains subdomains for CNAME records"
    
    while IFS= read -r subdomain; do
        # Skip empty lines and comments
        if [[ -z "$subdomain" || "$subdomain" =~ ^[[:space:]]*# ]]; then
                continue
            fi
            
        # Trim whitespace
        subdomain=$(echo "$subdomain" | tr -d ' \t\r\n')
        
        ((count++))
        if ${CONFIG[VERBOSE]}; then
            if ((count % 10 == 0)); then
                log "[*] Progress: $count/$total_subdomains"
            fi
        fi
        
        # Get CNAME record
        local cname=$(dig +short CNAME "$subdomain" 2>/dev/null)
            
            if [[ -n "$cname" ]]; then
                ((total++))
            debug "Found CNAME for $subdomain: $cname"
                
            # Check against filters if provided
                if [[ ${#CNAME_FILTERS[@]} -eq 0 ]]; then
                record_cname_match "$subdomain" "$cname" "$dir"
                    ((cname_count++))
                else
                    for filter in "${CNAME_FILTERS[@]}"; do
                        if [[ "$cname" == *"$filter"* ]]; then
                        record_cname_match "$subdomain" "$cname" "$dir"
                            ((cname_count++))
                            break
                        fi
                    done
                fi
            fi
    done < "$subdomains_file"
    
    log "[+] CNAME check completed: Found $cname_count matching CNAMEs out of $total total CNAMEs"
    
    # Record results for validation
    if [[ $cname_count -gt 0 ]]; then
        echo "$target" >> "${CONFIG[RESULTS_DIR]}/domains_with_matches.txt"
    fi
    
    return 0
}

record_cname_match() {
    local subdomain="$1"
    local cname="$2"
    local dir="$3"
    
    local finding="$subdomain -> $cname"
    printf "%s\n" "$finding"
    printf "%s\n" "$finding" >> "$dir/cname_results.txt"
    printf "%s\n" "$finding" >> "${CONFIG[RESULTS_DIR]}/${CONFIG[MATCHES_FILE]}"
    
    if [[ -n "${CONFIG[DISCORD_WEBHOOK]}" && "$SEND_INDIVIDUAL" == "true" ]]; then
        send_message_to_discord "$finding"
    fi
}

process_domains_file() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        error "Domain file not found: $file"
        return 1
    fi
    
    # Count valid domains (non-empty, non-comment lines)
    local domain_count=$(grep -v '^#' "$file" | grep -v '^$' | wc -l)
    log "[+] Processing $domain_count domains from $file"
    
    # Check if there are any domains to process
    if [[ $domain_count -eq 0 ]]; then
        error "No domains to process in $file"
        return 1
    fi
    
    # Create main results directory if it doesn't exist
    if ! mkdir -p "${CONFIG[RESULTS_DIR]}"; then
        error "Failed to create main results directory: ${CONFIG[RESULTS_DIR]}"
        return 1
    fi
    
    # Process domains in batches
    local batch_size=10
    local delay_minutes=2
    local count=0
    local batch_count=0
    local total_batches=$(( (domain_count + batch_size - 1) / batch_size ))
    
    # Create a temporary array to store domains
    declare -a domains
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        # Skip empty lines and comments
        if [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]]; then
            continue
        fi
        
        # Trim whitespace
        domain=$(echo "$domain" | tr -d ' \t\r\n')
        
        # Skip if still empty after trimming
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        domains+=("$domain")
        ((count++))
        
        # Process batch when we reach batch_size or end of file
        if [[ $count -eq $batch_size || $count -eq $domain_count ]]; then
            ((batch_count++))
            log "[+] Processing batch $batch_count of $total_batches"
            
            # Process each domain in the current batch
            for domain in "${domains[@]}"; do
                log "[+] Processing domain: $domain"
                
                # Validate domain before processing
                if ! validate_domain "$domain"; then
                    log "[-] Skipping invalid domain: $domain"
                    continue
                fi
                
                # Setup directory and collect subdomains
                if setup_results_dir "$domain"; then
                    collect_subdomains "$domain"
                    check_cname "$domain"
                else
                    log "[-] Failed to setup directory for domain: $domain"
                    continue
                fi
            done
            
            # Clear the domains array for next batch
            domains=()
            count=0
            
            # Wait between batches if not the last batch
            if [[ $batch_count -lt $total_batches && "$BATCH_DELAY_ENABLED" == "true" ]]; then
                log "[+] Batch complete. Waiting $delay_minutes minutes before next batch..."
                sleep $(( delay_minutes * 60 ))
            fi
        fi
    done < "$file"
    
    log "[+] Completed processing all domains from file"
    return 0
}

# ======================
# Discord Integration
# ======================

send_message_to_discord() {
    local message="$1"
    
    if [[ -z "${CONFIG[DISCORD_WEBHOOK]}" ]]; then
        debug "Discord webhook not configured, skipping notification"
        return
    fi

    local webhook_url="${CONFIG[DISCORD_WEBHOOK]}"
    webhook_url=$(echo "$webhook_url" | sed 's/^\[*https\?:\/\///g' | sed 's/\]*$//g')
    
    local result=$(curl -s -H "Content-Type: application/json" \
                       -d "{\"content\": \"$message\"}" \
                       "https://$webhook_url" 2>&1)
    
    if [[ $? -eq 0 ]]; then
        debug "Successfully sent Discord message"
    else
        error "Failed to send Discord message: $result"
    fi
}

# ======================
# Command Handlers
# ======================

handle_collect_command() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                TARGET="$2"
                shift 2
                ;;
            -l|--file)
                DOMAIN_FILE="$2"
                shift 2
                ;;
            -s|--subdomains-file)
                SUBDOMAINS_INPUT_FILE="$2"
                shift 2
                ;;
            -db|--save-to-db)
                CONFIG[SAVE_TO_DB]=true
                shift
                ;;
            *)
                error "Unknown option for collect command: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    if [[ -n "$TARGET" ]]; then
        validate_domain "$TARGET" && setup_results_dir "$TARGET" && collect_subdomains "$TARGET"
    elif [[ -n "$DOMAIN_FILE" ]]; then
        validate_file "$DOMAIN_FILE" && while IFS= read -r domain || [[ -n "$domain" ]]; do
            domain=$(echo "$domain" | xargs)
            if [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]]; then
                continue
            fi
            validate_domain "$domain" && setup_results_dir "$domain" && collect_subdomains "$domain"
        done < "$DOMAIN_FILE"
    else
        error "No input specified. Use -d or -l option."
        show_help
        exit 1
    fi
}

handle_scan_command() {
    # Parse scan-specific options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                TARGET="$2"
                shift 2
                ;;
            -l|--file)
                DOMAIN_FILE="$2"
                shift 2
                ;;
            -f|--filter)
                IFS=',' read -r -a CNAME_FILTERS <<< "$2"
                shift 2
                ;;
            --send-individual)
                SEND_INDIVIDUAL=true
                shift
                ;;
            --no-batch-delay)
                BATCH_DELAY_ENABLED=false
                shift
                ;;
            *)
                echo "Unknown option for scan command: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # If Discord webhook is set and SEND_INDIVIDUAL was not explicitly set, enable it by default
    if [[ -n "${CONFIG[DISCORD_WEBHOOK]}" && "$SEND_INDIVIDUAL" == "false" ]]; then
        SEND_INDIVIDUAL=true
    fi

    if [[ -n "$TARGET" ]]; then
        setup_results_dir "$TARGET"
        collect_subdomains "$TARGET"
        check_cname "$TARGET"
    elif [[ -n "$DOMAIN_FILE" ]]; then
        process_domains_file "$DOMAIN_FILE"
    else
        echo "Error: No target specified. Use -d or -l option."
        show_help
        exit 1
    fi
}

handle_check_cname_command() {
    # Parse check-cname-specific options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                TARGET="$2"
                shift 2
                ;;
            -l|--file)
                DOMAIN_FILE="$2"
                shift 2
                ;;
            -s|--subdomains-file)
                SUBDOMAINS_INPUT_FILE="$2"
                shift 2
                ;;
            -f|--filter)
                IFS=',' read -r -a CNAME_FILTERS <<< "$2"
                shift 2
                ;;
            --send-individual)
                SEND_INDIVIDUAL=true
                shift
                ;;
            *)
                error "Unknown option for check-cname command: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ -n "$SUBDOMAINS_INPUT_FILE" ]]; then
        if [[ ! -f "$SUBDOMAINS_INPUT_FILE" ]]; then
            error "Subdomains file not found: $SUBDOMAINS_INPUT_FILE"
            exit 1
        fi
        setup_results_dir "from_file"
        check_cname "from_file"
    elif [[ -n "$TARGET" ]]; then
        setup_results_dir "$TARGET"
        # First collect subdomains, then check CNAMEs
        log "[+] Starting subdomain enumeration for $TARGET"
        collect_subdomains "$TARGET"
        check_cname "$TARGET"
    elif [[ -n "$DOMAIN_FILE" ]]; then
        while IFS= read -r domain || [[ -n "$domain" ]]; do
            domain=$(echo "$domain" | xargs)
            if [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]]; then
                continue
            fi
            setup_results_dir "$domain"
            # First collect subdomains, then check CNAMEs for each domain
            log "[+] Starting subdomain enumeration for $domain"
            collect_subdomains "$domain"
            check_cname "$domain"
        done < "$DOMAIN_FILE"
    else
        error "No input specified. Use -d, -l, or -s option."
        show_help
        exit 1
    fi
}

# ======================
# Help Function
# ======================

show_help() {
    cat << EOF
        CNM (CNAME Matcher) - A tool for subdomain collection and CNAME checking

        Usage: $0 <command> [options]

        Commands:
            collect         Collect subdomains and save to SQLite database
            scan           Full scan: collect subdomains, check CNAMEs, and process results
            check-cname    Only check CNAMEs for given domains/subdomains
            help           Show this help message

        Common Options:
            -d, --domain DOMAIN       Target domain to scan
            -l, --file FILE          File containing list of domains to scan
            -v, --verbose            Enable verbose output
            --debug                  Enable debug output
            --discord-webhook URL    Discord webhook for notifications

        Collect Command Options:
            -s, --subdomains-file FILE  File containing subdomains to use (skip collection)
            --save-to-db               Save results to SQLite database

        Scan Command Options:
            -f, --filter FILTERS     Comma-separated list of CNAME filters
            --send-individual        Send individual results for each domain
            --no-batch-delay         Disable waiting between batches

        Check-CNAME Command Options:
            -f, --filter FILTERS     Comma-separated list of CNAME filters
            --send-individual        Send individual results for each domain

        Examples:
            $0 collect -d example.com
            $0 collect -l domains.txt
            $0 scan -l domains.txt --filter zendesk,freshdesk
            $0 check-cname -s subdomains.txt -f zendesk
EOF
}

# ======================
# Main Function
# ======================

main() {
    # Initialize
    mkdir -p "${CONFIG[RESULTS_DIR]}"
    > "${CONFIG[RESULTS_DIR]}/${CONFIG[SUBDOMAINS_FILE]}"
    > "${CONFIG[RESULTS_DIR]}/${CONFIG[MATCHES_FILE]}"
    
    # Load configuration
    load_config "/home/sallam/AutoAR/autoar.yaml" || exit 1
    
    # Check if help is requested
    if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" || "$1" == "help" ]]; then
        show_help
        exit 0
    fi
    
    # Parse command and options
    local command="$1"
    shift
    
    # Handle debug mode
    if [[ "$1" == "--debug" ]]; then
        DEBUG=true
        shift
    fi
    
    # Show configuration with sensitive info for operational commands
    case "$command" in
        collect|scan|check-cname)
            print_config true  # Show sensitive info for operational commands
            ;;
        *)
            print_config false  # Hide sensitive info for other commands
            ;;
    esac
    
    # Execute command
    case "$command" in
        collect)
            handle_collect_command "$@"
            ;;
        scan)
            handle_scan_command "$@"
            ;;
        check-cname)
            handle_check_cname_command "$@"
            ;;
        *)
            error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
    
    log "[+] All operations completed at $(date)"
}

# Start the script
main "$@" 