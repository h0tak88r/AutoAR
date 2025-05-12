#!/bin/bash

# Load config
CONFIG_FILE="./autar.conf"
if [[ -n "$AUTOAR_CONFIG" ]]; then CONFIG_FILE="$AUTOAR_CONFIG"; fi
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    export MONGO_URI
    export DB_NAME
fi

# CNM (CNAME Matcher) Logo
printf "==============================\n"
printf "
   ____ _   _ __  __
  / ___| \ | |  \/  |
 | |   |  \| | |\/| |
 | |___| |\  | |  | |
  \____|_| \_|_|  |_|
                    
"
printf "==============================\n"

# Constants
TARGET=""
DOMAIN_FILE=""
RESULTS_DIR="cnm_results"
VERBOSE=false
DISCORD_WEBHOOK=""
SEND_INDIVIDUAL=false
DEBUG=false
CNAME_FILTERS=() # Array to hold CNAME filters
H1_TOKEN="" # HackerOne API token
H1_USERNAME="" # HackerOne username
USE_BBSCOPE=false # Flag to use bbscope
USE_YWH=false
YWH_TOKEN=""
SUBDOMAINS_FILE="subdomains.txt" # File to store all subdomains
MATCHES_FILE="cnm_matches.txt" # File to store all CNAME matches
SUBDOMAINS_INPUT_FILE="" # User-supplied subdomains file
SAVE_TO_DB=false  # Default to false
RAW_SCOPE_FILE=""  # New variable to store raw scope file path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse command line arguments
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
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        --discord-webhook)
            DISCORD_WEBHOOK="$2"
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
        --h1-token)
            H1_TOKEN="$2"
            shift 2
            ;;
        --h1-username)
            H1_USERNAME="$2"
            shift 2
            ;;
        --use-bbscope)
            USE_BBSCOPE=true
            shift
            ;;
        --use-ywh)
            USE_YWH=true
            shift
            ;;
        --ywh-token)
            YWH_TOKEN="$2"
            shift 2
            ;;
        --save-to-db)
            SAVE_TO_DB=true
            shift
            ;;
        --raw-scope-file)
            RAW_SCOPE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -d, --domain DOMAIN       Target domain to scan"
            echo "  -l, --file FILE           File containing list of domains to scan"
            echo "  -s, --subdomains-file FILE  File containing subdomains to use (skip subdomain collection)"
            echo "  -v, --verbose             Enable verbose output"
            echo "  --debug                   Enable debug output"
            echo "  --discord-webhook URL     Discord webhook for notifications"
            echo "  -f, --filter FILTERS      Comma-separated list of CNAME filters (e.g., zendesk,freshdesk)"
            echo "  --send-individual         Send individual results for each domain (default: only send combined results)"
            echo "  --h1-token TOKEN          HackerOne API token (for bbscope)"
            echo "  --h1-username USERNAME    HackerOne username (for bbscope)"
            echo "  --use-bbscope             Use bbscope to collect domains from HackerOne"
            echo "  --use-ywh                 Use YesWeHack (YWH) with bbscope"
            echo "  --ywh-token TOKEN         YWH API token for bbscope"
            echo "  --save-to-db              Save results to MongoDB database"
            echo "  --raw-scope-file FILE     Use existing raw scope file instead of running bbscope"
            echo "  -h, --help                Show this help message"
            exit 0
            ;;
        *)
            if [[ -z "$TARGET" && -z "$DOMAIN_FILE" ]]; then
                TARGET="$1"
                shift
            else
                echo "Unknown option: $1"
                exit 1
            fi
            ;;
    esac
done

# Function to log messages
log() {
    local message="$1"
    printf "%s\n" "$message"
}

# Debug function
debug() {
    if [[ "$DEBUG" == "true" ]]; then
        local message="[DEBUG] $1"
        printf "%s\n" "$message"
    fi
}

# Function to send a message to Discord
send_message_to_discord() {
    local message="$1"
    
    if [[ -z "$DISCORD_WEBHOOK" ]]; then
        log "[-] Discord webhook URL is empty, not sending message"
        return
    fi
    
    # Strip any https:// or http:// prefix and brackets for curl
    local webhook_url="$DISCORD_WEBHOOK"
    webhook_url=$(echo "$webhook_url" | sed 's/^\[*https\?:\/\///g' | sed 's/\]*$//g')
    
    debug "Sending message to Discord: $message"
    
    # Use curl to send the message
    local result=$(curl -s -H "Content-Type: application/json" \
             -d "{\"content\": \"$message\"}" \
             "https://$webhook_url" 2>&1)
    
    # Check if curl succeeded
    if [[ $? -eq 0 ]]; then
        log "[+] Sent message to Discord: $message"
        debug "Discord API response: $result"
    else
        log "[-] Failed to send message to Discord: $message"
        log "[-] Error: $result"
    fi
}

# Function to check and create results directory
setup_results_dir() {
    local target="$1"
    local dir="$RESULTS_DIR/$target"
    
    # Create main results directory if it doesn't exist
    mkdir -p "$RESULTS_DIR"
    
    if [[ -d "$dir" ]]; then
        log "[+] Removing previous results for $target"
        rm -rf "$dir"
    fi
    mkdir -p "$dir/subs"
    log "[+] Created fresh directory structure at $dir"
}

# Function to collect domains using bbscope
collect_domains_with_bbscope() {
    log "[+] Collecting domains from HackerOne using bbscope..."
    
    # Check if bbscope is installed
    if ! command -v bbscope &> /dev/null; then
        log "[-] Error: bbscope is not installed or not in PATH."
        log "[-] Please install it using: go install github.com/sw33tLie/bbscope@latest"
        exit 1
    fi
    
    # Check for required arguments
    if [[ -z "$H1_TOKEN" || -z "$H1_USERNAME" ]]; then
        log "[-] Error: HackerOne token and username are required for bbscope."
        log "[-] Use --h1-token and --h1-username flags."
        exit 1
    fi
    
    # Create directory for bbscope results
    mkdir -p "$RESULTS_DIR/bbscope"
    local raw_file="$RESULTS_DIR/bbscope/raw_scope.txt"
    local filtered_file="$RESULTS_DIR/bbscope/filtered_scope.txt"
    local root_domains_file="$RESULTS_DIR/bbscope/root_domains.txt"
    
    # Run bbscope to gather domains from HackerOne
    log "[+] Running bbscope to gather domains from HackerOne..."
    if ! bbscope h1 -t "$H1_TOKEN" -u "$H1_USERNAME" -b -o t > "$raw_file" 2>/dev/null; then
        log "[-] Error: Failed to run bbscope. Check your token and username."
        exit 1
    fi
    
    if [[ ! -s "$raw_file" ]]; then
        log "[-] Error: bbscope returned no results. Check your token and username."
        exit 1
    fi
    
    # Count raw entries
    local raw_count=$(wc -l < "$raw_file" | tr -d ' ')
    log "[+] Collected $raw_count raw entries from HackerOne"
    
    # Filter out non-web targets and executables
    log "[+] Filtering out mobile apps, executables, and other non-web targets..."
    grep -Eiv 'android|\.apk|ios|\.exe|\.ipa|^com\.|^WHOOP|^NO_|STRAP' "$raw_file" > "$filtered_file"
    
    # Further filter to keep only likely web domains/URLs
    grep -E 'https?:\/\/|\.com|\.org|\.net|\.io|\.app|\.dev|\.xyz|\.info|\.biz|\.me|\.co|\.ai' "$filtered_file" > "$filtered_file.tmp"
    mv "$filtered_file.tmp" "$filtered_file"
    
    # Count filtered entries
    local filtered_count=$(wc -l < "$filtered_file" | tr -d ' ')
    log "[+] $filtered_count entries remain after filtering"
    
    # Extract root domains
    extract_root_domains "$filtered_file" "$root_domains_file"
    
    # Count root domains
    local root_count=$(wc -l < "$root_domains_file" | tr -d ' ')
    log "[+] Extracted $root_count unique root domains"
    
    # Create a file for the domain list
    local domain_list_file="$RESULTS_DIR/domain_list.txt"
    > "$domain_list_file"
    
    # Add root domains to the domain list
    cat "$root_domains_file" >> "$domain_list_file"
    
    log "[+] Domain collection completed."
    log "[+] Found $root_count root domains for scanning."
    log "[+] Domain list saved to $domain_list_file"
    
    # Set the domain file to use the collected domains
    DOMAIN_FILE="$domain_list_file"

    # Check if domain file was created and has content
    if [[ ! -s "$DOMAIN_FILE" ]]; then
        log "[-] Error: Failed to create domain list or no domains were found."
        log "[-] Please check your HackerOne token and username."
        exit 1
    fi
}

# Function to extract root domains from a list of domains
extract_root_domains() {
    local input_file="$1"
    local output_file="$2"
    
    log "[+] Extracting root domains..."

    # Check if input file exists and has content
    if [[ ! -s "$input_file" ]]; then
        log "[-] Error: Input file for root domain extraction is empty or does not exist."
        return 1
    fi
    
    # Create temporary file for URLs
    local urls_file=$(mktemp)
    
    # Extract URLs and potential domains
    cat "$input_file" | while IFS= read -r line; do
        # Skip empty lines and comments
        if [[ -z "$line" || "$line" =~ ^# ]]; then
            continue
        fi
        echo "$line"
    done > "$urls_file"

    # Check if Python and tldextract are available
    if command -v python3 &> /dev/null && python3 -c "import tldextract" 2>/dev/null; then
        log "[+] Using Python domain extractor"
        
        # Make the Python script executable
        chmod +x "$SCRIPT_DIR/domain_extractor.py"
        
        # Process domains using the Python script
        cat "$urls_file" | "$SCRIPT_DIR/domain_extractor.py" > "$output_file" 2>/dev/null
        
        if [[ $? -ne 0 ]]; then
            log "[-] Error running Python domain extractor, falling back to basic extraction"
            basic_domain_extraction "$urls_file" "$output_file"
        fi
    else
        log "[!] Python/tldextract not available, using basic domain extraction"
        basic_domain_extraction "$urls_file" "$output_file"
    fi

    # Verify output file was created successfully
    if [[ ! -s "$output_file" ]]; then
        log "[-] Warning: No root domains were extracted. Output file is empty."
        return 1
    else
        local domains_count=$(wc -l < "$output_file" | tr -d ' ')
        log "[+] Successfully extracted $domains_count unique root domains"
    fi

    # Clean up temporary files
    rm -f "$urls_file"
}

# Add new function for basic domain extraction
basic_domain_extraction() {
    local input_file="$1"
    local output_file="$2"
    
    cat "$input_file" | \
        # Convert to lowercase
        tr '[:upper:]' '[:lower:]' | \
        # Extract domains from URLs
        sed -E 's|https?://||g' | \
        cut -d'/' -f1 | \
        # Basic domain validation
        grep -E '^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$' | \
        # Remove invalid entries
        grep -v '^js$' | \
        grep -v '^com$' | \
        grep -v '^net$' | \
        grep -v '^org$' | \
        sort -u > "$output_file"
}

# Function to collect domains using YWH bbscope
collect_domains_with_ywh() {
    log "[+] Collecting domains from YesWeHack using bbscope..."

    if ! command -v bbscope &> /dev/null; then
        log "[-] Error: bbscope is not installed or not in PATH."
        exit 1
    fi

    if [[ -z "$YWH_TOKEN" ]]; then
        log "[-] Error: YWH token is required for bbscope."
        exit 1
    fi

    mkdir -p "$RESULTS_DIR/ywh"
    local raw_file="$RESULTS_DIR/ywh/raw_scope.txt"
    local root_domains_file="$RESULTS_DIR/ywh/root_domains.txt"

    log "[+] Running bbscope for YWH..."
    if ! bbscope ywh -t "$YWH_TOKEN" --otpcommand "2fa yeswehack" -b -o t > "$raw_file" 2>/dev/null; then
        log "[-] Error: Failed to run bbscope for YWH."
        exit 1
    fi

    if [[ ! -s "$raw_file" ]]; then
        log "[-] Error: bbscope returned no results for YWH."
        exit 1
    fi

    # Extract root domains
    extract_root_domains "$raw_file" "$root_domains_file"

    # Save to domain_list.txt for scanning
    cat "$root_domains_file" > "$RESULTS_DIR/domain_list.txt"

    local root_count=$(wc -l < "$root_domains_file" | tr -d ' ')
    log "[+] YWH: Extracted $root_count unique root domains"
    log "[+] Domain list saved to $RESULTS_DIR/domain_list.txt"
    DOMAIN_FILE="$RESULTS_DIR/domain_list.txt"
}

# Improved subdomain collection function
collect_subdomains() {
    local target="$1"
    local dir="$RESULTS_DIR/$target"
    
    debug "Starting subdomain collection for: $target"
    log "[+] Collecting subdomains for $target using multiple sources"
    
    # Create temporary file for collecting subdomains
    local tmp_file="$dir/subs/tmp_subs.txt"
    touch "$tmp_file"
    
    # Using various sources to collect subdomains
    if $VERBOSE; then log "[*] Querying hackertarget"; fi
    curl -s "https://api.hackertarget.com/hostsearch/?q=$target" | cut -d',' -f1 >> "$tmp_file"
    
    if $VERBOSE; then log "[*] Querying crt.sh"; fi
    curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | grep -o '"name_value":"[^"]*' | cut -d':' -f2 | sed 's/"//g' >> "$tmp_file"
    
    # Key subdomains to always check
    if $VERBOSE; then log "[*] Adding key subdomains (help, support)"; fi
    echo "help.$target" >> "$tmp_file"
    echo "support.$target" >> "$tmp_file"
    echo "assistance.$target" >> "$tmp_file"
    echo "desk.$target" >> "$tmp_file"
    echo "helpdesk.$target" >> "$tmp_file"
    echo "feedback.$target" >> "$tmp_file"
    
    # Basic subdomain list for common prefixes when nothing else is found
    if $VERBOSE; then log "[*] Adding common subdomains"; fi
    for prefix in www admin mail support help desk portal api app blog dev stage test qa uat; do
        echo "$prefix.$target" >> "$tmp_file"
    done
    
    # Add some base entries to ensure we have something
    echo "$target" >> "$tmp_file"
    echo "www.$target" >> "$tmp_file"
    
    # If we have bbscope results, check if any match this domain
    if [[ -f "$RESULTS_DIR/bbscope/filtered_scope.txt" ]]; then
        if $VERBOSE; then log "[*] Adding relevant domains from bbscope"; fi
        grep -i "$target" "$RESULTS_DIR/bbscope/filtered_scope.txt" >> "$tmp_file" 2>/dev/null || true
    fi
    
    # Clean and sort unique subdomains - improved filtering
    if [[ -f "$tmp_file" ]]; then
        # Remove wildcards, special characters, and standardize
        cat "$tmp_file" | sed 's/\*//g' | sed 's/^\.//g' | sed 's/\.$//g' | sort -u | grep -v '^\s*$' | grep -v '\\\.' > "$dir/subs/all-subs.txt"
    fi
    
    # Count results and ensure valid file
    local total_subs=0
    if [[ -f "$dir/subs/all-subs.txt" ]]; then
        total_subs=$(wc -l < "$dir/subs/all-subs.txt" | tr -d ' ')
    else
        touch "$dir/subs/all-subs.txt"
    fi
    
    # Ensure we have a valid number
    if [[ -z "$total_subs" || ! "$total_subs" =~ ^[0-9]+$ ]]; then
        total_subs=0
        log "[-] Error counting subdomains, defaulting to 0"
    fi
    
    debug "Found $total_subs subdomains"
    log "[+] Found $total_subs unique subdomains for $target"
    
    # Append to the central subdomains file with domain prefix
    if [[ -f "$dir/subs/all-subs.txt" && -s "$dir/subs/all-subs.txt" ]]; then
        # Create the subdomains file if it doesn't exist
        if [[ ! -f "$RESULTS_DIR/$SUBDOMAINS_FILE" ]]; then
            mkdir -p "$RESULTS_DIR"
            touch "$RESULTS_DIR/$SUBDOMAINS_FILE"
        fi
        log "[+] Adding subdomains to central file $RESULTS_DIR/$SUBDOMAINS_FILE"
        cat "$dir/subs/all-subs.txt" >> "$RESULTS_DIR/$SUBDOMAINS_FILE"
    fi
    
    # Clean up temporary files
    rm -f "$tmp_file" 2>/dev/null
}

# Function to check CNAME records for specified entries
check_cname() {
    local target="$1"
    local dir="$RESULTS_DIR/$target"
    
    log "[+] Checking CNAME records for specified entries"
    
    # Remove header creation from results file
    > "$dir/cname_results.txt"  # Clear the file to start fresh
    
    # Create central matches file if it doesn't exist
    if [[ ! -f "$RESULTS_DIR/$MATCHES_FILE" ]]; then
        mkdir -p "$RESULTS_DIR"
        touch "$RESULTS_DIR/$MATCHES_FILE"
    fi
    
    # Counter for found CNAMEs
    local cname_count=0
    local total=0
    local count=0
    
    # Check if we have any subdomains to process
    if [[ ! -s "$dir/subs/all-subs.txt" ]]; then
        log "[-] No subdomains found to check"
        return
    fi
    
    local total_subdomains=$(wc -l < "$dir/subs/all-subs.txt" | tr -d ' ')
    log "[+] Processing $total_subdomains subdomains for CNAME records"
    
    # Process each subdomain
    while IFS= read -r subdomain; do
        # Clean the subdomain: remove \n, spaces, and split multiple entries
        echo "$subdomain" | tr '\n' ' ' | tr -s ' ' | tr ' ' '\n' | while read -r clean_subdomain; do
            # Skip if empty or contains invalid characters
            if [[ -z "$clean_subdomain" || "$clean_subdomain" =~ [^a-zA-Z0-9.-] ]]; then
                continue
            fi
            
            ((count++))
            
            # Show progress if verbose
            if $VERBOSE; then
                if ((count % 10 == 0)) || $DEBUG; then
                    log "[*] Progress: $count/$total_subdomains checking $clean_subdomain"
                fi
            fi
            
            # Get CNAME record - ensure we don't get DNS resolution errors
            cname=$(dig +short CNAME "$clean_subdomain" 2>/dev/null)
            
            if [[ -n "$cname" ]]; then
                ((total++))
                debug "Found CNAME for $clean_subdomain: $cname"
                
                if [[ ${#CNAME_FILTERS[@]} -eq 0 ]]; then
                    # No filter provided, output all CNAMEs
                    local finding="$clean_subdomain -> $cname"
                    printf "%s\n" "$finding"
                    printf "%s\n" "$finding" >> "$dir/cname_results.txt"
                    printf "%s\n" "$finding" >> "$RESULTS_DIR/$MATCHES_FILE"
                    debug "Found CNAME: $finding"
                    ((cname_count++))
                    if [[ -n "$DISCORD_WEBHOOK" && "$SEND_INDIVIDUAL" == "true" ]]; then
                        send_message_to_discord "$finding"
                    fi
                else
                    for filter in "${CNAME_FILTERS[@]}"; do
                        if [[ "$cname" == *"$filter"* ]]; then
                            local finding="$clean_subdomain -> $cname"
                            printf "%s\n" "$finding"
                            printf "%s\n" "$finding" >> "$dir/cname_results.txt"
                            printf "%s\n" "$finding" >> "$RESULTS_DIR/$MATCHES_FILE"
                            debug "Found CNAME: $finding"
                            ((cname_count++))
                            if [[ -n "$DISCORD_WEBHOOK" && "$SEND_INDIVIDUAL" == "true" ]]; then
                                send_message_to_discord "$finding"
                            fi
                            break
                        fi
                    done
                fi
            fi
        done
    done < "$dir/subs/all-subs.txt"
    
    log "[+] CNAME check completed: Found $cname_count matching CNAMEs out of $total total CNAMEs"
    
    # Record results for validation
    if [[ $cname_count -gt 0 ]]; then
        echo "$target" >> "$RESULTS_DIR/domains_with_matches.txt"
    fi
}

# Function to scan a single domain
scan_domain() {
    local target="$1"
    
    log "[+] Starting scan for $target"
    
    # Create domain-specific directory
    setup_results_dir "$target"
    
    # Run the scan process
    collect_subdomains "$target"
    check_cname "$target"
    
    log "[+] Scan completed for $target"
}

# Function to send a file to Discord
send_file_to_discord() {
    local file="$1"
    local description="$2"
    
    if [[ ! -f "$file" ]]; then
        log "[-] File not found: $file"
        return
    fi
    
    if [[ ! -s "$file" ]]; then
        log "[-] File is empty: $file"
        return
    fi
    
    if [[ -z "$DISCORD_WEBHOOK" ]]; then
        log "[-] Discord webhook URL is empty, not sending file"
        return
    fi
    
    # Strip any https:// or http:// prefix and brackets for curl
    local webhook_url="$DISCORD_WEBHOOK"
    webhook_url=$(echo "$webhook_url" | sed 's/^\[*https\?:\/\///g' | sed 's/\]*$//g')
    
    debug "Sending file: $file"
    debug "To webhook: https://$webhook_url"
    
    # Use curl to send the file
    local result=$(curl -s -F "file=@$file" \
             -F "payload_json={\"content\": \"$description\"}" \
             "https://$webhook_url" 2>&1)
    
    # Check if curl succeeded
    if [[ $? -eq 0 ]]; then
        log "[+] Sent file to Discord: $file"
        debug "Discord API response: $result"
    else
        log "[-] Failed to send file to Discord: $file"
        log "[-] Error: $result"
    fi
}

# Function to process a domains file
process_domains_file() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        log "[-] Error: Domain file $file not found"
        exit 1
    fi
    
    # Send start message to Discord
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        send_message_to_discord "Working on $file"
    fi
    
    # Count valid domains (non-empty, non-comment lines)
    local domain_count=$(grep -v '^#' "$file" | grep -v '^$' | wc -l)
    log "[+] Processing $domain_count domains from $file"
    
    # Check if there are any domains to process
    if [[ $domain_count -eq 0 ]]; then
        log "[-] Error: No domains to process in $file"
        exit 1
    fi
    
    # Create main results directory if it doesn't exist
    mkdir -p "$RESULTS_DIR"
    
    # Create a combined results file
    local combined_file="$RESULTS_DIR/all_cname_results.txt"
    > "$combined_file"  # Clear the file to start fresh
    
    # Create a file to track domains with matching CNAMEs
    > "$RESULTS_DIR/domains_with_matches.txt"
    
    # Track if we found any results
    local found_results=false
    
    # Process each domain
    local count=0
    while IFS= read -r domain; do
        # Skip empty lines and comments
        if [[ -z "$domain" || "$domain" =~ ^# ]]; then
            continue
        fi
        
        # Trim whitespace
        domain=$(echo "$domain" | tr -d ' \t\r\n')
        
        # Skip if still empty after trimming
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        ((count++))
        log "[+] Processing domain $count/$domain_count: $domain"
        
        # Scan the domain
        scan_domain "$domain"
        
        # Append results to combined file if any found
        if [[ -f "$RESULTS_DIR/$domain/cname_results.txt" ]]; then
            # Check if the file has actual results (not just headers)
            if grep -v "^#" "$RESULTS_DIR/$domain/cname_results.txt" | grep -q "." 2>/dev/null; then
                cat "$RESULTS_DIR/$domain/cname_results.txt" >> "$combined_file"
                found_results=true
                debug "Added results from $domain to combined file"
            fi
        fi
    done < "$file"
    
    log "[+] All domains processed. Combined results saved to $combined_file"
    
    # Count how many domains had matching CNAMEs
    if [[ -f "$RESULTS_DIR/domains_with_matches.txt" ]]; then
        local matching_domains=$(wc -l < "$RESULTS_DIR/domains_with_matches.txt" | tr -d ' ')
        log "[+] Found matching CNAMEs in $matching_domains out of $domain_count domains"
    fi
    
    # Send the combined results file to Discord if we found any results
    if [[ "$found_results" == "true" && -n "$DISCORD_WEBHOOK" ]]; then
        debug "Sending combined results to Discord"
        send_file_to_discord "$combined_file" "Combined CNAME Results"
    else
        log "[-] No matching CNAMEs found for any domain in the file"
    fi
}

# Function to clean up results after processing is complete
cleanup_results() {
    log "[+] Cleaning up results and removing duplicates..."
    
    # Clean up subdomains file
    if [[ -f "$RESULTS_DIR/$SUBDOMAINS_FILE" ]]; then
        # Remove duplicates and invalid entries
        cat "$RESULTS_DIR/$SUBDOMAINS_FILE" | \
        sed 's/\*//g' | \
        sed 's/^\.//g' | \
        sed 's/\.$//g' | \
        grep -v '^\s*$' | \
        grep -v '^#' | \
        grep -v '\\\.' | \
        sort -u > "$RESULTS_DIR/${SUBDOMAINS_FILE}.clean"
        
        mv "$RESULTS_DIR/${SUBDOMAINS_FILE}.clean" "$RESULTS_DIR/$SUBDOMAINS_FILE"
        
        local count=$(wc -l < "$RESULTS_DIR/$SUBDOMAINS_FILE" | tr -d ' ')
        log "[+] Cleaned subdomains file now contains $count unique entries"
    fi
    
    # Clean up matches file
    if [[ -f "$RESULTS_DIR/$MATCHES_FILE" ]]; then
        # Remove duplicates but preserve the format
        sort -u "$RESULTS_DIR/$MATCHES_FILE" -o "$RESULTS_DIR/$MATCHES_FILE"
        
        local count=$(wc -l < "$RESULTS_DIR/$MATCHES_FILE" | tr -d ' ')
        log "[+] Cleaned matches file now contains $count unique entries"
    fi
    
    # Remove any empty files
    find "$RESULTS_DIR" -type f -empty -delete 2>/dev/null
    
    log "[+] Cleanup completed"
}

# Function to clean subdomain
clean_subdomain() {
    local input="$1"
    # Remove \n, spaces, and other unwanted characters
    echo "$input" | tr -d '\n\\' | tr -s ' ' | grep -o '^[a-zA-Z0-9.-]*\.[a-zA-Z0-9.-]*$' || true
}

# Function to save subdomains to MongoDB
save_subdomains_to_mongodb() {
    if [[ "$SAVE_TO_DB" != "true" ]]; then
        return
    fi

    log "[+] Saving results to MongoDB database"
    
    # Save subdomains for each domain
    while IFS= read -r domain; do
        if [[ -f "$RESULTS_DIR/$domain/subs/all-subs.txt" ]]; then
            log "[+] Adding subdomains for $domain to database"
            ./mongo_db_handler.py add_subdomains_file "$domain" "$RESULTS_DIR/$domain/subs/all-subs.txt"
        fi
    done < "$RESULTS_DIR/domains_with_matches.txt"
}

# Main function
main() {
    # Create results directory if it doesn't exist
    mkdir -p "$RESULTS_DIR"
    
    # Initialize central files
    > "$RESULTS_DIR/$SUBDOMAINS_FILE"
    > "$RESULTS_DIR/$MATCHES_FILE"

    # Check if we should use bbscope to collect domains
    if [[ "$USE_BBSCOPE" == "true" && -z "$RAW_SCOPE_FILE" ]]; then
        collect_domains_with_bbscope
    fi

    # Check if we should use YWH to collect domains
    if [[ "$USE_YWH" == "true" && -z "$RAW_SCOPE_FILE" ]]; then
        collect_domains_with_ywh
    fi

    # If raw scope file is provided, use it directly
    if [[ -n "$RAW_SCOPE_FILE" ]]; then
        if [[ ! -f "$RAW_SCOPE_FILE" ]]; then
            log "[-] Error: Raw scope file $RAW_SCOPE_FILE not found"
            exit 1
        fi
        log "[+] Using provided raw scope file: $RAW_SCOPE_FILE"
        mkdir -p "$RESULTS_DIR/ywh"
        cp "$RAW_SCOPE_FILE" "$RESULTS_DIR/ywh/raw_scope.txt"
        extract_root_domains "$RAW_SCOPE_FILE" "$RESULTS_DIR/ywh/root_domains.txt"
        DOMAIN_FILE="$RESULTS_DIR/ywh/root_domains.txt"
    fi

    # If only subdomains file is provided, process it directly
    if [[ -n "$SUBDOMAINS_INPUT_FILE" && -z "$TARGET" && -z "$DOMAIN_FILE" ]]; then
        log "[+] Processing subdomains file: $SUBDOMAINS_INPUT_FILE"
        local cname_results_file="$RESULTS_DIR/cname_results_from_file.txt"
        > "$cname_results_file"
        local count=0
        local cname_count=0
        while IFS= read -r subdomain; do
            subdomain=$(echo "$subdomain" | tr -d ' \t\r\n')
            if [[ -z "$subdomain" ]]; then
                continue
            fi
            ((count++))
            cname=$(dig +short CNAME "$subdomain" 2>/dev/null)
            if [[ -n "$cname" ]]; then
                if [[ ${#CNAME_FILTERS[@]} -eq 0 ]]; then
                    local finding="$subdomain -> $cname"
                    printf "%s\n" "$finding"
                    printf "%s\n" "$finding" >> "$cname_results_file"
                    ((cname_count++))
                else
                    for filter in "${CNAME_FILTERS[@]}"; do
                        if [[ "$cname" == *"$filter"* ]]; then
                            local finding="$subdomain -> $cname"
                            printf "%s\n" "$finding"
                            printf "%s\n" "$finding" >> "$cname_results_file"
                            ((cname_count++))
                        fi
                    done
                fi
            fi
        done < "$SUBDOMAINS_INPUT_FILE"
        log "[+] Processed $count subdomains. Found $cname_count CNAMEs. Results saved to $cname_results_file."
        if [[ -n "$DISCORD_WEBHOOK" && -s "$cname_results_file" ]]; then
            send_file_to_discord "$cname_results_file" "CNAME Results from subdomains file"
        fi
        exit 0
    fi

    # Check for target or domain file
    if [[ -z "$TARGET" && -z "$DOMAIN_FILE" ]]; then
        printf "Error: No target specified. Use -d for a single domain, -l for a domains file, or -s for a subdomains file.\n"
        printf "Usage: %s -d domain.com or %s -l domains.txt or %s -s subdomains.txt\n" "$0" "$0" "$0"
        exit 1
    fi
    
    # Print start time
    log "[+] Starting CNAME check at $(date)"
    
    # Test Discord webhook if provided
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        log "[+] Testing Discord webhook connectivity"
        
        # Strip any brackets and protocol from the webhook URL
        local test_webhook="$DISCORD_WEBHOOK"
        test_webhook=$(echo "$test_webhook" | sed 's/^\[*https\?:\/\///g' | sed 's/\]*$//g')
        
        # Test webhook connectivity but don't send an actual test message
        if curl -s -o /dev/null -w "%{http_code}" "https://$test_webhook" | grep -q "^[23]"; then
            log "[+] Discord webhook test successful"
        else
            log "[-] Discord webhook test failed"
        fi
    fi
    
    # Process based on input type
    if [[ -n "$DOMAIN_FILE" ]]; then
        process_domains_file "$DOMAIN_FILE"
    else
        scan_domain "$TARGET"
        
        # For single domain mode, always send the results if they exist and have content
        if [[ -n "$DISCORD_WEBHOOK" && -f "$RESULTS_DIR/$TARGET/cname_results.txt" ]]; then
            # Check if the file has actual results
            if [[ -s "$RESULTS_DIR/$TARGET/cname_results.txt" ]]; then
                send_file_to_discord "$RESULTS_DIR/$TARGET/cname_results.txt" "CNAME Matches for $TARGET"
            else
                log "[-] No matching CNAMEs found for $TARGET"
            fi
        fi
    fi
    
    # Clean up results before finishing
    cleanup_results
    
    # Save subdomains to database before exiting
    save_subdomains_to_mongodb
    
    # Print completion time and summary
    log "[+] All scans completed at $(date)"
    
    # Print information about the simplified output structure
    local subdomain_count=0
    local matches_count=0
    
    if [[ -f "$RESULTS_DIR/$SUBDOMAINS_FILE" ]]; then
        subdomain_count=$(wc -l < "$RESULTS_DIR/$SUBDOMAINS_FILE" | tr -d ' ')
    fi
    
    if [[ -f "$RESULTS_DIR/$MATCHES_FILE" ]]; then
        matches_count=$(wc -l < "$RESULTS_DIR/$MATCHES_FILE" | tr -d ' ')
    fi
    
    printf "\n"
    printf "=== CNM Results Summary ===\n"
    printf "Total subdomains collected: %d\n" "$subdomain_count"
    printf "Total CNAME matches found: %d\n" "$matches_count"
    printf "\n"
    printf "Results saved to:\n"
    printf "Subdomains: %s/%s\n" "$RESULTS_DIR" "$SUBDOMAINS_FILE"
    printf "CNAME matches: %s/%s\n" "$RESULTS_DIR" "$MATCHES_FILE"
    if [[ "$SAVE_TO_DB" == "true" ]]; then
        printf "MongoDB: domains and subdomains saved\n"
    fi
    printf "\n"
}

# Start the script
main 