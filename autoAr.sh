#!/bin/bash

# Add color variables at the top of the script
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Path to YAML config
CONFIG_FILE="/home/sallam/AutoAR/autoar.yaml"

# Helper to get a value from YAML using yq
yaml_get() {
    yq -r "$1" "$CONFIG_FILE"
}

DB_NAME=$(yaml_get '.DB_NAME')
DOMAINS_COLLECTION=$(yaml_get '.mongodb.domains_collection')
SUBDOMAINS_COLLECTION=$(yaml_get '.mongodb.subdomains_collection')
SECURITYTRAILS_API_KEY=$(yaml_get '.securitytrails[0]')
DISCORD_WEBHOOK=$(yaml_get '.DISCORD_WEBHOOK')
SAVE_TO_DB=$(yaml_get '.SAVE_TO_DB')
VERBOSE=$(yaml_get '.VERBOSE')
GITHUB_TOKEN=$(yaml_get '.github[0]')

# At the top of the script, after other globals:
JS_MONITOR_MODE=0

# autoAR Logo
printf "==============================\n"
printf "

 ▗▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▖  ▗▄▖ ▗▄▄▖ 
▐▌ ▐▌▐▌ ▐▌  █ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌
▐▛▀▜▌▐▌ ▐▌  █ ▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖
▐▌ ▐▌▝▚▄▞▘  █ ▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌
                              By: h0tak88r
                                    
"
printf "==============================\n"

# Constants
RESULTS_DIR="results"
WORDLIST_DIR="Wordlists"
FUZZ_WORDLIST="$WORDLIST_DIR/quick_fuzz.txt"
LOG_FILE="autoAR.log"
DOMAIN_DIR=""

# Improved log function with color and prefix
log() {
    local type="$1"
    local message="$2"
    local color prefix

    case "$type" in
        INFO)
            color="$CYAN"
            prefix="ℹ️ [INFO]"
            ;;
        SUCCESS)
            color="$GREEN"
            prefix="✅ [SUCCESS]"
            ;;
        WARNING)
            color="$YELLOW"
            prefix="⚠️ [WARNING]"
            ;;
        ERROR)
            color="$RED"
            prefix="❌ [ERROR]"
            ;;
        *)
            color="$NC"
            prefix="•"
            ;;
    esac

    printf "${color}${prefix} %s${NC}\n" "$message"
    printf "[%s] %s\n" "$type" "$message" >> "$LOG_FILE"
}

# Function to send messages to Discord
send_to_discord() {
    local content="$1"
    curl -H "Content-Type: application/json" \
         -X POST \
         -d "{\"content\": \"$content\"}" \
         "$DISCORD_WEBHOOK" > /dev/null 2>&1
}

# Function to send files to Discord
send_file_to_discord() {
    local file="$1"
    local description="$2"
    if [[ -f "$file" ]]; then
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            curl -F "file=@$file" \
                 -F "payload_json={\"content\": \"$description\"}" \
                 "$DISCORD_WEBHOOK" > /dev/null 2>&1
        else
            log WARNING "Discord webhook not provided, skipping file upload."
        fi
    else
        log ERROR "Error: File $file does not exist."
    fi
}

# Function to check if required tools are installed
check_tools() {
    local tools=("subfinder" "httpx" "naabu" "nuclei" "ffuf" "kxss" "qsreplace" "gf" "dalfox" "urlfinder" "interlace" "jsleak" "jsfinder" "dnsx")
    local missing_tools=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log ERROR "Error: The following tools are not installed:"
        for tool in "${missing_tools[@]}"; do
            log ERROR "- $tool"
        done
        log ERROR "Please install missing tools before running the script."
        exit 1
    fi
}

# Function to setup results directory
setup_results_dir() {
    # Set up domain-specific directory path first
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        DOMAIN_DIR="$RESULTS_DIR/$SINGLE_SUBDOMAIN"
    elif [[ -n "$TARGET" ]]; then
        DOMAIN_DIR="$RESULTS_DIR/$TARGET"
    else
        log ERROR "Error: No target specified"
        exit 1
    fi
    
    # Remove domain-specific directory if it exists
    if [[ -d "$DOMAIN_DIR" ]]; then
        log INFO "Removing previous results for ${SINGLE_SUBDOMAIN:-$TARGET}"
        rm -rf "$DOMAIN_DIR"
    fi
    
    # Create fresh domain directory and subdirectories
    mkdir -p "$DOMAIN_DIR"/{subs,urls,vulnerabilities/{xss,sqli,ssrf,ssti,lfi,rce,idor,js,takeovers},fuzzing,ports}
    
    # Create initial empty files
    touch "$DOMAIN_DIR/urls/all-urls.txt"
    touch "$DOMAIN_DIR/urls/js-urls.txt"
    touch "$DOMAIN_DIR/ports/ports.txt"
    touch "$DOMAIN_DIR/vulnerabilities/put-scan.txt"
    touch "$DOMAIN_DIR/fuzzing/ffuf.html"
    touch "$DOMAIN_DIR/fuzzing/ffuf-post.html"
    touch "$DOMAIN_DIR/subs/all-subs.txt"
    touch "$DOMAIN_DIR/subs/apis-subs.txt"
    touch "$DOMAIN_DIR/subs/subfinder-subs.txt"
    touch "$DOMAIN_DIR/subs/live-subs.txt"
    
    log SUCCESS "Created fresh directory structure at $DOMAIN_DIR"
}

# Function to run fuzzing with ffuf
run_ffuf() {
    log INFO "Fuzzing with ffuf"
    
    # Ensure fuzzing directory exists
    mkdir -p "$DOMAIN_DIR/fuzzing"
    
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        log INFO "Fuzzing single subdomain: $SINGLE_SUBDOMAIN"
        ffuf -u "https://$SINGLE_SUBDOMAIN/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique > "$DOMAIN_DIR/fuzzing/ffuf.html" 2>> "$LOG_FILE"
        ffuf -u "https://$SINGLE_SUBDOMAIN/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique -X POST > "$DOMAIN_DIR/fuzzing/ffuf-post.html" 2>> "$LOG_FILE"
        
        # Check if files were created and have content
        if [[ -s "$DOMAIN_DIR/fuzzing/ffuf.html" ]]; then
            send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf.html" "ffuf GET Fuzz Results"
        else
            log WARNING "No GET fuzzing results found"
        fi
        
        if [[ -s "$DOMAIN_DIR/fuzzing/ffuf-post.html" ]]; then
            send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf-post.html" "ffuf POST Fuzz Results"
        else
            log WARNING "No POST fuzzing results found"
        fi
    else
        while IFS= read -r url; do
            log INFO "Fuzzing $url with ffuf"
            ffuf -u "$url/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique > "$DOMAIN_DIR/fuzzing/ffuf.html" 2>> "$LOG_FILE"
            ffuf -u "$url/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique -X POST > "$DOMAIN_DIR/fuzzing/ffuf-post.html" 2>> "$LOG_FILE"
            
            # Check if files were created and have content
            if [[ -s "$DOMAIN_DIR/fuzzing/ffuf.html" ]]; then
                send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf.html" "ffuf GET Fuzz Results for $url"
            else
                log WARNING "No GET fuzzing results found for $url"
            fi
            
            if [[ -s "$DOMAIN_DIR/fuzzing/ffuf-post.html" ]]; then
                send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf-post.html" "ffuf POST Fuzz Results for $url"
            else
                log WARNING "No POST fuzzing results found for $url"
            fi
        done < "$DOMAIN_DIR/subs/live-subs.txt"
    fi
}

# Function to run SQL injection scanning with sqlmap
run_sql_injection_scan() {
    log INFO "SQL Injection Scanning with sqlmap"
    
    # Check if gf results file exists and is not empty
    if [[ ! -f "$DOMAIN_DIR/vulnerabilities/sqli/gf-results.txt" ]]; then
        log WARNING "No SQL injection parameters found to scan"
        return
    fi
    
    if [[ ! -s "$DOMAIN_DIR/vulnerabilities/sqli/gf-results.txt" ]]; then
        log WARNING "SQL injection parameters file is empty"
        return
    fi

    # Create a temporary file with clean URLs
    local temp_urls="$DOMAIN_DIR/vulnerabilities/sqli/clean_urls.txt"
    # Clean and validate URLs before passing to interlace
    while IFS= read -r url; do
        # Remove any special characters and validate URL format
        cleaned_url=$(echo "$url" | tr -cd '[:print:]' | grep -E '^https?://')
        if [[ -n "$cleaned_url" ]]; then
            echo "$cleaned_url" >> "$temp_urls"
        fi
    done < "$DOMAIN_DIR/vulnerabilities/sqli/gf-results.txt"

    if [[ ! -s "$temp_urls" ]]; then
        log WARNING "No valid URLs found for SQL injection scanning"
        rm -f "$temp_urls"
        return
    fi

    # Run sqlmap scan with proper error handling
    log INFO "Running sqlmap on $(wc -l < "$temp_urls") URLs"
    if ! interlace -tL "$temp_urls" -threads 5 -c "sqlmap -u _target_ --batch --dbs --random-agent" -o "$DOMAIN_DIR/vulnerabilities/sqli/sqlmap-results.txt" 2>/dev/null; then
        log ERROR "Error running sqlmap scan"
    fi

    # Check results
    if [[ -s "$DOMAIN_DIR/vulnerabilities/sqli/sqlmap-results.txt" ]]; then
        log SUCCESS "SQL injection scan completed. Results saved to sqlmap-results.txt"
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$DOMAIN_DIR/vulnerabilities/sqli/sqlmap-results.txt" "SQL Injection Scan Results"
        fi
    else
        log WARNING "No SQL injection vulnerabilities found"
    fi

    # Cleanup
    rm -f "$temp_urls"
}

# Function to run reflection scanning
run_reflection_scan() {
    log INFO "Reflection Scanning"
    
    # Create temp file for filtered results
    local temp_results="/tmp/kxss_filtered.txt"
    
    # Run kxss and filter out empty reflection results
    kxss < "$DOMAIN_DIR/urls/all-urls.txt" | grep -v "Unfiltered: \[\]" > "$temp_results"
    
    # Only save and send non-empty results
    if [[ -s "$temp_results" ]]; then
        cp "$temp_results" "$DOMAIN_DIR/vulnerabilities/kxss-results.txt"
        log SUCCESS "Found reflection points, saved to kxss-results.txt"
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$DOMAIN_DIR/vulnerabilities/kxss-results.txt" "Reflection Scan Results"
        fi
    else
        log INFO "No reflection points found"
        touch "$DOMAIN_DIR/vulnerabilities/kxss-results.txt"
    fi
    
    # Cleanup
    rm -f "$temp_results"
}

# Function to run subdomain enumeration
subEnum() {
    local domain="$1"
    log INFO "Subdomain Enumeration using SubFinder and free API Sources"
    
    # Create temporary file for collecting subdomains
    local tmp_file="$DOMAIN_DIR/subs/tmp_subs.txt"
    
    # Ensure subs directory exists
    mkdir -p "$DOMAIN_DIR/subs"
    
    # Initialize/clear files
    > "$DOMAIN_DIR/subs/apis-subs.txt"
    > "$DOMAIN_DIR/subs/subfinder-subs.txt"
    > "$DOMAIN_DIR/subs/all-subs.txt"
    > "$tmp_file"
    
    # Collect subdomains from various sources
    log INFO "Collecting subdomains from APIs..."
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://certspotter.com/api/v0/certs?domain=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://crt.sh/?q=%.$domain&output=json" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> "$tmp_file" 2>> "$LOG_FILE"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file" 2>> "$LOG_FILE"
    
    # SecurityTrails API Integration
    if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
        log INFO "Collecting subdomains from SecurityTrails API..."
        response=$(curl -s -X GET "https://api.securitytrails.com/v1/domain/$domain/subdomains?children_only=false" \
            -H "accept: application/json" \
            -H "apikey: $SECURITYTRAILS_API_KEY")
        
        # Check if the response contains subdomains
        if echo "$response" | grep -q "subdomains"; then
            # Extract and format subdomains
            echo "$response" | jq -r '.subdomains[]' 2>/dev/null | \
            while read -r subdomain; do
                if [[ -n "$subdomain" ]]; then
                    echo "${subdomain}.$domain" >> "$tmp_file"
                fi
            done
            log SUCCESS "Successfully collected subdomains from SecurityTrails"
        else
            log WARNING "No results from SecurityTrails or invalid API key"
        fi
    else
        log INFO "SecurityTrails API key not provided, skipping..."
    fi
    
    # Clean and sort API results
    if [[ -f "$tmp_file" ]]; then
        cat "$tmp_file" | sed -e "s/\*\.$domain//g" -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$DOMAIN_DIR/subs/apis-subs.txt"
        rm "$tmp_file"
    fi
    
    # Run subfinder
    log INFO "Running subfinder..."
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" -all -silent -o "$DOMAIN_DIR/subs/subfinder-subs.txt" -pc $CONFIG_FILE >> "$LOG_FILE" 2>&1
    else
        log WARNING "[-] subfinder not found, skipping subfinder enumeration"
    fi
    
    # Combine and sort all results
    cat "$DOMAIN_DIR/subs/subfinder-subs.txt" "$DOMAIN_DIR/subs/apis-subs.txt" 2>/dev/null | grep -v "*" | sort -u > "$DOMAIN_DIR/subs/all-subs.txt"
    
    # Count results
    local total_subs=$(wc -l < "$DOMAIN_DIR/subs/all-subs.txt")
    log SUCCESS "Found $total_subs unique subdomains"
    
    # Save to SQLite only if <= 3000
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        if [[ "$total_subs" -le 3000 ]]; then
            log INFO "Saving results to SQLite..."
            ./sqlite_db_handler.py add_subdomains_file "$domain" "$DOMAIN_DIR/subs/all-subs.txt"
            log SUCCESS "Subdomain Enumeration completed. Results saved in SQLite and $DOMAIN_DIR/subs/all-subs.txt"
        else
            log WARNING "Too many subdomains ($total_subs > 2000). Skipping database insert to avoid overload."
        fi
        if [[ $JS_MONITOR_MODE -ne 1 ]]; then
            send_file_to_discord "$DOMAIN_DIR/subs/all-subs.txt" "Subdomain Enumeration completed - Found $total_subs subdomains"
        fi
    else
        log WARNING "[-] No subdomains found for $domain"
    fi
}

# Function to fetch URLs
fetch_urls() {
    log INFO "Fetching URLs using URLFinder and extracting JS files"
    
    # Ensure urls directory exists
    mkdir -p "$DOMAIN_DIR/urls"
    
    # Initialize/clear files
    > "$DOMAIN_DIR/urls/all-urls.txt"
    > "$DOMAIN_DIR/urls/js-urls.txt"

    # Check if we're working with a single subdomain or full domain
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        # For single subdomain, only fetch URLs for that subdomain
        log INFO "Fetching URLs for single subdomain: $SINGLE_SUBDOMAIN"
        urlfinder -d "$SINGLE_SUBDOMAIN" -all -silent -config $CONFIG_FILE -o "$DOMAIN_DIR/urls/all-urls.txt" >> "$LOG_FILE" 2>&1
        log INFO "Running JSFinder on $SINGLE_SUBDOMAIN"
        jsfinder -l "$DOMAIN_DIR/subs/live-subs.txt" -c 50 -s -o "$DOMAIN_DIR/urls/js-urls.txt" >> "$LOG_FILE" 2>&1
        
    elif [[ -n "$TARGET" ]]; then
        # 1. First collect URLs using urlfinder
        log INFO "Running URLFinder for initial URL collection"
        urlfinder -d "$TARGET" -all -silent -o "$DOMAIN_DIR/urls/all-urls.txt" -pc $CONFIG_FILE >> "$LOG_FILE" 2>&1
        
        # 2. Run JSFinder on live subdomains to find JS files and endpoints
        if [[ -s "$DOMAIN_DIR/subs/live-subs.txt" ]]; then
            log INFO "Running JSFinder on live subdomains"
            jsfinder -l "$DOMAIN_DIR/subs/live-subs.txt" -c 50 -s -o "$DOMAIN_DIR/urls/js-urls.txt" >> "$LOG_FILE" 2>&1
        fi
    fi

            # Extract .js URLs from all-urls.txt if it exists
    if [[ -s "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        log INFO "Extracting .js URLs from collected URLs"
        grep -i "\.js" "$DOMAIN_DIR/urls/all-urls.txt" >> "$DOMAIN_DIR/urls/js-urls.txt"
        
        # Remove duplicates from js-urls.txt
        sort -u -o "$DOMAIN_DIR/urls/js-urls.txt" "$DOMAIN_DIR/urls/js-urls.txt"
        
        # Merge results and remove duplicates from all-urls.txt
        cat "$DOMAIN_DIR/urls/js-urls.txt" >> "$DOMAIN_DIR/urls/all-urls.txt"
        sort -u -o "$DOMAIN_DIR/urls/all-urls.txt" "$DOMAIN_DIR/urls/all-urls.txt"
    fi
    
    # Count total unique URLs
    if [[ -s "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        local total_urls=$(wc -l < "$DOMAIN_DIR/urls/all-urls.txt")
        local js_urls=$(wc -l < "$DOMAIN_DIR/urls/js-urls.txt")
        log SUCCESS "Found $total_urls total unique URLs"
        log SUCCESS "Found $js_urls JavaScript files/endpoints"
        if [[ -n "$DISCORD_WEBHOOK" && $JS_MONITOR_MODE -ne 1 ]]; then
            send_file_to_discord "$DOMAIN_DIR/urls/all-urls.txt" "Found $total_urls unique URLs"
            if [[ -s "$DOMAIN_DIR/urls/js-urls.txt" ]]; then
                local js_urls=$(wc -l < "$DOMAIN_DIR/urls/js-urls.txt")
                send_file_to_discord "$DOMAIN_DIR/urls/js-urls.txt" "Found $js_urls JavaScript files/endpoints"
            fi
        fi
    else
        log WARNING "[-] No URLs found"
        touch "$DOMAIN_DIR/urls/all-urls.txt"
    fi
}

# Function to filter live hosts
filter_live_hosts() {
    if [[ ! -f "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        log WARNING "[-] No subdomains file found at $DOMAIN_DIR/subs/all-subs.txt"
        return
    fi
    
    log INFO "Filtering live hosts"
    mkdir -p "$DOMAIN_DIR/subs"
    
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        cat "$DOMAIN_DIR/subs/all-subs.txt" | httpx -silent -nc -o "$DOMAIN_DIR/subs/live-subs.txt" >> "$LOG_FILE" 2>&1
        local total_subs=$(wc -l < "$DOMAIN_DIR/subs/all-subs.txt")
        local live_subs=$(wc -l < "$DOMAIN_DIR/subs/live-subs.txt")
        log SUCCESS "Found $live_subs live subdomains out of $total_subs total"
        if [[ $JS_MONITOR_MODE -ne 1 ]]; then
            send_file_to_discord "$DOMAIN_DIR/subs/live-subs.txt" "Live Subdomains Found ($live_subs out of $total_subs)"
        fi
    else
        log WARNING "[-] No subdomains found to filter"
        touch "$DOMAIN_DIR/subs/live-subs.txt"
    fi
}

# Function to run port scanning
run_port_scan() {
    log INFO "Port Scanning with naabu"
    if [[ -s "$DOMAIN_DIR/subs/live-subs.txt" ]]; then
        naabu -l "$DOMAIN_DIR/subs/live-subs.txt"-tp 10000 -ec -c 500 -Pn --silent -rate 1000 -o "$DOMAIN_DIR/ports/ports.txt" >> "$LOG_FILE" 2>&1
        if [[ -s "$DOMAIN_DIR/ports/ports.txt" ]]; then
            send_file_to_discord "$DOMAIN_DIR/ports/ports.txt" "Port Scan Results"
        else
            log WARNING "[-] No open ports found"
        fi
    else
        log WARNING "[-] No subdomains found to scan ports"
    fi
}

# Function to run GF pattern scans
run_gf_scans() {
    log INFO "Starting GF pattern scanning"
    
    # Create vulnerabilities directory if it doesn't exist
    mkdir -p "$DOMAIN_DIR/vulnerabilities"
    
    # Check if we have URLs to scan
    if [[ ! -f "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        log WARNING "No URLs file found at $DOMAIN_DIR/urls/all-urls.txt"
        return
    fi

    # Check if URLs file is empty
    if [[ ! -s "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        log WARNING "URLs file is empty, nothing to scan"
        return
    fi

    local total_urls=$(wc -l < "$DOMAIN_DIR/urls/all-urls.txt")
    log INFO "Found $total_urls URLs to scan"
    
    # Get available GF patterns
    local patterns=(debug_logic idor iext img-traversal iparams isubs jsvar lfi rce redirect sqli ssrf ssti xss)
    
    # Scan for each GF pattern
    for pattern in "${patterns[@]}"; do
        # Create directory for this vulnerability type
        mkdir -p "$DOMAIN_DIR/vulnerabilities/$pattern"
        
        log INFO "Scanning for $pattern pattern ($(date '+%H:%M:%S'))"
        
        # Run GF scan and save results
        if ! cat "$DOMAIN_DIR/urls/all-urls.txt" | gf "$pattern" > "$DOMAIN_DIR/vulnerabilities/$pattern/gf-results.txt" 2>> "$LOG_FILE"; then
            log ERROR "GF scan failed for $pattern pattern"
            continue
        fi
        
        # Check if we found any matches
        if [[ -s "$DOMAIN_DIR/vulnerabilities/$pattern/gf-results.txt" ]]; then
            local count=$(wc -l < "$DOMAIN_DIR/vulnerabilities/$pattern/gf-results.txt")
            log SUCCESS "Found $count potential $pattern matches"
            
            if [[ -n "$DISCORD_WEBHOOK" ]]; then
                send_file_to_discord "$DOMAIN_DIR/vulnerabilities/$pattern/gf-results.txt" "[$pattern] Found $count potentially vulnerable endpoints"
            fi
        else
            log INFO "No $pattern matches found"
            rm -f "$DOMAIN_DIR/vulnerabilities/$pattern/gf-results.txt"
        fi
    done

    log SUCCESS "GF pattern scanning completed at $(date '+%H:%M:%S')"
}

# Function to check CNAME records using dnsx
check_cname_records() {
    local domain_dir="$1"
    log INFO "Checking CNAME records using dnsx"
    
    if [[ -s "$domain_dir/subs/all-subs.txt" ]]; then
        # Use dnsx to get CNAME records - much faster than dig
        log INFO "Collecting CNAME records with dnsx..."
        cat "$domain_dir/subs/all-subs.txt" | dnsx -cname -silent -resp -nc -o "$domain_dir/subs/cname-records.txt" 2>/dev/null
        
        if [[ -s "$domain_dir/subs/cname-records.txt" ]]; then
            local cname_count=$(wc -l < "$domain_dir/subs/cname-records.txt")
            log SUCCESS "Found $cname_count CNAME records using dnsx"
            
            # Print a sample of the CNAME records
            log INFO "Sample CNAME records:"
            head -n 5 "$domain_dir/subs/cname-records.txt" | while read -r line; do
                log INFO "    $line"
            done
            
            send_file_to_discord "$domain_dir/subs/cname-records.txt" "CNAME Records Found ($cname_count records)"
        else
            log WARNING "[-] No CNAME records found"
            touch "$domain_dir/subs/cname-records.txt"
        fi
    else
        log WARNING "[-] No subdomains found to check CNAME records"
        touch "$domain_dir/subs/cname-records.txt"
    fi
}

# Function to check NS records using dnsx
check_ns_records() {
    local domain_dir="$1"
    log INFO "Checking NS records using dnsx"
    
    if [[ -s "$domain_dir/subs/all-subs.txt" ]]; then
        # Use dnsx to get NS records
        log INFO "Collecting NS records with dnsx..."
        cat "$domain_dir/subs/all-subs.txt" | dnsx -ns -resp -silent > "$domain_dir/subs/ns-records-raw.txt" 2>/dev/null
        
        # Format the output for better readability
        if [[ -s "$domain_dir/subs/ns-records-raw.txt" ]]; then
            # Convert dnsx output format to readable format
            sed 's/\[NS\] \[/ -> /g; s/\]$//g' "$domain_dir/subs/ns-records-raw.txt" > "$domain_dir/subs/ns-records.txt"
            rm "$domain_dir/subs/ns-records-raw.txt"
            
            local ns_count=$(wc -l < "$domain_dir/subs/ns-records.txt")
            log SUCCESS "Found $ns_count NS records using dnsx"
            
            # Print a sample of the NS records
            log INFO "Sample NS records:"
            head -n 5 "$domain_dir/subs/ns-records.txt" | while read -r line; do
                log INFO "    $line"
            done
            
            send_file_to_discord "$domain_dir/subs/ns-records.txt" "NS Records Found ($ns_count records)"
        else
            log WARNING "[-] No NS records found"
            touch "$domain_dir/subs/ns-records.txt"
        fi
    else
        log WARNING "[-] No subdomains found to check NS records"
        touch "$domain_dir/subs/ns-records.txt"
    fi
}

# Function to check enabled PUT Method and S3 bucket vulnerabilities
put_scan() {
    local domain_dir="$1"
    local target_domain="$2"
    local web_output="$domain_dir/vulnerabilities/put-scan.txt"
    local s3_output="$domain_dir/vulnerabilities/put-s3-scan.txt"

    # --- Web PUT Scan ---
    _scan_web_put "$domain_dir" "$web_output"

    # --- S3 Bucket PUT Scan ---
    _scan_s3_put "$domain_dir" "$s3_output" "$target_domain"
}

# Helper function for web PUT scanning
_scan_web_put() {
    local domain_dir="$1"
    local output_file="$2"
    local total_hosts=0
    local vulnerable_hosts=0

    log INFO "Starting PUT method vulnerability scan"

    # Count total hosts and initialize output
    total_hosts=$(wc -l < "$domain_dir/subs/live-subs.txt")
    log INFO "Scanning $total_hosts hosts for PUT method vulnerabilities"
    > "$output_file"

    # Test each host
    while IFS= read -r host; do
        local path="evil.txt"
        # Clean host and build URL
        host=$(echo "$host" | sed 's:/*$::')
        local test_url
        if [[ "$host" =~ ^https?:// ]]; then
            test_url="${host}/${path}"
        else
            test_url="https://${host}/${path}"
        fi

        # Try PUT request and verify with GET
        curl -s -X PUT -d "hello world" "$test_url" > /dev/null 2>&1
        local get_response=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$test_url" 2>/dev/null)
        
        if [[ "$get_response" == "200" ]]; then
            echo "[VULNERABLE] $test_url" >> "$output_file"
            ((vulnerable_hosts++))
            log SUCCESS "PUT vulnerability found: $test_url"
        fi
    done < "$domain_dir/subs/live-subs.txt"

    # Report results
    if [[ $vulnerable_hosts -gt 0 ]]; then
        log SUCCESS "Found $vulnerable_hosts vulnerable hosts out of $total_hosts"
        send_file_to_discord "$output_file" "PUT Method Vulnerabilities Found ($vulnerable_hosts hosts)"
    else
        log WARNING "No PUT vulnerabilities found across $total_hosts hosts"
    fi

    log SUCCESS "PUT Method vulnerability scan completed"
}

# Helper function for S3 bucket PUT scanning
_scan_s3_put() {
    local domain_dir="$1" 
    local output_file="$2"
    local target_domain="$3"  # Pass the target domain directly

    log INFO "Starting parallel S3 bucket PUT scan using root domain..."
    > "$output_file"

    # Extract root domain (e.g., hackerone.com -> hackerone)
    local root_domain=$(echo "$target_domain" | sed 's/\..*$//' | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
    
    log INFO "Using root domain: $root_domain for S3 bucket generation"

    # Check if mutations wordlist exists and load it
    local mutations_file="Wordlists/mutations.txt"
    local mutations=()
    
    if [[ ! -f "$mutations_file" ]]; then
        log WARNING "Mutations wordlist not found at $mutations_file"
        log WARNING "Using basic suffixes instead"
        mutations=("" "-files" "-data" "-backup" "-static" "-uploads" "-assets" "-media" "-images" "-docs" "-api" "-storage" "-logs" "-tmp" "-web" "-admin")
    else
        log INFO "Loading mutations from $mutations_file"
        # Read mutations from file into array
        while IFS= read -r mutation; do
            [[ -n "$mutation" && ! "$mutation" =~ ^# ]] && mutations+=("$mutation")
        done < "$mutations_file"
        log INFO "Loaded ${#mutations[@]} mutations from wordlist"
    fi

    # Generate bucket names using root domain + mutations
    local bucket_names=()
    local valid_buckets=()
    local vulnerable_buckets=()
    
    # Add root domain without any mutation
    bucket_names+=("$root_domain")
    
    # Generate permutations with mutations
    for mutation in "${mutations[@]}"; do
        # Skip empty mutations that are already covered
        [[ -z "$mutation" ]] && continue
        
        # Add mutation as suffix
        bucket_names+=("${root_domain}${mutation}")
        
        # Add mutation as prefix (for some patterns that start with letters)
        if [[ "$mutation" =~ ^[a-z] ]]; then
            bucket_names+=("${mutation}${root_domain}")
        fi
    done

    log INFO "Generated ${#bucket_names[@]} potential bucket names"

    # Create temporary directory for parallel processing
    local temp_dir="/tmp/s3_scan_$$"
    mkdir -p "$temp_dir"

    # Function to check a single bucket (will be called in parallel)
    check_single_bucket() {
        local bucket="$1"
        local temp_dir="$2"
        local result_file="$temp_dir/result_$bucket"
        
        # Only test the most common HTTPS format with short timeout
        local bucket_url="https://$bucket.s3.amazonaws.com/"
        
        # Fast check with minimal timeout
        local http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 1 --max-time 2 "$bucket_url" 2>/dev/null)
        
        # Check for bucket existence indicators
        if [[ "$http_code" =~ ^(200|403|301|302)$ ]]; then
            echo "EXISTS|$bucket_url|$http_code|DIRECT" > "$result_file"
            return 0
        elif [[ "$http_code" == "404" ]]; then
            # For 404, test with common paths that often exist in buckets
            local test_paths=("1" "test" "robots.txt" "favicon.ico" "index.html" "uploads/1" "files/1" "images/1" "assets/1" "categories/1" "products/1")
            
            for test_path in "${test_paths[@]}"; do
                local test_url="${bucket_url}${test_path}"
                local test_resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 1 --max-time 1 "$test_url" 2>/dev/null)
                
                # If we get 200 (file exists) or 403 (access denied but bucket exists)
                if [[ "$test_resp" =~ ^(200|403)$ ]]; then
                    echo "EXISTS|$bucket_url|$http_code|LISTING_DISABLED_$test_path" > "$result_file"
                    return 0
                fi
            done
        fi
        
        # No bucket found
        return 1
    }

    # Export the function for parallel execution
    export -f check_single_bucket

    # Phase 1: Parallel bucket existence check
    log INFO "Phase 1: Parallel bucket existence check..."
    local exists_count=0

    # Use GNU parallel if available, otherwise use xargs
    if command -v parallel &> /dev/null; then
        log INFO "Using GNU parallel for maximum speed..."
        printf '%s\n' "${bucket_names[@]}" | parallel -j 50 --no-notice check_single_bucket {} "$temp_dir"
    else
        log INFO "Using xargs for parallel processing..."
        printf '%s\n' "${bucket_names[@]}" | xargs -n 1 -P 20 -I {} bash -c 'check_single_bucket "$1" "$2"' _ {} "$temp_dir"
    fi

    # Collect results
    log INFO "Collecting results..."
    
    for result_file in "$temp_dir"/result_*; do
        if [[ -f "$result_file" ]]; then
            IFS='|' read -r status bucket_url http_code method < "$result_file"
            if [[ "$status" == "EXISTS" ]]; then
                valid_buckets+=("$bucket_url")
                ((exists_count++))
                
                if [[ "$method" =~ ^LISTING_DISABLED ]]; then
                    detected_via=$(echo "$method" | cut -d'_' -f3-)
                    log SUCCESS "Found existing bucket: $bucket_url (Listing Disabled - found $detected_via)"
                    echo "[EXISTS] $bucket_url (Listing Disabled - found $detected_via)" >> "$output_file"
                else
                    log SUCCESS "Found existing bucket: $bucket_url (HTTP $http_code)"
                    echo "[EXISTS] $bucket_url (HTTP $http_code)" >> "$output_file"
                fi
            fi
        fi
    done

    # Cleanup temp directory
    rm -rf "$temp_dir"

    log INFO "Phase 1 complete: Found $exists_count existing buckets out of ${#bucket_names[@]} tested"

    # Phase 2: Test PUT operations on existing buckets
    if [[ ${#valid_buckets[@]} -gt 0 ]]; then
        log INFO "Phase 2: Testing PUT operations on ${#valid_buckets[@]} existing buckets..."
        
        for bucket_url in "${valid_buckets[@]}"; do
            # Test PUT operation with short timeout
            local test_file="test-put-autoar-$(date +%s).txt"
            local put_url="${bucket_url%/}/$test_file"
            
            log INFO "Testing PUT on: $put_url"
            
            # Try PUT request with short timeout
            local put_resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 3 -X PUT --data "autoar-test-$(date)" "$put_url" 2>/dev/null)
            
            if [[ "$put_resp" == "200" || "$put_resp" == "201" ]]; then
                vulnerable_buckets+=("$put_url")
                echo "[VULNERABLE] Writable S3 bucket: $put_url (HTTP $put_resp)" | tee -a "$output_file"
                log SUCCESS "VULNERABLE: Writable S3 bucket found: $put_url"
                
                # Quick verification
                local get_resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 1 --max-time 2 -X GET "$put_url" 2>/dev/null)
                if [[ "$get_resp" == "200" ]]; then
                    echo "[CONFIRMED] File successfully written and readable: $put_url" >> "$output_file"
                    log SUCCESS "CONFIRMED: File write/read successful on $put_url"
                fi
                
            elif [[ "$put_resp" == "403" ]]; then
                echo "[FORBIDDEN] Bucket exists but PUT not allowed: $put_url (HTTP 403)" >> "$output_file"
                log INFO "Bucket exists but not writable: $put_url"
            elif [[ "$put_resp" == "405" ]]; then
                echo "[METHOD_NOT_ALLOWED] PUT method not allowed: $put_url (HTTP 405)" >> "$output_file"
            else
                echo "[INFO] PUT test result: HTTP $put_resp for $put_url" >> "$output_file"
            fi
        done
    else
        log INFO "No existing buckets found to test PUT operations"
    fi

    # Generate summary
    {
        echo "=== S3 BUCKET SCAN SUMMARY ==="
        echo "Target Domain: $target_domain"
        echo "Root Domain Used: $root_domain"
        echo "Total Bucket Names Generated: ${#bucket_names[@]} (using mutations.txt)"
        echo "Existing Buckets Found: $exists_count"
        echo "Vulnerable Buckets Found: ${#vulnerable_buckets[@]}"
        echo ""
        
        if [[ ${#vulnerable_buckets[@]} -gt 0 ]]; then
            echo "=== VULNERABLE BUCKETS ==="
            for vuln_bucket in "${vulnerable_buckets[@]}"; do
                echo "- $vuln_bucket"
            done
            echo ""
        fi
        
        echo "=== EXPLOITATION NOTES ==="
        echo "1. Vulnerable buckets allow file uploads via PUT requests"
        echo "2. You can upload malicious files or defacement content"
        echo "3. Check bucket policies and permissions for further access"
        echo "4. Look for sensitive files that might be stored in these buckets"
        echo ""
        echo "Example exploitation:"
        if [[ ${#vulnerable_buckets[@]} -gt 0 ]]; then
            echo "curl -X PUT --data 'Your content here' '${vulnerable_buckets[0]}'"
        else
            echo "curl -X PUT --data 'Your content here' 'https://bucket.s3.amazonaws.com/yourfile.txt'"
        fi
        
    } >> "$output_file"

    # Send results to Discord
    if [[ -s "$output_file" ]]; then
        local summary_msg="**S3 Bucket Scan Results for $target_domain**\n"
        summary_msg+="\`\`\`"
        summary_msg+="Root Domain: $root_domain\n"
        summary_msg+="Bucket Names Generated: ${#bucket_names[@]} (using mutations.txt)\n"
        summary_msg+="Existing Buckets: $exists_count\n"
        summary_msg+="Vulnerable Buckets: ${#vulnerable_buckets[@]}"
        summary_msg+="\`\`\`"
        
        send_to_discord "$summary_msg"
        send_file_to_discord "$output_file" "S3 Bucket Scan Results - $exists_count existing, ${#vulnerable_buckets[@]} vulnerable"
    else
        log INFO "No S3 buckets found for $target_domain"
    fi

    log SUCCESS "S3 bucket scan completed. Found $exists_count existing buckets, ${#vulnerable_buckets[@]} vulnerable"
}

# Function to run Dalfox scans
run_dalfox_scan() {
    log INFO "Starting Dalfox XSS scanning..."

    # Check if input file exists
    if [[ ! -f "$DOMAIN_DIR/vulnerabilities/xss/gf-results.txt" ]]; then
        log WARNING "No parameters file found for XSS scanning"
        return
    fi

    # Count number of URLs to scan
    local total_urls=$(wc -l < "$DOMAIN_DIR/vulnerabilities/xss/gf-results.txt")
    log INFO "Found $total_urls URLs to scan for XSS vulnerabilities"

    # Run Dalfox scan
    log INFO "Running Dalfox with 50 workers and custom XSS payload"
    dalfox file "$DOMAIN_DIR/vulnerabilities/xss/gf-results.txt" \
        --no-spinner \
        --only-poc r \
        --ignore-return 302,404,403 \
        --skip-bav \
        -b "0x88.xss.cl" \
        -w 50 \
        -o "$DOMAIN_DIR/dalfox-results.txt" \
        2>> "$LOG_FILE"

    # Check results
    if [[ -s "$DOMAIN_DIR/dalfox-results.txt" ]]; then
        local vuln_count=$(grep -c "POC" "$DOMAIN_DIR/dalfox-results.txt")
        log SUCCESS "Dalfox scan completed. Found $vuln_count potential XSS vulnerabilities"
        send_file_to_discord "$DOMAIN_DIR/dalfox-results.txt" "Dalfox XSS Scan Results - Found $vuln_count vulnerabilities"
    else
        log WARNING "Dalfox scan completed. No XSS vulnerabilities found"
        touch "$DOMAIN_DIR/dalfox-results.txt"
    fi
}

# Function to scan for JS exposures
scan_js_exposures() {
    local domain_dir="$1"
    local js_urls_file="${2:-$domain_dir/urls/js-urls.txt}"
    log INFO "Starting JS Analysis"
    
    if [[ ! -f "$js_urls_file" || ! -s "$js_urls_file" ]]; then
        log WARNING "[-] No JavaScript files found to analyze"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/js"
    
    local js_count=$(wc -l < "$js_urls_file")
    log SUCCESS "Analyzing $js_count JavaScript files"
    
    local findings=()
    local files_to_send=()
    
    # 1. Find secrets using trufflehog patterns
    log INFO "Running trufflehog scan on JavaScript files"
    cat "$js_urls_file" | jsleak -t regexes/trufflehog-v3.yaml -s -c 20 > "$domain_dir/vulnerabilities/js/trufflehog.txt" 2>/dev/null
    local secrets_count=$(wc -l < "$domain_dir/vulnerabilities/js/trufflehog.txt" 2>/dev/null || echo 0)
    if [[ $secrets_count -gt 0 ]]; then
        findings+=("trufflehog: $secrets_count")
        files_to_send+=("$domain_dir/vulnerabilities/js/trufflehog.txt")
    fi
    
    # 2. Find links and endpoints
    log INFO "Running jsleak scan on JavaScript files"
    cat "$js_urls_file" | jsleak -l -e -c 20 > "$domain_dir/vulnerabilities/js/links.txt" 2>/dev/null
    local links_count=$(wc -l < "$domain_dir/vulnerabilities/js/links.txt" 2>/dev/null || echo 0)
    if [[ $links_count -gt 0 ]]; then
        findings+=("links: $links_count")
        files_to_send+=("$domain_dir/vulnerabilities/js/links.txt")
    fi
    
    # 3. Check active URLs
    log INFO "Running jsleak URLS scan on JavaScript files"
    cat "$js_urls_file" | jsleak -c 20 -k > "$domain_dir/vulnerabilities/js/active-urls.txt" 2>/dev/null
    local active_count=$(wc -l < "$domain_dir/vulnerabilities/js/active-urls.txt" 2>/dev/null || echo 0)
    if [[ $active_count -gt 0 ]]; then
        findings+=("active-urls: $active_count")
        files_to_send+=("$domain_dir/vulnerabilities/js/active-urls.txt")
    fi
    
    # 4. Scan with various regex patterns
    local regex_files=(
        "regexes/confident-regexes.yaml"
        "regexes/nuclei-regexes.yaml"
        "regexes/nuclei-generic.yaml"
        "regexes/pii-regexes.yaml"
        "regexes/risky-regexes.yaml"
        "regexes/rules-regexes.yaml"
    )
    log INFO "Running jsleak regex scan on JavaScript files"
    for regex_file in "${regex_files[@]}"; do
        local filename=$(basename "$regex_file" .yaml)
        cat "$js_urls_file" | jsleak -t "$regex_file" -s -c 20 > "$domain_dir/vulnerabilities/js/$filename.txt" 2>/dev/null
        local count=$(wc -l < "$domain_dir/vulnerabilities/js/$filename.txt" 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            findings+=("$filename: $count")
            files_to_send+=("$domain_dir/vulnerabilities/js/$filename.txt")
        fi
    done
    
    # 5. Scan with nuclei
    log INFO "Running nuclei scan on JavaScript files"
    nuclei -l "$js_urls_file" -t nuclei_templates/js/js-exposures.yaml -o "$domain_dir/vulnerabilities/js/nuclei-js.txt" >> "$LOG_FILE" 2>&1
    local nuclei_count=$(wc -l < "$domain_dir/vulnerabilities/js/nuclei-js.txt" 2>/dev/null || echo 0)
    if [[ $nuclei_count -gt 0 ]]; then
        findings+=("nuclei: $nuclei_count")
        files_to_send+=("$domain_dir/vulnerabilities/js/nuclei-js.txt")
    fi
    
    log SUCCESS "JS Analysis Summary:"
    for finding in "${findings[@]}"; do
        log SUCCESS "    $finding"
    done
    
    if [[ -n "$DISCORD_WEBHOOK" && ${#files_to_send[@]} -gt 0 ]]; then
        for file in "${files_to_send[@]}"; do
            if [[ -f "$file" && -s "$file" ]]; then
                local filename=$(basename "$file")
                sort -u -o "$file" "$file"
                send_file_to_discord "$file" "Found Regex Matches in $filename"
            fi
        done
    fi
}

# Function to run nuclei scans
run_nuclei_scans() {
    local domain_dir="$1"
    log INFO "Nuclei Scanning"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        nuclei -u "https://$SINGLE_SUBDOMAIN"  -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt" >> "$LOG_FILE" 2>&1
        nuclei -u "https://$SINGLE_SUBDOMAIN"  -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt" >> "$LOG_FILE" 2>&1
    else
        nuclei -l "$domain_dir/subs/live-subs.txt" -s low,medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt" >> "$LOG_FILE" 2>&1
        nuclei -l "$domain_dir/subs/live-subs.txt" -s low,medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt" >> "$LOG_FILE" 2>&1
    fi
    if [[ -s "$domain_dir/vulnerabilities/nuclei_templates-results.txt" && -n "$DISCORD_WEBHOOK" ]]; then
        send_file_to_discord "$domain_dir/vulnerabilities/nuclei_templates-results.txt" "Collected Templates Nuclei Scans Results"
    else
        log WARNING "No nuclei_templates-results.txt file found"
        send_to_discord "No Nuclei Collected Templates Scans Results"
    fi
    if [[ -s "$domain_dir/vulnerabilities/nuclei-templates-results.txt" && -n "$DISCORD_WEBHOOK" ]]; then
        send_file_to_discord "$domain_dir/vulnerabilities/nuclei-templates-results.txt" "Public Nuclei Scans Results"
    else
        log WARNING "No nuclei-templates-results.txt file found"
        send_to_discord "No Nuclei Public Scans Results"
    fi
}

# Function to detect technologies using httpx
detect_technologies() {
    log INFO "Detecting technologies with httpx"
    local tech_file="$DOMAIN_DIR/subs/tech-detect.txt"
    if [[ -s "$DOMAIN_DIR/subs/live-subs.txt" ]]; then
        httpx -l "$DOMAIN_DIR/subs/live-subs.txt" -tech-detect -title -status-code -server -nc -silent -o "$tech_file" >> "$LOG_FILE" 2>&1
        local tech_count=$(wc -l < "$tech_file")
        log SUCCESS "Technology detection completed for $tech_count hosts (saved to $tech_file)"
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$tech_file" "Technology Detection Results ($tech_count hosts)"
        fi
    else
        log WARNING "No live subdomains found for technology detection"
    fi
}

# Function to scan for dangling DNS records using dnsx
scan_dangling_dns() {
    local domain_dir="$1"
    log INFO "Starting Unified DNS Takeover Scan (CNAME & NS)"
    
    if [[ ! -f "$domain_dir/subs/all-subs.txt" ]]; then
        log WARNING "[-] No subdomains file found at $domain_dir/subs/all-subs.txt"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/dns-takeover"
    local findings_dir="$domain_dir/vulnerabilities/dns-takeover"
    > "$findings_dir/nuclei-takeover-public.txt"
    > "$findings_dir/nuclei-takeover-custom.txt"
    > "$findings_dir/azureSDT.txt"
    > "$findings_dir/ns-takeover-raw.txt"
    > "$findings_dir/ns-takeover-vuln.txt"
    > "$findings_dir/ns-servers.txt"
    > "$findings_dir/ns-servers-vuln.txt"
    > "$findings_dir/dns-takeover-summary.txt"
    > "$findings_dir/dnsreaper-results.txt"
    > "$findings_dir/filtered-ns-takeover-vuln.txt"

    # --- CNAME Takeover: Nuclei and subov88r only ---
    log INFO "Running Nuclei public takeover templates..."
    if [[ -d "nuclei-templates" ]]; then
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei-templates/http/takeovers/ -o "$findings_dir/nuclei-takeover-public.txt" >> "$LOG_FILE" 2>&1
        if [[ -s "$findings_dir/nuclei-takeover-public.txt" && -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$findings_dir/nuclei-takeover-public.txt" "Nuclei Public Takeover Findings"
        fi
    fi
    
    log INFO "Running Nuclei custom takeover templates..."
    if [[ -d "nuclei_templates" ]]; then
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/takeover/detect-all-takeover.yaml -o "$findings_dir/nuclei-takeover-custom.txt" >> "$LOG_FILE" 2>&1
        if [[ -s "$findings_dir/nuclei-takeover-custom.txt" && -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$findings_dir/nuclei-takeover-custom.txt" "Nuclei Custom Takeover Findings"
        fi
    fi

    # Run DNSReaper scan
    log INFO "Running DNSReaper scan..."
    cp "$domain_dir/subs/all-subs.txt" "$findings_dir/dnsreaper-input.txt"
    docker run -it --rm -v "$(pwd):/etc/dnsreaper" punksecurity/dnsreaper file --filename "/etc/dnsreaper/$findings_dir/dnsreaper-input.txt" > "$findings_dir/dnsreaper-results.txt" 2>> "$LOG_FILE"
    if [[ -s "$findings_dir/dnsreaper-results.txt" && -n "$DISCORD_WEBHOOK" ]]; then
        send_file_to_discord "$findings_dir/dnsreaper-results.txt" "DNSReaper Takeover Results"
    fi

    if command -v subov88r &> /dev/null; then
        log INFO "Running subov88r for Azure and AWS subdomain takeover check..."
        subov88r -f "$domain_dir/subs/all-subs.txt" -awsto -nc -asto > "$findings_dir/subov88r-results.txt" 2>> "$LOG_FILE"
        if [[ -s "$findings_dir/subov88r-results.txt" && -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$findings_dir/subov88r-results.txt" "Azure and AWS Subdomain Takeover Results (subov88r)"
        fi
    fi

    # --- NS Takeover: Enhanced scanning ---
    log INFO "Running enhanced NS takeover scan..."
    
    # First get all NS records
    log INFO "Extracting NS records..."
    dnsx -l "$domain_dir/subs/all-subs.txt" -ns -silent -ro > "$findings_dir/ns-servers.txt"
    
    # Check both subdomains and NS servers for DNS errors
    log INFO "Checking subdomains for DNS errors..."
    dnsx -l "$domain_dir/subs/all-subs.txt" -rcode servfail,refused -silent > "$findings_dir/ns-takeover-raw.txt"
    
    log INFO "Checking NS servers for DNS errors..."
    dnsx -l "$findings_dir/ns-servers.txt" -rcode servfail,refused -silent >> "$findings_dir/ns-servers-vuln.txt"
    
    local ns_takeover_raw_count=$(wc -l < "$findings_dir/ns-takeover-raw.txt")
    local ns_servers_vuln_count=$(wc -l < "$findings_dir/ns-servers-vuln.txt")
    
    log INFO "Found $ns_takeover_raw_count subdomains and $ns_servers_vuln_count NS servers with DNS errors"

    if [[ $ns_takeover_raw_count -gt 0 && -n "$DISCORD_WEBHOOK" ]]; then
        send_file_to_discord "$findings_dir/ns-takeover-raw.txt" "NS Takeover Candidates (Subdomain DNS Errors)"
    fi

    if [[ $ns_servers_vuln_count -gt 0 && -n "$DISCORD_WEBHOOK" ]]; then
        send_file_to_discord "$findings_dir/ns-servers-vuln.txt" "NS Takeover Candidates (NS Server DNS Errors)"
    fi

    # Filter for known vulnerable/edge-case NS providers
    local ns_vuln_regex='ns1-.*\.azure-dns\.com|ns2-.*\.azure-dns\.net|ns3-.*\.azure-dns\.org|ns4-.*\.azure-dns\.info|ns1\.dnsimple\.com|ns2\.dnsimple\.com|ns3\.dnsimple\.com|ns4\.dnsimple\.com|ns1\.domain\.com|ns2\.domain\.com|ns1\.dreamhost\.com|ns2\.dreamhost\.com|ns3\.dreamhost\.com|ns-cloud-.*\.googledomains\.com|ns5\.he\.net|ns4\.he\.net|ns3\.he\.net|ns2\.he\.net|ns1\.he\.net|ns1\.linode\.com|ns2\.linode\.com|ns1.*\.name\.com|ns2.*\.name\.com|ns3.*\.name\.com|ns4.*\.name\.com|ns1\.domaindiscover\.com|ns2\.domaindiscover\.com|yns1\.yahoo\.com|yns2\.yahoo\.com|ns1\.reg\.ru|ns2\.reg\.ru'
    grep -Ei "$ns_vuln_regex" "$findings_dir/ns-takeover-raw.txt" > "$findings_dir/ns-takeover-vuln.txt"
    local ns_takeover_vuln_count=$(wc -l < "$findings_dir/filtered-ns-takeover-vuln.txt")
    
    if [[ -s "$findings_dir/filtered-ns-takeover-vuln.txt" && -n "$DISCORD_WEBHOOK" ]]; then
        send_file_to_discord "$findings_dir/filtered-ns-takeover-vuln.txt" "NS Takeover Filtered Targets (Vulnerable Providers)"
    fi

    # --- Summary/reporting ---
    {
        echo "=== DNS TAKEOVER SCAN SUMMARY ==="
        echo "Scan Date: $(date)"
        echo "Total Subdomains Scanned: $(wc -l < "$domain_dir/subs/all-subs.txt")"
        echo "Tools Used: dnsx, nuclei, subov88r, dnsreaper"
        echo ""
        echo "CNAME Takeover (Nuclei public): $(wc -l < "$findings_dir/nuclei-takeover-public.txt")"
        echo "CNAME Takeover (Nuclei custom): $(wc -l < "$findings_dir/nuclei-takeover-custom.txt")"
        echo "DNSReaper Results: $(wc -l < "$findings_dir/dnsreaper-results.txt")"
        echo "Azure Subdomain Takeover (subov88r): $(wc -l < "$findings_dir/azureSDT.txt")"
        echo "NS Takeover (Subdomain DNS Errors): $ns_takeover_raw_count"
        echo "NS Takeover (NS Server DNS Errors): $ns_servers_vuln_count"
        echo "NS Takeover (Vulnerable Providers): $ns_takeover_vuln_count"
        echo ""
        echo "=== Exploitation Notes ==="
        echo "- CNAME Takeover: Use Nuclei/subov88r/DNSReaper findings for actionable subdomain takeovers."
        echo "- NS Takeover: Check both subdomain and NS server DNS errors, prioritize those matching known vulnerable providers."
        echo "- Always verify manually before reporting."
        echo ""
        echo "References:"
        echo "- https://github.com/indianajson/can-i-take-over-dns"
        echo "- https://trickest.com/blog/dns-takeover-explained-protect-your-online-domain/"
        echo "- https://hackerone.com/reports/1226891"
        echo "- https://github.com/punk-security/dnsreaper"
    } > "$findings_dir/dns-takeover-summary.txt"

    log SUCCESS "DNS Takeover scan completed. Results saved in $findings_dir/"
}

# Function to run lite scan
lite_scan() {
    local domain="$1"
    log INFO "Starting Lite Scan for domain: $domain"
    
    # Create necessary directories
    mkdir -p "$DOMAIN_DIR"/{subs,urls,vulnerabilities/js}
    
    # 1. Subdomain Enumeration
    log INFO "Running subdomain enumeration"
    subEnum "$domain"
    
    # 2. CNAME Check
    log INFO "Running CNAME check"
    check_cname_records "$DOMAIN_DIR"
    
    # 3. Filter Live Hosts
    log INFO "Filtering live hosts"
    filter_live_hosts
    
    # 3.5 Technology Detection
    log INFO "Detecting technologies on live hosts"
    detect_technologies

    # 4. Dangling DNS Scan
    log INFO "Running Dangling DNS Scan"
    scan_dangling_dns "$DOMAIN_DIR"

    # 5. Reflection Scan
    log INFO "Running Reflection Scan"
    run_reflection_scan

    # put scan
    put_scan "$DOMAIN_DIR" "$domain"

    # 4. URL Collection
    log INFO "Collecting URLs"
    fetch_urls
    
    # 5. JS File Extraction and Analysis
    log INFO "Extracting and analyzing JavaScript files"
    scan_js_exposures "$DOMAIN_DIR"

    # Nuclei Scanning
    log INFO "Running Nuclei scans"
    run_nuclei_scans "$DOMAIN_DIR"
    
    log SUCCESS "Lite scan completed successfully!"
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        send_to_discord "🎉 Lite scan completed for $domain! Check $DOMAIN_DIR for detailed findings."
    fi
}

# Function to scan a single subdomain
scan_single_subdomain() {
    local subdomain="$1"
    log INFO "Running scans on subdomain: $subdomain"
    
    # Create necessary directories and initialize files
    mkdir -p "$DOMAIN_DIR"/{subs,urls,vulnerabilities/{xss,sqli,ssrf,ssti,lfi,rce,idor,js,takeovers},fuzzing,ports}
    
    # Initialize subdomain files
    echo "$subdomain" > "$DOMAIN_DIR/subs/all-subs.txt"
    echo "https://$subdomain" > "$DOMAIN_DIR/subs/live-subs.txt"
    
    # Initialize empty files
    touch "$DOMAIN_DIR/urls/all-urls.txt"
    touch "$DOMAIN_DIR/urls/js-urls.txt"
    touch "$DOMAIN_DIR/fuzzing/ffuf.html"
    touch "$DOMAIN_DIR/fuzzing/ffuf-post.html"
    
    # Run scans
    fetch_urls
    scan_js_exposures "$DOMAIN_DIR"
    run_reflection_scan
    check_cname_records "$DOMAIN_DIR"
    detect_technologies
    put_scan "$DOMAIN_DIR" "$subdomain"
    run_port_scan
    run_nuclei_scans "$DOMAIN_DIR"
    run_ffuf
    run_gf_scans
    run_sql_injection_scan
    run_dalfox_scan
    scan_dangling_dns "$DOMAIN_DIR"
}

# Function to scan entire domain
scan_domain() {
    local domain="$1"
    log INFO "Running scans on domain: $domain"
    subEnum "$domain"
    fetch_urls
    filter_live_hosts
    run_reflection_scan
    detect_technologies
    check_cname_records "$DOMAIN_DIR"
    scan_dangling_dns "$DOMAIN_DIR"
    put_scan "$DOMAIN_DIR" "$domain"
    run_port_scan
    scan_js_exposures "$DOMAIN_DIR"
    run_nuclei_scans "$DOMAIN_DIR"
    run_ffuf
    run_gf_scans
    run_sql_injection_scan
    run_dalfox_scan
}

# Function to monitor JS files for a domain
js_monitor() {
    local domain="$1"
    local subdomain="$2"
    if [[ -n "$subdomain" ]]; then
        log INFO "[jsMonitor] Monitoring single subdomain: $subdomain"
        SINGLE_SUBDOMAIN="$subdomain"
        setup_results_dir
        echo "$subdomain" > "$DOMAIN_DIR/subs/all-subs.txt"
        echo "https://$subdomain" > "$DOMAIN_DIR/subs/live-subs.txt"
        fetch_urls
    else
        log INFO "[jsMonitor] Starting JS monitoring for $domain"
        setup_results_dir
        subEnum "$domain"
        fetch_urls
    fi

    local js_urls_file="$DOMAIN_DIR/urls/js-urls.txt"
    local tmp_dir="/tmp/jsmonitor_${subdomain:-$domain}"
    mkdir -p "$tmp_dir"

    if [[ ! -s "$js_urls_file" ]]; then
        log WARNING "[jsMonitor] No JS files found for ${subdomain:-$domain}"
        return
    fi

    local js_url_count=$(wc -l < "$js_urls_file")
    log INFO "[jsMonitor] Found $js_url_count JS URLs in this scan."

    # Get previous JS file info from DB
    local prev_file="$tmp_dir/prev_jsfiles.json"
    log INFO "[jsMonitor] Fetching previous JS file metadata from database..."
    ./sqlite_db_handler.py get_jsfiles "${subdomain:-$domain}" > "$prev_file"
    local prev_count=$(jq length "$prev_file" 2>/dev/null || echo 0)
    log INFO "[jsMonitor] Found $prev_count JS file records in database."

    # Prepare temp file for new/changed JS URLs
    local changed_js_urls="$tmp_dir/changed_js_urls.txt"
    > "$changed_js_urls"
    > "$tmp_dir/jsfile_list.json"
    echo '[' > "$tmp_dir/jsfile_list.json"
    local first=1
    local changed_count=0

    while IFS= read -r jsurl; do
        local jsfile="$tmp_dir/$(echo "$jsurl" | md5sum | awk '{print $1}')"
        curl -s --max-time 10 "$jsurl" -o "$jsfile"
        local clen=$(stat -c %s "$jsfile" 2>/dev/null || echo 0)
        local now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

        # Find previous size
        local prev_meta=$(jq -c --arg url "$jsurl" 'map(select(.url==$url)) | .[0]' "$prev_file")
        local prev_size=$(echo "$prev_meta" | jq -r '.size // empty')

        # If new or size changed by >20 bytes, add to changed list
        local size_diff=0
        if [[ -z "$prev_size" ]]; then
            size_diff=$clen
        else
            size_diff=$(( clen > prev_size ? clen - prev_size : prev_size - clen ))
        fi
        if [[ -z "$prev_size" ]]; then
            log INFO "[jsMonitor] New JS file detected: $jsurl (size: $clen bytes)"
            echo "$jsurl" >> "$changed_js_urls"
            ((changed_count++))
            if [[ $first -eq 0 ]]; then echo ',' >> "$tmp_dir/jsfile_list.json"; fi
            echo -n '{' >> "$tmp_dir/jsfile_list.json"
            echo -n "\"url\": \"$jsurl\", \"size\": $clen, \"last_seen\": \"$now\"" >> "$tmp_dir/jsfile_list.json"
            echo -n '}' >> "$tmp_dir/jsfile_list.json"
            first=0
        elif [[ $size_diff -gt 20 ]]; then
            log INFO "[jsMonitor] Changed JS file detected: $jsurl (old size: $prev_size, new size: $clen, diff: $size_diff bytes)"
            echo "$jsurl" >> "$changed_js_urls"
            ((changed_count++))
            if [[ $first -eq 0 ]]; then echo ',' >> "$tmp_dir/jsfile_list.json"; fi
            echo -n '{' >> "$tmp_dir/jsfile_list.json"
            echo -n "\"url\": \"$jsurl\", \"size\": $clen, \"last_seen\": \"$now\"" >> "$tmp_dir/jsfile_list.json"
            echo -n '}' >> "$tmp_dir/jsfile_list.json"
            first=0
        else
            log INFO "[jsMonitor] Unchanged JS file: $jsurl (size: $clen bytes, previous: $prev_size bytes)"
        fi
    done < "$js_urls_file"
    echo ']' >> "$tmp_dir/jsfile_list.json"

    log INFO "[jsMonitor] $changed_count JS files are new or changed and will be scanned."

    # Scan only new/changed JS files
    if [[ -s "$changed_js_urls" ]]; then
        scan_js_exposures "$DOMAIN_DIR" "$changed_js_urls"
        log INFO "[jsMonitor] Updating database with $changed_count new/changed JS files."
        ./sqlite_db_handler.py add_jsfiles "${subdomain:-$domain}" "$tmp_dir/jsfile_list.json"
    fi

    rm -rf "$tmp_dir"
    log SUCCESS "[jsMonitor] Monitoring complete for ${subdomain:-$domain}"
}

# Help function
show_help() {
    cat << EOF
    Usage: ./autoAr.sh <subcommand> [options]

    Subcommands:
        domain      Full scan mode (customizable with skip flags)
        subdomain   Scan a single subdomain
        liteScan    Quick scan (subdomains, CNAME, live hosts, URLs, JS, nuclei)
        fastLook    Fast look (subenum, live subdomains, collect urls, tech detect, cname checker)
        jsMonitor   Monitor JS files for a domain or single subdomain and alert on changes
        monitor     Run the Python monitoring script
        help        Show this help message

    Examples:
        ./autoAr.sh domain -d example.com
        ./autoAr.sh subdomain -s sub.example.com
        ./autoAr.sh liteScan -d example.com
        ./autoAr.sh fastLook -d example.com
        ./autoAr.sh jsMonitor -d example.com
        ./autoAr.sh jsMonitor -s sub.example.com
        ./autoAr.sh monitor
        ./autoAr.sh monitor --all
        ./autoAr.sh monitor -c company
EOF
}

# Subcommand parser (should be right after all functions and config)
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    if [[ "$1" =~ ^(domain|subdomain|liteScan|fastLook|jsMonitor|monitor|help|--help|-h)$ ]]; then
        subcommand="$1"
        shift
        case "$subcommand" in
            domain)
                # Parse flags for domain scan
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        -d|--domain)
                            TARGET="$2"; shift 2;;
                        -v|--verbose)
                            VERBOSE=true; shift;;
                        -dw|--discord-webhook)
                            DISCORD_WEBHOOK="$2"; shift 2;;
                        -st|--save-to-db)
                            SAVE_TO_DB=true; shift;;
                        -sk|--securitytrails-key)
                            SECURITYTRAILS_API_KEY="$2"; shift 2;;
                        *)
                            echo "Unknown option: $1"; show_help; exit 1;;
                    esac
                done
                if [[ -z "$TARGET" ]]; then
                    echo "Error: Must specify a domain with -d"; show_help; exit 1;
                fi
                setup_results_dir
                scan_domain "$TARGET"
                exit 0
                ;;
            subdomain)
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        -s|--subdomain)
                            SINGLE_SUBDOMAIN="$2"; shift 2;;
                        -v|--verbose)
                            VERBOSE=true; shift;;
                        -dw|--discord-webhook)
                            DISCORD_WEBHOOK="$2"; shift 2;;
                        -st|--save-to-db)
                            SAVE_TO_DB=true; shift;;
                        *)
                            echo "Unknown option: $1"; show_help; exit 1;;
                    esac
                done
                if [[ -z "$SINGLE_SUBDOMAIN" ]]; then
                    echo "Error: Must specify a subdomain with -s"; show_help; exit 1;
                fi
                setup_results_dir
                scan_single_subdomain "$SINGLE_SUBDOMAIN"
                exit 0
                ;;
            liteScan)
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        -d|--domain)
                            TARGET="$2"; shift 2;;
                        -v|--verbose)
                            VERBOSE=true; shift;;
                        -dw|--discord-webhook)
                            DISCORD_WEBHOOK="$2"; shift 2;;
                        -st|--save-to-db)
                            SAVE_TO_DB=true; shift;;
                        -sk|--securitytrails-key)
                            SECURITYTRAILS_API_KEY="$2"; shift 2;;
                        *)
                            echo "Unknown option: $1"; show_help; exit 1;;
                    esac
                done
                if [[ -z "$TARGET" ]]; then
                    echo "Error: Must specify a domain with -d"; show_help; exit 1;
                fi
                setup_results_dir
                lite_scan "$TARGET"
                exit 0
                ;;
            fastLook)
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        -d|--domain)
                            TARGET="$2"; shift 2;;
                        -v|--verbose)
                            VERBOSE=true; shift;;
                        -dw|--discord-webhook)
                            DISCORD_WEBHOOK="$2"; shift 2;;
                        -sk|--securitytrails-key)
                            SECURITYTRAILS_API_KEY="$2"; shift 2;;
                        *)
                            echo "Unknown option: $1"; show_help; exit 1;;
                    esac
                done
                if [[ -z "$TARGET" ]]; then
                    echo "Error: Must specify a domain with -d"; show_help; exit 1;
                fi
                setup_results_dir
                subEnum "$TARGET"
                filter_live_hosts
                fetch_urls
                detect_technologies
                check_cname_records "$DOMAIN_DIR"
                run_reflection_scan
                exit 0
                ;;
            jsMonitor)
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        -d|--domain)
                            TARGET="$2"; shift 2;;
                        -s|--subdomain)
                            SINGLE_SUBDOMAIN="$2"; shift 2;;
                        -v|--verbose)
                            VERBOSE=true; shift;;
                        -dw|--discord-webhook)
                            DISCORD_WEBHOOK="$2"; shift 2;;
                        *)
                            echo "Unknown option: $1"; show_help; exit 1;;
                    esac
                done
                JS_MONITOR_MODE=1
                if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
                    js_monitor "" "$SINGLE_SUBDOMAIN"
                elif [[ -n "$TARGET" ]]; then
                    js_monitor "$TARGET" ""
                else
                    echo "Error: Must specify a domain with -d or a subdomain with -s"; show_help; exit 1;
                fi
                exit 0
                ;;
            monitor)
                # Convert '-c all' to '--all' for compatibility
                if [[ "$1" == "-c" && "$2" == "all" ]]; then
                    shift 2
                    python3 monitor-comapany.py --all "$@"
                else
                    python3 monitor-comapany.py "$@"
                fi
                exit 0
                ;;
            help|--help|-h)
                show_help
                exit 0
                ;;
        esac
    else
        show_help
        exit 1
    fi
}

# Log config file detection and variable loading
if [[ -f "$CONFIG_FILE" ]]; then
    log INFO "Config file $CONFIG_FILE found."
else
    log ERROR "Config file $CONFIG_FILE not found!"
fi

log INFO "DB_NAME: $DB_NAME"
log INFO "DISCORD_WEBHOOK: ${DISCORD_WEBHOOK:0:10}..."
log INFO "SAVE_TO_DB: $SAVE_TO_DB"
log INFO "VERBOSE: $VERBOSE"
log INFO "GITHUB_TOKEN: ${GITHUB_TOKEN:0:6}..."
log INFO "SECURITYTRAILS_API_KEY: ${SECURITYTRAILS_API_KEY:0:6}..."              

main "$@"