#!/bin/bash

# Add color variables at the top of the script
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default config file location
CONFIG_FILE="./autar.conf"

# Allow override via environment variable
if [[ -n "$AUTOAR_CONFIG" ]]; then
    CONFIG_FILE="$AUTOAR_CONFIG"
fi

# Load config if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    export MONGO_URI
    export DB_NAME
    # Use Discord webhook from config if not set via command line
    if [[ -z "$DISCORD_WEBHOOK" && -n "$DISCORD_WEBHOOK_CONFIG" ]]; then
        DISCORD_WEBHOOK="$DISCORD_WEBHOOK_CONFIG"
    fi
else
    echo "Warning: Config file $CONFIG_FILE not found. Using environment variables or defaults."
fi

# Fallback: If DISCORD_WEBHOOK is still empty, use config value
if [[ -z "$DISCORD_WEBHOOK" && -n "$DISCORD_WEBHOOK_CONFIG" ]]; then
    DISCORD_WEBHOOK="$DISCORD_WEBHOOK_CONFIG"
fi

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
    local tools=("subfinder" "httpx" "naabu" "nuclei" "ffuf" "kxss" "qsreplace" "gf" "dalfox" "urlfinder" "interlace" "jsleak" "jsfinder")
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
    kxss < "$DOMAIN_DIR/urls/all-urls.txt" | tee "$DOMAIN_DIR/vulnerabilities/kxss-results.txt" >> "$LOG_FILE" 2>&1
    send_file_to_discord "$DOMAIN_DIR/vulnerabilities/kxss-results.txt" "Reflection Scan Results"
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
        subfinder -d "$domain" -all -silent -o "$DOMAIN_DIR/subs/subfinder-subs.txt" >> "$LOG_FILE" 2>&1
    else
        log WARNING "[-] subfinder not found, skipping subfinder enumeration"
    fi
    
    # Combine and sort all results
    cat "$DOMAIN_DIR/subs/subfinder-subs.txt" "$DOMAIN_DIR/subs/apis-subs.txt" 2>/dev/null | grep -v "*" | sort -u > "$DOMAIN_DIR/subs/all-subs.txt"
    
    # Count results
    local total_subs=$(wc -l < "$DOMAIN_DIR/subs/all-subs.txt")
    log SUCCESS "Found $total_subs unique subdomains"
    
    # Save to MongoDB
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        log INFO "Saving results to MongoDB..."
        
        # Then add all subdomains from file
        ./mongo_db_handler.py add_subdomains_file "$domain" "$DOMAIN_DIR/subs/all-subs.txt"
        
        log SUCCESS "Subdomain Enumeration completed. Results saved in MongoDB and $DOMAIN_DIR/subs/all-subs.txt"
        send_file_to_discord "$DOMAIN_DIR/subs/all-subs.txt" "Subdomain Enumeration completed - Found $total_subs subdomains"
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
        urlfinder -d "$SINGLE_SUBDOMAIN" -all -silent -o "$DOMAIN_DIR/urls/all-urls.txt" >> "$LOG_FILE" 2>&1
        jsfinder -l "$DOMAIN_DIR/subs/live-subs.txt" -c 50 -s -o "$DOMAIN_DIR/urls/js-urls.txt" >> "$LOG_FILE" 2>&1
        
    elif [[ -n "$TARGET" ]]; then
        # 1. First collect URLs using urlfinder
        log INFO "Running URLFinder for initial URL collection"
        urlfinder -d "$TARGET" -all -silent -o "$DOMAIN_DIR/urls/all-urls.txt" >> "$LOG_FILE" 2>&1
        
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
        log SUCCESS "Found $total_urls total unique URLs"
        
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
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
    else
        log WARNING "[-] No subdomains found to filter"
        touch "$DOMAIN_DIR/subs/live-subs.txt"
    fi
}

# Function to run port scanning
run_port_scan() {
    log INFO "Port Scanning with naabu"
    if [[ -s "$DOMAIN_DIR/subs/live-subs.txt" ]]; then
        naabu -l "$DOMAIN_DIR/subs/live-subs.txt" -p - -o "$DOMAIN_DIR/ports/ports.txt" >> "$LOG_FILE" 2>&1
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

# Function to check CNAME records
check_cname_records() {
    local domain_dir="$1"
    log INFO "Checking CNAME records"
    
    # Create a temporary file for formatted CNAME records
    local temp_cname_file="$domain_dir/subs/temp_cname.txt"
    > "$temp_cname_file"
    
    if [[ -s "$domain_dir/subs/all-subs.txt" ]]; then
        while IFS= read -r subdomain; do
            local cname=$(dig CNAME "$subdomain" +short 2>/dev/null)
            if [[ -n "$cname" ]]; then
                echo "$subdomain -> $cname" >> "$temp_cname_file"
            fi
        done < "$domain_dir/subs/all-subs.txt"
        
        # Sort and format the CNAME records
        if [[ -s "$temp_cname_file" ]]; then
            sort -u "$temp_cname_file" > "$domain_dir/subs/cname-records.txt"
            rm "$temp_cname_file"
            
            local cname_count=$(wc -l < "$domain_dir/subs/cname-records.txt")
            log SUCCESS "Found $cname_count CNAME records"
            log SUCCESS "CNAME records saved to $domain_dir/subs/cname-records.txt"
            
            # Print a sample of the CNAME records
            log INFO "Sample CNAME records:"
            head -n 5 "$domain_dir/subs/cname-records.txt" | while read -r line; do
                log INFO "    $line"
            done
            
            send_file_to_discord "$domain_dir/subs/cname-records.txt" "CNAME Records Found"
        else
            log WARNING "[-] No CNAME records found"
            touch "$domain_dir/subs/cname-records.txt"
        fi
    else
        log WARNING "[-] No subdomains found to check CNAME records"
        touch "$domain_dir/subs/cname-records.txt"
    fi
}

# Function to check enabled PUT Method
put_scan() {
    local domain_dir="$1"
    local output_file="$domain_dir/vulnerabilities/put-scan.txt"
    local total_hosts=0
    local vulnerable_hosts=0

    log INFO "Starting PUT method vulnerability scan"

    # Count total hosts
    total_hosts=$(wc -l < "$domain_dir/subs/live-subs.txt")
    log INFO "Scanning $total_hosts hosts for PUT method vulnerabilities"

    # Clear output file
    > "$output_file"

    # Test each host
    while IFS= read -r host; do
        local path="evil.txt"
        local test_url="${host}/${path}"
        
        # Try to upload file via PUT
        curl -s -X PUT -d "hello world" "$test_url" > /dev/null 2>&1
        
        # Check if file exists
        if curl -s -o /dev/null -w "%{http_code}" -X GET "$test_url" 2>/dev/null | grep -q "200"; then
            echo "[VULNERABLE] $host" >> "$output_file"
            ((vulnerable_hosts++))
            log SUCCESS "PUT vulnerability found: $host"
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

# Function to run subdomain takeover scanning
subdomain_takeover_scan() {
    local domain_dir="$1"
    log INFO "Subdomain Takeover Scanning"
    
    # Check if subs.txt exists
    if [[ ! -f "$domain_dir/subs/all-subs.txt" ]]; then
        log WARNING "[-] No subdomains file found at $domain_dir/subs/all-subs.txt"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/takeovers"
    
    # Run subov88r if available
    if command -v subov88r &> /dev/null; then
        log INFO "Running subov88r for Azure services check"
        subov88r -f "$domain_dir/subs/all-subs.txt" > "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" 2>> "$LOG_FILE"
    else
        log WARNING "[-] subov88r not found, skipping Azure subdomain takeover check"
    fi
    
    # Run nuclei scans
    if [[ -d "nuclei-templates" ]]; then
        log INFO "Running nuclei takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei-templates/http/takeovers/ -o "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" >> "$LOG_FILE" 2>&1
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" "Nuclei Takeover Scan Results"
        fi
    fi
    
    if [[ -d "nuclei_templates" ]]; then
        log INFO "Running custom takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/takeover/detect-all-takeover.yaml -o "$domain_dir/vulnerabilities/takeovers/custom-results.txt" >> "$LOG_FILE" 2>&1
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/custom-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/custom-results.txt" "Custom Takeover Scan Results"
        fi
    fi
    
    # Send Azure results if they exist and are not empty
    if [[ -s "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" ]]; then
        send_file_to_discord "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" "Azure Subdomain Takeover Results"
    fi
    
}

# Function to scan for JS exposures
scan_js_exposures() {
    local domain_dir="$1"
    log INFO "Starting JS Analysis"
    
    # Check if urls.txt exists
    if [[ ! -f "$domain_dir/urls/all-urls.txt" ]]; then
        log WARNING "[-] No URLs found to analyze"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/js"
        
    # Only proceed if we found JS files
    if [[ -s "$domain_dir/urls/js-urls.txt" ]]; then
        local js_count=$(wc -l < "$domain_dir/urls/js-urls.txt")
        log SUCCESS "Analyzing $js_count JavaScript files"
        
        # Initialize findings array
        local findings=()
        local files_to_send=()
        
        # 1. Find secrets using trufflehog patterns
        cat "$domain_dir/urls/js-urls.txt" | jsleak -t regexes/trufflehog-v3.yaml -s -c 20 > "$domain_dir/vulnerabilities/js/trufflehog.txt" 2>/dev/null
        local secrets_count=$(wc -l < "$domain_dir/vulnerabilities/js/trufflehog.txt" 2>/dev/null || echo 0)
        if [[ $secrets_count -gt 0 ]]; then
            findings+=("trufflehog: $secrets_count")
            files_to_send+=("$domain_dir/vulnerabilities/js/trufflehog.txt")
        fi
        
        # 2. Find links and endpoints
        cat "$domain_dir/urls/js-urls.txt" | jsleak -l -e -c 20 > "$domain_dir/vulnerabilities/js/links.txt" 2>/dev/null
        local links_count=$(wc -l < "$domain_dir/vulnerabilities/js/links.txt" 2>/dev/null || echo 0)
        if [[ $links_count -gt 0 ]]; then
            findings+=("links: $links_count")
            files_to_send+=("$domain_dir/vulnerabilities/js/links.txt")
        fi
        
        # 3. Check active URLs
        cat  "$domain_dir/urls/js-urls.txt" | jsleak -c 20 -k > "$domain_dir/vulnerabilities/js/active-urls.txt" 2>/dev/null
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
        
        for regex_file in "${regex_files[@]}"; do
            local filename=$(basename "$regex_file" .yaml)
            cat "$domain_dir/urls/js-urls.txt" | jsleak -t "$regex_file" -s -c 20 > "$domain_dir/vulnerabilities/js/$filename.txt" 2>/dev/null
            local count=$(wc -l < "$domain_dir/vulnerabilities/js/$filename.txt" 2>/dev/null || echo 0)
            if [[ $count -gt 0 ]]; then
                findings+=("$filename: $count")
                files_to_send+=("$domain_dir/vulnerabilities/js/$filename.txt")
            fi
        done
        
        # Print summary
        log SUCCESS "JS Analysis Summary:"
        for finding in "${findings[@]}"; do
            log INFO "    $finding"
        done
        
        # Send files to Discord if webhook is set
        if [[ -n "$DISCORD_WEBHOOK" && ${#files_to_send[@]} -gt 0 ]]; then
            for file in "${files_to_send[@]}"; do
                if [[ -f "$file" && -s "$file" ]]; then
                    local filename=$(basename "$file")
                    send_file_to_discord "$file" "Found Regex Matches in $filename"
                fi
            done
        fi
    else
        log WARNING "[-] No JavaScript files found to analyze"
    fi
}

# Function to run nuclei scans
run_nuclei_scans() {
    local domain_dir="$1"
    log INFO "Nuclei Scanning with severity filtering"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        nuclei -u "https://$SINGLE_SUBDOMAIN"  -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt" >> "$LOG_FILE" 2>&1
        nuclei -u "https://$SINGLE_SUBDOMAIN"  -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt" >> "$LOG_FILE" 2>&1
    else
        nuclei -l "$domain_dir/subs/live-subs.txt" -s low,medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt" >> "$LOG_FILE" 2>&1
        nuclei -l "$domain_dir/subs/live-subs.txt" -s low,medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt" >> "$LOG_FILE" 2>&1
    fi
    send_file_to_discord "$domain_dir/vulnerabilities/nuclei_templates-results.txt" "Collected Templates Nuclei Scans Results"
    send_file_to_discord "$domain_dir/vulnerabilities/nuclei-templates-results.txt" "Public Nuclei Scans Results"
}

# Function to detect technologies using httpx
# Stores results in $DOMAIN_DIR/subs/tech-detect.txt and sends to Discord
# Only runs if live-subs.txt exists and is not empty

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
    check_cname_records "$DOMAIN_DIR"
    
    # 3. Filter Live Hosts
    log INFO "Filtering live hosts"
    filter_live_hosts
    
    # 3.5 Technology Detection
    log INFO "Detecting technologies on live hosts"
    detect_technologies
    
    put_scan "$DOMAIN_DIR"

    # 4. URL Collection
    log INFO "Collecting URLs"
    fetch_urls
    
    # 5. JS File Extraction and Analysis
    log INFO "Extracting and analyzing JavaScript files"
    scan_js_exposures "$DOMAIN_DIR"
    
    # 6. Nuclei Scanning
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
    put_scan "$DOMAIN_DIR"
    subdomain_takeover_scan "$DOMAIN_DIR"
    run_port_scan
    run_nuclei_scans "$DOMAIN_DIR"
    run_ffuf
    run_gf_scans
    run_sql_injection_scan
    run_dalfox_scan
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
    put_scan "$DOMAIN_DIR"
    subdomain_takeover_scan "$DOMAIN_DIR"
    run_port_scan
    scan_js_exposures "$DOMAIN_DIR"
    run_nuclei_scans "$DOMAIN_DIR"
    run_ffuf
    run_gf_scans
    run_sql_injection_scan
    run_dalfox_scan
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
        help        Show this help message

    Examples:
        ./autoAr.sh domain -d example.com
        ./autoAr.sh subdomain -s sub.example.com
        ./autoAr.sh liteScan -d example.com
        ./autoAr.sh fastLook -d example.com
EOF
}

# Subcommand parser (should be right after all functions and config)
if [[ "$1" =~ ^(domain|subdomain|liteScan|fastLook|help|--help|-h)$ ]]; then
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
            exit 0
            ;;
        help|--help|-h)
            show_help
            exit 0
            ;;
    esac
fi

# Only run main if script is executed directly, not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # If no subcommand provided, show help
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi
    main "$@"
fi