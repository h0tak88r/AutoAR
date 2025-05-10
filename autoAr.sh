#!/bin/bash

# Add color variables at the top of the script
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
TARGET=""
SINGLE_SUBDOMAIN=""
LOG_FILE="autoAR.log"
DISCORD_WEBHOOK=""
VERBOSE=false
SKIP_PORT_SCAN=false
SKIP_FUZZING=false
SKIP_SQLI=false
SKIP_PARAMX=false
SKIP_DALFOX=false
PARAMX_TEMPLATES="paramx-templates"
DOMAIN_DIR=""
LITE_MODE=false
SAVE_TO_DB=false  # Default to false
SECURITYTRAILS_API_KEY=""  # SecurityTrails API key

# Help function
show_help() {
    cat << EOF
Usage: ./autoAr.sh [-d domain.com] [-s subdomain.domain.com] [options]

Options:
    -l, --lite              Run in lite mode (subdomains, CNAME, live hosts, URLs, JS, nuclei)
    -h, --help              Show this help message
    -d, --domain           Target domain (e.g., example.com)
    -s, --subdomain        Single subdomain to scan (e.g., sub.example.com)
    -v, --verbose          Enable verbose output
    -sp, --skip-port            Skip port scanning
    -sf, --skip-fuzzing         Skip fuzzing scans
    -ss, --skip-sqli           Skip SQL injection scanning
    -spx, --skip-paramx         Skip ParamX scanning
    -sd, --skip-dalfox         Skip Dalfox XSS scanning
    -dw, --discord-webhook     Discord webhook URL for notifications
    -st, --save-to-db          Save results to MongoDB database
    -sk, --securitytrails-key  SecurityTrails API key for additional subdomain enumeration

Examples:
    ./autoAr.sh -d example.com
    ./autoAr.sh -s sub.example.com --skip-port
    ./autoAr.sh -d example.com --skip-fuzzing --skip-sqli
    ./autoAr.sh -d example.com -l  # Run in lite mode
EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--domain)
            TARGET="$2"
            shift 2
            ;;
        -s|--subdomain)
            SINGLE_SUBDOMAIN="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -sp|--skip-port)
            SKIP_PORT_SCAN=true
            shift
            ;;
        -sf|--skip-fuzzing)
            SKIP_FUZZING=true
            shift
            ;;
        -ss|--skip-sqli)
            SKIP_SQLI=true
            shift
            ;;
        -spx|--skip-paramx)
            SKIP_PARAMX=true
            shift
            ;;
        -sd|--skip-dalfox)
            SKIP_DALFOX=true
            shift
            ;;
        -dw|--discord-webhook)
            DISCORD_WEBHOOK="$2"
            shift 2
            ;;
        -l|--lite)
            LITE_MODE=true
            shift
            ;;
        -st|--save-to-db)
            SAVE_TO_DB=true
            shift
            ;;
        -sk|--securitytrails-key)
            SECURITYTRAILS_API_KEY="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validate input
if [[ -z "$TARGET" ]] && [[ -z "$SINGLE_SUBDOMAIN" ]]; then
    log ERROR "Error: Must specify either -d (domain) or -s (subdomain)"
    show_help
    exit 1
fi

if [[ -n "$TARGET" ]] && [[ -n "$SINGLE_SUBDOMAIN" ]]; then
    log ERROR "Error: Cannot specify both domain and subdomain. Choose one."
    show_help
    exit 1
fi

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

# Function to check and clone repositories if they do not exist
check_and_clone() {
    local dir="$1"
    local repo_url="$2"
    if [[ ! -d "$dir" ]]; then
        log ERROR "Error: $dir directory not found."
        log ERROR "To clone $dir, run:"
        log ERROR "git clone $repo_url"
        exit 1
    fi
}

# Function to check if required tools are installed
check_tools() {
    local tools=("subfinder" "httpx" "naabu" "nuclei" "ffuf" "kxss" "qsreplace" "paramx" "dalfox" "urlfinder" "interlace" "jsleak" "jsfinder")
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
    mkdir -p "$DOMAIN_DIR"/{subs,urls,vulnerabilities/{xss,sqli,ssrf,ssti,lfi,rce,idor},fuzzing,ports}
    
    # Create initial empty files
    touch "$DOMAIN_DIR/urls/live.txt"
    touch "$DOMAIN_DIR/urls/all-urls.txt"
    touch "$DOMAIN_DIR/ports/ports.txt"
    touch "$DOMAIN_DIR/vulnerabilities/put-scan.txt"
    touch "$DOMAIN_DIR/fuzzing/ffufGet.txt"
    touch "$DOMAIN_DIR/fuzzing/ffufPost.txt"
    touch "$DOMAIN_DIR/subs/all-subs.txt"
    touch "$DOMAIN_DIR/subs/apis-subs.txt"
    touch "$DOMAIN_DIR/subs/subfinder-subs.txt"
    
    log SUCCESS "Created fresh directory structure at $DOMAIN_DIR"
}

# Function to run fuzzing with ffuf
run_ffuf() {
    log INFO "Fuzzing with ffuf"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        ffuf -u "https://$SINGLE_SUBDOMAIN/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique > "$DOMAIN_DIR/fuzzing/ffuf.html"
        ffuf -u "https://$SINGLE_SUBDOMAIN/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique -X POST > "$DOMAIN_DIR/fuzzing/ffuf-post.html"
        send_file_to_discord "$DOMAIN_DIRR/fuzzing/ffuf.html" "ffuf GET Fuzz Results"
        send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf-post.html" "ffuf POST Fuzz Results"
    else
        while IFS= read -r url; do
            log INFO "Fuzzing $url with ffuf"
            ffuf -u "$url/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique > "$DOMAIN_DIR/fuzzing/ffuf.html"
            ffuf -u "$url/FUZZ" -w "$FUZZ_WORDLIST" -fc 403,404,400,402,401 -unique -X POST > "$DOMAIN_DIR/fuzzing/ffuf-post.html"
            send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf.html" "ffuf GET Fuzz Results for $url"
            send_file_to_discord "$DOMAIN_DIR/fuzzing/ffuf-post.html" "ffuf POST Fuzz Results for $url"
        done < "$DOMAIN_DIR/subs/live-subs.txt"
    fi
}

# Function to run SQL injection scanning with sqlmap
run_sql_injection_scan() {
    log INFO "SQL Injection Scanning with sqlmap"
    interlace -tL "$DOMAIN_DIR/gf-sqli.txt" -threads 5 -c "sqlmap -u _target_ --batch --dbs --random-agent >> '$DOMAIN_DIR/sqlmap-sqli.txt'"
    send_file_to_discord "$DOMAIN_DIR/sqlmap-sqli.txt" "SQL Injection Scan Results"
}

# Function to run reflection scanning
run_reflection_scan() {
    log INFO "Reflection Scanning"
    kxss < "$DOMAIN_DIR/urls/all-urls.txt" | tee "$DOMAIN_DIR/vulnerabilities/kxss-results.txt"
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
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://certspotter.com/api/v0/certs?domain=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://crt.sh/?q=%.$domain&output=json" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> "$tmp_file"
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> "$tmp_file"
    
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
        subfinder -d "$domain" -all -silent -o "$DOMAIN_DIR/subs/subfinder-subs.txt"
    else
        log WARNING "[-] subfinder not found, skipping subfinder enumeration"
    fi
    
    # Combine and sort all results
    cat "$DOMAIN_DIR/subs/subfinder-subs.txt" "$DOMAIN_DIR/subs/apis-subs.txt" 2>/dev/null | grep -v "*" | sort -u > "$DOMAIN_DIR/subs/all-subs.txt"
    
    # Count results
    local total_subs=$(wc -l < "$DOMAIN_DIR/subs/all-subs.txt")
    log SUCCESS "Found $total_subs unique subdomains"
    
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        log SUCCESS "Subdomain Enumeration completed. Results saved in $DOMAIN_DIR/subs/all-subs.txt"
        send_file_to_discord "$DOMAIN_DIR/subs/all-subs.txt" "Subdomain Enumeration completed - Found $total_subs subdomains"
    else
        log WARNING "[-] No subdomains found for $domain"
    fi
}

# Function to fetch URLs
fetch_urls() {
    log INFO "Fetching URLs using URLFinder and JSFinder"
    
    # Ensure urls directory exists
    mkdir -p "$DOMAIN_DIR/urls"
    
    # Initialize/clear files
    > "$DOMAIN_DIR/urls/all-urls.txt"
    > "$DOMAIN_DIR/urls/js-urls.txt"
    
    # 1. First collect URLs using urlfinder (redirect both stdout and stderr to /dev/null)
    log INFO "Running URLFinder for initial URL collection"
    urlfinder -d "$TARGET" -all -silent -o "$DOMAIN_DIR/urls/all-urls.txt" >/dev/null 2>&1
    
    # 2. Run JSFinder on live subdomains to find JS files and endpoints
    if [[ -s "$DOMAIN_DIR/subs/live-subs.txt" ]]; then
        log INFO "Running JSFinder on live subdomains"
        jsfinder -l "$DOMAIN_DIR/subs/live-subs.txt" -c 50 -s -o "$DOMAIN_DIR/urls/js-urls.txt"
        
        # Merge results and remove duplicates
        if [[ -s "$DOMAIN_DIR/urls/js-urls.txt" ]]; then
            cat "$DOMAIN_DIR/urls/js-urls.txt" >> "$DOMAIN_DIR/urls/all-urls.txt"
            sort -u -o "$DOMAIN_DIR/urls/all-urls.txt" "$DOMAIN_DIR/urls/all-urls.txt"
            
            # Count URLs
            local js_urls=$(wc -l < "$DOMAIN_DIR/urls/js-urls.txt")
            log SUCCESS "Found $js_urls JavaScript files/endpoints using JSFinder"
        fi
    fi
    
    # Count total unique URLs
    if [[ -s "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        local total_urls=$(wc -l < "$DOMAIN_DIR/urls/all-urls.txt")
        log SUCCESS "Found $total_urls total unique URLs"
        
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$DOMAIN_DIR/urls/all-urls.txt" "Found $total_urls unique URLs"
            if [[ -s "$DOMAIN_DIR/urls/js-urls.txt" ]]; then
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
        cat "$DOMAIN_DIR/subs/all-subs.txt" | httpx -silent -mc 200,201,301,302,403 -o "$DOMAIN_DIR/subs/live-subs.txt"
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
    if [[ -s "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
        naabu -l "$DOMAIN_DIR/subs/all-subs.txt" -p - -o "$DOMAIN_DIR/ports/ports.txt"
        if [[ -s "$DOMAIN_DIR/ports/ports.txt" ]]; then
            send_file_to_discord "$DOMAIN_DIR/ports/ports.txt" "Port Scan Results"
        else
            log WARNING "[-] No open ports found"
        fi
    else
        log WARNING "[-] No subdomains found to scan ports"
    fi
}

# Function to run ParamX scans
run_paramx_scans() {
    log INFO "Running ParamX scans for different vulnerability patterns"
    
    # Create vulnerabilities directory if it doesn't exist
    mkdir -p "$DOMAIN_DIR/vulnerabilities"
    
    # Define vulnerability patterns to scan for
    local patterns=("xss" "sqli" "lfi" "rce" "idor" "ssrf" "ssti" "redirect")
    
    # Check if we have URLs to scan
    if [[ ! -f "$DOMAIN_DIR/urls/all-urls.txt" ]]; then
        log WARNING "[!] No URLs found to scan"
        return
    fi
    
    # Scan for each vulnerability pattern
    for pattern in "${patterns[@]}"; do
        # Create directory for this vulnerability type
        mkdir -p "$DOMAIN_DIR/vulnerabilities/$pattern"
        
        log INFO "  [*] Scanning for $pattern parameters"
        cat "$DOMAIN_DIR/urls/all-urls.txt" | paramx -tp "$PARAMX_TEMPLATES" -tag "$pattern" -o "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt"
        
        # Check if we found any parameters
        if [[ -s "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt" ]]; then
            local count=$(wc -l < "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt")
            log SUCCESS "  [+] Found $count potential $pattern parameters"
            
            if [[ -n "$DISCORD_WEBHOOK" ]]; then
                send_file_to_discord "$DOMAIN_DIR/vulnerabilities/$pattern/paramx-results.txt" "Found $count potential $pattern parameters"
            fi
        fi
    done
}

# Function to check and setup paramx templates
setup_paramx_templates() {
    # Check if templates directory exists
    if [[ ! -d "$PARAMX_TEMPLATES" ]]; then
        log INFO "Creating ParamX templates directory"
        mkdir -p "$PARAMX_TEMPLATES"
        
        # Clone default templates if directory is empty
        if [[ -z "$(ls -A "$PARAMX_TEMPLATES")" ]]; then
            log INFO "Cloning default ParamX templates"
            git clone https://github.com/cyinnove/paramx-templates.git tmp_templates
            cp -r tmp_templates/* "$PARAMX_TEMPLATES/"
            rm -rf tmp_templates
        fi
    fi
    
    # Verify templates exist
    if [[ -z "$(ls -A "$PARAMX_TEMPLATES")" ]]; then
        log ERROR "Error: No ParamX templates found in $PARAMX_TEMPLATES"
        log ERROR "Please add your templates to this directory or use -t to specify a different directory"
        exit 1
    fi
    
    log SUCCESS "Using ParamX templates from: $PARAMX_TEMPLATES"
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
    log INFO "Checking for PUT method"
    while IFS= read -r host; do
        local path="evil.txt"
        curl -s -X PUT -d "hello world" "${host}/${path}" > /dev/null
        if curl -s -o /dev/null -w "%{http_code}" -X GET "${host}/${path}" | grep -q "200"; then
            echo "$host" >> "$domain_dir/vulnerabilities/put-scan.txt"
        fi
    done < "$domain_dir/subs/live-subs.txt"
    send_file_to_discord "$domain_dir/vulnerabilities/put-scan.txt" "PUT Scan results"
    log SUCCESS "PUT Method scan completed"
}

# Function to run Dalfox scans
run_dalfox_scan() {
    log INFO "Dalfox Scanning"
    dalfox file "$DOMAIN_DIR/gf-xss.txt" --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav -b "XSS Server here" -w 50 -o "$DOMAIN_DIR/dalfox-results.txt"
    send_file_to_discord "$DOMAIN_DIR/dalfox-results.txt" "Dalfox XSS Scan Results"
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
        subov88r -f "$domain_dir/subs/all-subs.txt" -o "$domain_dir/vulnerabilities/takeovers/azureSDT.txt"
    else
        log WARNING "[-] subov88r not found, skipping Azure subdomain takeover check"
    fi
    
    # Run nuclei scans
    if [[ -d "nuclei_templates" ]]; then
        log INFO "Running nuclei takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/http/takeovers/ -o "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt"
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" "Nuclei Takeover Scan Results"
        fi
    fi
    
    if [[ -d "nuclei_templates" ]]; then
        log INFO "Running custom takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/takeover/detect-all-takeover.yaml -o "$domain_dir/vulnerabilities/takeovers/custom-results.txt"
        
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
    
    # Extract JS URLs from all collected URLs
    grep -i "\.js" "$domain_dir/urls/all-urls.txt" > "$domain_dir/vulnerabilities/js/js-urls.txt"
    
    # Only proceed if we found JS files
    if [[ -s "$domain_dir/vulnerabilities/js/js-urls.txt" ]]; then
        local js_count=$(wc -l < "$domain_dir/vulnerabilities/js/js-urls.txt")
        log SUCCESS "Analyzing $js_count JavaScript files"
        
        # Initialize findings array
        local findings=()
        local files_to_send=()
        
        # 1. Find secrets using trufflehog patterns
        cat "$domain_dir/vulnerabilities/js/js-urls.txt" | jsleak -t regexes/trufflehog-v3.yaml -s -c 20 > "$domain_dir/vulnerabilities/js/trufflehog.txt" 2>/dev/null
        local secrets_count=$(wc -l < "$domain_dir/vulnerabilities/js/trufflehog.txt" 2>/dev/null || echo 0)
        if [[ $secrets_count -gt 0 ]]; then
            findings+=("trufflehog: $secrets_count")
            files_to_send+=("$domain_dir/vulnerabilities/js/trufflehog.txt")
        fi
        
        # 2. Find links and endpoints
        cat "$domain_dir/vulnerabilities/js/js-urls.txt" | jsleak -l -e -c 20 > "$domain_dir/vulnerabilities/js/links.txt" 2>/dev/null
        local links_count=$(wc -l < "$domain_dir/vulnerabilities/js/links.txt" 2>/dev/null || echo 0)
        if [[ $links_count -gt 0 ]]; then
            findings+=("links: $links_count")
            files_to_send+=("$domain_dir/vulnerabilities/js/links.txt")
        fi
        
        # 3. Check active URLs
        cat "$domain_dir/vulnerabilities/js/links.txt" | jsleak -c 20 -k > "$domain_dir/vulnerabilities/js/active-urls.txt" 2>/dev/null
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
            cat "$domain_dir/vulnerabilities/js/js-urls.txt" | jsleak -t "$regex_file" -s -c 20 > "$domain_dir/vulnerabilities/js/$filename.txt" 2>/dev/null
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
    log INFO "Nuclei Scanning with severity filtering (medium,high,critical)"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        nuclei -u "https://$SINGLE_SUBDOMAIN" -s medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt"
        nuclei -u "https://$SINGLE_SUBDOMAIN" -s medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt"
    else
        nuclei -l "$domain_dir/subs/live-subs.txt" -s medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt"
        nuclei -l "$domain_dir/subs/live-subs.txt" -s medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt"
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
        httpx -l "$DOMAIN_DIR/subs/live-subs.txt" -tech-detect -title -status-code -server -silent -o "$tech_file"
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
    
    # Create initial URL list and discover URLs
    mkdir -p "$DOMAIN_DIR/urls"
    echo "https://$subdomain" > "$DOMAIN_DIR/urls/live.txt"
    echo "http://$subdomain" >> "$DOMAIN_DIR/urls/live.txt"
    
    # Use urlfinder to discover URLs
    log INFO "Running urlfinder on subdomain"
    urlfinder -d "$subdomain" -all -silent -o "$DOMAIN_DIR/urls/all-urls.txt"
    
    # Check CNAME records
    check_cname_records "$DOMAIN_DIR"
    
    # Filter live hosts (simulate for single subdomain)
    echo "$subdomain" > "$DOMAIN_DIR/subs/live-subs.txt"
    
    # Technology detection
    detect_technologies
    
    put_scan "$DOMAIN_DIR"
    scan_js_exposures "$DOMAIN_DIR"
    run_nuclei_scans "$DOMAIN_DIR"

    # Run focused scans
    if [[ "$SKIP_FUZZING" != "true" ]]; then
        run_ffuf
    fi
    
    if [[ "$SKIP_SQLI" != "true" ]]; then
        run_sql_injection_scan
    fi
    
    if [[ "$SKIP_DALFOX" != "true" ]]; then
        run_dalfox_scan
    fi
}

# Function to scan entire domain
scan_domain() {
    local domain="$1"
    log INFO "Running scans on domain: $domain"
    
    # Initial domain reconnaissance
    subEnum "$domain"
    fetch_urls
    filter_live_hosts
    
    # Technology detection
    detect_technologies
    
    # Check CNAME records
    check_cname_records "$DOMAIN_DIR"
    
    # Create vulnerabilities directory
    mkdir -p "$DOMAIN_DIR/vulnerabilities"
    
    put_scan "$DOMAIN_DIR"
    subdomain_takeover_scan "$DOMAIN_DIR"
    scan_js_exposures "$DOMAIN_DIR"
    
    # Run port scan if not skipped
    if [[ "$SKIP_PORT_SCAN" != "true" ]]; then
        log INFO "[+] Port scanning enabled"
        run_port_scan
    else
        log WARNING "[-] Port scanning disabled"
    fi
    
    # Run security scans
    if [[ "$SKIP_FUZZING" != "true" ]]; then
        run_ffuf
    fi
    
    if [[ "$SKIP_SQLI" != "true" ]]; then
        run_sql_injection_scan
    fi
    
    if [[ "$SKIP_DALFOX" != "true" ]]; then
        run_dalfox_scan
    else
        log WARNING "[-] Dalfox scanning disabled"
    fi
}

# Function to save all discovered subdomains to MongoDB
save_subdomains_to_mongodb() {
    if [[ "$SAVE_TO_DB" != "true" ]]; then
        return
    fi

    log INFO "Saving results to MongoDB database"
    
    # If scanning a full domain
    if [[ -n "$TARGET" && -z "$SINGLE_SUBDOMAIN" ]]; then
        if [[ -f "$DOMAIN_DIR/subs/all-subs.txt" ]]; then
            log INFO "Adding subdomains to database for $TARGET"
            ./mongo_db_handler.py add_subdomains_file "$TARGET" "$DOMAIN_DIR/subs/all-subs.txt"
        fi
    # If scanning a single subdomain
    elif [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        local domain=$(echo "$SINGLE_SUBDOMAIN" | awk -F. '{print $(NF-1)"."$NF}')
        if [[ -n "$domain" ]]; then
            log INFO "Adding single subdomain to database"
            ./mongo_db_handler.py add_subdomain "$domain" "$SINGLE_SUBDOMAIN"
        fi
    fi
}

# Main function
main() {
    # Check required tools first
    check_tools
    
    # Validate input
    if [[ -z "$TARGET" ]] && [[ -z "$SINGLE_SUBDOMAIN" ]]; then
        log ERROR "Error: Must specify either -d (domain) or -s (subdomain)"
        show_help
        exit 1
    fi
    
    if [[ -n "$TARGET" ]] && [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        log ERROR "Error: Cannot specify both domain and subdomain. Choose one."
        show_help
        exit 1
    fi
    
    # Setup results directory and structure
    setup_results_dir
    
    # Clone required repositories if they don't exist
    if [[ ! -d "$WORDLIST_DIR" ]]; then
        log INFO "[+] Cloning wordlists repository..."
        git clone https://github.com/h0tak88r/Wordlists.git "$WORDLIST_DIR"
    fi
    
    if [[ ! -d "nuclei_templates" ]]; then
        log INFO "[+] Cloning nuclei templates..."
        git clone https://github.com/h0tak88r/nuclei_templates.git
    fi
    
    # Setup ParamX templates if not skipping
    if [[ "$SKIP_PARAMX" != "true" ]]; then
        setup_paramx_templates
    fi
    
    # Execute appropriate scan based on input and mode
    if [[ "$LITE_MODE" == "true" ]]; then
        if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
            log ERROR "Error: Lite mode is not supported for single subdomain scanning"
            exit 1
        fi
        lite_scan "$TARGET"
    else
        if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
            scan_single_subdomain "$SINGLE_SUBDOMAIN"
        else
            scan_domain "$TARGET"
        fi
    fi
    
    # Final reporting
    log SUCCESS "All scans completed successfully!"
    log SUCCESS "Results are saved in: $DOMAIN_DIR"
    
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        send_to_discord "🎉 AutoAR scan completed! Check $DOMAIN_DIR for detailed findings."
    fi

    # Save subdomains to database before exiting (for both domain and subdomain scans)
    save_subdomains_to_mongodb
}

main