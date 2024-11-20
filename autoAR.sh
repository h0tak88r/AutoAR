#!/bin/bash

# autoAR Logo
printf "==============================\n"
printf "  

              _          _    ____  
   __ _ _   _| |_ ___   / \  |  _ \ 
  / _` | | | | __/ _ \ / _ \ | |_) |
 | (_| | |_| | || (_) / ___ \|  _ < 
  \__,_|\__,_|\__\___/_/   \_\_| \_\
                                    
==============================\n"

# Constants
RESULTS_DIR="results"
WORDLIST_DIR="Wordlists"
FUZZ_WORDLIST="$WORDLIST_DIR/h0tak88r_fuzz.txt"
TARGET=""
DOMAIN_LIST=""
SINGLE_SUBDOMAIN=""
LOG_FILE="autoAR.log"
DISCORD_WEBHOOK=""
VERBOSE=false
SKIP_PORT_SCAN=false
SKIP_FUZZING=false
SKIP_SQLI=false
SKIP_PARAMX=false
PARAMX_TEMPLATES="paramx-templates"

# Help function
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
    -d DOMAIN         Single target domain
    -l FILE          File containing list of domains
    -s SUBDOMAIN     Single subdomain to scan
    -w WEBHOOK       Discord webhook URL for notifications
    -o DIR          Output directory (default: results)
    -t DIR          ParamX templates directory (default: paramx-templates)
    -v              Verbose output
    --skip-ports    Skip port scanning
    --skip-fuzz     Skip fuzzing
    --skip-sqli     Skip SQL injection scanning
    --skip-paramx   Skip ParamX scanning
    -h              Show this help message

Example:
    $(basename "$0") -d example.com
    $(basename "$0") -l domains.txt -w https://discord.webhook.url
    $(basename "$0") -d example.com -s sub.example.com --skip-ports --skip-sqli
    $(basename "$0") -d example.com -t /path/to/paramx/templates
EOF
    exit 1
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) TARGET="$2"; shift 2 ;;
        -l) DOMAIN_LIST="$2"; shift 2 ;;
        -s) SINGLE_SUBDOMAIN="$2"; shift 2 ;;
        -w) DISCORD_WEBHOOK="$2"; shift 2 ;;
        -o) RESULTS_DIR="$2"; shift 2 ;;
        -t) PARAMX_TEMPLATES="$2"; shift 2 ;;
        -v) VERBOSE=true; shift ;;
        --skip-ports) SKIP_PORT_SCAN=true; shift ;;
        --skip-fuzz) SKIP_FUZZING=true; shift ;;
        --skip-sqli) SKIP_SQLI=true; shift ;;
        --skip-paramx) SKIP_PARAMX=true; shift ;;
        -h) show_help ;;
        *) printf "Unknown option: %s\n" "$1"; show_help ;;
    esac
done

# Validate input
if [[ -z "$TARGET" ]] && [[ -z "$DOMAIN_LIST" ]]; then
    printf "Error: Either -d or -l option must be specified\n"
    show_help
fi

if [[ -n "$DOMAIN_LIST" ]] && [[ ! -f "$DOMAIN_LIST" ]]; then
    printf "Error: Domain list file '%s' not found\n" "$DOMAIN_LIST"
    exit 1
fi

# Function to log messages
log() {
    local message="$1"
    printf "%s\n" "$message"
    printf "%s\n" "$message" >> "$LOG_FILE"
    
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        send_to_discord "$message"
    fi
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
            log "Discord webhook not provided, skipping file upload."
        fi
    else
        log "Error: File $file does not exist."
    fi
}

# Function to check and clone repositories if they do not exist
check_and_clone() {
    local dir="$1"
    local repo_url="$2"
    if [[ ! -d "$dir" ]]; then
        log "Error: $dir directory not found."
        log "To clone $dir, run:"
        log "git clone $repo_url"
        exit 1
    fi
}

# Function to check if required tools are installed
check_tools() {
    local tools=("subfinder" "httpx" "waymore" "subov88r" "nuclei" "naabu" "kxss" "qsreplace" "paramx" "dalfox" "ffuf" "interlace" "urldedupe")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log "Error: $tool is not installed."
            if [[ "$tool" == "paramx" ]]; then
                log "To install paramx, run: go install github.com/cyinnove/paramx/cmd/paramx@latest"
            fi
            exit 1
        fi
    done
}

# Function to setup results directory for a domain
setup_domain_dir() {
    local domain="$1"
    local domain_dir="$RESULTS_DIR/$domain"
    
    # Create directory structure
    mkdir -p "$domain_dir"/{subs,urls,vulnerabilities/{xss,sqli,ssrf,ssti,lfi,rce,idor},fuzzing,ports}
    
    # Return the domain directory path
    echo "$domain_dir"
}

# Function to remove and create results directory
setup_results_dir() {
    # Create results directory if it doesn't exist
    mkdir -p "$RESULTS_DIR"
    
    # If a domain is specified, clean only that domain's directory
    if [[ -n "$TARGET" ]]; then
        local domain_dir=$(setup_domain_dir "$TARGET")
        if [[ -d "$domain_dir" ]]; then
            log "[+] Cleaning previous results for domain $TARGET"
            rm -rf "$domain_dir"
        fi
    fi
}

# Function to check and setup paramx templates
setup_paramx_templates() {
    # Check if templates directory exists
    if [[ ! -d "$PARAMX_TEMPLATES" ]]; then
        log "[+] Creating ParamX templates directory"
        mkdir -p "$PARAMX_TEMPLATES"
        
        # Clone default templates if directory is empty
        if [[ -z "$(ls -A "$PARAMX_TEMPLATES")" ]]; then
            log "[+] Cloning default ParamX templates"
            git clone https://github.com/cyinnove/paramx-templates.git tmp_templates
            cp -r tmp_templates/* "$PARAMX_TEMPLATES/"
            rm -rf tmp_templates
        fi
    fi
    
    # Verify templates exist
    if [[ -z "$(ls -A "$PARAMX_TEMPLATES")" ]]; then
        log "Error: No ParamX templates found in $PARAMX_TEMPLATES"
        log "Please add your templates to this directory or use -t to specify a different directory"
        exit 1
    fi
    
    log "[+] Using ParamX templates from: $PARAMX_TEMPLATES"
}

# Function to run subdomain enumeration
subEnum() {
    local domain="$1"
    local domain_dir="$2"
    
    log "[+] Subdomain Enumeration using SubFinder and free API Sources"
    #--------------------------------------------------------------------------------------------------------------------
    curl --silent "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    curl --silent "https://crt.sh/?q=%.$domain" | grep -oP "\<TD\>\K.*\.$domain" | sed -e 's/\<BR\>/\n/g' | grep -oP "\K.*\.$domain" | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$domain"  >> tmp.txt
    curl --silent "https://crt.sh/?q=%.%.$domain" | grep -oP "\<TD\>\K.*\.$domain" | sed -e 's/\<BR\>/\n/g' | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    curl --silent "https://crt.sh/?q=%.%.%.$domain" | grep "$domain" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$domain" | sort -u >> tmp.txt
    curl --silent "https://crt.sh/?q=%.%.%.%.$domain" | grep "$domain" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$domain" |  sort -u >> tmp.txt
    curl --silent "https://spyse.2com/target/domain/$domain" | grep -E -o "button.*>.*\.$domain\/button>" |  grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    curl 'https://tls.bufferover.run/dns?q=.google.com' -H 'x-api-key: lx6FXQo1sd54gAIBWnwlWa8WR4rgzCyR87LBlV6l' -X POST | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    curl --silent "https://urlscan.io/api/v1/search/?q=$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    curl --silent -X POST "https://synapsint.com/report.php" -d "name=http%3A%2F%2F$domain" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    curl --silent "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> tmp.txt
    curl --silent "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | grep -o -E "[a-zA-Z0-9._-]+\.$domain" >> tmp.txt
    #--------------------------------------------------------------------------------------------------------------------
    sed -e "s/\*\.$domain//g" -e "s/^\..*//g" tmp.txt | grep -o -E "[a-zA-Z0-9._-]+\.$domain" | sort -u > "$domain_dir/subs/apis-subs.txt"
    rm tmp.txt 
    subfinder -d "$domain" --all -silent -o "$domain_dir/subs/subfinder-subs.txt"
    sort -u "$domain_dir/subs/subfinder-subs.txt" "$domain_dir/subs/apis-subs.txt" | grep -v "*" | sort -u > "$domain_dir/subs/all-subs.txt"
    log "Subdomain Enumeration completed. Results saved in $domain_dir/subs/all-subs.txt"
    send_file_to_discord "$domain_dir/subs/all-subs.txt" "Subdomain Enumeration completed"
}

# Function to fetch URLs
fetch_urls() {
    local domain_dir="$1"
    local target="${SINGLE_SUBDOMAIN:-$TARGET}"
    
    log "[+] Fetching URLs using URLFinder"
    mkdir -p "$domain_dir/urls"
    
    # Run URLFinder with all sources and proper filtering
    if [[ -n "$VERBOSE" ]]; then
        urlfinder -d "$target" -all -s alienvault,commoncrawl,waybackarchive,urlscan -v -o "$domain_dir/urls/all-urls.txt"
    else
        urlfinder -d "$target" -all -s alienvault,commoncrawl,waybackarchive,urlscan -silent -o "$domain_dir/urls/all-urls.txt"
    fi
    
    # Check if we found any URLs
    if [[ -f "$domain_dir/urls/all-urls.txt" && -s "$domain_dir/urls/all-urls.txt" ]]; then
        # Filter live URLs
        cat "$domain_dir/urls/all-urls.txt" | httpx -silent -mc 200,201,301,302,403 -o "$domain_dir/urls/live.txt"
        
        # Count URLs
        local total_urls=$(wc -l < "$domain_dir/urls/all-urls.txt")
        local live_urls=$(wc -l < "$domain_dir/urls/live.txt")
        log "[+] Found $total_urls unique URLs ($live_urls live)"
        
        if [[ -n "$DISCORD_WEBHOOK" ]]; then
            send_file_to_discord "$domain_dir/urls/live.txt" "Found $live_urls live URLs"
        fi
    else
        log "[!] No URLs found for $target"
    fi
}

# Function to filter live hosts
filter_live_hosts() {
    local domain_dir="$1"
    log "[+] Filtering live hosts"
    cat "$domain_dir/subs/all-subs.txt" | httpx -silent -o "$domain_dir/urls/live.txt"
    send_file_to_discord "$domain_dir/urls/live.txt" "Live Hosts"
}

# Function to run port scanning
run_port_scan() {
    local domain_dir="$1"
    log "[+] Port Scanning with naabu"
    naabu -l "$domain_dir/subs/all-subs.txt" -p - -o "$domain_dir/ports/ports.txt"
    send_file_to_discord "$domain_dir/ports/ports.txt" "Port Scan Results"
}

# Function to run ParamX scans
run_paramx_scans() {
    local domain_dir="$1"
    log "[+] Running ParamX scans for different vulnerability patterns"
    
    # Create vulnerabilities directory if it doesn't exist
    mkdir -p "$domain_dir/vulnerabilities"
    
    # Define vulnerability patterns to scan for
    local patterns=("xss" "sqli" "lfi" "rce" "idor" "ssrf" "ssti" "redirect")
    
    # Check if we have URLs to scan
    if [[ ! -f "$domain_dir/urls/all-urls.txt" ]]; then
        log "[!] No URLs found to scan"
        return
    fi
    
    # Scan for each vulnerability pattern
    for pattern in "${patterns[@]}"; do
        # Create directory for this vulnerability type
        mkdir -p "$domain_dir/vulnerabilities/$pattern"
        
        log "  [*] Scanning for $pattern parameters"
        cat "$domain_dir/urls/all-urls.txt" | paramx -tp "$PARAMX_TEMPLATES" -tag "$pattern" > "$domain_dir/vulnerabilities/$pattern/paramx-results.txt"
        
        # Check if we found any parameters
        if [[ -s "$domain_dir/vulnerabilities/$pattern/paramx-results.txt" ]]; then
            local count=$(wc -l < "$domain_dir/vulnerabilities/$pattern/paramx-results.txt")
            log "  [+] Found $count potential $pattern parameters"
            
            if [[ -n "$DISCORD_WEBHOOK" ]]; then
                send_file_to_discord "$domain_dir/vulnerabilities/$pattern/paramx-results.txt" "Found $count potential $pattern parameters"
            fi
        fi
    done
}

# Function to run fuzzing with ffuf
run_ffuf() {
    local domain_dir="$1"
    log "[+] Directory Fuzzing with ffuf"
    while IFS= read -r domain; do
        ffuf -w "$FUZZ_WORDLIST" -u "https://$domain/FUZZ" -mc 200,204,301,302,307,401,403,405 -o "$domain_dir/fuzzing/$domain.json"
    done < "$domain_dir/urls/live.txt"
    send_file_to_discord "$domain_dir/fuzzing" "Fuzzing Results"
}

# Function to process single domain
process_domain() {
    local domain="$1"
    log "Processing domain: $domain"
    
    # Setup domain-specific directory
    local domain_dir=$(setup_domain_dir "$domain")
    
    # Run all scans for this domain
    TARGET="$domain"
    subEnum "$domain" "$domain_dir"
    fetch_urls "$domain_dir"
    filter_live_hosts "$domain_dir"
    
    if [[ "$SKIP_PORT_SCAN" != "true" ]]; then
        run_port_scan "$domain_dir"
    fi

    # Run security scans
    put_scan "$domain_dir"
    run_nuclei_scans "$domain_dir"
    
    if [[ "$SKIP_PARAMX" == false ]]; then
        run_paramx_scans "$domain_dir"
    fi
    
    if [[ "$SKIP_FUZZING" != "true" ]]; then
        run_ffuf "$domain_dir"
    fi
    
    # Run these scans after we have gathered all subdomains and URLs
    subdomain_takeover_scan "$domain_dir"
    scan_js_exposures "$domain_dir"
    
    log "Completed scanning domain: $domain"
    log "Results are saved in: $domain_dir"
}

# Function to check enabled PUT Method
put_scan() {
    local domain_dir="$1"
    log "[+] Checking for PUT method"
    while IFS= read -r host; do
        curl -s -o /dev/null -w "URL: %{url_effective} - Response: %{response_code}\n" -X PUT -d "hello world" "${host}/evil.txt" | tee -a "$domain_dir/vulnerabilities/put-scan.txt"
    done < "$domain_dir/urls/live.txt"
    send_file_to_discord "$domain_dir/vulnerabilities/put-scan.txt" "PUT Scan results"
}

# Function to run subdomain takeover scanning
subdomain_takeover_scan() {
    local domain_dir="$1"
    log "[+] Subdomain Takeover Scanning"
    
    # Check if subs.txt exists
    if [[ ! -f "$domain_dir/subs/all-subs.txt" ]]; then
        log "[-] No subdomains file found at $domain_dir/subs/all-subs.txt"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/takeovers"
    
    # Run subov88r if available
    if command -v subov88r &> /dev/null; then
        log "[+] Running subov88r for Azure services check"
        subov88r -f "$domain_dir/subs/all-subs.txt" | grep -E 'cloudapp.net|azurewebsites.net|cloudapp.azure.com' > "$domain_dir/vulnerabilities/takeovers/azureSDT.txt"
    else
        log "[-] subov88r not found, skipping Azure subdomain takeover check"
    fi
    
    # Run nuclei scans
    if [[ -d "nuclei-templates" ]]; then
        log "[+] Running nuclei takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei-templates/http/takeovers/ -o "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt"
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" "Nuclei Takeover Scan Results"
        fi
    fi
    
    if [[ -d "nuclei_templates" ]]; then
        log "[+] Running custom takeover templates"
        nuclei -l "$domain_dir/subs/all-subs.txt" -t nuclei_templates/takeover/detect-all-takeover.yaml -o "$domain_dir/vulnerabilities/takeovers/custom-results.txt"
        
        if [[ -s "$domain_dir/vulnerabilities/takeovers/custom-results.txt" ]]; then
            send_file_to_discord "$domain_dir/vulnerabilities/takeovers/custom-results.txt" "Custom Takeover Scan Results"
        fi
    fi
    
    # Send Azure results if they exist and are not empty
    if [[ -s "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" ]]; then
        send_file_to_discord "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" "Azure Subdomain Takeover Results"
    fi
    
    # Create a summary of all findings
    {
        echo "=== Subdomain Takeover Scan Summary ==="
        echo "Time: $(date)"
        echo
        echo "=== Azure Services ==="
        if [[ -s "$domain_dir/vulnerabilities/takeovers/azureSDT.txt" ]]; then
            cat "$domain_dir/vulnerabilities/takeovers/azureSDT.txt"
        else
            echo "No Azure services found"
        fi
        echo
        echo "=== Nuclei Takeover Results ==="
        if [[ -s "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt" ]]; then
            cat "$domain_dir/vulnerabilities/takeovers/nuclei-results.txt"
        else
            echo "No findings from nuclei takeover templates"
        fi
        echo
        echo "=== Custom Takeover Results ==="
        if [[ -s "$domain_dir/vulnerabilities/takeovers/custom-results.txt" ]]; then
            cat "$domain_dir/vulnerabilities/takeovers/custom-results.txt"
        else
            echo "No findings from custom takeover templates"
        fi
    } > "$domain_dir/vulnerabilities/takeovers/summary.txt"
    
    send_file_to_discord "$domain_dir/vulnerabilities/takeovers/summary.txt" "Subdomain Takeover Summary"
}

# Function to scan for JS exposures
scan_js_exposures() {
    local domain_dir="$1"
    log "[+] JS Exposures"
    
    # Check if urls.txt exists
    if [[ ! -f "$domain_dir/urls/all-urls.txt" ]]; then
        log "[-] No URLs file found at $domain_dir/urls/all-urls.txt"
        return
    fi
    
    mkdir -p "$domain_dir/vulnerabilities/js"
    
    # Extract JS URLs and save them
    log "[+] Extracting JavaScript URLs"
    grep -i "\.js" "$domain_dir/urls/all-urls.txt" > "$domain_dir/vulnerabilities/js/js-urls.txt"
    
    # Only proceed if we found JS files
    if [[ -s "$domain_dir/vulnerabilities/js/js-urls.txt" ]]; then
        local js_count=$(wc -l < "$domain_dir/vulnerabilities/js/js-urls.txt")
        log "[+] Found $js_count JavaScript files"
        
        if [[ -d "nuclei_templates" ]]; then
            log "[+] Scanning JavaScript files with nuclei"
            nuclei -l "$domain_dir/vulnerabilities/js/js-urls.txt" -t nuclei_templates/js/ -o "$domain_dir/vulnerabilities/js/exposures.txt"
            
            # Send results only if we found exposures
            if [[ -s "$domain_dir/vulnerabilities/js/exposures.txt" ]]; then
                local vuln_count=$(wc -l < "$domain_dir/vulnerabilities/js/exposures.txt")
                log "[+] Found $vuln_count potential JavaScript vulnerabilities"
                send_file_to_discord "$domain_dir/vulnerabilities/js/exposures.txt" "JS Exposures Scan Results"
            else
                log "[+] No JavaScript vulnerabilities found"
            fi
        else
            log "[-] nuclei_templates directory not found, skipping JS exposure scan"
        fi
    else
        log "[-] No JavaScript files found in URLs"
    fi
    
    # Create a summary report
    {
        echo "=== JavaScript Analysis Summary ==="
        echo "Time: $(date)"
        echo
        if [[ -s "$domain_dir/vulnerabilities/js/js-urls.txt" ]]; then
            echo "Total JavaScript files found: $(wc -l < "$domain_dir/vulnerabilities/js/js-urls.txt")"
            echo
            echo "=== JavaScript URLs ==="
            cat "$domain_dir/vulnerabilities/js/js-urls.txt"
            echo
            echo "=== Vulnerabilities Found ==="
            if [[ -s "$domain_dir/vulnerabilities/js/exposures.txt" ]]; then
                cat "$domain_dir/vulnerabilities/js/exposures.txt"
            else
                echo "No vulnerabilities found"
            fi
        else
            echo "No JavaScript files found"
        fi
    } > "$domain_dir/vulnerabilities/js/summary.txt"
    
    send_file_to_discord "$domain_dir/vulnerabilities/js/summary.txt" "JavaScript Analysis Summary"
}

# Function to run nuclei scans
run_nuclei_scans() {
    local domain_dir="$1"
    log "[+] Nuclei Scanning with severity filtering (medium,high,critical)"
    if [[ -n "$SINGLE_SUBDOMAIN" ]]; then
        nuclei -u "https://$SINGLE_SUBDOMAIN" -s medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt"
        nuclei -u "https://$SINGLE_SUBDOMAIN" -s medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt"
    else
        nuclei -l "$domain_dir/urls/live.txt" -s medium,high,critical -t nuclei_templates/Others -o "$domain_dir/vulnerabilities/nuclei_templates-results.txt"
        nuclei -l "$domain_dir/urls/live.txt" -s medium,high,critical -t nuclei-templates/http -o "$domain_dir/vulnerabilities/nuclei-templates-results.txt"
    fi
    send_file_to_discord "$domain_dir/vulnerabilities/nuclei_templates-results.txt" "Collected Templates Nuclei Scans Results"
    send_file_to_discord "$domain_dir/vulnerabilities/nuclei-templates-results.txt" "Public Nuclei Scans Results"
}

# Main function
main() {
    check_and_clone "nuclei_templates" "https://github.com/h0tak88r/nuclei_templates.git"
    check_and_clone "nuclei-templates" "https://github.com/projectdiscovery/nuclei-templates.git"
    check_and_clone "$WORDLIST_DIR" "https://github.com/h0tak88r/Wordlists.git"
    setup_paramx_templates

    if [[ -z "$TARGET" ]] && [[ -z "$DOMAIN_LIST" ]]; then
        log "Error: No target specified. Use -d for single domain or -l for domain list."
        exit 1
    fi

    check_tools
    setup_results_dir
    
    if [[ -n "$DOMAIN_LIST" ]]; then
        while IFS= read -r domain; do
            [[ "$domain" =~ ^#.*$ ]] && continue  # Skip comments
            [[ -z "$domain" ]] && continue        # Skip empty lines
            process_domain "$domain"
        done < "$DOMAIN_LIST"
    else
        process_domain "$TARGET"
    fi
    
    log "All scans completed!"
    log "Results are saved in: $domain_dir"
}

main
