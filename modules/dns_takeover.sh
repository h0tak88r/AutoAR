#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/
# lib/discord.sh functionality in gomodules/ - functionality in gomodules/

usage() { 
    echo "Usage: dns takeover -d <domain>"
    echo "       dns cname -d <domain>"
    echo "       dns ns -d <domain>"
    echo "       dns azure-aws -d <domain>"
    echo "       dns dnsreaper -d <domain>"
    echo "       dns all -d <domain>"
}

# Function to check Azure and AWS subdomain takeover vulnerabilities
check_azure_aws_takeover() {
    local domain_dir="$1"
    local findings_dir="$2"
    
    log_info "Checking Azure and AWS subdomain takeover vulnerabilities..."
    
    local azure_output="$findings_dir/azure-takeover.txt"
    local aws_output="$findings_dir/aws-takeover.txt" 
    local combined_output="$findings_dir/azure-aws-takeover.txt"
    
    > "$azure_output"
    > "$aws_output" 
    > "$combined_output"
    
    local vulnerable_count=0 azure_count=0 aws_count=0
    
    local subs_file="$domain_dir/subs/all-subs.txt"
    log_info "Looking for subdomains file at: $subs_file"
    
    if [[ ! -f "$subs_file" ]]; then
        log_warn "Subdomains file not found at: $subs_file"
        return
    fi
    
    if [[ ! -s "$subs_file" ]]; then
        log_warn "Subdomains file is empty: $subs_file"
        return
    fi
    
    log_info "Found subdomains file with $(wc -l < "$subs_file") subdomains"
    
    while IFS= read -r subdomain; do
        [[ -z "$subdomain" ]] && continue
        
        local cname="" dig_output="" status=""
        
        if dig_output=$(dig +short +noall +answer "$subdomain" CNAME 2>/dev/null); then
            cname=$(echo "$dig_output" | head -n1 | tr -d '[:space:]')
        fi
        
        if dig_output=$(dig +noall +answer "$subdomain" 2>/dev/null); then
            if echo "$dig_output" | grep -q "status: NXDOMAIN"; then
                status="NXDOMAIN"
            elif echo "$dig_output" | grep -q "status: NOERROR"; then
                status="NOERROR"
            elif echo "$dig_output" | grep -q "status: SERVFAIL"; then
                status="SERVFAIL"
            else
                status="UNKNOWN"
            fi
        else
            status="ERROR"
        fi
        
        [[ -z "$cname" || "$status" != "NXDOMAIN" ]] && continue
        
        if [[ "$cname" =~ \.(cloudapp\.net|azurewebsites\.net|cloudapp\.azure\.com|trafficmanager\.net)$ ]]; then
            local service_type=""
            case "$cname" in
                *.cloudapp.net) service_type="Azure CloudApp" ;;
                *.azurewebsites.net) service_type="Azure Websites" ;;
                *.cloudapp.azure.com) service_type="Azure VM" ;;
                *.trafficmanager.net) service_type="Azure Traffic Manager" ;;
            esac
            
            echo "[VULNERABLE] [SUBDOMAIN:$subdomain] [CNAME:$cname] [SERVICE:$service_type] [STATUS:$status]" | tee -a "$azure_output" "$combined_output"
            ((azure_count++))
            ((vulnerable_count++))
            log_success "Azure takeover found: $subdomain -> $cname ($service_type)"
        fi
        
        if [[ "$cname" =~ \.(elasticbeanstalk\.com|s3\.amazonaws\.com|elb\.amazonaws\.com|execute-api\..*\.amazonaws\.com)$ ]]; then
            local service_type=""
            case "$cname" in
                *.elasticbeanstalk.com) service_type="AWS Elastic Beanstalk" ;;
                *.s3.amazonaws.com) service_type="AWS S3" ;;
                *.elb.amazonaws.com) service_type="AWS Elastic Load Balancer" ;;
                *.execute-api.*.amazonaws.com) service_type="AWS API Gateway" ;;
            esac
            
            echo "[VULNERABLE] [SUBDOMAIN:$subdomain] [CNAME:$cname] [SERVICE:$service_type] [STATUS:$status]" | tee -a "$aws_output" "$combined_output"
            ((aws_count++))
            ((vulnerable_count++))
            log_success "AWS takeover found: $subdomain -> $cname ($service_type)"
        fi
        
    done < "$subs_file"
    
    # Generate summary
    {
        echo "=== AZURE & AWS SUBDOMAIN TAKEOVER DETECTION SUMMARY ==="
        echo "Scan Date: $(date)"
        echo "Total Subdomains Checked: $(wc -l < "$subs_file")"
        echo "Azure Vulnerabilities Found: $azure_count"
        echo "AWS Vulnerabilities Found: $aws_count"
        echo "Total Vulnerabilities: $vulnerable_count"
        echo ""
        
        if [[ $azure_count -gt 0 ]]; then
            echo "=== AZURE TAKEOVER VULNERABILITIES ==="
            cat "$azure_output"
            echo ""
        fi
        
        if [[ $aws_count -gt 0 ]]; then
            echo "=== AWS TAKEOVER VULNERABILITIES ==="
            cat "$aws_output"
            echo ""
        fi
        
        echo "=== EXPLOITATION NOTES ==="
        echo "Azure Services:"
        echo "- CloudApp: Register at https://portal.azure.com/?quickstart=True#create/Microsoft.CloudService"
        echo "- Websites: Register at https://portal.azure.com/#create/Microsoft.WebApp"
        echo "- VM: Register at https://portal.azure.com/#create/Microsoft.VirtualMachine"
        echo "- Traffic Manager: Register at https://portal.azure.com/#create/Microsoft.TrafficManager"
        echo ""
        echo "AWS Services:"
        echo "- Elastic Beanstalk: Register at https://console.aws.amazon.com/elasticbeanstalk/"
        echo "- S3: Register at https://console.aws.amazon.com/s3/"
        echo "- ELB: Register at https://console.aws.amazon.com/ec2/v2/home#LoadBalancers:"
        echo "- API Gateway: Register at https://console.aws.amazon.com/apigateway/"
        echo ""
        echo "References:"
        echo "- Azure: https://godiego.co/posts/STO-Azure/"
        echo "- AWS: https://godiego.co/posts/STO-AWS/"
        
    } >> "$combined_output"
    
    # Send results to Discord
    if [[ $vulnerable_count -gt 0 ]]; then
        log_success "Found $vulnerable_count subdomain takeover vulnerabilities ($azure_count Azure, $aws_count AWS)"
        
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_azure_aws_$(date +%s)}"
        if [[ $azure_count -gt 0 ]]; then
            discord_send_file "$azure_output" "Azure Subdomain Takeover Results ($azure_count vulnerabilities)" "$scan_id"
        fi
        
        if [[ $aws_count -gt 0 ]]; then
            discord_send_file "$aws_output" "AWS Subdomain Takeover Results ($aws_count vulnerabilities)" "$scan_id"
        fi
        
        discord_send_file "$combined_output" "Azure & AWS Subdomain Takeover Summary ($vulnerable_count total)" "$scan_id"
    else
        log_info "No Azure or AWS subdomain takeover vulnerabilities found"
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_azure_aws_$(date +%s)}"
        discord_send_file "$combined_output" "Azure & AWS Subdomain Takeover Scan - No vulnerabilities found" "$scan_id"
    fi
    
    log_success "Azure and AWS takeover detection completed. Found $vulnerable_count total vulnerabilities"
}

# Function to run DNSReaper scan
run_dnsreaper_scan() {
    local domain_dir="$1"
    local findings_dir="$2"
    
    log_info "Running DNSReaper scan..."
    
    # Check if we're in Docker environment
    if [[ "${AUTOAR_ENV:-}" == "docker" ]]; then
        log_warn "DNSReaper requires Docker-in-Docker configuration in Docker environment"
        log_info "To enable DNSReaper in Docker, mount Docker socket: -v /var/run/docker.sock:/var/run/docker.sock"
        log_info "Or run DNSReaper separately: docker run --rm -v \$(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/path/to/subdomains.txt"
        return
    fi
    
    # Check if Docker is available and we can run containers (local environment)
    if ! command -v docker >/dev/null 2>&1; then
        log_warn "Docker not available, skipping DNSReaper scan"
        return
    fi
    
    # Test if we can actually run Docker containers
    if ! docker ps >/dev/null 2>&1; then
        log_warn "Cannot run Docker containers (permission issues), skipping DNSReaper scan"
        return
    fi
    
    # Copy subdomains file for DNSReaper
    cp "$domain_dir/subs/all-subs.txt" "$findings_dir/dnsreaper-input.txt"
    
    # Run DNSReaper in Docker
    if docker run --rm -v "$(pwd):/etc/dnsreaper" punksecurity/dnsreaper file --filename "/etc/dnsreaper/$findings_dir/dnsreaper-input.txt" > "$findings_dir/dnsreaper-results.txt" 2>/dev/null; then
        if [[ -s "$findings_dir/dnsreaper-results.txt" ]]; then
            log_success "DNSReaper scan completed with findings"
            local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_takeover_$(date +%s)}"
            discord_send_file "$findings_dir/dnsreaper-results.txt" "DNSReaper Takeover Results" "$scan_id"
        else
            log_info "DNSReaper scan completed - no findings"
        fi
    else
        log_warn "DNSReaper scan failed"
    fi
}

# Function to run Nuclei takeover scans
run_nuclei_takeover() {
    local domain_dir="$1"
    local findings_dir="$2"
    
    log_info "Running Nuclei takeover templates..."
    
    # Check if nuclei is available
    if ! command -v nuclei >/dev/null 2>&1; then
        log_warn "Nuclei not available, skipping takeover templates"
        return
    fi
    
    # Run public takeover templates - check multiple possible locations
    local nuclei_templates_dir=""
    for template_dir in "/app/nuclei-templates" "/app/nuclei-templates-backup" "nuclei-templates" "/usr/local/share/nuclei-templates" "/opt/nuclei-templates" "/root/nuclei-templates" "/home/autoar/nuclei-templates" "/home/autoar/.cache/nuclei/nuclei-templates"; do
        if [[ -d "$template_dir" && -d "$template_dir/http/takeovers" ]]; then
            nuclei_templates_dir="$template_dir"
            log_info "Found Nuclei templates in: $template_dir"
            break
        fi
    done
    
    if [[ -n "$nuclei_templates_dir" && -d "$nuclei_templates_dir/http/takeovers" ]]; then
        log_info "Running Nuclei public takeover templates from $nuclei_templates_dir..."
        if nuclei -l "$domain_dir/subs/all-subs.txt" -t "$nuclei_templates_dir/http/takeovers/" -o "$findings_dir/nuclei-takeover-public.txt" >/dev/null 2>&1; then
            if [[ -s "$findings_dir/nuclei-takeover-public.txt" ]]; then
                log_success "Nuclei public takeover scan completed with findings"
                local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_takeover_$(date +%s)}"
                discord_send_file "$findings_dir/nuclei-takeover-public.txt" "Nuclei Public Takeover Findings" "$scan_id"
            else
                log_info "Nuclei public takeover scan completed - no findings"
            fi
        else
            log_warn "Nuclei public takeover scan failed"
        fi
    else
        log_warn "nuclei-templates directory not found in any standard location, skipping public templates"
        log_info "Searched in: nuclei-templates, /app/nuclei-templates, /usr/local/share/nuclei-templates, /opt/nuclei-templates"
    fi
    
    # Run custom takeover templates - check multiple possible locations
    local nuclei_custom_dir=""
    for custom_dir in "/app/nuclei_templates" "/app/nuclei-templates-backup" "nuclei_templates" "/usr/local/share/nuclei_templates" "/opt/nuclei_templates" "/root/nuclei_templates" "/home/autoar/nuclei_templates" "/home/autoar/.cache/nuclei/nuclei-templates"; do
        if [[ -d "$custom_dir" && -d "$custom_dir/http/takeovers" ]]; then
            nuclei_custom_dir="$custom_dir"
            log_info "Found custom Nuclei templates in: $custom_dir"
            break
        fi
    done
    
    if [[ -n "$nuclei_custom_dir" ]]; then
        log_info "Running Nuclei custom takeover templates from $nuclei_custom_dir..."
        if nuclei -l "$domain_dir/subs/all-subs.txt" -t "$nuclei_custom_dir/http/takeovers/" -o "$findings_dir/nuclei-takeover-custom.txt" >/dev/null 2>&1; then
            if [[ -s "$findings_dir/nuclei-takeover-custom.txt" ]]; then
                log_success "Nuclei custom takeover scan completed with findings"
                local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_takeover_$(date +%s)}"
                discord_send_file "$findings_dir/nuclei-takeover-custom.txt" "Nuclei Custom Takeover Findings" "$scan_id"
            else
                log_info "Nuclei custom takeover scan completed - no findings"
            fi
        else
            log_warn "Nuclei custom takeover scan failed"
        fi
    else
        log_warn "nuclei_templates directory with detect-all-takeover.yaml not found, skipping custom templates"
        log_info "Searched in: nuclei_templates, /app/nuclei_templates, /usr/local/share/nuclei_templates, /opt/nuclei_templates"
    fi
}

# Function to run NS takeover scan
run_ns_takeover() {
    local domain_dir="$1"
    local findings_dir="$2"
    
    log_info "Running NS takeover scan..."
    
    # Check if dnsx is available
    if ! command -v dnsx >/dev/null 2>&1; then
        log_warn "dnsx not available, skipping NS takeover scan"
        return
    fi
    
    # First get all NS records
    log_info "Extracting NS records..."
    dnsx -l "$domain_dir/subs/all-subs.txt" -ns -silent -ro > "$findings_dir/ns-servers.txt" 2>/dev/null || true
    
    # Check both subdomains and NS servers for DNS errors
    log_info "Checking subdomains for DNS errors..."
    dnsx -l "$domain_dir/subs/all-subs.txt" -rcode servfail,refused -silent > "$findings_dir/ns-takeover-raw.txt" 2>/dev/null || true
    
    log_info "Checking NS servers for DNS errors..."
    dnsx -l "$findings_dir/ns-servers.txt" -rcode servfail,refused -silent > "$findings_dir/ns-servers-vuln.txt" 2>/dev/null || true
    
    local ns_takeover_raw_count=$(wc -l < "$findings_dir/ns-takeover-raw.txt" 2>/dev/null || echo "0")
    local ns_servers_vuln_count=$(wc -l < "$findings_dir/ns-servers-vuln.txt" 2>/dev/null || echo "0")
    
    log_info "Found $ns_takeover_raw_count subdomains and $ns_servers_vuln_count NS servers with DNS errors"

    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_ns_$(date +%s)}"
    if [[ $ns_takeover_raw_count -gt 0 ]]; then
        discord_send_file "$findings_dir/ns-takeover-raw.txt" "NS Takeover Candidates (Subdomain DNS Errors)" "$scan_id"
    fi

    if [[ $ns_servers_vuln_count -gt 0 ]]; then
        discord_send_file "$findings_dir/ns-servers-vuln.txt" "NS Takeover Candidates (NS Server DNS Errors)" "$scan_id"
    fi

    # Filter for known vulnerable/edge-case NS providers
    local ns_vuln_regex='ns1-.*\.azure-dns\.com|ns2-.*\.azure-dns\.net|ns3-.*\.azure-dns\.org|ns4-.*\.azure-dns\.info|ns1\.dnsimple\.com|ns2\.dnsimple\.com|ns3\.dnsimple\.com|ns4\.dnsimple\.com|ns1\.domain\.com|ns2\.domain\.com|ns1\.dreamhost\.com|ns2\.dreamhost\.com|ns3\.dreamhost\.com|ns-cloud-.*\.googledomains\.com|ns5\.he\.net|ns4\.he\.net|ns3\.he\.net|ns2\.he\.net|ns1\.he\.net|ns1\.linode\.com|ns2\.linode\.com|ns1.*\.name\.com|ns2.*\.name\.com|ns3.*\.name\.com|ns4.*\.name\.com|ns1\.domaindiscover\.com|ns2\.domaindiscover\.com|yns1\.yahoo\.com|yns2\.yahoo\.com|ns1\.reg\.ru|ns2\.reg\.ru'
    grep -Ei "$ns_vuln_regex" "$findings_dir/ns-takeover-raw.txt" > "$findings_dir/ns-takeover-vuln.txt" 2>/dev/null || true
    local ns_takeover_vuln_count=$(wc -l < "$findings_dir/ns-takeover-vuln.txt" 2>/dev/null || echo "0")
    
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_ns_$(date +%s)}"
    if [[ $ns_takeover_vuln_count -gt 0 ]]; then
        discord_send_file "$findings_dir/ns-takeover-vuln.txt" "NS Takeover Filtered Targets (Vulnerable Providers)" "$scan_id"
    fi
    
    log_success "NS takeover scan completed. Found $ns_takeover_raw_count subdomain errors, $ns_servers_vuln_count NS server errors, $ns_takeover_vuln_count vulnerable providers"
}

# Main comprehensive DNS takeover scan function
dns_takeover_comprehensive() {
    local domain=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain) domain="$2"; shift 2;;
            *) usage; exit 1;;
        esac
    done
    [[ -z "$domain" ]] && { usage; exit 1; }

    local dir subs findings_dir
    dir="$(results_dir "$domain")"
    log_info "Debug: Initial dir variable is: $dir"
    subs="$dir/subs/all-subs.txt"
    findings_dir="$dir/vulnerabilities/dns-takeover"
    log_info "Debug: After setting subs and findings_dir, dir is still: $dir"
    ensure_dir "$findings_dir"
    
    # Initialize all output files
    > "$findings_dir/nuclei-takeover-public.txt"
    > "$findings_dir/nuclei-takeover-custom.txt"
    > "$findings_dir/azure-takeover.txt"
    > "$findings_dir/aws-takeover.txt"
    > "$findings_dir/azure-aws-takeover.txt"
    > "$findings_dir/ns-takeover-raw.txt"
    > "$findings_dir/ns-takeover-vuln.txt"
    > "$findings_dir/ns-servers.txt"
    > "$findings_dir/ns-servers-vuln.txt"
    > "$findings_dir/dns-takeover-summary.txt"
    > "$findings_dir/dnsreaper-results.txt"
    > "$findings_dir/filtered-ns-takeover-vuln.txt"
    
    # Ensure subdomains exist
    ensure_subdomains "$domain" "$subs" || { log_warn "Failed to get subdomains for $domain"; exit 1; }
    
    # Send progress notification
    discord_send_progress "🔍 **Starting Comprehensive DNS Takeover Scan for $domain**"
    
    # 1. Run Nuclei takeover templates
    log_info "Step 1/5: Running Nuclei takeover templates"
    discord_send_progress "🔬 **Step 1/5:** Running Nuclei takeover templates for $domain"
    run_nuclei_takeover "$dir" "$findings_dir"
    
    # 2. Run DNSReaper scan
    log_info "Step 2/5: Running DNSReaper scan"
    discord_send_progress "🕵️ **Step 2/5:** Running DNSReaper scan for $domain"
    run_dnsreaper_scan "$dir" "$findings_dir"
    
    # 3. Run Azure and AWS subdomain takeover detection
    log_info "Step 3/5: Running Azure and AWS subdomain takeover detection"
    log_info "Debug: dir variable is: $dir"
    log_info "Debug: findings_dir variable is: $findings_dir"
    discord_send_progress "☁️ **Step 3/5:** Checking Azure & AWS subdomain takeovers for $domain"
    check_azure_aws_takeover "$dir" "$findings_dir"
    
    # 4. Run NS takeover scan
    log_info "Step 4/5: Running NS takeover scan"
    discord_send_progress "🌐 **Step 4/5:** Running NS takeover scan for $domain"
    run_ns_takeover "$dir" "$findings_dir"
    
    # 5. Generate comprehensive summary
    log_info "Step 5/5: Generating comprehensive summary"
    discord_send_progress "📊 **Step 5/5:** Generating comprehensive summary for $domain"
    
    local nuclei_public_count=$(wc -l < "$findings_dir/nuclei-takeover-public.txt" 2>/dev/null || echo "0")
    local nuclei_custom_count=$(wc -l < "$findings_dir/nuclei-takeover-custom.txt" 2>/dev/null || echo "0")
    local dnsreaper_count=$(wc -l < "$findings_dir/dnsreaper-results.txt" 2>/dev/null || echo "0")
    local azure_count=$(wc -l < "$findings_dir/azure-takeover.txt" 2>/dev/null || echo "0")
    local aws_count=$(wc -l < "$findings_dir/aws-takeover.txt" 2>/dev/null || echo "0")
    local ns_raw_count=$(wc -l < "$findings_dir/ns-takeover-raw.txt" 2>/dev/null || echo "0")
    local ns_servers_count=$(wc -l < "$findings_dir/ns-servers-vuln.txt" 2>/dev/null || echo "0")
    local ns_vuln_count=$(wc -l < "$findings_dir/ns-takeover-vuln.txt" 2>/dev/null || echo "0")
    
    # Generate comprehensive summary
    {
        echo "=== COMPREHENSIVE DNS TAKEOVER SCAN SUMMARY ==="
        echo "Scan Date: $(date)"
        echo "Target Domain: $domain"
        echo "Total Subdomains Scanned: $(wc -l < "$subs" 2>/dev/null || echo "0")"
        echo "Tools Used: dnsx, nuclei, dnsreaper, dig (bash implementation)"
        echo ""
        echo "=== FINDINGS SUMMARY ==="
        echo "CNAME Takeover (Nuclei public): $nuclei_public_count"
        echo "CNAME Takeover (Nuclei custom): $nuclei_custom_count"
        echo "DNSReaper Results: $dnsreaper_count"
        echo "Azure Subdomain Takeover: $azure_count"
        echo "AWS Subdomain Takeover: $aws_count"
        echo "NS Takeover (Subdomain DNS Errors): $ns_raw_count"
        echo "NS Takeover (NS Server DNS Errors): $ns_servers_count"
        echo "NS Takeover (Vulnerable Providers): $ns_vuln_count"
        echo ""
        echo "=== EXPLOITATION NOTES ==="
        echo "- CNAME Takeover: Use Nuclei/DNSReaper findings for actionable subdomain takeovers."
        echo "- Azure Takeover: Check azure-takeover.txt for CloudApp, Websites, VM, and Traffic Manager vulnerabilities."
        echo "- AWS Takeover: Check aws-takeover.txt for Elastic Beanstalk, S3, ELB, and API Gateway vulnerabilities."
        echo "- NS Takeover: Check both subdomain and NS server DNS errors, prioritize those matching known vulnerable providers."
        echo "- Always verify manually before reporting."
        echo ""
        echo "=== REFERENCES ==="
        echo "- https://github.com/indianajson/can-i-take-over-dns"
        echo "- https://trickest.com/blog/dns-takeover-explained-protect-your-online-domain/"
        echo "- https://hackerone.com/reports/1226891"
        echo "- https://github.com/punk-security/dnsreaper"
        echo "- Azure: https://godiego.co/posts/STO-Azure/"
        echo "- AWS: https://godiego.co/posts/STO-AWS/"
    } > "$findings_dir/dns-takeover-summary.txt"
    
    # Send final summary via bot
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-dns_takeover_$(date +%s)}"
    discord_send_file "$findings_dir/dns-takeover-summary.txt" "Comprehensive DNS Takeover Summary for $domain" "$scan_id"
    
    # Send completion notification
    local total_findings=$((nuclei_public_count + nuclei_custom_count + dnsreaper_count + azure_count + aws_count + ns_raw_count + ns_servers_count + ns_vuln_count))
    discord_send_progress "✅ **DNS Takeover scan completed for $domain** - Found $total_findings total findings"
    
    log_success "Comprehensive DNS takeover scan completed for $domain. Found $total_findings total findings."
}

# Individual scan functions
dns_cname_scan() {
    local domain=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain) domain="$2"; shift 2;;
            *) usage; exit 1;;
        esac
    done
    [[ -z "$domain" ]] && { usage; exit 1; }

    local dir subs findings_dir
    dir="$(results_dir "$domain")"
    subs="$dir/subs/all-subs.txt"
    findings_dir="$dir/vulnerabilities/dns-takeover"
    ensure_dir "$findings_dir"
    
    ensure_subdomains "$domain" "$subs" || { log_warn "Failed to get subdomains for $domain"; exit 1; }
    
    discord_send_progress "🔬 **Running CNAME takeover scan for $domain**"
    run_nuclei_takeover "$dir" "$findings_dir"
    run_dnsreaper_scan "$dir" "$findings_dir"
    check_azure_aws_takeover "$dir" "$findings_dir"
    
    discord_send_progress "✅ **CNAME takeover scan completed for $domain**"
}

dns_ns_scan() {
    local domain=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain) domain="$2"; shift 2;;
            *) usage; exit 1;;
        esac
    done
    [[ -z "$domain" ]] && { usage; exit 1; }

    local dir subs findings_dir
    dir="$(results_dir "$domain")"
    subs="$dir/subs/all-subs.txt"
    findings_dir="$dir/vulnerabilities/dns-takeover"
    ensure_dir "$findings_dir"
    
    ensure_subdomains "$domain" "$subs" || { log_warn "Failed to get subdomains for $domain"; exit 1; }
    
    discord_send_progress "🌐 **Running NS takeover scan for $domain**"
    run_ns_takeover "$dir" "$findings_dir"
    
    discord_send_progress "✅ **NS takeover scan completed for $domain**"
}

dns_azure_aws_scan() {
    local domain=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain) domain="$2"; shift 2;;
            *) usage; exit 1;;
        esac
    done
    [[ -z "$domain" ]] && { usage; exit 1; }

    local dir subs findings_dir
    dir="$(results_dir "$domain")"
    subs="$dir/subs/all-subs.txt"
    findings_dir="$dir/vulnerabilities/dns-takeover"
    ensure_dir "$findings_dir"
    
    ensure_subdomains "$domain" "$subs" || { log_warn "Failed to get subdomains for $domain"; exit 1; }
    
    discord_send_progress "☁️ **Running Azure & AWS takeover scan for $domain**"
    check_azure_aws_takeover "$dir" "$findings_dir"
    
    discord_send_progress "✅ **Azure & AWS takeover scan completed for $domain**"
}

dns_dnsreaper_scan() {
    local domain=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain) domain="$2"; shift 2;;
            *) usage; exit 1;;
        esac
    done
    [[ -z "$domain" ]] && { usage; exit 1; }

    local dir subs findings_dir
    dir="$(results_dir "$domain")"
    subs="$dir/subs/all-subs.txt"
    findings_dir="$dir/vulnerabilities/dns-takeover"
    ensure_dir "$findings_dir"
    
    ensure_subdomains "$domain" "$subs" || { log_warn "Failed to get subdomains for $domain"; exit 1; }
    
    discord_send_progress "🕵️ **Running DNSReaper scan for $domain**"
    run_dnsreaper_scan "$dir" "$findings_dir"
    
    discord_send_progress "✅ **DNSReaper scan completed for $domain**"
}

case "${1:-}" in
  takeover) shift; dns_takeover_comprehensive "$@" ;;
  cname) shift; dns_cname_scan "$@" ;;
  ns) shift; dns_ns_scan "$@" ;;
  azure-aws) shift; dns_azure_aws_scan "$@" ;;
  dnsreaper) shift; dns_dnsreaper_scan "$@" ;;
  all) shift; dns_takeover_comprehensive "$@" ;;
  *) usage; exit 1;;
esac