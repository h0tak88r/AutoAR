#!/usr/bin/env bash
# Unified Dependency Confusion Scanner using Confused tool
# Supports local files, GitHub repos/orgs, and web targets

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/.env" 2>/dev/null || true
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

# Find confused2 tool binary
CONFUSED_BIN=""
if command -v confused2 >/dev/null 2>&1; then
    CONFUSED_BIN="confused2"
elif [[ -f "/home/sallam/go/bin/confused2" ]]; then
    CONFUSED_BIN="/home/sallam/go/bin/confused2"
elif [[ -f "/usr/local/bin/confused2" ]]; then
    CONFUSED_BIN="/usr/local/bin/confused2"
else
    log_error "Confused2 tool not found. Please install it with: go install github.com/h0tak88r/confused2/cmd/confused2@latest"
    exit 1
fi

usage() {
    echo "Usage: depconfusion <command> [options]"
    echo ""
    echo "Commands:"
    echo "  web <url>                      Single target web scan with --deep"
    echo "  web-full <domain>              Domain scan with subdomain collection"
    echo "  github org <org>               GitHub organization scan"
    echo ""
    echo "Options:"
    echo "  -w, --workers <num>            Number of workers/threads (default: 10)"
    echo "  -v, --verbose                  Verbose output"
    echo ""
    echo "Examples:"
    echo "  depconfusion web https://your-target.com --deep -v -w 50"
    echo "  depconfusion web-full your-domain.com -v -w 50"
    echo "  depconfusion github org your-org --deep -v -w 50"
}

# Check if confused2 tool is available
check_confused2() {
    if [[ -z "$CONFUSED_BIN" ]]; then
        log_error "Confused2 tool not found. Please install it with: go install github.com/h0tak88r/confused2/cmd/confused2@latest"
        discord_send_progress "❌ **Confused2 tool not found. Please install it first.**"
        exit 1
    fi
}

# Scan a local dependency file
scan_local() {
    local file="$1"
    shift
    local args=("$@")
    
    log_info "Scanning local file: $file"
    discord_send_progress "🔍 **Scanning local file: $file**"
    
    # Set default output directory
    local output_dir="$(results_dir "local-$(basename "$file" .json)")/depconfusion"
    ensure_dir "$output_dir"
    
    # Build confused command
    local cmd=("$CONFUSED_BIN" "scan" "$file")
    
    # Add common arguments
    for arg in "${args[@]}"; do
        cmd+=("$arg")
    done
    
    # Add output directory if not specified
    if ! printf '%s\n' "${args[@]}" | grep -q -- "--output-dir"; then
        cmd+=("--output-dir" "$output_dir")
    fi
    
    # Add output file if not specified
    if ! printf '%s\n' "${args[@]}" | grep -q -- "--output"; then
        cmd+=("--output" "$output_dir/scan-results.txt")
    fi
    
    # Run confused tool
    "${cmd[@]}" > "$output_dir/scan-output.txt" 2>&1
    local exit_code=$?
    
    log_success "Local file scan completed"
    
    # Check for vulnerabilities (regardless of exit code, as the tool may fail on file saving but still find issues)
    if grep -q "Issues found" "$output_dir/scan-output.txt"; then
        log_warn "Dependency confusion vulnerabilities found in $file"
        discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in $file**"
    else
        log_success "No dependency confusion vulnerabilities found in $file"
        discord_send_progress "✅ **No dependency confusion vulnerabilities found in $file**"
    fi
    
    # Send final results via bot
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-depconfusion_$(date +%s)}"
    discord_send_file "$output_dir/scan-output.txt" "Dependency confusion scan results for $file" "$scan_id"
    
    # Only exit with error if there was a real failure (not just file saving issues)
    if [[ $exit_code -ne 0 ]] && ! grep -q "Issues found" "$output_dir/scan-output.txt"; then
        log_error "Local file scan failed"
        discord_send_progress "❌ **Local file scan failed**"
        exit 1
    fi
}

# Scan GitHub repository
scan_github_repo() {
    local repo="$1"
    shift
    local args=("$@")
    
    log_info "Scanning GitHub repository: $repo"
    discord_send_progress "🔍 **Scanning GitHub repository: $repo**"
    
    # Set default output directory
    local output_dir="$(results_dir "github-$repo")/depconfusion"
    ensure_dir "$output_dir"
    
    # Build confused command
    local cmd=("$CONFUSED_BIN" "github" "repo" "$repo")
    
    # Add common arguments
    for arg in "${args[@]}"; do
        cmd+=("$arg")
    done
    
    # Add output directory if not specified
    if ! printf '%s\n' "${args[@]}" | grep -q -- "--output-dir"; then
        cmd+=("--output-dir" "$output_dir")
    fi
    
    # Add GitHub token if available (always check environment first)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        cmd+=("--github-token" "$GITHUB_TOKEN")
    fi
    
    # Run confused tool
    if "${cmd[@]}" > "$output_dir/github-scan-output.txt" 2>&1; then
        log_success "GitHub repository scan completed"
        
        # Check for vulnerabilities
        if grep -q "Issues found" "$output_dir/github-scan-output.txt"; then
            log_warn "Dependency confusion vulnerabilities found in $repo"
            discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in $repo**"
        else
            log_success "No dependency confusion vulnerabilities found in $repo"
            discord_send_progress "✅ **No dependency confusion vulnerabilities found in $repo**"
        fi
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-depconfusion_github_$(date +%s)}"
        discord_send_file "$output_dir/github-scan-output.txt" "Dependency confusion scan results for $repo" "$scan_id"
    else
        log_error "GitHub repository scan failed"
        discord_send_progress "❌ **GitHub repository scan failed**"
        exit 1
    fi
}

# Scan GitHub organization
scan_github_org() {
    local org="$1"
    shift
    local args=("$@")
    
    log_info "Scanning GitHub organization: $org"
    discord_send_progress "🔍 **Scanning GitHub organization: $org**"
    
    # Set default output directory
    local output_dir="$(results_dir "github-org-$org")/depconfusion"
    ensure_dir "$output_dir"
    
    # Build confused command
    local cmd=("$CONFUSED_BIN" "github" "org" "$org")
    
    # Add common arguments
    for arg in "${args[@]}"; do
        cmd+=("$arg")
    done
    
    # Add output directory if not specified
    if ! printf '%s\n' "${args[@]}" | grep -q -- "--output-dir"; then
        cmd+=("--output-dir" "$output_dir")
    fi
    
    # Add GitHub token if available (always check environment first)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        cmd+=("--github-token" "$GITHUB_TOKEN")
    fi
    
    # Run confused tool
    if "${cmd[@]}" > "$output_dir/github-org-scan-output.txt" 2>&1; then
        log_success "GitHub organization scan completed"
        
        # Check for vulnerabilities
        if grep -q "Issues found" "$output_dir/github-org-scan-output.txt"; then
            log_warn "Dependency confusion vulnerabilities found in $org"
            discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in $org**"
        else
            log_success "No dependency confusion vulnerabilities found in $org"
            discord_send_progress "✅ **No dependency confusion vulnerabilities found in $org**"
        fi
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-depconfusion_github_org_$(date +%s)}"
        discord_send_file "$output_dir/github-org-scan-output.txt" "Dependency confusion scan results for $org" "$scan_id"
    else
        log_error "GitHub organization scan failed"
        discord_send_progress "❌ **GitHub organization scan failed**"
        exit 1
    fi
}

# Scan web targets
scan_web() {
    local targets=("$@")
    
    log_info "Scanning web targets: ${targets[*]}"
    discord_send_progress "🔍 **Scanning web targets: ${targets[*]}**"
    
    # Set default output directory
    local output_dir="$(results_dir "web-$(date +%Y%m%d-%H%M%S)")/depconfusion"
    ensure_dir "$output_dir"
    
    # Build confused command
    local cmd=("$CONFUSED_BIN" "web" "--deep")
    
    # Add targets
    for target in "${targets[@]}"; do
        cmd+=("$target")
    done
    
    # Add output directory
    cmd+=("--output-dir" "$output_dir")
    
    # Run confused tool
    if "${cmd[@]}" > "$output_dir/web-scan-output.txt" 2>&1; then
        log_success "Web targets scan completed"
        
        # Check for vulnerabilities
        if grep -q "Issues found" "$output_dir/web-scan-output.txt"; then
            log_warn "Dependency confusion vulnerabilities found in web targets"
            discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in web targets**"
        else
            log_success "No dependency confusion vulnerabilities found in web targets"
            discord_send_progress "✅ **No dependency confusion vulnerabilities found in web targets**"
        fi
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-depconfusion_web_$(date +%s)}"
        discord_send_file "$output_dir/web-scan-output.txt" "Dependency confusion scan results for web targets" "$scan_id"
    else
        log_error "Web targets scan failed"
        discord_send_progress "❌ **Web targets scan failed**"
        exit 1
    fi
}

# Scan web targets from file
scan_web_file() {
    local file="$1"
    shift
    local args=("$@")
    
    if [[ ! -f "$file" ]]; then
        log_error "Target file not found: $file"
        exit 1
    fi
    
    log_info "Scanning web targets from file: $file"
    discord_send_progress "🔍 **Scanning web targets from file: $file**"
    
    # Set default output directory
    local output_dir="$(results_dir "web-file-$(basename "$file" .txt)")/depconfusion"
    ensure_dir "$output_dir"
    
    # Build confused command
    local cmd=("$CONFUSED_BIN" "web" "--target-file" "$file")
    
    # Add common arguments
    for arg in "${args[@]}"; do
        cmd+=("$arg")
    done
    
    # Add output directory if not specified
    if ! printf '%s\n' "${args[@]}" | grep -q -- "--output-dir"; then
        cmd+=("--output-dir" "$output_dir")
    fi
    
    # Run confused tool
    if "${cmd[@]}" > "$output_dir/web-file-scan-output.txt" 2>&1; then
        log_success "Web targets file scan completed"
        
        # Check for vulnerabilities
        if grep -q "Issues found" "$output_dir/web-file-scan-output.txt"; then
            log_warn "Dependency confusion vulnerabilities found in web targets"
            discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in web targets**"
        else
            log_success "No dependency confusion vulnerabilities found in web targets"
            discord_send_progress "✅ **No dependency confusion vulnerabilities found in web targets**"
        fi
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-depconfusion_web_file_$(date +%s)}"
        discord_send_file "$output_dir/web-file-scan-output.txt" "Dependency confusion scan results for web targets" "$scan_id"
    else
        log_error "Web targets file scan failed"
        discord_send_progress "❌ **Web targets file scan failed**"
        exit 1
    fi
}

# Scan web targets with subdomain enumeration (full scan)
scan_web_full() {
    local domain="$1"
    shift
    local args=("$@")
    
    log_info "Starting full web dependency confusion scan for domain: $domain"
    discord_send_progress "🔍 **Starting full web dependency confusion scan for $domain**"
    
    # Set default output directory
    local output_dir="$(results_dir "web-full-$domain")/depconfusion"
    ensure_dir "$output_dir"
    
    # Step 1: Subdomain enumeration
    log_info "Step 1: Enumerating subdomains for $domain"
    discord_send_progress "🔍 **Step 1: Enumerating subdomains for $domain**"
    
    local subs_dir="$output_dir/subs"
    ensure_dir "$subs_dir"
    
    # Run subfinder
    local subfinder_bin=""
    if command -v subfinder >/dev/null 2>&1; then
        subfinder_bin="subfinder"
    elif [[ -f "/home/sallam/go/bin/subfinder" ]]; then
        subfinder_bin="/home/sallam/go/bin/subfinder"
    elif [[ -f "/usr/local/bin/subfinder" ]]; then
        subfinder_bin="/usr/local/bin/subfinder"
    else
        log_error "Subfinder not found. Please install it with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        discord_send_progress "❌ **Subfinder not found. Please install it first.**"
        exit 1
    fi
    
    if "$subfinder_bin" -d "$domain" -silent > "$subs_dir/all-subs.txt" 2>/dev/null; then
        local sub_count=$(wc -l < "$subs_dir/all-subs.txt")
        log_success "Found $sub_count subdomains"
        
        if [[ $sub_count -eq 0 ]]; then
            log_warn "No subdomains found for $domain"
            discord_send_progress "⚠️ **No subdomains found for $domain**"
            exit 0
        fi
    else
        log_error "Subdomain enumeration failed for $domain"
        discord_send_progress "❌ **Subdomain enumeration failed for $domain**"
        exit 1
    fi
    
    # Step 2: Live host detection
    log_info "Step 2: Detecting live hosts"
    discord_send_progress "🔍 **Step 2: Detecting live hosts**"
    
    # Run httpx for live host detection
    local httpx_bin=""
    if command -v httpx >/dev/null 2>&1; then
        httpx_bin="httpx"
    elif [[ -f "/home/sallam/go/bin/httpx" ]]; then
        httpx_bin="/home/sallam/go/bin/httpx"
    elif [[ -f "/usr/local/bin/httpx" ]]; then
        httpx_bin="/usr/local/bin/httpx"
    else
        log_error "Httpx not found. Please install it with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        discord_send_progress "❌ **Httpx not found. Please install it first.**"
        exit 1
    fi
    
    if "$httpx_bin" -l "$subs_dir/all-subs.txt" -silent -o "$subs_dir/live-subs.txt" 2>/dev/null; then
        local live_count=$(wc -l < "$subs_dir/live-subs.txt")
        log_success "Found $live_count live hosts"
        
        if [[ $live_count -eq 0 ]]; then
            log_warn "No live hosts found for $domain"
            discord_send_progress "⚠️ **No live hosts found for $domain**"
            exit 0
        fi
    else
        log_error "Live host detection failed for $domain"
        discord_send_progress "❌ **Live host detection failed for $domain**"
        exit 1
    fi
    
    # Step 3: Dependency confusion scanning
    log_info "Step 3: Scanning live hosts for dependency confusion vulnerabilities"
    discord_send_progress "🔍 **Step 3: Scanning $live_count live hosts for dependency confusion**"
    
    # Build confused2 command for web scanning with target file
    local cmd=("$CONFUSED_BIN" "web" "--target-file" "$subs_dir/live-subs.txt")
    
    # Add common arguments
    for arg in "${args[@]}"; do
        cmd+=("$arg")
    done
    
    # Add output directory if not specified
    if ! printf '%s\n' "${args[@]}" | grep -q -- "--output-dir"; then
        cmd+=("--output-dir" "$output_dir")
    fi
    
    # Run confused2 tool
    if "${cmd[@]}" > "$output_dir/web-full-scan-output.txt" 2>&1; then
        log_success "Full web dependency confusion scan completed"
        
        # Check for vulnerabilities
        if grep -q "Issues found" "$output_dir/web-full-scan-output.txt"; then
            log_warn "Dependency confusion vulnerabilities found in live hosts"
            discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in live hosts**"
        else
            log_success "No dependency confusion vulnerabilities found in live hosts"
            discord_send_progress "✅ **No dependency confusion vulnerabilities found in live hosts**"
        fi
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-depconfusion_web_full_$(date +%s)}"
        discord_send_file "$output_dir/web-full-scan-output.txt" "Full web dependency confusion scan results for $domain" "$scan_id"
    else
        log_error "Full web dependency confusion scan failed"
        discord_send_progress "❌ **Full web dependency confusion scan failed**"
        exit 1
    fi
}

# Main function
main() {
    check_confused2
    
    # Handle help flags
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        usage
        exit 0
    fi
    
    case "${1:-}" in
        web)
            shift
            # Single target web scan with --deep
            scan_web "$@"
            ;;
        web-full)
            shift
            # Domain scan with subdomain collection
            scan_web_full "$@"
            ;;
        github)
            case "${2:-}" in
                org)
                    shift 2
                    # GitHub organization scan
                    scan_github_org "$@"
                    ;;
                *)
                    log_error "Invalid GitHub command. Use: depconfusion github org <org>"
                    exit 1
                    ;;
            esac
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
