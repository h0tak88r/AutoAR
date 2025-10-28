#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: github scan -r <owner/repo> | github org -o <org> [-m <max-repos>] | github depconfusion -r <owner/repo>"; }

# Function to generate HTML report for GitHub secrets
generate_github_html_report() {
    local repo_name="$1"
    local org_name="$2"
    local json_file="$3"
    local html_file="$4"
    local secret_count="$5"
    
    log_info "Generating HTML report for $repo_name..."
    
    cat > "$html_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Secrets Scan Report - $repo_name</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 5px 0;
            font-size: 1.1em;
        }
        .timestamp {
            font-style: italic;
            opacity: 0.9;
        }
        .summary {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        .summary h2 {
            color: #667eea;
            margin-top: 0;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        .secrets-section {
            padding: 30px;
        }
        .secret-item {
            background: #fff;
            border: 1px solid #e1e5e9;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .secret-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e1e5e9;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .secret-title {
            font-weight: bold;
            color: #333;
            font-size: 1.1em;
        }
        .severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .severity.high {
            background: #ffebee;
            color: #c62828;
        }
        .severity.medium {
            background: #fff3e0;
            color: #ef6c00;
        }
        .severity.low {
            background: #e8f5e8;
            color: #2e7d32;
        }
        .secret-content {
            padding: 20px;
        }
        .secret-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }
        .meta-item {
            display: flex;
            flex-direction: column;
        }
        .meta-label {
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        .meta-value {
            color: #333;
            word-break: break-all;
        }
        .secret-value {
            background: #f8f9fa;
            border: 1px solid #e1e5e9;
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            margin: 10px 0;
        }
        .no-secrets {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }
        .no-secrets h3 {
            color: #2e7d32;
            margin-bottom: 10px;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e1e5e9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 GitHub Secrets Scan Report</h1>
            <p>Repository: <strong>$repo_name</strong></p>
            <p>Organization: <strong>$org_name</strong></p>
            <p class="timestamp">Generated: $(date)</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">$secret_count</div>
                    <div class="stat-label">Secrets Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$(date +%Y-%m-%d)</div>
                    <div class="stat-label">Scan Date</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">TruffleHog</div>
                    <div class="stat-label">Scanner Used</div>
                </div>
            </div>
        </div>
        
        <div class="secrets-section">
            <h2>🔐 Detected Secrets</h2>
EOF

    if [[ "$secret_count" -gt 0 ]]; then
        # Process JSON file and generate secret items
        jq -r '.[] | @base64' "$json_file" 2>/dev/null | while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local secret_data=$(echo "$line" | base64 -d)
                local detector_name=$(echo "$secret_data" | jq -r '.DetectorName // "Unknown"')
                local severity=$(echo "$secret_data" | jq -r '.Severity // "medium"')
                local verified=$(echo "$secret_data" | jq -r '.Verified // false')
                local raw=$(echo "$secret_data" | jq -r '.Raw // ""')
                local redacted=$(echo "$secret_data" | jq -r '.Redacted // ""')
                local file=$(echo "$secret_data" | jq -r '.File // "N/A"')
                local line_num=$(echo "$secret_data" | jq -r '.Line // "N/A"')
                local commit=$(echo "$secret_data" | jq -r '.Commit // "N/A"')
                local link=$(echo "$secret_data" | jq -r '.Link // "N/A"')
                local is_canary=$(echo "$secret_data" | jq -r '.Canary // false')
                
                echo "            <div class=\"secret-item\">" >> "$html_file"
                echo "                <div class=\"secret-header\">" >> "$html_file"
                echo "                    <div class=\"secret-title\">$detector_name</div>" >> "$html_file"
                echo "                    <div class=\"severity $severity\">$severity</div>" >> "$html_file"
                echo "                </div>" >> "$html_file"
                echo "                <div class=\"secret-content\">" >> "$html_file"
                echo "                    <div class=\"secret-meta\">" >> "$html_file"
                echo "                        <div class=\"meta-item\"><span class=\"meta-label\">File:</span> $file</div>" >> "$html_file"
                echo "                        <div class=\"meta-item\"><span class=\"meta-label\">Line:</span> $line_num</div>" >> "$html_file"
                echo "                        <div class=\"meta-item\"><span class=\"meta-label\">Commit:</span> $commit</div>" >> "$html_file"
                echo "                        <div class=\"meta-item\"><span class=\"meta-label\">Verified:</span> $verified</div>" >> "$html_file"
                
                if [[ "$is_canary" == "true" ]]; then
                    echo "                        <div class=\"meta-item\"><span class=\"meta-label\">⚠️ Canary Token:</span> Yes</div>" >> "$html_file"
                fi
                
                if [[ "$link" != "N/A" ]]; then
                    echo "                        <div class=\"meta-item\"><span class=\"meta-label\">Link:</span> <a href=\"$link\" target=\"_blank\">View in GitHub</a></div>" >> "$html_file"
                fi
                
                echo "                    </div>" >> "$html_file"
                
                if [[ -n "$redacted" && "$redacted" != "null" ]]; then
                    echo "                    <div class=\"secret-value\">$redacted</div>" >> "$html_file"
                fi
                
                echo "                </div>" >> "$html_file"
                echo "            </div>" >> "$html_file"
            fi
        done
    else
        echo "            <div class=\"no-secrets\">" >> "$html_file"
        echo "                <h3>✅ No Secrets Found</h3>" >> "$html_file"
        echo "                <p>Great! No secrets were detected in this repository.</p>" >> "$html_file"
        echo "            </div>" >> "$html_file"
    fi
    
    cat >> "$html_file" <<EOF
        </div>
        
        <div class="footer">
            <p>Generated by AutoAR GitHub Secrets Scanner | Powered by TruffleHog</p>
            <p>Scan completed at $(date)</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_success "HTML report generated: $html_file"
}

# Function to scan GitHub repository for secrets
github_scan() {
    local repo_url=""
    local verbose=false
    
    # Debug logging
    log_info "Debug: Received $# arguments: $@"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--repo)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing repository URL after -r flag"
                    exit 1
                fi
                repo_url="$2"
                shift
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            *)
                # If no flag, treat as repo URL for backward compatibility
                if [[ -z "$repo_url" ]]; then
                    repo_url="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$repo_url" ]]; then
        log_error "Repository URL is required. Use: github scan -r <owner/repo>"
        exit 1
    fi
    
    # Convert owner/repo to full GitHub URL if needed
    if [[ "$repo_url" != http* ]]; then
        repo_url="https://github.com/$repo_url"
    fi
    
    local repo_name=$(basename "$repo_url" .git)
    local org_name=$(echo "$repo_url" | sed 's|.*github.com/||' | cut -d'/' -f1)
    
    log_info "Starting GitHub secrets scan for: $repo_name"
    
    # Create results directory
    local dir; dir="$(results_dir "github_$repo_name")"
    local github_dir="$dir/vulnerabilities/github"
    ensure_dir "$github_dir"
    
    # Create temporary directory for this scan
    local temp_dir="/tmp/github_scan_$$_$repo_name"
    mkdir -p "$temp_dir"
    
    # Clone the repository
    log_info "Cloning $repo_url..."
    if git clone --depth 1 "$repo_url" "$temp_dir/$repo_name" 2>/dev/null; then
        log_success "Cloned $repo_name successfully"
        
        # Scan for secrets using TruffleHog
        local secrets_file="$temp_dir/${repo_name}_secrets.json"
        log_info "Scanning for secrets using TruffleHog..."
        
        # Check if TruffleHog is available
        if ! command -v trufflehog >/dev/null 2>&1; then
            log_error "TruffleHog is not installed or not in PATH"
            return 1
        fi
        
        # Send progress notification
        discord_send_progress "🔍 **Scanning GitHub repository: $repo_name**"
        
        # Disable TruffleHog auto-update to prevent updater errors
        export TRUFFLEHOG_NO_UPDATE=true
        export TRUFFLEHOG_AUTOUPDATE=false
        if trufflehog filesystem "$temp_dir/$repo_name" --json --no-update > "$secrets_file" 2>&1; then
            # Convert newline-delimited JSON to JSON array for counting
            local temp_json_array="$github_dir/${repo_name}_secrets_array.json"
            if [[ -s "$secrets_file" ]]; then
                # Filter out any non-finding log lines; keep only real findings
                jq -s '[.[] | select(.DetectorName != null)]' "$secrets_file" > "$temp_json_array" 2>/dev/null || echo "[]" > "$temp_json_array"
            else
                echo "[]" > "$temp_json_array"
            fi
            
            local secret_count=$(jq '. | length' "$temp_json_array" 2>/dev/null || echo "0")
            
            if [[ "$secret_count" -gt 0 ]]; then
                log_success "Found $secret_count secrets in $repo_name"
                
                # Generate HTML report
                local html_report="$github_dir/${repo_name}_secrets.html"
                generate_github_html_report "$repo_name" "$org_name" "$temp_json_array" "$html_report" "$secret_count"
                
                # Discord notification will be handled by the bot automatically
                
                log_success "GitHub scan completed for $repo_name - Found $secret_count secrets"
            else
                log_info "No secrets found in $repo_name"
                
                # Generate empty reports for no findings
                local json_report="$github_dir/${repo_name}_secrets.json"
                local html_report="$github_dir/${repo_name}_secrets.html"
                echo "[]" > "$json_report"
                generate_github_html_report "$repo_name" "$org_name" "$json_report" "$html_report" "0"
                
                # Discord notification will be handled by the bot automatically
                
                log_success "GitHub scan completed for $repo_name - No secrets found"
            fi
        else
            log_error "TruffleHog scan failed for $repo_name"
            if [[ -s "$secrets_file" ]]; then
                log_error "TruffleHog output:"
                cat "$secrets_file" | head -20
                if [[ $(wc -l < "$secrets_file") -gt 20 ]]; then
                    log_error "... (truncated, see full output in $secrets_file)"
                fi
            fi
            return 1
        fi
    else
        log_error "Failed to clone $repo_url"
        return 1
    fi
    
    # Clean up temporary directory
    rm -rf "$temp_dir"
}

# Function to scan GitHub repository for dependency confusion vulnerabilities
github_depconfusion_scan() {
    local repo_url=""
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--repo)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing repository URL after -r flag"
                    exit 1
                fi
                repo_url="$2"
                shift
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            *)
                if [[ -z "$repo_url" ]]; then
                    repo_url="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$repo_url" ]]; then
        log_error "Repository URL is required. Use: github depconfusion -r <owner/repo>"
        exit 1
    fi
    
    # Convert owner/repo to full GitHub URL if needed
    if [[ "$repo_url" != http* ]]; then
        repo_url="https://github.com/$repo_url"
    fi
    
    local repo_name=$(basename "$repo_url" .git)
    local org_name=$(echo "$repo_url" | sed 's|.*github.com/||' | cut -d'/' -f1)
    
    log_info "Starting GitHub dependency confusion scan for: $repo_name"
    
    # Check if confused tool is installed
    if ! command -v confused >/dev/null 2>&1; then
        log_error "Confused tool not found. Please install it with: go install github.com/h0tak88r/confused@latest"
        return 1
    fi
    
    # Create results directory
    local dir; dir="$(results_dir "github_$repo_name")"
    local depconfusion_dir="$dir/vulnerabilities/depconfusion"
    ensure_dir "$depconfusion_dir"
    
    # Send progress notification
    discord_send_progress "🔍 **Scanning GitHub repository for dependency confusion: $repo_name**"
    
    # Use confused tool's GitHub scanning capabilities
    local confused_output="$depconfusion_dir/confused-results.txt"
    if confused github repo "$org_name/$repo_name" > "$confused_output" 2>&1; then
        # Check if vulnerabilities were found
        if grep -q "Issues found" "$confused_output"; then
            log_warn "Dependency confusion vulnerabilities found in $repo_name"
            
            # Generate HTML report for dependency confusion
            local html_report="$depconfusion_dir/depconfusion-report.html"
            generate_depconfusion_html_report "$repo_name" "$org_name" "$confused_output" "$html_report"
            
            discord_send_progress "⚠️ **Found dependency confusion vulnerabilities in $repo_name**"
            log_success "GitHub dependency confusion scan completed for $repo_name - Vulnerabilities found"
        else
            log_info "No dependency confusion vulnerabilities found in $repo_name"
            
            # Generate empty report
            local html_report="$depconfusion_dir/depconfusion-report.html"
            generate_depconfusion_html_report "$repo_name" "$org_name" "$confused_output" "$html_report"
            
            discord_send_progress "✅ **No dependency confusion vulnerabilities found in $repo_name**"
            log_success "GitHub dependency confusion scan completed for $repo_name - No vulnerabilities found"
        fi
    else
        log_error "Confused dependency confusion scan failed for $repo_name"
        if [[ -s "$confused_output" ]]; then
            log_error "Confused output:"
            cat "$confused_output" | head -20
        fi
        return 1
    fi
}

# Function to generate HTML report for dependency confusion
generate_depconfusion_html_report() {
    local repo_name="$1"
    local org_name="$2"
    local confused_output="$3"
    local html_file="$4"
    
    log_info "Generating HTML report for dependency confusion scan of $repo_name..."
    
    cat > "$html_file" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dependency Confusion Scan Report - $repo_name</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 5px 0;
            font-size: 1.1em;
        }
        .timestamp {
            font-style: italic;
            opacity: 0.9;
        }
        .summary {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        .summary h2 {
            color: #ff6b6b;
            margin-top: 0;
        }
        .results-section {
            padding: 30px;
        }
        .results-content {
            background: #f8f9fa;
            border: 1px solid #e1e5e9;
            border-radius: 8px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            overflow-x: auto;
        }
        .no-vulnerabilities {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }
        .no-vulnerabilities h3 {
            color: #2e7d32;
            margin-bottom: 10px;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e1e5e9;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Dependency Confusion Scan Report</h1>
            <p>Repository: <strong>$repo_name</strong></p>
            <p>Organization: <strong>$org_name</strong></p>
            <p class="timestamp">Generated: $(date)</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <p>This report contains the results of a dependency confusion vulnerability scan performed using the Confused tool.</p>
        </div>
        
        <div class="results-section">
            <h2>🔍 Scan Results</h2>
EOF

    if grep -q "Issues found" "$confused_output"; then
        echo "            <div class=\"results-content\">" >> "$html_file"
        cat "$confused_output" >> "$html_file"
        echo "            </div>" >> "$html_file"
    else
        echo "            <div class=\"no-vulnerabilities\">" >> "$html_file"
        echo "                <h3>✅ No Dependency Confusion Vulnerabilities Found</h3>" >> "$html_file"
        echo "                <p>Great! No dependency confusion vulnerabilities were detected in this repository.</p>" >> "$html_file"
        echo "            </div>" >> "$html_file"
    fi
    
    cat >> "$html_file" <<EOF
        </div>
        
        <div class="footer">
            <p>Generated by AutoAR Dependency Confusion Scanner | Powered by Confused Tool</p>
            <p>Scan completed at $(date)</p>
        </div>
    </div>
</body>
</html>
EOF
    
    log_success "HTML report generated: $html_file"
}

# Function to scan GitHub organization for secrets
github_org_scan() {
    local org_name=""
    local max_repos="50"
    local verbose=false
    
    # Debug logging
    log_info "Debug: Received $# arguments: $@"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--org)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing organization name after -o flag"
                    exit 1
                fi
                org_name="$2"
                shift
                shift
                ;;
            -m|--max-repos)
                if [[ $# -lt 2 ]]; then
                    log_error "Missing max repositories value after -m flag"
                    exit 1
                fi
                max_repos="$2"
                shift
                shift
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            *)
                # If no flag, treat as org name for backward compatibility
                if [[ -z "$org_name" ]]; then
                    org_name="$1"
                fi
                shift
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$org_name" ]]; then
        log_error "Organization name is required. Use: github org -o <org> [-m <max-repos>]"
        exit 1
    fi
    
    log_info "Starting GitHub organization scan for: $org_name"
    log_info "Maximum repositories to scan: $max_repos"
    
    # Create results directory
    local dir; dir="$(results_dir "github_org_$org_name")"
    local org_dir="$dir/vulnerabilities/github"
    ensure_dir "$org_dir"
    
    # Use TruffleHog organization scan
    local org_results_file="$org_dir/org_secrets.json"
    log_info "Scanning organization with TruffleHog..."
    
    # Ensure GitHub auth is available to TruffleHog
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        export GITHUB_TOKEN
    fi
    
    # Check if TruffleHog is available
    if ! command -v trufflehog >/dev/null 2>&1; then
        log_error "TruffleHog is not installed or not in PATH"
        return 1
    fi
    
    # Check if GitHub token is available
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        log_error "GITHUB_TOKEN environment variable is required for organization scanning"
        return 1
    fi
    
    # Send progress notification
    discord_send_progress "🔍 **Scanning GitHub organization: $org_name** (max $max_repos repos)"
    
    log_info "Running TruffleHog with GitHub token..."
    # Disable TruffleHog auto-update to prevent updater errors
    export TRUFFLEHOG_NO_UPDATE=true
    export TRUFFLEHOG_AUTOUPDATE=false
    if trufflehog github --org="$org_name" --issue-comments --pr-comments --json --no-update > "$org_results_file" 2>&1; then
        # Convert newline-delimited JSON to JSON array for counting
        local temp_json_array="$org_dir/org_secrets_array.json"
        if [[ -s "$org_results_file" ]]; then
            # Filter out any non-finding log lines; keep only real findings
            jq -s '[.[] | select(.DetectorName != null)]' "$org_results_file" > "$temp_json_array" 2>/dev/null || echo "[]" > "$temp_json_array"
        else
            echo "[]" > "$temp_json_array"
        fi
        
        local total_secrets=$(jq '. | length' "$temp_json_array" 2>/dev/null || echo "0")
        
        if [[ "$total_secrets" -gt 0 ]]; then
            log_success "Found $total_secrets secrets in organization $org_name"
            
            # Generate HTML report for organization
            local html_report="$org_dir/org_secrets.html"
            generate_github_html_report "$org_name" "$org_name" "$temp_json_array" "$html_report" "$total_secrets"
            
            # Send HTML report to Discord
            discord_file "$html_report" "GitHub Organization Secrets Report for $org_name"
            
            log_success "Organization scan completed for $org_name - Found $total_secrets secrets"
        else
            log_info "No secrets found in organization $org_name"
            
            # Generate empty reports for no findings
            local html_report="$org_dir/org_secrets.html"
            generate_github_html_report "$org_name" "$org_name" "$temp_json_array" "$html_report" "0"
            
            # Send HTML report to Discord
            discord_file "$html_report" "GitHub Organization Secrets Report for $org_name (No secrets found)"
            
            log_success "Organization scan completed for $org_name - No secrets found"
        fi
        else
            log_error "TruffleHog organization scan failed for $org_name"
            if [[ -s "$org_results_file" ]]; then
                log_error "TruffleHog output:"
                cat "$org_results_file" | head -20
                if [[ $(wc -l < "$org_results_file") -gt 20 ]]; then
                    log_error "... (truncated, see full output in $org_results_file)"
                fi
            fi
            return 1
        fi
}

case "${1:-}" in
  scan) shift; github_scan "$@" ;;
  org) shift; github_org_scan "$@" ;;
  depconfusion) shift; github_depconfusion_scan "$@" ;;
  *) usage; exit 1;;
esac
