#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: github scan -r <owner/repo> | github org -o <org> [-m <max-repos>] | github depconfusion -r <owner/repo> | github experimental -r <owner/repo>"; }

# Function to generate HTML report for GitHub secrets using Python script
generate_github_html_report() {
    local repo_name="$1"
    local org_name="$2"
    local json_file="$3"
    local html_file="$4"
    local secret_count="$5"
    
    log_info "Generating HTML report for $repo_name..."
    
    # Use Python script for HTML generation (more reliable and handles large files better)
    local python_script="$ROOT_DIR/python/github_html_report.py"
    
    if [[ ! -f "$python_script" ]]; then
        log_error "Python HTML report generator not found: $python_script"
        return 1
    fi
    
    if python3 "$python_script" "$json_file" "$html_file" "$repo_name" "$org_name" "$secret_count"; then
        log_success "HTML report generated: $html_file"
        return 0
    else
        log_error "Failed to generate HTML report"
        return 1
    fi
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
    
    # Detect if input is organization vs repository
    # If it doesn't contain a "/" and isn't a full URL, it's likely an organization
    if [[ "$repo_url" != http* && "$repo_url" != */* ]]; then
        log_error "Input '$repo_url' appears to be an organization, not a repository."
        log_error "For organization scans, use: github org -o $repo_url"
        log_error "For repository scans, use: github scan -r <owner/repo> (e.g., github scan -r $repo_url/some-repo)"
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
    
    # Create temporary directory for scan output
    local temp_dir="/tmp/github_scan_$$_$repo_name"
    mkdir -p "$temp_dir"
    local secrets_file="$temp_dir/${repo_name}_secrets.json"
    
    # Check if TruffleHog is available
    if ! command -v trufflehog >/dev/null 2>&1; then
        log_error "TruffleHog is not installed or not in PATH"
        return 1
    fi
    
    # Test TruffleHog installation
    local trufflehog_version=$(trufflehog --version 2>&1 || echo "unknown")
    if [[ "$verbose" == "true" ]]; then
        log_info "TruffleHog version: $trufflehog_version"
    fi
    
    # Send progress notification
    discord_send_progress "🔍 **Scanning GitHub repository: $repo_name**"
    
    log_info "Scanning for secrets using TruffleHog git scanner..."
    
    # Disable TruffleHog auto-update to prevent updater errors
    export TRUFFLEHOG_NO_UPDATE=true
    export TRUFFLEHOG_AUTOUPDATE=false
    
    # Set GitHub token as environment variable (trufflehog git may not support --token flag)
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        export GITHUB_TOKEN
        export GH_TOKEN="$GITHUB_TOKEN"
        log_info "Using GitHub token for improved rate limits (via environment variable)"
    fi
    
    # Use trufflehog git to scan the repository directly (scans commit history)
    # Note: trufflehog git doesn't support --token flag, use environment variables instead
    local trufflehog_stderr="$temp_dir/trufflehog_stderr.log"
    
    # Log the exact command being run
    if [[ "$verbose" == "true" ]]; then
        log_info "Running command: trufflehog git \"$repo_url\" --json --no-update"
    fi
    
    # Run trufflehog and capture both stdout and stderr separately
    local trufflehog_exit=0
    trufflehog git "$repo_url" --json --no-update > "$secrets_file" 2> "$trufflehog_stderr" || trufflehog_exit=$?
    
    # If remote git scan returns empty output, try cloning and scanning locally
    if [[ ! -s "$secrets_file" && $trufflehog_exit -ne 0 ]]; then
        log_info "Remote git scan returned empty, trying to clone and scan locally..."
        
        # Clone the repository
        local cloned_repo="$temp_dir/$repo_name"
        if git clone --depth 1 "$repo_url" "$cloned_repo" 2>/dev/null; then
            log_info "Cloned repository successfully, scanning local clone..."
            
            # Try scanning the cloned repository
            trufflehog git "$cloned_repo" --json --no-update > "$secrets_file" 2> "$trufflehog_stderr" || trufflehog_exit=$?
            
            if [[ "$verbose" == "true" ]]; then
                log_info "Local scan exit code: $trufflehog_exit"
                log_info "Local scan output size: $(wc -l < "$secrets_file" 2>/dev/null || echo 0) lines"
            fi
        else
            log_warn "Failed to clone repository, continuing with empty results"
        fi
    fi
    
    # Check stderr for errors
    if [[ -s "$trufflehog_stderr" ]]; then
        log_warn "TruffleHog stderr output:"
        cat "$trufflehog_stderr" | while IFS= read -r line; do
            log_warn "  $line"
        done
    fi
    
    # Debug: Check what TruffleHog actually returned
    if [[ "$verbose" == "true" ]]; then
        log_info "TruffleHog exit code: $trufflehog_exit"
        log_info "TruffleHog stdout file size: $(wc -l < "$secrets_file" 2>/dev/null || echo 0) lines"
        log_info "TruffleHog stderr file size: $(wc -l < "$trufflehog_stderr" 2>/dev/null || echo 0) lines"
        if [[ -s "$secrets_file" ]]; then
            log_info "First 5 lines of TruffleHog stdout:"
            head -5 "$secrets_file" | while IFS= read -r line; do
                log_info "  $line"
            done
        fi
        if [[ -s "$trufflehog_stderr" ]]; then
            log_info "First 5 lines of TruffleHog stderr:"
            head -5 "$trufflehog_stderr" | while IFS= read -r line; do
                log_info "  $line"
            done
        fi
    fi
    
    # Process output even if exit code is non-zero (some TruffleHog versions return non-zero on findings)
    if [[ $trufflehog_exit -eq 0 || -s "$secrets_file" ]]; then
        
        # Convert newline-delimited JSON to JSON array for counting
        local temp_json_array="$github_dir/${repo_name}_secrets_array.json"
        if [[ -s "$secrets_file" ]]; then
            # Filter out any non-finding log lines; keep only real findings
            # First try to parse as NDJSON (newline-delimited JSON)
            jq -s '[.[] | select(.DetectorName != null)]' "$secrets_file" > "$temp_json_array" 2>/dev/null || {
                # If that fails, try parsing line by line
                if [[ "$verbose" == "true" ]]; then
                    log_warn "Failed to parse as NDJSON, trying line-by-line parsing"
                fi
                echo "[]" > "$temp_json_array"
                while IFS= read -r line; do
                    if [[ -n "$line" ]]; then
                        # Try to parse each line as JSON
                        if echo "$line" | jq -e '.DetectorName != null' >/dev/null 2>&1; then
                            # This line is a valid finding, add it to the array
                            jq --argjson new "$line" '. += [$new]' "$temp_json_array" > "${temp_json_array}.tmp" && mv "${temp_json_array}.tmp" "$temp_json_array"
                        fi
                    fi
                done < "$secrets_file"
            }
        else
            echo "[]" > "$temp_json_array"
        fi
        
        local secret_count=$(jq '. | length' "$temp_json_array" 2>/dev/null || echo "0")
        
        if [[ "$secret_count" -gt 0 ]]; then
            log_success "Found $secret_count secrets in $repo_name"
            
            # Generate HTML report
            local html_report="$github_dir/${repo_name}_secrets.html"
            generate_github_html_report "$repo_name" "$org_name" "$temp_json_array" "$html_report" "$secret_count"
            
            # Send summary message to Discord
            discord_send "**GitHub Repository Scan Results**\n**Repository:** \`$repo_name\`\n**Organization:** \`$org_name\`\n**Secrets found:** \`$secret_count\`\n**Timestamp:** \`$(date)\`"
            
            # Send both JSON and HTML reports to Discord
            discord_file "$temp_json_array" "**GitHub Repository Secrets Report (JSON) for \`$repo_name\`**"
            discord_file "$html_report" "**GitHub Repository Secrets Report (HTML) for \`$repo_name\`**"
            
            log_success "GitHub scan completed for $repo_name - Found $secret_count secrets"
        else
            log_info "No secrets found in $repo_name"
            
            # Generate empty reports for no findings
            local json_report="$github_dir/${repo_name}_secrets.json"
            local html_report="$github_dir/${repo_name}_secrets.html"
            echo "[]" > "$json_report"
            generate_github_html_report "$repo_name" "$org_name" "$json_report" "$html_report" "0"
            
            # Send summary message to Discord
            discord_send "**GitHub Repository Scan Results**\n**Repository:** \`$repo_name\`\n**Organization:** \`$org_name\`\n**Secrets found:** \`0\`\n**Timestamp:** \`$(date)\`"
            
            # Send both JSON and HTML reports to Discord
            discord_file "$temp_json_array" "**GitHub Repository Secrets Report (JSON) for \`$repo_name\`**"
            discord_file "$html_report" "**GitHub Repository Secrets Report (HTML) for \`$repo_name\`**"
            
            log_success "GitHub scan completed for $repo_name - No secrets found"
        fi
    else
        log_error "TruffleHog scan failed for $repo_name (exit code: $trufflehog_exit)"
        if [[ -s "$trufflehog_stderr" ]]; then
            log_error "TruffleHog stderr:"
            cat "$trufflehog_stderr" | head -20
            if [[ $(wc -l < "$trufflehog_stderr") -gt 20 ]]; then
                log_error "... (truncated, see full output in $trufflehog_stderr)"
            fi
        fi
        if [[ -s "$secrets_file" ]]; then
            log_error "TruffleHog stdout:"
            cat "$secrets_file" | head -20
            if [[ $(wc -l < "$secrets_file") -gt 20 ]]; then
                log_error "... (truncated, see full output in $secrets_file)"
            fi
        fi
        log_error "TruffleHog command that failed: trufflehog git \"$repo_url\" --json --no-update"
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
    discord_send_progress "**Scanning GitHub organization: $org_name** (max $max_repos repos)"
    
    log_info "Running TruffleHog with GitHub token..."
    # Disable TruffleHog auto-update to prevent updater errors
    export TRUFFLEHOG_NO_UPDATE=true
    export TRUFFLEHOG_AUTOUPDATE=false
    
    # Build trufflehog command with token
    local trufflehog_cmd=("trufflehog" "github" "--org=$org_name" "--issue-comments" "--pr-comments" "--json" "--no-update")
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        trufflehog_cmd+=("--token" "$GITHUB_TOKEN")
        log_info "Using GitHub token for improved rate limits"
    fi
    
    if "${trufflehog_cmd[@]}" > "$org_results_file" 2>&1; then
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
            
            # Send summary message to Discord
            discord_send "**GitHub Organization Scan Results**\n**Organization:** \`$org_name\`\n**Secrets found:** \`$total_secrets\`\n**Timestamp:** \`$(date)\`"
            
            # Send both JSON and HTML reports to Discord
            discord_file "$temp_json_array" "**GitHub Organization Secrets Report (JSON) for \`$org_name\`**"
            discord_file "$html_report" "**GitHub Organization Secrets Report (HTML) for \`$org_name\`**"
            
            log_success "Organization scan completed for $org_name - Found $total_secrets secrets"
        else
            log_info "No secrets found in organization $org_name"
            
            # Generate empty reports for no findings
            local html_report="$org_dir/org_secrets.html"
            generate_github_html_report "$org_name" "$org_name" "$temp_json_array" "$html_report" "0"
            
            # Send summary message to Discord
            discord_send "**GitHub Organization Scan Results**\n**Organization:** \`$org_name\`\n**Secrets found:** \`0\`\n**Timestamp:** \`$(date)\`"
            
            # Send both JSON and HTML reports to Discord
            discord_file "$temp_json_array" "**GitHub Organization Secrets Report (JSON) for \`$org_name\`**"
            discord_file "$html_report" "**GitHub Organization Secrets Report (HTML) for \`$org_name\`**"
            
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

# Function to scan GitHub repository using experimental TruffleHog mode
github_experimental_scan() {
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
        log_error "Repository URL is required. Use: github experimental -r <owner/repo>"
        exit 1
    fi
    
    # Convert owner/repo to full GitHub URL if needed
    if [[ "$repo_url" != http* ]]; then
        repo_url="https://github.com/$repo_url"
    fi
    
    # Ensure .git extension for TruffleHog experimental
    if [[ "$repo_url" != *.git ]]; then
        repo_url="${repo_url}.git"
    fi
    
    local repo_name=$(basename "$repo_url" .git)
    local org_name=$(echo "$repo_url" | sed 's|.*github.com/||' | cut -d'/' -f1)
    
    log_info "Starting GitHub experimental scan for: $repo_name"
    
    # Create results directory
    local dir; dir="$(results_dir "github_experimental_$repo_name")"
    local github_dir="$dir/vulnerabilities/github"
    ensure_dir "$github_dir"
    
    # Create temporary directory for scan output
    local temp_dir="/tmp/github_experimental_scan_$$_$repo_name"
    mkdir -p "$temp_dir"
    local secrets_file="$temp_dir/${repo_name}_secrets.json"
    
    # Check if TruffleHog is available
    if ! command -v trufflehog >/dev/null 2>&1; then
        log_error "TruffleHog is not installed or not in PATH"
        return 1
    fi
    
    # Send progress notification
    discord_send_progress "**Scanning GitHub repository (experimental mode): $repo_name**"
    
    log_info "Scanning for secrets using TruffleHog experimental scanner with object discovery..."
    
    # Disable TruffleHog auto-update to prevent updater errors
    export TRUFFLEHOG_NO_UPDATE=true
    export TRUFFLEHOG_AUTOUPDATE=false
    
    # Build trufflehog experimental command with token if available
    local trufflehog_cmd=("trufflehog" "github-experimental" "--repo" "$repo_url" "--object-discovery" "--json" "--no-update")
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        trufflehog_cmd+=("--token" "$GITHUB_TOKEN")
        log_info "Using GitHub token for improved rate limits"
    fi
    
    # Use trufflehog github-experimental with object discovery
    if "${trufflehog_cmd[@]}" > "$secrets_file" 2>&1; then
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
            log_success "Found $secret_count secrets in $repo_name (experimental scan)"
            
            # Generate HTML report
            local html_report="$github_dir/${repo_name}_secrets.html"
            generate_github_html_report "$repo_name" "$org_name" "$temp_json_array" "$html_report" "$secret_count"
            
            # Discord notification will be handled by the bot automatically
            
            log_success "GitHub experimental scan completed for $repo_name - Found $secret_count secrets"
        else
            log_info "No secrets found in $repo_name (experimental scan)"
            
            # Generate empty reports for no findings
            local json_report="$github_dir/${repo_name}_secrets.json"
            local html_report="$github_dir/${repo_name}_secrets.html"
            echo "[]" > "$json_report"
            generate_github_html_report "$repo_name" "$org_name" "$json_report" "$html_report" "0"
            
            # Discord notification will be handled by the bot automatically
            
            log_success "GitHub experimental scan completed for $repo_name - No secrets found"
        fi
    else
        log_error "TruffleHog experimental scan failed for $repo_name"
        if [[ -s "$secrets_file" ]]; then
            log_error "TruffleHog output:"
            cat "$secrets_file" | head -20
            if [[ $(wc -l < "$secrets_file") -gt 20 ]]; then
                log_error "... (truncated, see full output in $secrets_file)"
            fi
        fi
        return 1
    fi
    
    # Clean up temporary directory
    rm -rf "$temp_dir"
}

case "${1:-}" in
  scan) shift; github_scan "$@" ;;
  org) shift; github_org_scan "$@" ;;
  depconfusion) shift; github_depconfusion_scan "$@" ;;
  experimental) shift; github_experimental_scan "$@" ;;
  *) usage; exit 1;;
esac
