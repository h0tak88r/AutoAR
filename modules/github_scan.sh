#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: github scan -r <owner/repo> | github org -o <org> [-m <max-repos>] | github depconfusion -r <owner/repo> | github experimental -r <owner/repo>"; }

# Function to extract unique secrets (deduplicate by raw secret value only) using jq
extract_unique_secrets() {
    local json_file="$1"
    local output_file="$2"
    
    log_info "Extracting unique secrets from JSON (deduplicating by raw secret value)..."
    
    # Extract secrets and deduplicate by raw secret value only
    # This ensures the same secret value appears only once, regardless of detector name
    jq -r '.[] | 
        select((.Raw != null and .Raw != "" and .Raw != "null") or 
               (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) |
        {
            "detector": (.SourceMetadata.DetectorName // .DetectorName // "Unknown"),
            "secret": (.Raw // .SourceMetadata.Raw // "")
        } | 
        select(.secret != "")' \
        "$json_file" 2>/dev/null | \
    jq -s 'unique_by(.secret) | .[] | "\(.detector): \(.secret)"' \
        > "$output_file" 2>/dev/null || {
        # Fallback: try Redacted if Raw is not available
        jq -r '.[] | 
            select((.Redacted != null and .Redacted != "" and .Redacted != "null") or 
                   (.SourceMetadata.Redacted != null and .SourceMetadata.Redacted != "" and .SourceMetadata.Redacted != "null")) |
            {
                "detector": (.SourceMetadata.DetectorName // .DetectorName // "Unknown"),
                "secret": (.Redacted // .SourceMetadata.Redacted // "")
            } | 
            select(.secret != "")' \
            "$json_file" 2>/dev/null | \
        jq -s 'unique_by(.secret) | .[] | "\(.detector): \(.secret)"' \
            > "$output_file" 2>/dev/null || {
            echo "No secrets found" > "$output_file"
        }
    }
    
    if [[ -f "$output_file" && -s "$output_file" ]]; then
        local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
        log_success "Extracted $count unique secrets (deduplicated by raw value) to $output_file"
        return 0
    else
        log_warn "Failed to extract secrets"
        return 1
    fi
}

# Function to generate table format using jtbl (if available) or plain text
# Deduplicates by raw secret value only
generate_secrets_table() {
    local json_file="$1"
    local output_file="$2"
    
    log_info "Generating secrets table (deduplicating by raw secret value)..."
    
    # Check if jtbl is available (try multiple methods)
    local jtbl_cmd=""
    if command -v jtbl >/dev/null 2>&1; then
        jtbl_cmd="jtbl"
    elif python3 -m jtbl --version >/dev/null 2>&1; then
        jtbl_cmd="python3 -m jtbl"
    elif python3 -c "import jtbl" >/dev/null 2>&1; then
        jtbl_cmd="python3 -m jtbl"
    fi
    
    if [[ -n "$jtbl_cmd" ]]; then
        # Use jtbl to create a nice table from JSON
        # Extract detector name, raw secret, and link, deduplicate by secret value only
        # jtbl expects JSON array input, so we collect all objects into an array
        local temp_json=$(mktemp)
        local jq_error=$(mktemp)
        
        # Extract and deduplicate secrets (include link from SourceMetadata.Data.Github.link)
        jq -r '.[] | 
            select((.Raw != null and .Raw != "" and .Raw != "null") or 
                   (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) |
            {
                "Detector": (.SourceMetadata.DetectorName // .DetectorName // "Unknown"),
                "Secret": (.Raw // .SourceMetadata.Raw // ""),
                "Link": (.SourceMetadata.Data.Github.link // .SourceMetadata.Data.Git.link // "N/A")
            } | 
            select(.Secret != "")' \
            "$json_file" 2>"$jq_error" | \
        jq -s 'unique_by(.Secret)' > "$temp_json" 2>>"$jq_error"
        
        if [[ -f "$temp_json" && -s "$temp_json" ]]; then
            # jtbl works with JSON arrays
            local jtbl_error=$(mktemp)
            if $jtbl_cmd < "$temp_json" > "$output_file" 2>"$jtbl_error"; then
                rm -f "$temp_json" "$jq_error" "$jtbl_error"
                log_success "Secrets table generated using jtbl: $output_file"
                return 0
            else
                if [[ -s "$jtbl_error" ]]; then
                    log_warn "jtbl error: $(cat "$jtbl_error" | head -1)"
                fi
                rm -f "$temp_json" "$jq_error" "$jtbl_error"
                log_warn "jtbl processing failed, generating simple table format"
                # Generate simple table format manually
                {
                    echo "Detector|Secret|Link"
                    echo "--------|------|----"
                    jq -r '.[] | 
                        select((.Raw != null and .Raw != "" and .Raw != "null") or 
                               (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) |
                        "\(.SourceMetadata.DetectorName // .DetectorName // "Unknown")|\(.Raw // .SourceMetadata.Raw // "")|\(.SourceMetadata.Data.Github.link // .SourceMetadata.Data.Git.link // "N/A")"' \
                        "$json_file" 2>/dev/null | \
                    sort -u -t'|' -k2 | \
                    awk -F'|' '{if ($2 != "") print $1 "|" $2 "|" $3}'
                } > "$output_file" 2>/dev/null || {
                    log_warn "Failed to generate table, using minimal format"
                    extract_unique_secrets "$json_file" "$output_file"
                }
            fi
        else
            if [[ -s "$jq_error" ]]; then
                log_warn "jq extraction error: $(cat "$jq_error" | head -1)"
            fi
            rm -f "$temp_json" "$jq_error"
            log_warn "Failed to extract secrets for table, generating simple format"
            # Generate simple table format manually
            {
                echo "Detector|Secret|Link"
                echo "--------|------|----"
                jq -r '.[] | 
                    select((.Raw != null and .Raw != "" and .Raw != "null") or 
                           (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) |
                    "\(.SourceMetadata.DetectorName // .DetectorName // "Unknown")|\(.Raw // .SourceMetadata.Raw // "")|\(.SourceMetadata.Data.Github.link // .SourceMetadata.Data.Git.link // "N/A")"' \
                    "$json_file" 2>/dev/null | \
                sort -u -t'|' -k2 | \
                awk -F'|' '{if ($2 != "") print $1 "|" $2 "|" $3}'
            } > "$output_file" 2>/dev/null || {
                log_warn "Failed to generate table, using minimal format"
                extract_unique_secrets "$json_file" "$output_file"
            }
        fi
    else
        # Fallback to simple table format if jtbl is not available
        log_warn "jtbl not found, generating simple table format"
        {
            echo "Detector|Secret|Link"
            echo "--------|------|----"
            jq -r '.[] | 
                select((.Raw != null and .Raw != "" and .Raw != "null") or 
                       (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) |
                "\(.SourceMetadata.DetectorName // .DetectorName // "Unknown")|\(.Raw // .SourceMetadata.Raw // "")|\(.SourceMetadata.Data.Github.link // .SourceMetadata.Data.Git.link // "N/A")"' \
                "$json_file" 2>/dev/null | \
            sort -u -t'|' -k2 | \
            awk -F'|' '{if ($2 != "") print $1 "|" $2 "|" $3}'
        } > "$output_file" 2>/dev/null || {
            log_warn "Failed to generate table, using minimal format"
            extract_unique_secrets "$json_file" "$output_file"
        }
    fi
    
    if [[ -f "$output_file" && -s "$output_file" ]]; then
        return 0
    else
        log_warn "Failed to generate secrets table"
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
            
            # Generate table format with unique secrets (includes Detector, Secret, and Link)
            local secrets_table="$github_dir/${repo_name}_secrets_table.txt"
            generate_secrets_table "$temp_json_array" "$secrets_table"
            
            # Count unique secrets from the table (if generated) or from JSON
            local unique_count=0
            if [[ -f "$secrets_table" && -s "$secrets_table" ]]; then
                # Count non-header lines in table (subtract 2 for header and separator)
                unique_count=$(grep -v "^Detector" "$secrets_table" | grep -v "^---" | grep -v "^$" | wc -l 2>/dev/null || echo "0")
            else
                # Fallback: count unique secrets from JSON
                unique_count=$(jq -r '.[] | select((.Raw != null and .Raw != "" and .Raw != "null") or (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) | .Raw // .SourceMetadata.Raw // ""' "$temp_json_array" 2>/dev/null | sort -u | wc -l 2>/dev/null || echo "0")
            fi
            
            # Send summary message to Discord
            discord_send "**GitHub Repository Scan Results**\n**Repository:** \`$repo_name\`\n**Organization:** \`$org_name\`\n**Total findings:** \`$secret_count\`\n**Unique secrets:** \`$unique_count\`\n**Timestamp:** \`$(date)\`"
            
            # Send JSON file and secrets table to Discord
            discord_file "$temp_json_array" "**GitHub Repository Secrets Report (JSON) for \`$repo_name\`**"
            if [[ -f "$secrets_table" && -s "$secrets_table" ]]; then
                discord_file "$secrets_table" "**GitHub Repository Secrets Table for \`$repo_name\`**"
            fi
            
            log_success "GitHub scan completed for $repo_name - Found $secret_count secrets ($unique_count unique)"
        else
            log_info "No secrets found in $repo_name"
            
            # Send summary message to Discord
            discord_send "**GitHub Repository Scan Results**\n**Repository:** \`$repo_name\`\n**Organization:** \`$org_name\`\n**Secrets found:** \`0\`\n**Timestamp:** \`$(date)\`"
            
            # Send JSON report to Discord (even if empty)
            discord_file "$temp_json_array" "**GitHub Repository Secrets Report (JSON) for \`$repo_name\`**"
            
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
            
            # Generate table format with unique secrets (includes Detector, Secret, and Link)
            local secrets_table="$org_dir/org_secrets_table.txt"
            generate_secrets_table "$temp_json_array" "$secrets_table"
            
            # Count unique secrets from the table (if generated) or from JSON
            local unique_count=0
            if [[ -f "$secrets_table" && -s "$secrets_table" ]]; then
                # Count non-header lines in table (subtract 2 for header and separator)
                unique_count=$(grep -v "^Detector" "$secrets_table" | grep -v "^---" | grep -v "^$" | wc -l 2>/dev/null || echo "0")
            else
                # Fallback: count unique secrets from JSON
                unique_count=$(jq -r '.[] | select((.Raw != null and .Raw != "" and .Raw != "null") or (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) | .Raw // .SourceMetadata.Raw // ""' "$temp_json_array" 2>/dev/null | sort -u | wc -l 2>/dev/null || echo "0")
            fi
            
            # Send summary message to Discord
            discord_send "**GitHub Organization Scan Results**\n**Organization:** \`$org_name\`\n**Total findings:** \`$total_secrets\`\n**Unique secrets:** \`$unique_count\`\n**Timestamp:** \`$(date)\`"
            
            # Send JSON file and secrets table to Discord
            discord_file "$temp_json_array" "**GitHub Organization Secrets Report (JSON) for \`$org_name\`**"
            if [[ -f "$secrets_table" && -s "$secrets_table" ]]; then
                discord_file "$secrets_table" "**GitHub Organization Secrets Table for \`$org_name\`**"
            fi
            
            log_success "Organization scan completed for $org_name - Found $total_secrets secrets ($unique_count unique)"
        else
            log_info "No secrets found in organization $org_name"
            
            # Send summary message to Discord
            discord_send "**GitHub Organization Scan Results**\n**Organization:** \`$org_name\`\n**Secrets found:** \`0\`\n**Timestamp:** \`$(date)\`"
            
            # Send JSON report to Discord (even if empty)
            discord_file "$temp_json_array" "**GitHub Organization Secrets Report (JSON) for \`$org_name\`**"
            
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
            
            # Generate table format with unique secrets (includes Detector, Secret, and Link)
            local secrets_table="$github_dir/${repo_name}_secrets_table.txt"
            generate_secrets_table "$temp_json_array" "$secrets_table"
            
            # Count unique secrets from the table (if generated) or from JSON
            local unique_count=0
            if [[ -f "$secrets_table" && -s "$secrets_table" ]]; then
                # Count non-header lines in table (subtract 2 for header and separator)
                unique_count=$(grep -v "^Detector" "$secrets_table" | grep -v "^---" | grep -v "^$" | wc -l 2>/dev/null || echo "0")
            else
                # Fallback: count unique secrets from JSON
                unique_count=$(jq -r '.[] | select((.Raw != null and .Raw != "" and .Raw != "null") or (.SourceMetadata.Raw != null and .SourceMetadata.Raw != "" and .SourceMetadata.Raw != "null")) | .Raw // .SourceMetadata.Raw // ""' "$temp_json_array" 2>/dev/null | sort -u | wc -l 2>/dev/null || echo "0")
            fi
            
            # Send summary message to Discord
            discord_send "**GitHub Repository Scan Results (Experimental)**\n**Repository:** \`$repo_name\`\n**Organization:** \`$org_name\`\n**Total findings:** \`$secret_count\`\n**Unique secrets:** \`$unique_count\`\n**Timestamp:** \`$(date)\`"
            
            # Send JSON file and secrets table to Discord
            discord_file "$temp_json_array" "**GitHub Repository Secrets Report (JSON) for \`$repo_name\`**"
            if [[ -f "$secrets_table" && -s "$secrets_table" ]]; then
                discord_file "$secrets_table" "**GitHub Repository Secrets Table for \`$repo_name\`**"
            fi
            
            log_success "GitHub experimental scan completed for $repo_name - Found $secret_count secrets ($unique_count unique)"
        else
            log_info "No secrets found in $repo_name (experimental scan)"
            
            # Send summary message to Discord
            discord_send "**GitHub Repository Scan Results (Experimental)**\n**Repository:** \`$repo_name\`\n**Organization:** \`$org_name\`\n**Secrets found:** \`0\`\n**Timestamp:** \`$(date)\`"
            
            # Send JSON report to Discord (even if empty)
            discord_file "$temp_json_array" "**GitHub Repository Secrets Report (JSON) for \`$repo_name\`**"
            
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
