#!/usr/bin/env bash
# Live Hosts Dependency Confusion Scanner
# Scans live hosts for dependency files and checks them with Confused tool

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/.env" 2>/dev/null || true
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: live_depconfusion scan -d <domain> [-o <output_dir>] [-t <threads>] [-d <delay>]"
  echo "  -d, --domain      Target domain to scan"
  echo "  -o, --output      Output directory (default: results/<domain>/live-depconfusion)"
  echo "  -t, --threads     Number of threads (default: 10)"
  echo "  -d, --delay       Delay between requests in ms (default: 100)"
}

live_depconfusion_scan() {
  local domain="" output_dir="" threads="10" delay="100"
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -o|--output) output_dir="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      --delay) delay="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  
  [[ -z "$domain" ]] && { usage; exit 1; }
  
  # Set default output directory if not provided
  if [[ -z "$output_dir" ]]; then
    output_dir="$(results_dir "$domain")/live-depconfusion"
  fi
  
  ensure_dir "$output_dir"
  
  log_info "Starting live hosts dependency confusion scan for $domain"
  discord_send_progress "🔍 **Starting live hosts dependency confusion scan for $domain**"
  
  # Check if confused tool is installed
  if ! command -v confused >/dev/null 2>&1; then
    log_error "Confused tool not found. Please install it with: go install github.com/visma-prodsec/confused@latest"
    discord_send_progress "❌ **Confused tool not found. Please install it first.**"
    exit 1
  fi
  
  # Check for existing live hosts file
  local live_hosts_file="$(results_dir "$domain")/subs/live-subs.txt"
  
  if [[ ! -f "$live_hosts_file" ]]; then
    log_info "No existing live hosts found for $domain, running live hosts scan first"
    discord_send_progress "🔍 **No existing live hosts found, running live hosts scan first**"
    
    # Run live hosts scan
    if ! "$ROOT_DIR/main.sh" livehosts get -d "$domain"; then
      log_error "Failed to run live hosts scan for $domain"
      discord_send_progress "❌ **Failed to run live hosts scan for $domain**"
      exit 1
    fi
    
    # Check if live hosts file was created
    if [[ ! -f "$live_hosts_file" ]]; then
      log_error "Live hosts scan completed but no live hosts file found"
      discord_send_progress "❌ **Live hosts scan completed but no live hosts found**"
      exit 1
    fi
  else
    log_info "Using existing live hosts file: $live_hosts_file"
  fi
  
  # Discover dependency files on live hosts using dep-files.txt
  discover_dependency_files "$live_hosts_file" "$output_dir" "$threads" "$delay"
  
  # Scan discovered files with confused tool
  scan_dependency_files "$output_dir"
  
  # Generate summary report
  generate_live_depconfusion_summary "$output_dir"
  
  log_success "Live hosts dependency confusion scan completed"
}


discover_dependency_files() {
  local live_hosts_file="$1"
  local output_dir="$2"
  local threads="$3"
  local delay="$4"
  
  log_info "Discovering dependency files on live hosts"
  discord_send_progress "🔍 **Discovering dependency files on live hosts**"
  
  local dep_files_wordlist="$ROOT_DIR/Wordlists/dep-files.txt"
  local discovered_files="$output_dir/discovered-files.txt"
  
  # Check if dep-files.txt exists
  if [[ ! -f "$dep_files_wordlist" ]]; then
    log_error "Dependency files wordlist not found: $dep_files_wordlist"
    discord_send_progress "❌ **Dependency files wordlist not found**"
    exit 1
  fi
  
  log_info "Using dependency files wordlist: $dep_files_wordlist"
  
  # Use ffuf to discover dependency files
  log_info "Running ffuf to discover dependency files"
  
  # Convert delay from milliseconds to seconds (simple division)
  local delay_seconds=$(awk "BEGIN {printf \"%.3f\", $delay/1000}")
  
  if ffuf -w "$live_hosts_file:HOSTS" -w "$dep_files_wordlist:ENDPOINTS" \
     -u "HOSTSENDPOINTS" \
     -mc 200 \
     -t "$threads" \
     -p "$delay_seconds" \
     -o "$discovered_files" \
     -of json \
     -s > "$output_dir/ffuf-output.log" 2>&1; then
    
    # Process ffuf results
    if [[ -f "$discovered_files" ]]; then
      local found_count=$(jq -r '.results | length' "$discovered_files" 2>/dev/null || echo "0")
      
      if [[ "$found_count" -gt 0 ]]; then
        log_success "Found $found_count dependency files"
        
        # Extract URLs and download files
        jq -r '.results[] | .url' "$discovered_files" > "$output_dir/found-urls.txt"
        
        # Download each discovered file
        download_dependency_files "$output_dir"
        
      else
        log_warn "No dependency files found"
        discord_send_progress "⚠️ **No dependency files found on live hosts**"
      fi
    else
      log_warn "No ffuf results file generated"
    fi
  else
    log_error "ffuf scan failed"
    discord_send_progress "❌ **ffuf scan failed**"
    exit 1
  fi
}

download_dependency_files() {
  local output_dir="$1"
  local found_urls="$output_dir/found-urls.txt"
  local downloads_dir="$output_dir/downloads"
  
  ensure_dir "$downloads_dir"
  
  log_info "Downloading discovered dependency files"
  
  local downloaded_count=0
  
  while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    
    # Extract filename from URL
    local filename=$(basename "$url")
    local file_path="$downloads_dir/$filename"
    
    # Download the file
    if curl -s -L "$url" -o "$file_path" --max-time 10; then
      # Check if file has content
      if [[ -s "$file_path" ]]; then
        log_success "Downloaded: $url"
        downloaded_count=$((downloaded_count + 1))
      else
        rm -f "$file_path"
        log_warn "Empty file: $url"
      fi
    else
      log_warn "Failed to download: $url"
    fi
  done < "$found_urls"
  
  log_success "Downloaded $downloaded_count dependency files"
}

scan_dependency_files() {
  local output_dir="$1"
  local downloads_dir="$output_dir/downloads"
  
  log_info "Scanning dependency files with Confused tool"
  discord_send_progress "🔍 **Scanning dependency files with Confused tool**"
  
  local scan_results_dir="$output_dir/scan-results"
  ensure_dir "$scan_results_dir"
  
  local total_scanned=0
  local total_vulnerable=0
  local vulnerable_files=()
  
  # Scan each downloaded file
  for file_path in "$downloads_dir"/*; do
    [[ ! -f "$file_path" ]] && continue
    
    local filename=$(basename "$file_path")
    local language=""
    
    # Determine language based on filename
    case "$filename" in
      package.json|package-lock.json|yarn.lock|npm-shrinkwrap.json) language="npm" ;;
      requirements*.txt|Pipfile|Pipfile.lock|pyproject.toml|setup.py) language="pip" ;;
      composer.json|composer.lock) language="composer" ;;
      pom.xml) language="mvn" ;;
      Gemfile|Gemfile.lock) language="rubygems" ;;
      go.mod|go.sum) language="go" ;;
      Cargo.toml|Cargo.lock) language="cargo" ;;
      *) continue ;;
    esac
    
    log_info "Scanning $filename with confused ($language)"
    
    # Run confused tool
    local confused_output="$scan_results_dir/confused-${filename%.*}.txt"
    if confused -l "$language" "$file_path" > "$confused_output" 2>&1; then
      # Check if vulnerabilities were found
      if grep -q "Issues found" "$confused_output"; then
        log_warn "Dependency confusion vulnerabilities found in $filename"
        vulnerable_files+=("$filename")
        total_vulnerable=$((total_vulnerable + 1))
      else
        log_success "No vulnerabilities found in $filename"
      fi
    else
      log_warn "Failed to scan $filename with confused"
    fi
    
    total_scanned=$((total_scanned + 1))
  done
  
  # Save scan statistics
  echo "$total_scanned" > "$output_dir/total-scanned.txt"
  echo "$total_vulnerable" > "$output_dir/total-vulnerable.txt"
  printf '%s\n' "${vulnerable_files[@]}" > "$output_dir/vulnerable-files.txt"
  
  log_success "Scanned $total_scanned files, found $total_vulnerable vulnerabilities"
}

generate_live_depconfusion_summary() {
  local output_dir="$1"
  local summary_file="$output_dir/live-depconfusion-summary.txt"
  
  local total_scanned=$(cat "$output_dir/total-scanned.txt" 2>/dev/null || echo "0")
  local total_vulnerable=$(cat "$output_dir/total-vulnerable.txt" 2>/dev/null || echo "0")
  local vulnerable_files=()
  
  if [[ -f "$output_dir/vulnerable-files.txt" ]]; then
    while IFS= read -r file; do
      [[ -n "$file" ]] && vulnerable_files+=("$file")
    done < "$output_dir/vulnerable-files.txt"
  fi
  
  {
    echo "Live Hosts Dependency Confusion Scan Summary"
    echo "============================================"
    echo "Scan Date: $(date)"
    echo "Total Files Scanned: $total_scanned"
    echo "Total Vulnerabilities Found: $total_vulnerable"
    echo ""
    
    if [[ $total_vulnerable -gt 0 ]]; then
      echo "Vulnerable Files:"
      echo "================"
      for file in "${vulnerable_files[@]}"; do
        echo "- $file"
      done
      echo ""
      
      echo "Vulnerability Details:"
      echo "====================="
      for file in "${vulnerable_files[@]}"; do
        local report_file="$output_dir/scan-results/confused-${file%.*}.txt"
        if [[ -f "$report_file" ]]; then
          echo ""
          echo "File: $file"
          echo "----------------------------------------"
          cat "$report_file"
          echo ""
        fi
      done
    else
      echo "No dependency confusion vulnerabilities found."
      echo ""
      echo "This means all package names referenced in discovered dependency files"
      echo "are either available in public repositories or properly secured."
    fi
    
    echo ""
    echo "Scan completed using Confused tool:"
    echo "https://github.com/visma-prodsec/confused"
  } > "$summary_file"
  
  log_info "Generated live dependency confusion summary: $summary_file"
  
  # Send summary to Discord
  discord_file "$summary_file" "Live hosts dependency confusion scan summary"
}

case "${1:-}" in
  scan) shift; live_depconfusion_scan "$@" ;;
  *) usage; exit 1;;
esac
