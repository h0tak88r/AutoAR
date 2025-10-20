#!/usr/bin/env bash
# Backup Scan Module using Fuzzuli
# Finds critical backup files by creating dynamic wordlists based on the domain

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/.env" 2>/dev/null || true
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: backup scan -d <domain> [-o <output_dir>] [-t <threads>] [-d <delay>]"
  echo "       backup scan -l <live_hosts_file> [-o <output_dir>] [-t <threads>] [-d <delay>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -l, --live-hosts File containing list of live hosts"
  echo "  -o, --output     Output directory (default: results/<domain>/backup or results/backup)"
  echo "  -t, --threads    Number of threads (default: 10)"
  echo "  -d, --delay      Delay between requests in ms (default: 100)"
}

backup_scan() {
  local domain="" live_hosts_file="" output_dir="" threads="10" delay="100"
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -l|--live-hosts) live_hosts_file="$2"; shift 2;;
      -o|--output) output_dir="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      --delay) delay="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  
  # Validate that either domain or live_hosts_file is provided
  if [[ -z "$domain" && -z "$live_hosts_file" ]]; then
    log_error "Either domain (-d) or live hosts file (-l) must be provided"
    usage
    exit 1
  fi
  
  if [[ -n "$domain" && -n "$live_hosts_file" ]]; then
    log_error "Cannot specify both domain and live hosts file"
    usage
    exit 1
  fi
  
  # Set default output directory
  if [[ -z "$output_dir" ]]; then
    if [[ -n "$domain" ]]; then
      output_dir="$(results_dir "$domain")/backup"
    else
      output_dir="$(results_dir "backup")"
    fi
  fi
  
  ensure_dir "$output_dir"
  
  # Determine scan type and target
  if [[ -n "$domain" ]]; then
    log_info "Starting backup file discovery scan for domain: $domain"
    discord_send_progress "🔍 **Starting backup file discovery for $domain**"
    scan_backup_files "$domain" "$output_dir" "$threads" "$delay"
  else
    [[ ! -f "$live_hosts_file" ]] && { log_error "Live hosts file not found: $live_hosts_file"; exit 1; }
    log_info "Starting backup file discovery scan for live hosts: $live_hosts_file"
    discord_send_progress "🔍 **Starting backup file discovery for live hosts**"
    scan_backup_files_from_list "$live_hosts_file" "$output_dir" "$threads" "$delay"
  fi
}

scan_backup_files() {
  local domain="$1"
  local output_dir="$2"
  local threads="$3"
  local delay="$4"
  
  # Check if fuzzuli is installed
  if ! command -v fuzzuli >/dev/null 2>&1; then
    log_error "Fuzzuli not found. Please install it with: go install github.com/musana/fuzzuli@latest"
    discord_send_progress "❌ **Fuzzuli tool not found. Please install it first.**"
    exit 1
  fi
  
  log_info "Running Fuzzuli command line tool"
  log_info "Command: echo 'https://$domain' | fuzzuli -mt all"
  
  # Run fuzzuli scan
  log_info "Executing backup file discovery scan..."
  discord_send_progress "⚙️ **Executing backup file discovery scan for $domain**"
  
  local start_time=$(date +%s)
  
  if echo "https://$domain" | fuzzuli -mt all -w 100 > "$output_dir/fuzzuli-results.txt" 2>"$output_dir/fuzzuli-output.log"; then
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Fuzzuli scan completed in ${duration}s"
    
    # Check if results file exists and has content
    if [[ -f "$output_dir/fuzzuli-results.txt" && -s "$output_dir/fuzzuli-results.txt" ]]; then
      # Process the web service results
      process_fuzzuli_results "$domain" "$output_dir"
      
      # Count results
      local found_count=$(grep -c "http" "$output_dir/fuzzuli-results.txt" 2>/dev/null || echo "0")
      
      if [[ "$found_count" -gt 0 ]]; then
        log_success "Found $found_count potential backup files"
        
        # Send results to Discord
        discord_file "$output_dir/fuzzuli-results.txt" "Backup files discovered for $domain ($found_count files found)"
        
        # Also send the output log for debugging
        if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
          discord_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan output for $domain"
        fi
        
        discord_send_progress "✅ **Backup scan completed for $domain - Found $found_count potential backup files**"
      else
        log_warn "No backup files found for $domain"
        discord_send_progress "⚠️ **No backup files found for $domain**"
      fi
    else
      log_warn "No results file generated for $domain"
      discord_send_progress "⚠️ **No results file generated for $domain**"
    fi
    
  else
    local exit_code=$?
    log_error "Fuzzuli scan failed with exit code: $exit_code"
    
    # Check if there's any output
    if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
      log_error "Fuzzuli output:"
      cat "$output_dir/fuzzuli-output.log" | tail -20
      
      # Send error log to Discord
      discord_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan error for $domain (exit code: $exit_code)"
    fi
    
    discord_send_progress "❌ **Backup scan failed for $domain (exit code: $exit_code)**"
    exit 1
  fi
  
  log_success "Backup file discovery scan completed for $domain"
}

scan_backup_files_from_list() {
  local live_hosts_file="$1"
  local output_dir="$2"
  local threads="$3"
  local delay="$4"
  
  # Check if fuzzuli is installed
  if ! command -v fuzzuli >/dev/null 2>&1; then
    log_error "Fuzzuli not found. Please install it with: go install github.com/musana/fuzzuli@latest"
    discord_send_progress "❌ **Fuzzuli tool not found. Please install it first.**"
    exit 1
  fi
  
  local total_hosts=$(wc -l < "$live_hosts_file")
  log_info "Running Fuzzuli on $total_hosts live hosts"
  log_info "Command: fuzzuli -mt all -f '$live_hosts_file'"
  
  # Run fuzzuli scan on all hosts at once
  log_info "Executing backup file discovery scan..."
  discord_send_progress "⚙️ **Executing backup file discovery scan for $total_hosts hosts**"
  
  local start_time=$(date +%s)
  
  if fuzzuli -mt all -f "$live_hosts_file" -w 100 > "$output_dir/fuzzuli-results.txt" 2>"$output_dir/fuzzuli-output.log"; then
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Fuzzuli scan completed in ${duration}s"
    
    # Check if results file exists and has content
    if [[ -f "$output_dir/fuzzuli-results.txt" && -s "$output_dir/fuzzuli-results.txt" ]]; then
      # Process the results
      process_fuzzuli_results "live_hosts" "$output_dir"
      
      # Count results
      local found_count=$(grep -c "http" "$output_dir/fuzzuli-results.txt" 2>/dev/null || echo "0")
      
      if [[ "$found_count" -gt 0 ]]; then
        log_success "Found $found_count potential backup files"
        
        # Send results to Discord
        discord_file "$output_dir/fuzzuli-results.txt" "Backup files discovered for live hosts ($found_count files found)"
        
        # Also send the output log for debugging
        if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
          discord_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan output for live hosts"
        fi
        
        discord_send_progress "✅ **Backup scan completed for live hosts - Found $found_count potential backup files**"
      else
        log_warn "No backup files found for live hosts"
        discord_send_progress "⚠️ **No backup files found for live hosts**"
      fi
    else
      log_warn "No results file generated for live hosts"
      discord_send_progress "⚠️ **No results file generated for live hosts**"
    fi
    
  else
    local exit_code=$?
    log_error "Fuzzuli scan failed with exit code: $exit_code"
    
    # Check if there's any output
    if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
      log_error "Fuzzuli output:"
      cat "$output_dir/fuzzuli-output.log" | tail -20
      
      # Send error log to Discord
      discord_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan error for live hosts (exit code: $exit_code)"
    fi
    
    discord_send_progress "❌ **Backup scan failed for live hosts (exit code: $exit_code)**"
    exit 1
  fi
  
  log_success "Backup file discovery scan completed for live hosts"
}

process_fuzzuli_results() {
  local domain="$1"
  local output_dir="$2"
  
  log_info "Processing Fuzzuli web service results for $domain"
  
  # Create a summary file
  local summary_file="$output_dir/backup-summary.txt"
  {
    echo "Backup File Discovery Summary for $domain"
    echo "=========================================="
    echo "Scan Date: $(date)"
    echo "Source: Fuzzuli Command Line Tool"
    echo ""
    
    if [[ -f "$output_dir/fuzzuli-results.txt" ]]; then
      local total_count=$(wc -l < "$output_dir/fuzzuli-results.txt")
      echo "Total URLs Generated: $total_count"
      echo ""
      
      # Categorize results by file type
      local sql_files=$(grep -i "\.sql" "$output_dir/fuzzuli-results.txt" | wc -l)
      local zip_files=$(grep -i "\.zip\|\.tar\.gz\|\.rar\|\.7z" "$output_dir/fuzzuli-results.txt" | wc -l)
      local bak_files=$(grep -i "\.bak\|\.backup" "$output_dir/fuzzuli-results.txt" | wc -l)
      local config_files=$(grep -i "\.conf\|\.config\|\.ini" "$output_dir/fuzzuli-results.txt" | wc -l)
      
      echo "File Type Breakdown:"
      echo "==================="
      echo "SQL Files: $sql_files"
      echo "Archive Files: $zip_files"
      echo "Backup Files: $bak_files"
      echo "Config Files: $config_files"
      echo ""
      
      # Show sample results
      echo "Sample Generated URLs:"
      echo "====================="
      head -20 "$output_dir/fuzzuli-results.txt"
      
      if [[ $total_count -gt 20 ]]; then
        echo "... and $((total_count - 20)) more URLs"
      fi
    else
      echo "No results file found"
    fi
  } > "$summary_file"
  
  log_info "Created backup summary: $summary_file"
  
  # Send summary to Discord
  discord_file "$summary_file" "Backup scan summary for $domain"
}

case "${1:-}" in
  scan) shift; backup_scan "$@" ;;
  *) usage; exit 1;;
esac
