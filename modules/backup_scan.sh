#!/usr/bin/env bash
# Backup Scan Module using Fuzzuli
# Finds critical backup files by creating dynamic wordlists based on the domain

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/.env" 2>/dev/null || true

# Load compatibility functions
if [[ -f "$ROOT_DIR/gomodules/compat.sh" ]]; then
  source "$ROOT_DIR/gomodules/compat.sh"
fi

usage() { 
  echo "Usage: backup scan -d <domain> [-o <output_dir>] [-t <threads>] [-d <delay>] [--full]"
  echo "       backup scan -l <live_hosts_file> [-o <output_dir>] [-t <threads>] [-d <delay>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -l, --live-hosts File containing list of live hosts"
  echo "  -o, --output     Output directory (default: results/<domain>/backup or results/backup)"
  echo "  -t, --threads    Number of threads/workers (default: 100)"
  echo "  -d, --delay      Delay between requests in ms (default: 100)"
  echo "  --full           Run full backup scan on all subdomains (collects subdomains first)"
}

backup_scan() {
  local domain="" live_hosts_file="" output_dir="" threads="100" delay="100" full_mode=false
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -l|--live-hosts) live_hosts_file="$2"; shift 2;;
      -o|--output) output_dir="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      --delay) delay="$2"; shift 2;;
      --full) full_mode=true; shift;;
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
    if [[ "$full_mode" == true ]]; then
      log_info "Starting full backup file discovery scan for domain: $domain (with subdomain collection)"
      discord_send_progress "🔍 **Starting full backup file discovery for $domain (collecting subdomains first)**"
      scan_backup_files_full "$domain" "$output_dir" "$threads" "$delay"
    else
      log_info "Starting backup file discovery scan for domain: $domain"
      discord_send_progress "🔍 **Starting backup file discovery for $domain**"
      scan_backup_files "$domain" "$output_dir" "$threads" "$delay"
    fi
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
  
  log_info "Running Fuzzuli command line tool with $threads workers"
  log_info "Command: echo 'https://$domain' | fuzzuli -mt all -w $threads"
  
  # Run fuzzuli scan
  log_info "Executing backup file discovery scan..."
  discord_send_progress "⚙️ **Executing backup file discovery scan for $domain**"
  
  local start_time=$(date +%s)
  
  if echo "https://$domain" | fuzzuli -mt all -w "$threads" > "$output_dir/fuzzuli-results.txt" 2>"$output_dir/fuzzuli-output.log"; then
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Fuzzuli scan completed in ${duration}s"
    
    # Check if results file exists and has content
    if [[ -f "$output_dir/fuzzuli-results.txt" && -s "$output_dir/fuzzuli-results.txt" ]]; then
      # Count results
      local found_count=$(grep -c "http" "$output_dir/fuzzuli-results.txt" 2>/dev/null || echo "0")
      
      if [[ "$found_count" -gt 0 ]]; then
        log_success "Found $found_count potential backup files"
        
        # Send final results via bot (webhook used for logging)
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-backup_scan_$(date +%s)}"
        discord_send_file "$output_dir/fuzzuli-results.txt" "Backup files discovered for $domain ($found_count files found)" "$scan_id"
        
        # Also send the output log for debugging
        if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
          discord_send_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan output for $domain" "$scan_id"
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
      
      # Send error log via bot
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-backup_scan_$(date +%s)}"
      discord_send_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan error for $domain (exit code: $exit_code)" "$scan_id"
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
  log_info "Running Fuzzuli on $total_hosts live hosts with $threads workers"
  log_info "Command: fuzzuli -mt all -f '$live_hosts_file' -w $threads"
  
  # Run fuzzuli scan on all hosts at once
  log_info "Executing backup file discovery scan..."
  discord_send_progress "⚙️ **Executing backup file discovery scan for $total_hosts hosts**"
  
  local start_time=$(date +%s)
  
  if fuzzuli -mt all -f "$live_hosts_file" -w "$threads" > "$output_dir/fuzzuli-results.txt" 2>"$output_dir/fuzzuli-output.log"; then
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Fuzzuli scan completed in ${duration}s"
    
    # Check if results file exists and has content
    if [[ -f "$output_dir/fuzzuli-results.txt" && -s "$output_dir/fuzzuli-results.txt" ]]; then
      # Count results
      local found_count=$(grep -c "http" "$output_dir/fuzzuli-results.txt" 2>/dev/null || echo "0")
      
      if [[ "$found_count" -gt 0 ]]; then
        log_success "Found $found_count potential backup files"
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-backup_scan_live_$(date +%s)}"
        discord_send_file "$output_dir/fuzzuli-results.txt" "Backup files discovered for live hosts ($found_count files found)" "$scan_id"
        
        # Also send the output log for debugging
        if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
          discord_send_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan output for live hosts" "$scan_id"
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
      
      # Send error log via bot
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-backup_scan_live_$(date +%s)}"
      discord_send_file "$output_dir/fuzzuli-output.log" "Fuzzuli scan error for live hosts (exit code: $exit_code)" "$scan_id"
    fi
    
    discord_send_progress "❌ **Backup scan failed for live hosts (exit code: $exit_code)**"
    exit 1
  fi
  
  log_success "Backup file discovery scan completed for live hosts"
}

scan_backup_files_full() {
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
  
  # Step 1: Collect subdomains
  log_info "Step 1: Collecting subdomains for $domain"
  discord_send_progress "📡 **Step 1/2: Collecting subdomains for $domain**"
  
  local subs_dir="$(domain_dir_init "$domain")/subs"
  ensure_dir "$subs_dir"
  
  # Run subdomain collection using the subdomains module
  if ! "$ROOT_DIR/modules/subdomains.sh" get -d "$domain"; then
    log_error "Failed to collect subdomains for $domain"
    discord_send_progress "❌ **Failed to collect subdomains for $domain**"
    exit 1
  fi
  
  # Check if we have subdomains
  local subs_file="$subs_dir/all-subs.txt"
  if [[ ! -f "$subs_file" || ! -s "$subs_file" ]]; then
    log_warn "No subdomains found for $domain, falling back to domain-only scan"
    discord_send_progress "⚠️ **No subdomains found, running domain-only backup scan**"
    scan_backup_files "$domain" "$output_dir" "$threads" "$delay"
    return
  fi
  
  local total_subs=$(wc -l < "$subs_file")
  log_success "Found $total_subs subdomains for $domain"
  discord_send_progress "✅ **Found $total_subs subdomains for $domain**"
  
  # Step 2: Run backup scan on all subdomains
  log_info "Step 2: Running backup file discovery on $total_subs subdomains with $threads workers"
  discord_send_progress "🔍 **Step 2/2: Running backup file discovery on $total_subs subdomains**"
  
  local start_time=$(date +%s)
  
  # Convert subdomains to URLs for fuzzuli
  local urls_file="$output_dir/subdomain-urls.txt"
  {
    echo "https://$domain"
    sed 's/^/https:\/\//' "$subs_file"
  } > "$urls_file"
  
  log_info "Running Fuzzuli on $((total_subs + 1)) URLs (domain + subdomains)"
  log_info "Command: fuzzuli -mt all -f '$urls_file' -w $threads"
  
  if fuzzuli -mt all -f "$urls_file" -w "$threads" > "$output_dir/fuzzuli-results.txt" 2>"$output_dir/fuzzuli-output.log"; then
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "Full backup scan completed in ${duration}s"
    
    # Check if results file exists and has content
    if [[ -f "$output_dir/fuzzuli-results.txt" && -s "$output_dir/fuzzuli-results.txt" ]]; then
      # Count results
      local found_count=$(grep -c "http" "$output_dir/fuzzuli-results.txt" 2>/dev/null || echo "0")
      
      if [[ "$found_count" -gt 0 ]]; then
        log_success "Found $found_count potential backup files across $total_subs subdomains"
        
        # Send final results via bot
        local scan_id="${AUTOAR_CURRENT_SCAN_ID:-backup_scan_full_$(date +%s)}"
        discord_send_file "$output_dir/fuzzuli-results.txt" "Full backup scan results for $domain ($found_count files found across $total_subs subdomains)" "$scan_id"
        
        # Also send the output log for debugging
        if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
          discord_send_file "$output_dir/fuzzuli-output.log" "Fuzzuli full scan output for $domain" "$scan_id"
        fi
        
        # Send subdomain list as well
        discord_send_file "$subs_file" "Subdomains used in full backup scan for $domain" "$scan_id"
        
        discord_send_progress "✅ **Full backup scan completed for $domain - Found $found_count potential backup files across $total_subs subdomains**"
      else
        log_warn "No backup files found across $total_subs subdomains for $domain"
        discord_send_progress "⚠️ **No backup files found across $total_subs subdomains for $domain**"
      fi
    else
      log_warn "No results file generated for full backup scan of $domain"
      discord_send_progress "⚠️ **No results file generated for full backup scan of $domain**"
    fi
    
  else
    local exit_code=$?
    log_error "Full backup scan failed with exit code: $exit_code"
    
    # Check if there's any output
    if [[ -f "$output_dir/fuzzuli-output.log" ]]; then
      log_error "Fuzzuli output:"
      cat "$output_dir/fuzzuli-output.log" | tail -20
      
      # Send error log via bot
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-backup_scan_full_$(date +%s)}"
      discord_send_file "$output_dir/fuzzuli-output.log" "Fuzzuli full scan error for $domain (exit code: $exit_code)" "$scan_id"
    fi
    
    discord_send_progress "❌ **Full backup scan failed for $domain (exit code: $exit_code)**"
    exit 1
  fi
  
  log_success "Full backup file discovery scan completed for $domain"
}

case "${1:-}" in
  scan) shift; backup_scan "$@" ;;
  *) usage; exit 1;;
esac
