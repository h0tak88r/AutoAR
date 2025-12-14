#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: wp_plugin_confusion scan -d <domain> | -l <live_hosts_file>"
  echo "  -d, --domain     Target domain to scan"
  echo "  -l, --list       File containing list of live hosts"
}

# Run WordPress Plugin Confusion scan using the original Python tool
run_wp_confusion_scan() {
  local target="$1"
  local scan_type="${2:-plugins}"
  local output_dir="$3"
  
  # Generate output filename
  local timestamp=$(date +"%Y%m%d_%H%M%S")
  local target_name=$(echo "$target" | sed 's|https\?://||' | sed 's|/|_|g')
  local output_file="$output_dir/wp-confusion-${target_name}-${timestamp}.txt"
  
  log_info "Running WordPress Plugin Confusion scan for: $target"
  
  # Build command using Go binary
  local cmd=("wp-confusion")
  
  if [[ "$target" =~ ^https?:// ]]; then
    cmd+=("-u" "$target")
  else
    cmd+=("-l" "$target")
  fi
  
  if [[ "$scan_type" == "plugins" ]]; then
    cmd+=("-p")
  elif [[ "$scan_type" == "themes" ]]; then
    cmd+=("-t")
  else
    cmd+=("-p" "-t")  # Both plugins and themes
  fi
  
  cmd+=("-o" "$output_file")
  if [[ -n "${DISCORD_WEBHOOK:-}" ]] || [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
    cmd+=("--discord")
  fi
  
  log_info "Command: ${cmd[*]}"
  
  # Run the scan with timeout
  local start_time=$(date +%s)
  
  if timeout 60 "${cmd[@]}" 2>"$output_file.log"; then
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_success "WordPress Plugin Confusion scan completed in ${duration}s"
    
    # Check if results file was created and has content
    if [[ -f "$output_file" && -s "$output_file" ]]; then
      local found_count=$(wc -l < "$output_file")
      log_success "Found $found_count vulnerable plugins/themes"
      return 0
    else
      log_info "No vulnerable plugins/themes found"
      return 0
    fi
  else
    local exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
      log_error "WordPress Plugin Confusion scan timed out after 60 seconds"
    else
      log_error "WordPress Plugin Confusion scan failed with exit code: $exit_code"
    fi
    return 1
  fi
}

wp_plugin_confusion_scan() {
  local domain="" live_hosts_file=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -l|--list) live_hosts_file="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  
  # If live hosts file is provided, use Python script's native list handling
  if [[ -n "$live_hosts_file" ]]; then
    if [[ ! -f "$live_hosts_file" ]]; then
      log_error "Live hosts file not found: $live_hosts_file"
      exit 1
    fi
    
    # Extract domain from live hosts file path for results directory
    local base_domain=$(basename "$(dirname "$live_hosts_file")")
    local dir="$(results_dir "$base_domain")"
    local base="$dir/vulnerabilities/wp-plugin-confusion"
    ensure_dir "$base"
    
    local total_hosts=$(wc -l < "$live_hosts_file")
    log_info "Scanning $total_hosts hosts for WordPress Plugin Confusion vulnerabilities"
    discord_send_progress "🔍 **Scanning $total_hosts hosts for WordPress Plugin Confusion**"
    
    # Generate output filename
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local output_file="$base/wp-confusion-all-hosts-${timestamp}.txt"
    
    # Run the Python script with the live hosts file
    # Use Go binary wp-confusion (built in Docker)
    if ! command -v wp-confusion >/dev/null 2>&1; then
      log_error "WordPress confusion tool not found: wp-confusion"
      log_error "Make sure wp-confusion is installed and in PATH"
      return 1
    fi
    
    log_info "Running WordPress Plugin Confusion scan for all hosts"
    
    # Build command using Go binary
    local cmd=("wp-confusion" "-l" "$live_hosts_file" "-p" "-o" "$output_file")
    if [[ -n "${DISCORD_WEBHOOK:-}" ]] || [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
      cmd+=("--discord")
    fi
    
    log_info "Command: ${cmd[*]}"
    
    # Run the scan with timeout
    local start_time=$(date +%s)
    
    if timeout 300 "${cmd[@]}" 2>"$output_file.log"; then
      local end_time=$(date +%s)
      local duration=$((end_time - start_time))
      
      log_success "WordPress Plugin Confusion scan completed in ${duration}s"
      
      # Check if results file was created and has content
      if [[ -f "$output_file" && -s "$output_file" ]]; then
        local found_count=$(wc -l < "$output_file")
        log_success "Found $found_count vulnerable plugins across all hosts"
        discord_send_progress "✅ **WordPress Plugin Confusion scan completed - Found $found_count vulnerabilities across $total_hosts hosts**"
      else
        log_info "No vulnerable plugins found across all hosts"
        discord_send_progress "✅ **WordPress Plugin Confusion scan completed - No vulnerabilities found across $total_hosts hosts**"
      fi
      
      return 0
    else
      local exit_code=$?
      if [[ $exit_code -eq 124 ]]; then
        log_error "WordPress Plugin Confusion scan timed out after 5 minutes"
      else
        log_error "WordPress Plugin Confusion scan failed with exit code: $exit_code"
      fi
      return 1
    fi
  fi
  
  # If domain is provided, check for existing live hosts or run fastlook
  if [[ -n "$domain" ]]; then
    local dir="$(results_dir "$domain")"
    local live_hosts="$dir/subs/live-subs.txt"
    
    # Check if live hosts file exists
    if [[ -f "$live_hosts" && -s "$live_hosts" ]]; then
      log_info "Found existing live hosts file, scanning multiple hosts"
      wp_plugin_confusion_scan -l "$live_hosts"
      return 0
    else
      log_info "No existing live hosts found, running fastlook first"
      discord_send_progress "🔄 **No live hosts found for $domain, running fastlook first**"
      
      # Run fastlook to get live hosts
      if "$ROOT_DIR/modules/fastlook.sh" run -d "$domain"; then
        # Check if live hosts file was created
        if [[ -f "$live_hosts" && -s "$live_hosts" ]]; then
          log_info "Fastlook completed, scanning live hosts"
          wp_plugin_confusion_scan -l "$live_hosts"
          return 0
        else
          log_warn "Fastlook completed but no live hosts found, scanning domain directly"
        fi
      else
        log_warn "Fastlook failed, scanning domain directly"
      fi
    fi
  fi
  
  # Fallback to single domain scan
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir="$(results_dir "$domain")"
  local base="$dir/vulnerabilities/wp-plugin-confusion"
  ensure_dir "$base"
  
  log_info "Scanning for WordPress Plugin Confusion vulnerabilities on $domain"
  discord_send_progress "🔍 **Scanning for WordPress Plugin Confusion on $domain**"
  
  # Run the scan
  if run_wp_confusion_scan "https://$domain" "plugins" "$base"; then
    log_success "WordPress Plugin Confusion scanning completed for $domain"
  else
    log_error "WordPress Plugin Confusion scanning failed for $domain"
    return 1
  fi
}

case "${1:-}" in
  scan) shift; wp_plugin_confusion_scan "$@" ;;
  *) usage; exit 1;;
esac