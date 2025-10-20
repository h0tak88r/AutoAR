#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: wp_plugin_confusion scan -d <domain>"; }

wp_plugin_confusion_scan() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir="$(results_dir "$domain")"
  local base="$dir/vulnerabilities/wp-plugin-confusion"
  ensure_dir "$base"
  
  log_info "Scanning for WordPress Plugin Confusion vulnerabilities on $domain"
  discord_send_progress "🔍 **Scanning for WordPress Plugin Confusion on $domain**"
  
  # Check if wp_update_confusion.py exists, if not download it
  local script_path="$ROOT_DIR/tools/wp_update_confusion.py"
  if [[ ! -f "$script_path" ]]; then
    log_info "Downloading wp_update_confusion.py tool..."
    ensure_dir "$(dirname "$script_path")"
    curl -s "https://raw.githubusercontent.com/vavkamil/wp-update-confusion/refs/heads/main/wp_update_confusion.py" -o "$script_path" || {
      log_error "Failed to download wp_update_confusion.py"
      exit 1
    }
    chmod +x "$script_path"
  fi
  
  # Run the WordPress Plugin Confusion scan
  local output_file="$base/wp-plugin-confusion-results.txt"
  log_info "Running WordPress Plugin Confusion scan..."
  
  set +e
  python3 "$script_path" -u "https://$domain" -p -o "$output_file" -s 2>/dev/null
  local scan_exit_code=$?
  set -e
  
  # Check if the output file contains actual results (not just usage message)
  if [[ -f "$output_file" ]]; then
    # Remove the banner and usage message from the output
    sed -i '/^usage:/,$d' "$output_file" 2>/dev/null || true
    sed -i '/^WordPress Update Confusion/,$d' "$output_file" 2>/dev/null || true
    sed -i '/^[[:space:]]*$/d' "$output_file" 2>/dev/null || true
    sed -i '/^[[:space:]]*+-+[[:space:]]*$/d' "$output_file" 2>/dev/null || true
  fi
  
  if [[ $scan_exit_code -eq 0 && -s "$output_file" ]]; then
    log_info "Processing results and filtering false positives..."
    
    # Filter out false positives based on keywords and paid plugins list
    local filtered_file="$base/wp-plugin-confusion-filtered.txt"
    local paid_plugins_file="$ROOT_DIR/Wordlists/paid-wp-plugins.txt"
    
    # Create temporary file for processing
    local temp_file=$(mktemp)
    
    # Filter out lines containing premium/pro keywords
    grep -v -E "(pro-|-pro-|-pro$|premium-|-premium-|-premium$)" "$output_file" > "$temp_file" || true
    
    # If paid plugins wordlist exists, filter those out too
    if [[ -f "$paid_plugins_file" ]]; then
      log_info "Filtering out known paid plugins..."
      while IFS= read -r paid_plugin; do
        [[ -n "$paid_plugin" ]] && sed -i "/$paid_plugin/d" "$temp_file" 2>/dev/null || true
      done < "$paid_plugins_file"
    fi
    
    # Copy filtered results
    cp "$temp_file" "$filtered_file"
    rm -f "$temp_file"
    
    # Count results
    local total_results=$(wc -l < "$output_file" 2>/dev/null || echo 0)
    local filtered_results=$(wc -l < "$filtered_file" 2>/dev/null || echo 0)
    
    log_success "WordPress Plugin Confusion scan completed"
    log_info "Total plugins found: $total_results"
    log_info "After filtering false positives: $filtered_results"
    
    # Send results to Discord if any remain after filtering
    if [[ $filtered_results -gt 0 ]]; then
      log_success "Found $filtered_results potential WordPress Plugin Confusion vulnerabilities"
      discord_file "$filtered_file" "WordPress Plugin Confusion vulnerabilities for $domain ($filtered_results potential targets)"
      
      # Also send the raw results for reference
      discord_file "$output_file" "WordPress Plugin Confusion raw results for $domain ($total_results total)"
    else
      log_info "No WordPress Plugin Confusion vulnerabilities found after filtering"
      discord_send_progress "✅ **No WordPress Plugin Confusion vulnerabilities found for $domain**"
    fi
    
  else
    log_warn "WordPress Plugin Confusion scan failed or found no results"
    discord_send_progress "⚠️ **WordPress Plugin Confusion scan completed - no vulnerabilities found for $domain**"
  fi
  
  log_success "WordPress Plugin Confusion scanning completed for $domain"
}

case "${1:-}" in
  scan) shift; wp_plugin_confusion_scan "$@" ;;
  *) usage; exit 1;;
esac
