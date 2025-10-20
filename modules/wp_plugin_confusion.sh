#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: wp_plugin_confusion scan -d <domain>"; }

# Detect WordPress plugins from HTML content
detect_plugins() {
  local url="$1"
  local temp_file=$(mktemp)
  local plugins_file=$(mktemp)
  
  # Fetch the page content
  if curl -s -L -A "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0" \
          --connect-timeout 10 --max-time 30 "$url" > "$temp_file" 2>/dev/null; then
    
    # Extract plugin names from wp-content/plugins/ paths
    grep -o 'wp-content/plugins/[a-zA-Z0-9_-]*/' "$temp_file" 2>/dev/null | \
    sed 's|wp-content/plugins/||g' | sed 's|/||g' | \
    grep -E '^[a-zA-Z0-9_-]+$' | sort -u > "$plugins_file"
    
    # Also check for plugins in script src attributes
    grep -o 'src="[^"]*wp-content/plugins/[a-zA-Z0-9_-]*/' "$temp_file" 2>/dev/null | \
    sed 's|.*wp-content/plugins/||g' | sed 's|/.*||g' | \
    grep -E '^[a-zA-Z0-9_-]+$' | sort -u >> "$plugins_file"
    
    # Also check for plugins in href attributes
    grep -o 'href="[^"]*wp-content/plugins/[a-zA-Z0-9_-]*/' "$temp_file" 2>/dev/null | \
    sed 's|.*wp-content/plugins/||g' | sed 's|/.*||g' | \
    grep -E '^[a-zA-Z0-9_-]+$' | sort -u >> "$plugins_file"
    
    # Remove duplicates and empty lines
    sort -u "$plugins_file" | grep -v '^$' > "${plugins_file}.tmp"
    mv "${plugins_file}.tmp" "$plugins_file"
    
    # Clean up temp file
    rm -f "$temp_file"
    
    # Return the plugins file path
    echo "$plugins_file"
  else
    rm -f "$temp_file" "$plugins_file"
    echo ""
  fi
}

# Check if plugin exists on WordPress.org
check_wordpress_org_plugin() {
  local plugin="$1"
  
  # Check if plugin exists in WordPress.org SVN
  local svn_url="https://plugins.svn.wordpress.org/$plugin/"
  
  if curl -s -I -A "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0" \
          --connect-timeout 5 --max-time 10 "$svn_url" | grep -q "404 Not Found"; then
    return 0  # Plugin not found (vulnerable)
  else
    return 1  # Plugin exists (not vulnerable)
  fi
}

# Check if plugin is in paid plugins list
is_paid_plugin() {
  local plugin="$1"
  local paid_plugins_file="$ROOT_DIR/Wordlists/paid-wp-plugins.txt"
  
  if [[ -f "$paid_plugins_file" ]]; then
    grep -q "^$plugin$" "$paid_plugins_file" 2>/dev/null
    return $?
  fi
  return 1
}

# Check if plugin name contains premium/pro keywords
is_premium_plugin() {
  local plugin="$1"
  
  # Check for premium/pro keywords
  if echo "$plugin" | grep -qE "(pro-|-pro-|-pro$|premium-|-premium-|-premium$)"; then
    return 0  # Contains premium keywords
  fi
  return 1  # No premium keywords
}

# Filter plugins and check for vulnerabilities
process_plugins() {
  local plugins_file="$1"
  local output_file="$2"
  local filtered_file="$3"
  
  local vulnerable_count=0
  local filtered_count=0
  
  > "$output_file"
  > "$filtered_file"
  
  while IFS= read -r plugin; do
    [[ -z "$plugin" ]] && continue
    
    # Skip if it's a premium/pro plugin
    if is_premium_plugin "$plugin"; then
      ((filtered_count++))
      continue
    fi
    
    # Skip if it's in paid plugins list
    if is_paid_plugin "$plugin"; then
      ((filtered_count++))
      continue
    fi
    
    # Check if plugin exists on WordPress.org
    if check_wordpress_org_plugin "$plugin"; then
      echo "$plugin" >> "$output_file"
      echo "$plugin" >> "$filtered_file"
      ((vulnerable_count++))
    fi
    
    # Small delay to avoid rate limiting
    sleep 0.5
    
  done < "$plugins_file"
  
  echo "$vulnerable_count:$filtered_count"
}

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
  
  # Detect plugins from the WordPress site
  log_info "Fetching WordPress site content from https://$domain"
  local plugins_file=$(detect_plugins "https://$domain")
  
  if [[ -n "$plugins_file" && -f "$plugins_file" ]]; then
    local plugin_count=$(wc -l < "$plugins_file")
    log_info "Found $plugin_count unique plugins"
  else
    log_warn "No plugins detected or failed to fetch site content"
    log_info "This might mean:"
    log_info "1. The site is not a WordPress site"
    log_info "2. The site has no plugins installed"
    log_info "3. The site blocks automated requests"
    log_info "4. The site is not accessible"
    discord_send_progress "⚠️ **No WordPress plugins detected for $domain**"
    return 0
  fi
  
  local plugin_count=$(wc -l < "$plugins_file")
  log_info "Processing $plugin_count detected plugins"
  
  # Process plugins and check for vulnerabilities
  local output_file="$base/wp-plugin-confusion-results.txt"
  local filtered_file="$base/wp-plugin-confusion-filtered.txt"
  
  local results=$(process_plugins "$plugins_file" "$output_file" "$filtered_file")
  local vulnerable_count=$(echo "$results" | cut -d: -f1)
  local filtered_count=$(echo "$results" | cut -d: -f2)
  
  # Clean up temporary files
  rm -f "$plugins_file"
  
  log_success "WordPress Plugin Confusion scan completed"
  log_info "Total plugins checked: $plugin_count"
  log_info "Premium/paid plugins filtered: $filtered_count"
  log_info "Vulnerable plugins found: $vulnerable_count"
  
  # Send results to Discord
  if [[ $vulnerable_count -gt 0 ]]; then
    log_success "Found $vulnerable_count potential WordPress Plugin Confusion vulnerabilities"
    discord_file "$filtered_file" "WordPress Plugin Confusion vulnerabilities for $domain ($vulnerable_count potential targets)"
    
    # Also send raw results for reference
    discord_file "$output_file" "WordPress Plugin Confusion raw results for $domain"
  else
    log_info "No WordPress Plugin Confusion vulnerabilities found"
    discord_send_progress "✅ **No WordPress Plugin Confusion vulnerabilities found for $domain**"
  fi
  
  log_success "WordPress Plugin Confusion scanning completed for $domain"
}

case "${1:-}" in
  scan) shift; wp_plugin_confusion_scan "$@" ;;
  *) usage; exit 1;;
esac