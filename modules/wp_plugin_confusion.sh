#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: wp_plugin_confusion scan -d <domain> | -l <live_hosts_file>"; }

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

# Check if plugin name contains trademarked slugs
is_trademarked_plugin() {
  local plugin="$1"
  
  # Trademarked slugs that should be filtered
  local trademarked_slugs=(
    "adobe-" "adsense-" "advanced-custom-fields-" "adwords-" "akismet-"
    "all-in-one-wp-migration" "amazon-" "android-" "apple-" "applenews-"
    "aws-" "bbpress-" "bing-" "bootstrap-" "buddypress-" "contact-form-7-"
    "cpanel-" "disqus-" "divi-" "dropbox-" "easy-digital-downloads-"
    "elementor-" "envato-" "fbook" "facebook" "fb-" "fb-messenger"
    "fedex-" "feedburner" "ganalytics-" "gberg" "github-" "givewp-"
    "google-" "googlebot-" "googles-" "gravity-form-" "gravity-forms-"
    "gutenberg" "guten-" "hubspot-" "ig-" "insta-" "instagram"
    "internet-explorer-" "jetpack-" "macintosh-" "mailchimp-" "microsoft-"
    "ninja-forms-" "oculus" "onlyfans-" "only-fans-" "paddle-" "paypal-"
    "pinterest-" "stripe-" "tiktok-" "trustpilot" "twitter-" "tweet"
    "ups-" "usps-" "vvhatsapp" "vvcommerce" "vva-" "vvoo" "wa-"
    "wh4tsapps" "whatsapp" "whats-app" "watson" "windows-" "wocommerce"
    "woocom-" "woocommerce" "woocomerce" "woo-commerce" "woo-" "wo-"
    "wordpress" "wordpess" "wpress" "wp-" "wp-mail-smtp-" "yahoo-"
    "yoast" "youtube-"
  )
  
  for slug in "${trademarked_slugs[@]}"; do
    if echo "$plugin" | grep -q "^$slug"; then
      return 0  # Contains trademarked slug
    fi
  done
  return 1  # No trademarked slugs
}

# Check if plugin name contains reserved slugs
is_reserved_plugin() {
  local plugin="$1"
  
  # Reserved slugs that should be filtered
  local reserved_slugs=(
    "about" "admin" "browse" "category" "developers" "developer"
    "featured" "filter" "new" "page" "plugins" "popular" "post"
    "search" "tag" "updated" "upload" "wp-admin" "jquery"
    "wordpress" "akismet-anti-spam" "site-kit-by-google" "yoast-seo"
    "woo" "wp-media-folder" "wp-file-download" "wp-table-manager"
  )
  
  for slug in "${reserved_slugs[@]}"; do
    if [[ "$plugin" == "$slug" ]]; then
      return 0  # Exact match with reserved slug
    fi
  done
  return 1  # No reserved slugs
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
  
  while IFS= read -r plugin_entry; do
    [[ -z "$plugin_entry" ]] && continue
    
    # Extract plugin name (handle host:plugin format)
    local plugin="$plugin_entry"
    if echo "$plugin_entry" | grep -q ":"; then
      plugin=$(echo "$plugin_entry" | cut -d: -f2)
    fi
    
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
    
    # Skip if it contains trademarked slugs
    if is_trademarked_plugin "$plugin"; then
      ((filtered_count++))
      continue
    fi
    
    # Skip if it's a reserved slug
    if is_reserved_plugin "$plugin"; then
      ((filtered_count++))
      continue
    fi
    
    # Check if plugin exists on WordPress.org
    if check_wordpress_org_plugin "$plugin"; then
      echo "$plugin_entry" >> "$output_file"
      echo "$plugin_entry" >> "$filtered_file"
      ((vulnerable_count++))
    fi
    
    # Small delay to avoid rate limiting
    sleep 0.5
    
  done < "$plugins_file"
  
  echo "$vulnerable_count:$filtered_count"
}

# Scan multiple hosts from a live hosts file
scan_multiple_hosts() {
  local live_hosts_file="$1"
  local domain="$2"
  
  local dir="$(results_dir "$domain")"
  local base="$dir/vulnerabilities/wp-plugin-confusion"
  ensure_dir "$base"
  
  log_info "Scanning multiple hosts for WordPress Plugin Confusion vulnerabilities"
  discord_send_progress "🔍 **Scanning multiple hosts for WordPress Plugin Confusion**"
  
  local all_plugins_file=$(mktemp)
  local processed_hosts=0
  
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    
    # Clean up host (remove protocol, trailing slashes, etc.)
    host=$(echo "$host" | sed 's|^https\?://||' | sed 's|/$||')
    
    log_info "Scanning host: $host"
    
    # Detect plugins from this host
    local plugins_file=$(detect_plugins "https://$host")
    
    if [[ -n "$plugins_file" && -f "$plugins_file" && -s "$plugins_file" ]]; then
      local plugin_count=$(wc -l < "$plugins_file")
      log_info "Found $plugin_count plugins on $host"
      
      # Add host prefix to plugins for identification
      while IFS= read -r plugin; do
        [[ -n "$plugin" ]] && echo "$host:$plugin" >> "$all_plugins_file"
      done < "$plugins_file"
      
      rm -f "$plugins_file"
      ((processed_hosts++))
    else
      log_info "No plugins found on $host"
    fi
    
    # Small delay between hosts
    sleep 1
    
  done < "$live_hosts_file"
  
  local total_plugins=$(wc -l < "$all_plugins_file" 2>/dev/null || echo 0)
  log_info "Processed $processed_hosts hosts, found $total_plugins total plugins"
  
  if [[ $total_plugins -eq 0 ]]; then
    log_warn "No plugins found across all hosts"
    discord_send_progress "⚠️ **No WordPress plugins found across all hosts**"
    rm -f "$all_plugins_file"
    return 0
  fi
  
  # Process all collected plugins
  local output_file="$base/wp-plugin-confusion-results.txt"
  local filtered_file="$base/wp-plugin-confusion-filtered.txt"
  
  local results=$(process_plugins "$all_plugins_file" "$output_file" "$filtered_file")
  local vulnerable_count=$(echo "$results" | cut -d: -f1)
  local filtered_count=$(echo "$results" | cut -d: -f2)
  
  # Clean up temporary files
  rm -f "$all_plugins_file"
  
  log_success "WordPress Plugin Confusion scan completed"
  log_info "Total hosts processed: $processed_hosts"
  log_info "Total plugins checked: $total_plugins"
  log_info "Premium/paid/trademarked/reserved plugins filtered: $filtered_count"
  log_info "Vulnerable plugins found: $vulnerable_count"
  
  # Send results to Discord
  if [[ $vulnerable_count -gt 0 ]]; then
    log_success "Found $vulnerable_count potential WordPress Plugin Confusion vulnerabilities"
    discord_file "$filtered_file" "WordPress Plugin Confusion vulnerabilities across $processed_hosts hosts ($vulnerable_count potential targets)"
    
    # Also send raw results for reference
    discord_file "$output_file" "WordPress Plugin Confusion raw results across $processed_hosts hosts"
  else
    log_info "No WordPress Plugin Confusion vulnerabilities found"
    discord_send_progress "✅ **No WordPress Plugin Confusion vulnerabilities found across $processed_hosts hosts**"
  fi
  
  log_success "WordPress Plugin Confusion scanning completed for $processed_hosts hosts"
}

wp_plugin_confusion_scan() {
  local domain="" live_hosts_file=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -l|--list) live_hosts_file="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  
  # If live hosts file is provided, scan multiple hosts
  if [[ -n "$live_hosts_file" ]]; then
    if [[ ! -f "$live_hosts_file" ]]; then
      log_error "Live hosts file not found: $live_hosts_file"
      exit 1
    fi
    
    # Extract domain from live hosts file path for results directory
    local base_domain=$(basename "$(dirname "$live_hosts_file")")
    scan_multiple_hosts "$live_hosts_file" "$base_domain"
    return 0
  fi
  
  # If domain is provided, check for existing live hosts or run fastlook
  if [[ -n "$domain" ]]; then
    local dir="$(results_dir "$domain")"
    local live_hosts="$dir/subs/live-subs.txt"
    
    # Check if live hosts file exists
    if [[ -f "$live_hosts" && -s "$live_hosts" ]]; then
      log_info "Found existing live hosts file, scanning multiple hosts"
      scan_multiple_hosts "$live_hosts" "$domain"
      return 0
    else
      log_info "No existing live hosts found, running fastlook first"
      discord_send_progress "🔄 **No live hosts found for $domain, running fastlook first**"
      
      # Run fastlook to get live hosts
      if "$ROOT_DIR/modules/fastlook.sh" run -d "$domain"; then
        # Check if live hosts file was created
        if [[ -f "$live_hosts" && -s "$live_hosts" ]]; then
          log_info "Fastlook completed, scanning live hosts"
          scan_multiple_hosts "$live_hosts" "$domain"
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