#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat << EOF
Usage: react2shell_scan run [OPTIONS]

Options:
  -d, --domain <domain>        Target domain to scan
  -l, --list <file>            File containing list of domains (one per line)
  -t, --threads <num>          Number of threads for livehosts detection (default: 100)
  -h, --help                   Show this help message

Description:
  Scans live hosts for React Server Components RCE vulnerability (CVE-2025-55182).
  Uses livehosts module to get live hosts, then scans with:
  - Nuclei template (CVE-2025-55182.yaml)
  - react2shell.py with --waf-bypass flag
  - react2shell.py with --vercel-waf-bypass flag

Examples:
  # Scan single domain for React2Shell vulnerability
  react2shell_scan run -d example.com

  # Scan with custom threads
  react2shell_scan run -d example.com -t 200

  # Scan multiple domains from a file
  react2shell_scan run -l domains.txt

  # Scan multiple domains from a file with custom threads
  react2shell_scan run -l domains.txt -t 200
EOF
}

react2shell_scan_run() {
  local domain="" list_file="" threads="100"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -l|--list) list_file="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) log_error "Unknown option: $1"; usage; exit 1;;
    esac
  done

  # Validation
  if [[ -z "$domain" && -z "$list_file" ]]; then
    log_error "Either domain (-d) or list file (-l) is required"
    usage
    exit 1
  fi

  if [[ -n "$domain" && -n "$list_file" ]]; then
    log_error "Cannot specify both domain (-d) and list file (-l). Use one or the other."
    usage
    exit 1
  fi

  # If list file is provided, process each domain
  if [[ -n "$list_file" ]]; then
    if [[ ! -f "$list_file" ]]; then
      log_error "List file not found: $list_file"
      exit 1
    fi

    if [[ ! -s "$list_file" ]]; then
      log_error "List file is empty: $list_file"
      exit 1
    fi

    log_info "Processing domains from file: $list_file"
    local domain_count=0
    local processed_count=0
    local failed_count=0

    # Count total domains
    domain_count=$(grep -v '^[[:space:]]*$' "$list_file" | grep -v '^[[:space:]]*#' | wc -l)
    log_info "Found $domain_count domain(s) to scan"

    # Process each domain
    # Use explicit file descriptor to avoid issues with background processes
    exec 3< "$list_file"
    while IFS= read -r current_domain <&3 || [[ -n "$current_domain" ]]; do
      # Skip empty lines and comments
      [[ -z "$current_domain" ]] && continue
      [[ "$current_domain" =~ ^[[:space:]]*# ]] && continue
      
      # Trim whitespace
      current_domain=$(echo "$current_domain" | xargs)
      [[ -z "$current_domain" ]] && continue

      log_info "=========================================="
      log_info "Processing domain: $current_domain ($((processed_count + failed_count + 1))/$domain_count)"
      log_info "=========================================="

      if react2shell_scan_single_domain "$current_domain" "$threads"; then
        processed_count=$((processed_count + 1))
        log_success "Completed scan for: $current_domain"
      else
        failed_count=$((failed_count + 1))
        log_error "Failed scan for: $current_domain"
      fi

      log_info ""
    done
    exec 3<&-

    log_info "=========================================="
    log_success "Batch scan completed!"
    log_info "Total domains: $domain_count"
    log_info "Successfully processed: $processed_count"
    log_info "Failed: $failed_count"
    log_info "=========================================="

    return 0
  fi

  # Single domain mode
  react2shell_scan_single_domain "$domain" "$threads"
}

react2shell_scan_single_domain() {
  local domain="$1"
  local threads="${2:-100}"

  # Validation
  [[ -z "$domain" ]] && { log_error "Domain is required"; return 1; }

  # Check if react2shell.py exists
  local react2shell_script="$ROOT_DIR/python/react2shell.py"
  if [[ ! -f "$react2shell_script" ]]; then
    log_error "react2shell.py not found at $react2shell_script"
    return 1
  fi

  # Check if Python 3 is available
  if ! command -v python3 >/dev/null 2>&1; then
    log_error "python3 is not installed or not in PATH"
    return 1
  fi

  # Check if nuclei is available
  if ! command -v nuclei >/dev/null 2>&1; then
    log_error "nuclei is not installed or not in PATH"
    return 1
  fi

  # Check if Nuclei template exists
  local nuclei_template="$ROOT_DIR/nuclei_templates/cves/CVE-2025-55182.yaml"
  if [[ ! -f "$nuclei_template" ]]; then
    log_error "Nuclei template not found at $nuclei_template"
    return 1
  fi

  log_info "Starting React2Shell scan for domain: $domain"
  local dir; dir="$(results_dir "$domain")"
  local output_dir="$dir/vulnerabilities"
  ensure_dir "$output_dir"
  
  # Store domain for cleanup in Docker mode
  local domain_to_cleanup="$domain"

  # Step 1: Get live hosts using livehosts module
  log_info "Getting live hosts for $domain using livehosts module..."
  local livehosts_script="$ROOT_DIR/modules/livehosts.sh"
  
  if [[ -f "$livehosts_script" ]]; then
    log_info "Invoking livehosts module: $livehosts_script get -d $domain -t $threads --silent"
    "$livehosts_script" get -d "$domain" -t "$threads" --silent || log_warn "livehosts module exited with non-zero status"
  else
    log_error "livehosts module not found at $livehosts_script"
    return 1
  fi

  # Check for live hosts file
  local live_hosts_file="$dir/subs/live-subs.txt"
  ensure_dir "$dir/subs"
  
  if [[ ! -s "$live_hosts_file" ]]; then
    log_warn "No live hosts file found, trying to get from database..."
    
    # Try to get from database, but don't fail if it doesn't work
    ensure_live_hosts "$domain" "$live_hosts_file" || true
    
    # If still no file, check if all-subs.txt exists and use that
    if [[ ! -s "$live_hosts_file" && -s "$dir/subs/all-subs.txt" ]]; then
      log_info "Using all subdomains as live hosts"
      cp "$dir/subs/all-subs.txt" "$live_hosts_file"
    fi
  fi

  if [[ ! -s "$live_hosts_file" ]]; then
    log_error "No live hosts found for $domain"
    return 1
  fi

  local host_count=$(wc -l < "$live_hosts_file")
  log_success "Found $host_count live hosts to scan"

  # Normalize hosts (ensure they have http:// or https://)
  local temp_hosts_file="$dir/temp-hosts-normalized.txt"
  > "$temp_hosts_file"
  while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    if [[ ! "$host" =~ ^https?:// ]]; then
      echo "https://$host" >> "$temp_hosts_file"
    else
      echo "$host" >> "$temp_hosts_file"
    fi
  done < "$live_hosts_file"

  local scanned_count=$(wc -l < "$temp_hosts_file")

  # Step 2: Scan with Nuclei template
  log_info "=== Scanning with Nuclei template (CVE-2025-55182.yaml) ==="
  local nuclei_out="$output_dir/nuclei-cve-2025-55182.txt"
  local nuclei_log="$output_dir/nuclei-cve-2025-55182.log"
  
  # Capture both stdout and stderr to log file (but don't send to Discord)
  nuclei -l "$temp_hosts_file" \
    -t "$nuclei_template" \
    -c "$threads" \
    -silent \
    -duc \
    -o "$nuclei_out" \
    > "$nuclei_log" 2>&1 || true

  local nuclei_vulnerable=0
  local nuclei_hosts_file="$output_dir/nuclei-vulnerable-hosts.txt"
  > "$nuclei_hosts_file"
  if [[ -s "$nuclei_out" ]]; then
    nuclei_vulnerable=$(wc -l < "$nuclei_out")
    # Nuclei output format can be: [CVE-2025-55182] https://host/path or just https://host/path
    # Also handle JSON format if nuclei outputs JSON
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      
      # Skip lines that are just CVE tags without URLs
      if [[ "$line" =~ ^\[CVE-[0-9-]+\]$ ]]; then
        continue
      fi
      
      # Remove CVE tag if present, then extract hostname from URL
      # Handle formats like: [CVE-2025-55182] https://host/path or https://host/path
      local url=$(echo "$line" | sed -E 's/^\[[^\]]+\][[:space:]]*//' | awk '{print $1}')
      
      # Extract hostname from URL
      if [[ -n "$url" && "$url" =~ ^https?:// ]]; then
        local hostname=$(echo "$url" | sed 's|^https\?://||' | sed 's|/.*||' | sed 's|:.*||')
        if [[ -n "$hostname" ]]; then
          echo "$hostname" >> "$nuclei_hosts_file"
        fi
      # If line doesn't start with http but contains a domain-like pattern, try to extract it
      elif [[ "$line" =~ [a-zA-Z0-9.-]+\.[a-zA-Z]{2,} ]]; then
        # Extract potential hostname (skip CVE tags)
        local hostname=$(echo "$line" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
        if [[ -n "$hostname" && ! "$hostname" =~ ^CVE- ]]; then
          echo "$hostname" >> "$nuclei_hosts_file"
        fi
      fi
    done < "$nuclei_out"
    
    # Recalculate actual vulnerable count from extracted hosts
    if [[ -s "$nuclei_hosts_file" ]]; then
      nuclei_vulnerable=$(sort -u "$nuclei_hosts_file" | wc -l)
      sort -u "$nuclei_hosts_file" > "${nuclei_hosts_file}.tmp" && mv "${nuclei_hosts_file}.tmp" "$nuclei_hosts_file"
    else
      nuclei_vulnerable=0
    fi
  fi

  # Step 3: Scan with WAF bypass
  log_info "=== Scanning with WAF bypass (--waf-bypass) ==="
  local waf_bypass_out="$output_dir/react2shell-waf-bypass.txt"
  local waf_bypass_log="$output_dir/react2shell-waf-bypass.log"
  
  # Capture both stdout and stderr to log file (but don't send to Discord)
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --waf-bypass \
    --insecure \
    --quiet \
    --output "$waf_bypass_out" \
    --all-results \
    > "$waf_bypass_log" 2>&1 || true

  local waf_vulnerable=0
  local waf_hosts_file="$output_dir/waf-vulnerable-hosts.txt"
  > "$waf_hosts_file"
  if [[ -s "$waf_bypass_out" ]]; then
    # Extract vulnerable hosts from JSON output
    if command -v jq >/dev/null 2>&1; then
      jq -r '.results[] | select(.vulnerable == true) | .host' "$waf_bypass_out" 2>/dev/null | \
        sed -E 's|^https?://||' | sed 's|/.*||' >> "$waf_hosts_file" || true
      waf_vulnerable=$(wc -l < "$waf_hosts_file" 2>/dev/null || echo 0)
    else
      # Fallback: use Python to parse JSON
      python3 -c "
import json
import sys
try:
    with open('$waf_bypass_out', 'r') as f:
        data = json.load(f)
    for result in data.get('results', []):
        if result.get('vulnerable') is True:
            host = result.get('host', '')
            if host:
                # Remove protocol and path
                host = host.replace('https://', '').replace('http://', '')
                host = host.split('/')[0]
                print(host)
except:
    pass
" >> "$waf_hosts_file" 2>/dev/null || true
      waf_vulnerable=$(wc -l < "$waf_hosts_file" 2>/dev/null || echo 0)
    fi
  fi

  # Step 4: Scan with Vercel WAF bypass
  log_info "=== Scanning with Vercel WAF bypass (--vercel-waf-bypass) ==="
  local vercel_waf_bypass_out="$output_dir/react2shell-vercel-waf-bypass.txt"
  local vercel_waf_bypass_log="$output_dir/react2shell-vercel-waf-bypass.log"
  
  # Capture both stdout and stderr to log file (but don't send to Discord)
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --vercel-waf-bypass \
    --insecure \
    --quiet \
    --output "$vercel_waf_bypass_out" \
    --all-results \
    > "$vercel_waf_bypass_log" 2>&1 || true

  local vercel_vulnerable=0
  local vercel_hosts_file="$output_dir/vercel-vulnerable-hosts.txt"
  > "$vercel_hosts_file"
  if [[ -s "$vercel_waf_bypass_out" ]]; then
    # Extract vulnerable hosts from JSON output
    if command -v jq >/dev/null 2>&1; then
      jq -r '.results[] | select(.vulnerable == true) | .host' "$vercel_waf_bypass_out" 2>/dev/null | \
        sed -E 's|^https?://||' | sed 's|/.*||' >> "$vercel_hosts_file" || true
      vercel_vulnerable=$(wc -l < "$vercel_hosts_file" 2>/dev/null || echo 0)
    else
      # Fallback: use Python to parse JSON
      python3 -c "
import json
import sys
try:
    with open('$vercel_waf_bypass_out', 'r') as f:
        data = json.load(f)
    for result in data.get('results', []):
        if result.get('vulnerable') is True:
            host = result.get('host', '')
            if host:
                # Remove protocol and path
                host = host.replace('https://', '').replace('http://', '')
                host = host.split('/')[0]
                print(host)
except:
    pass
" >> "$vercel_hosts_file" 2>/dev/null || true
      vercel_vulnerable=$(wc -l < "$vercel_hosts_file" 2>/dev/null || echo 0)
    fi
  fi

  # Step 5: Scan with common Next.js/React paths
  log_info "=== Scanning with common framework paths (--path-file) ==="
  local paths_file="$ROOT_DIR/Wordlists/react-nextjs-paths.txt"
  local paths_scan_out="$output_dir/react2shell-paths-scan.txt"
  local paths_scan_log="$output_dir/react2shell-paths-scan.log"
  local paths_vulnerable=0
  local paths_hosts_file="$output_dir/paths-vulnerable-hosts.txt"
  > "$paths_hosts_file"
  
  if [[ -f "$paths_file" ]]; then
    log_info "Using paths file: $paths_file"
    # Capture both stdout and stderr to log file (but don't send to Discord)
    python3 "$react2shell_script" \
      -l "$temp_hosts_file" \
      --path-file "$paths_file" \
      --insecure \
      --quiet \
      --output "$paths_scan_out" \
      --all-results \
      > "$paths_scan_log" 2>&1 || true

    if [[ -s "$paths_scan_out" ]]; then
      # Extract vulnerable hosts from JSON output
      if command -v jq >/dev/null 2>&1; then
        jq -r '.results[] | select(.vulnerable == true) | .host' "$paths_scan_out" 2>/dev/null | \
          sed -E 's|^https?://||' | sed 's|/.*||' >> "$paths_hosts_file" || true
        paths_vulnerable=$(wc -l < "$paths_hosts_file" 2>/dev/null || echo 0)
      else
        # Fallback: use Python to parse JSON
        python3 -c "
import json
import sys
try:
    with open('$paths_scan_out', 'r') as f:
        data = json.load(f)
    for result in data.get('results', []):
        if result.get('vulnerable') is True:
            host = result.get('host', '')
            if host:
                # Remove protocol and path
                host = host.replace('https://', '').replace('http://', '')
                host = host.split('/')[0]
                print(host)
except:
    pass
" >> "$paths_hosts_file" 2>/dev/null || true
        paths_vulnerable=$(wc -l < "$paths_hosts_file" 2>/dev/null || echo 0)
      fi
    fi
  else
    log_warn "Paths file not found: $paths_file, skipping paths scan"
  fi

  # Step 6: Scan with double URL encoding bypass
  log_info "=== Scanning with double URL encoding bypass (--double-encode) ==="
  local double_encode_out="$output_dir/react2shell-double-encode.txt"
  local double_encode_log="$output_dir/react2shell-double-encode.log"
  local double_encode_vulnerable=0
  local double_encode_hosts_file="$output_dir/double-encode-vulnerable-hosts.txt"
  > "$double_encode_hosts_file"
  
  # Capture both stdout and stderr to log file (but don't send to Discord)
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --double-encode \
    --insecure \
    --quiet \
    --output "$double_encode_out" \
    --all-results \
    > "$double_encode_log" 2>&1 || true

  if [[ -s "$double_encode_out" ]]; then
    # Extract vulnerable hosts from JSON output
    if command -v jq >/dev/null 2>&1; then
      jq -r '.results[] | select(.vulnerable == true) | .host' "$double_encode_out" 2>/dev/null | \
        sed -E 's|^https?://||' | sed 's|/.*||' >> "$double_encode_hosts_file" || true
      double_encode_vulnerable=$(wc -l < "$double_encode_hosts_file" 2>/dev/null || echo 0)
    else
      # Fallback: use Python to parse JSON
      python3 -c "
import json
import sys
try:
    with open('$double_encode_out', 'r') as f:
        data = json.load(f)
    for result in data.get('results', []):
        if result.get('vulnerable') is True:
            host = result.get('host', '')
            if host:
                # Remove protocol and path
                host = host.replace('https://', '').replace('http://', '')
                host = host.split('/')[0]
                print(host)
except:
    pass
" >> "$double_encode_hosts_file" 2>/dev/null || true
      double_encode_vulnerable=$(wc -l < "$double_encode_hosts_file" 2>/dev/null || echo 0)
    fi
  fi

  # Step 7: Scan with semicolon bypass
  log_info "=== Scanning with semicolon bypass (--semicolon-bypass) ==="
  local semicolon_bypass_out="$output_dir/react2shell-semicolon-bypass.txt"
  local semicolon_bypass_log="$output_dir/react2shell-semicolon-bypass.log"
  local semicolon_bypass_vulnerable=0
  local semicolon_bypass_hosts_file="$output_dir/semicolon-bypass-vulnerable-hosts.txt"
  > "$semicolon_bypass_hosts_file"
  
  # Capture both stdout and stderr to log file (but don't send to Discord)
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --semicolon-bypass \
    --insecure \
    --quiet \
    --output "$semicolon_bypass_out" \
    --all-results \
    > "$semicolon_bypass_log" 2>&1 || true

  if [[ -s "$semicolon_bypass_out" ]]; then
    # Extract vulnerable hosts from JSON output
    if command -v jq >/dev/null 2>&1; then
      jq -r '.results[] | select(.vulnerable == true) | .host' "$semicolon_bypass_out" 2>/dev/null | \
        sed -E 's|^https?://||' | sed 's|/.*||' >> "$semicolon_bypass_hosts_file" || true
      semicolon_bypass_vulnerable=$(wc -l < "$semicolon_bypass_hosts_file" 2>/dev/null || echo 0)
    else
      # Fallback: use Python to parse JSON
      python3 -c "
import json
import sys
try:
    with open('$semicolon_bypass_out', 'r') as f:
        data = json.load(f)
    for result in data.get('results', []):
        if result.get('vulnerable') is True:
            host = result.get('host', '')
            if host:
                # Remove protocol and path
                host = host.replace('https://', '').replace('http://', '')
                host = host.split('/')[0]
                print(host)
except:
    pass
" >> "$semicolon_bypass_hosts_file" 2>/dev/null || true
      semicolon_bypass_vulnerable=$(wc -l < "$semicolon_bypass_hosts_file" 2>/dev/null || echo 0)
    fi
  fi

  # Step 8: Scan for source code exposure via ACTION_ID extraction
  log_info "=== Scanning for source code exposure (--check-source-exposure) ==="
  local source_exposure_out="$output_dir/react2shell-source-exposure.txt"
  local source_exposure_log="$output_dir/react2shell-source-exposure.log"
  local source_exposure_vulnerable=0
  local source_exposure_hosts_file="$output_dir/source-exposure-vulnerable-hosts.txt"
  > "$source_exposure_hosts_file"
  
  # Capture both stdout and stderr to log file (but don't send to Discord)
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --check-source-exposure \
    --insecure \
    --quiet \
    --output "$source_exposure_out" \
    --all-results \
    > "$source_exposure_log" 2>&1 || true

  if [[ -s "$source_exposure_out" ]]; then
    # Extract vulnerable hosts from JSON output
    if command -v jq >/dev/null 2>&1; then
      jq -r '.results[] | select(.vulnerable == true) | .host' "$source_exposure_out" 2>/dev/null | \
        sed -E 's|^https?://||' | sed 's|/.*||' >> "$source_exposure_hosts_file" || true
      source_exposure_vulnerable=$(wc -l < "$source_exposure_hosts_file" 2>/dev/null || echo 0)
    else
      # Fallback: use Python to parse JSON
      python3 -c "
import json
import sys
try:
    with open('$source_exposure_out', 'r') as f:
        data = json.load(f)
    for result in data.get('results', []):
        if result.get('vulnerable') is True:
            host = result.get('host', '')
            if host:
                # Remove protocol and path
                host = host.replace('https://', '').replace('http://', '')
                host = host.split('/')[0]
                print(host)
except:
    pass
" >> "$source_exposure_hosts_file" 2>/dev/null || true
      source_exposure_vulnerable=$(wc -l < "$source_exposure_hosts_file" 2>/dev/null || echo 0)
    fi
  fi

  # Cleanup temp file
  rm -f "$temp_hosts_file"

  # Collect all unique vulnerable hosts
  local all_vulnerable_hosts_file="$output_dir/all-vulnerable-hosts.txt"
  > "$all_vulnerable_hosts_file"
  [[ -s "$nuclei_hosts_file" ]] && cat "$nuclei_hosts_file" >> "$all_vulnerable_hosts_file"
  [[ -s "$waf_hosts_file" ]] && cat "$waf_hosts_file" >> "$all_vulnerable_hosts_file"
  [[ -s "$vercel_hosts_file" ]] && cat "$vercel_hosts_file" >> "$all_vulnerable_hosts_file"
  [[ -s "$paths_hosts_file" ]] && cat "$paths_hosts_file" >> "$all_vulnerable_hosts_file"
  [[ -s "$double_encode_hosts_file" ]] && cat "$double_encode_hosts_file" >> "$all_vulnerable_hosts_file"
  [[ -s "$semicolon_bypass_hosts_file" ]] && cat "$semicolon_bypass_hosts_file" >> "$all_vulnerable_hosts_file"
  [[ -s "$source_exposure_hosts_file" ]] && cat "$source_exposure_hosts_file" >> "$all_vulnerable_hosts_file"
  
  # Get unique vulnerable hosts
  local unique_vulnerable_hosts=0
  local unique_hosts_file="$output_dir/unique-vulnerable-hosts.txt"
  if [[ -s "$all_vulnerable_hosts_file" ]]; then
    sort -u "$all_vulnerable_hosts_file" > "$unique_hosts_file"
    unique_vulnerable_hosts=$(wc -l < "$unique_hosts_file")
  fi

  # Output results to stdout for Discord bot to process
  if [[ $unique_vulnerable_hosts -gt 0 ]]; then
    log_success "React2Shell scan completed: $unique_vulnerable_hosts unique vulnerable host(s) found"
    log_info "  - Nuclei: $nuclei_vulnerable"
    log_info "  - WAF Bypass: $waf_vulnerable"
    log_info "  - Vercel WAF Bypass: $vercel_vulnerable"
    log_info "  - Common Paths: $paths_vulnerable"
    log_info "  - Double Encoding: $double_encode_vulnerable"
    log_info "  - Semicolon Bypass: $semicolon_bypass_vulnerable"
    log_info "  - Source Code Exposure: $source_exposure_vulnerable"
    
    # Send Discord webhook notification for vulnerabilities found
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
      local vuln_message="🚨 **React2Shell Vulnerability Found!**\n"
      vuln_message+="**Domain:** $domain\n"
      vuln_message+="**Total Vulnerable Hosts:** $unique_vulnerable_hosts\n"
      vuln_message+="**Breakdown:**\n"
      vuln_message+="  • Nuclei: $nuclei_vulnerable\n"
      vuln_message+="  • WAF Bypass: $waf_vulnerable\n"
      vuln_message+="  • Vercel WAF Bypass: $vercel_vulnerable\n"
      vuln_message+="  • Common Paths: $paths_vulnerable\n"
      vuln_message+="  • Double Encoding: $double_encode_vulnerable\n"
      vuln_message+="  • Semicolon Bypass: $semicolon_bypass_vulnerable\n"
      vuln_message+="  • Source Code Exposure: $source_exposure_vulnerable\n"
      
      # Send notification message
      discord_send "$vuln_message"
      
      # Send vulnerable hosts file
      if [[ -s "$unique_hosts_file" ]]; then
        discord_send_file "$unique_hosts_file" "React2Shell Vulnerable Hosts for $domain"
      fi
      
      # Also send detailed results if available
      if [[ -s "$nuclei_out" ]]; then
        discord_send_file "$nuclei_out" "Nuclei CVE-2025-55182 results for $domain"
      fi
      if [[ -s "$waf_bypass_out" ]]; then
        discord_send_file "$waf_bypass_out" "WAF Bypass scan results for $domain"
      fi
      if [[ -s "$vercel_waf_bypass_out" ]]; then
        discord_send_file "$vercel_waf_bypass_out" "Vercel WAF Bypass scan results for $domain"
      fi
      if [[ -s "$paths_scan_out" ]]; then
        discord_send_file "$paths_scan_out" "Common Paths scan results for $domain"
      fi
      if [[ -s "$double_encode_out" ]]; then
        discord_send_file "$double_encode_out" "Double Encoding bypass results for $domain"
      fi
      if [[ -s "$semicolon_bypass_out" ]]; then
        discord_send_file "$semicolon_bypass_out" "Semicolon bypass results for $domain"
      fi
      if [[ -s "$source_exposure_out" ]]; then
        discord_send_file "$source_exposure_out" "Source Code Exposure scan results for $domain"
      fi
    fi
    
    # Output vulnerable hosts to stdout (bot will format this)
    echo "=== REACT2SHELL_SCAN_RESULTS ==="
    echo "STATUS: VULNERABLE"
    echo "DOMAIN: $domain"
      echo "TOTAL_VULNERABLE: $unique_vulnerable_hosts"
      echo "NUCLEI_COUNT: $nuclei_vulnerable"
      echo "WAF_BYPASS_COUNT: $waf_vulnerable"
      echo "VERCEL_WAF_BYPASS_COUNT: $vercel_vulnerable"
      echo "PATHS_SCAN_COUNT: $paths_vulnerable"
      echo "DOUBLE_ENCODE_COUNT: $double_encode_vulnerable"
      echo "SEMICOLON_BYPASS_COUNT: $semicolon_bypass_vulnerable"
      echo "SOURCE_EXPOSURE_COUNT: $source_exposure_vulnerable"
      echo "VULNERABLE_HOSTS_START"
    while IFS= read -r host; do
      [[ -z "$host" ]] && continue
      echo "$host"
    done < "$unique_hosts_file"
    echo "VULNERABLE_HOSTS_END"
  else
    log_success "React2Shell scan completed: No vulnerable hosts found"
    
    # Send progress update to Discord (optional, less verbose)
    if [[ -n "${DISCORD_WEBHOOK:-}" && -n "${REACT2SHELL_VERBOSE_NOTIFICATIONS:-}" ]]; then
      local progress_msg="✅ React2Shell scan completed for **$domain**\n"
      progress_msg+="Scanned $scanned_count live hosts - No vulnerabilities found"
      discord_send_progress "$progress_msg"
    fi
    
    # Output statistics to stdout
    echo "=== REACT2SHELL_SCAN_RESULTS ==="
    echo "STATUS: NOT_VULNERABLE"
    echo "DOMAIN: $domain"
      echo "LIVE_HOSTS: $host_count"
      echo "SCANNED: $scanned_count"
      echo "NUCLEI_COUNT: $nuclei_vulnerable"
      echo "WAF_BYPASS_COUNT: $waf_vulnerable"
      echo "VERCEL_WAF_BYPASS_COUNT: $vercel_vulnerable"
      echo "PATHS_SCAN_COUNT: $paths_vulnerable"
      echo "DOUBLE_ENCODE_COUNT: $double_encode_vulnerable"
      echo "SEMICOLON_BYPASS_COUNT: $semicolon_bypass_vulnerable"
      echo "SOURCE_EXPOSURE_COUNT: $source_exposure_vulnerable"
  fi

  # Cleanup: Remove domain results directory if running in Docker mode
  cleanup_domain_results "$domain_to_cleanup"

  return 0
}

case "${1:-}" in
  run) shift; react2shell_scan_run "$@" ;;
  -h|--help|help) usage; exit 0;;
  *) usage; exit 1;;
esac
