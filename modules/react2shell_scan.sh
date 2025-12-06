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
  -t, --threads <num>          Number of threads for livehosts detection (default: 100)
  -h, --help                   Show this help message

Description:
  Scans live hosts for React Server Components RCE vulnerability (CVE-2025-55182).
  Uses livehosts module to get live hosts, then scans with:
  - Nuclei template (CVE-2025-55182.yaml)
  - react2shell.py with --waf-bypass flag
  - react2shell.py with --vercel-waf-bypass flag

Examples:
  # Scan domain for React2Shell vulnerability
  react2shell_scan run -d example.com

  # Scan with custom threads
  react2shell_scan run -d example.com -t 200
EOF
}

react2shell_scan_run() {
  local domain="" threads="100"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) log_error "Unknown option: $1"; usage; exit 1;;
    esac
  done

  # Validation
  [[ -z "$domain" ]] && { log_error "Domain (-d) is required"; usage; exit 1; }

  # Check if react2shell.py exists
  local react2shell_script="$ROOT_DIR/python/react2shell.py"
  if [[ ! -f "$react2shell_script" ]]; then
    log_error "react2shell.py not found at $react2shell_script"
    exit 1
  fi

  # Check if Python 3 is available
  if ! command -v python3 >/dev/null 2>&1; then
    log_error "python3 is not installed or not in PATH"
    exit 1
  fi

  # Check if nuclei is available
  if ! command -v nuclei >/dev/null 2>&1; then
    log_error "nuclei is not installed or not in PATH"
    exit 1
  fi

  # Check if Nuclei template exists
  local nuclei_template="$ROOT_DIR/nuclei_templates/cves/CVE-2025-55182.yaml"
  if [[ ! -f "$nuclei_template" ]]; then
    log_error "Nuclei template not found at $nuclei_template"
    exit 1
  fi

  log_info "Starting React2Shell scan for domain: $domain"
  local dir; dir="$(results_dir "$domain")"
  local output_dir="$dir/vulnerabilities"
  ensure_dir "$output_dir"

  # Step 1: Get live hosts using livehosts module
  log_info "Getting live hosts for $domain using livehosts module..."
  local livehosts_script="$ROOT_DIR/modules/livehosts.sh"
  
  if [[ -f "$livehosts_script" ]]; then
    log_info "Invoking livehosts module: $livehosts_script get -d $domain -t $threads"
    "$livehosts_script" get -d "$domain" -t "$threads" || log_warn "livehosts module exited with non-zero status"
  else
    log_error "livehosts module not found at $livehosts_script"
    exit 1
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
    exit 1
  fi

  local host_count=$(wc -l < "$live_hosts_file")
  log_success "Found $host_count live hosts to scan"

  # Send scan start notification
  discord_send "**React2Shell scan started for:** \`$domain\` (hosts: \`$host_count\`)"

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

  # Step 2: Scan with Nuclei template
  log_info "=== Scanning with Nuclei template (CVE-2025-55182.yaml) ==="
  local nuclei_out="$output_dir/nuclei-cve-2025-55182.txt"
  local nuclei_log="$output_dir/nuclei-cve-2025-55182.log"
  
  # Capture both stdout and stderr to log file
  nuclei -l "$temp_hosts_file" \
    -t "$nuclei_template" \
    -c "$threads" \
    -silent \
    -duc \
    -o "$nuclei_out" \
    > "$nuclei_log" 2>&1 || true

  local nuclei_vulnerable=0
  if [[ -s "$nuclei_out" ]]; then
    nuclei_vulnerable=$(wc -l < "$nuclei_out")
  fi
  
  # Always send log file to Discord (contains stdout + stderr)
  if [[ -s "$nuclei_log" ]]; then
    discord_file "$nuclei_log" "**Nuclei - CVE-2025-55182 Logs (\`$domain\`)** - Vulnerable: $nuclei_vulnerable"
  fi
  
  # Send results file if vulnerabilities found
  if [[ $nuclei_vulnerable -gt 0 ]]; then
    log_success "Found $nuclei_vulnerable vulnerable host(s) with Nuclei"
    discord_file "$nuclei_out" "**Nuclei - CVE-2025-55182 Results (\`$domain\`)** - $nuclei_vulnerable vulnerable"
  else
    log_info "No vulnerable hosts found with Nuclei"
  fi

  # Step 3: Scan with WAF bypass
  log_info "=== Scanning with WAF bypass (--waf-bypass) ==="
  local waf_bypass_out="$output_dir/react2shell-waf-bypass.txt"
  local waf_bypass_log="$output_dir/react2shell-waf-bypass.log"
  
  # Capture both stdout and stderr to log file
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --waf-bypass \
    --insecure \
    --quiet \
    --output "$waf_bypass_out" \
    --all-results \
    > "$waf_bypass_log" 2>&1 || true

  local waf_vulnerable=0
  if [[ -s "$waf_bypass_out" ]]; then
    # Check JSON output for vulnerable hosts
    if command -v jq >/dev/null 2>&1; then
      waf_vulnerable=$(jq '.results[] | select(.vulnerable == true) | .host' "$waf_bypass_out" 2>/dev/null | wc -l)
    else
      # Fallback to grep if jq is not available
      waf_vulnerable=$(grep -c '"vulnerable": true' "$waf_bypass_out" 2>/dev/null || echo 0)
    fi
  fi
  
  # Always send log file to Discord (contains stdout + stderr)
  if [[ -s "$waf_bypass_log" ]]; then
    discord_file "$waf_bypass_log" "**React2Shell - WAF Bypass Logs (\`$domain\`)** - Vulnerable: $waf_vulnerable"
  fi
  
  # Send results file if vulnerabilities found
  if [[ $waf_vulnerable -gt 0 ]]; then
    log_success "Found $waf_vulnerable vulnerable host(s) with WAF bypass"
    discord_file "$waf_bypass_out" "**React2Shell - WAF Bypass Results (\`$domain\`)** - $waf_vulnerable vulnerable"
  else
    log_info "No vulnerable hosts found with WAF bypass"
  fi

  # Step 4: Scan with Vercel WAF bypass
  log_info "=== Scanning with Vercel WAF bypass (--vercel-waf-bypass) ==="
  local vercel_waf_bypass_out="$output_dir/react2shell-vercel-waf-bypass.txt"
  local vercel_waf_bypass_log="$output_dir/react2shell-vercel-waf-bypass.log"
  
  # Capture both stdout and stderr to log file
  python3 "$react2shell_script" \
    -l "$temp_hosts_file" \
    --vercel-waf-bypass \
    --insecure \
    --quiet \
    --output "$vercel_waf_bypass_out" \
    --all-results \
    > "$vercel_waf_bypass_log" 2>&1 || true

  local vercel_vulnerable=0
  if [[ -s "$vercel_waf_bypass_out" ]]; then
    # Check JSON output for vulnerable hosts
    if command -v jq >/dev/null 2>&1; then
      vercel_vulnerable=$(jq '.results[] | select(.vulnerable == true) | .host' "$vercel_waf_bypass_out" 2>/dev/null | wc -l)
    else
      # Fallback to grep if jq is not available
      vercel_vulnerable=$(grep -c '"vulnerable": true' "$vercel_waf_bypass_out" 2>/dev/null || echo 0)
    fi
  fi
  
  # Always send log file to Discord (contains stdout + stderr)
  if [[ -s "$vercel_waf_bypass_log" ]]; then
    discord_file "$vercel_waf_bypass_log" "**React2Shell - Vercel WAF Bypass Logs (\`$domain\`)** - Vulnerable: $vercel_vulnerable"
  fi
  
  # Send results file if vulnerabilities found
  if [[ $vercel_vulnerable -gt 0 ]]; then
    log_success "Found $vercel_vulnerable vulnerable host(s) with Vercel WAF bypass"
    discord_file "$vercel_waf_bypass_out" "**React2Shell - Vercel WAF Bypass Results (\`$domain\`)** - $vercel_vulnerable vulnerable"
  else
    log_info "No vulnerable hosts found with Vercel WAF bypass"
  fi

  # Cleanup temp file
  rm -f "$temp_hosts_file"

  # Summary
  local total_vulnerable=$((nuclei_vulnerable + waf_vulnerable + vercel_vulnerable))
  if [[ $total_vulnerable -gt 0 ]]; then
    log_success "React2Shell scan completed: $total_vulnerable vulnerable host(s) found"
    log_info "  - Nuclei: $nuclei_vulnerable"
    log_info "  - WAF Bypass: $waf_vulnerable"
    log_info "  - Vercel WAF Bypass: $vercel_vulnerable"
    discord_send "**React2Shell scan completed for:** \`$domain\` - **$total_vulnerable vulnerable host(s) found** (Nuclei: $nuclei_vulnerable, WAF: $waf_vulnerable, Vercel: $vercel_vulnerable)"
  else
    log_success "React2Shell scan completed: No vulnerable hosts found"
    discord_send "**React2Shell scan completed for:** \`$domain\` - No vulnerable hosts found"
  fi
}

case "${1:-}" in
  run) shift; react2shell_scan_run "$@" ;;
  -h|--help|help) usage; exit 0;;
  *) usage; exit 1;;
esac
