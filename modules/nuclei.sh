#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat << EOF
Usage: nuclei run [OPTIONS]

Options:
  -d, --domain <domain>        Target domain
  -u, --url <url>              Single URL to scan (skips subdomain enumeration)
  -m, --mode <mode>            Scan mode: full, cves, panels (default: full)

  -t, --threads <num>          Number of threads (default: 100)
  -h, --help                   Show this help message

Scan Modes:
  full          - Scan with all custom (nuclei_templates/), public (nuclei-templates/http), and default logins templates
  cves          - Scan only with CVE templates (nuclei_templates/cves + nuclei-templates/http/cves)
  panels        - Scan only with panel discovery templates (nuclei_templates/panels + nuclei-templates/http/exposed-panels)
  default-logins - Scan only with default logins templates (custom & public)
  vulnerabilities - Scan only with generic vulnerability templates (nuclei_templates/vulns + nuclei-templates/http/vulnerabilities)

Examples:
  # Full scan on a domain (subdomain/livehost enumeration is automatic)
  nuclei run -d example.com -m full

  # CVEs scan on a single URL (no subdomain enum)
  nuclei run -u https://example.com -m cves

  # Panel discovery on a domain
  nuclei run -d example.com -m panels

  # Default logins scan on a domain
  nuclei run -d example.com -m default-logins

  # Default logins scan on a single URL
  nuclei run -u https://example.com -m default-logins

  # Generic vulnerabilities scan on a domain
  nuclei run -d example.com -m vulnerabilities

  # Generic vulnerabilities scan on a single URL
  nuclei run -u https://example.com -m vulnerabilities

  # Full scan on existing subdomains (no new enum)
  nuclei run -d example.com -m full
EOF
}

nuclei_run() {
  local domain="" url="" mode="full" threads="100"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -u|--url) url="$2"; shift 2;;
      -m|--mode) mode="$2"; shift 2;;

      -t|--threads) threads="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) log_error "Unknown option: $1"; usage; exit 1;;
    esac
  done

  # Validation
  [[ -z "$domain" && -z "$url" ]] && { log_error "Either -d (domain) or -u (url) must be provided"; usage; exit 1; }
  [[ -n "$domain" && -n "$url" ]] && { log_error "Cannot use both -d and -u together"; usage; exit 1; }
  [[ ! "$mode" =~ ^(full|cves|panels|default-logins|vulnerabilities)$ ]] && { log_error "Invalid mode: $mode. Must be full, cves, panels, default-logins, or vulnerabilities"; exit 1; }

  # Check if nuclei is installed
  if ! command -v nuclei >/dev/null 2>&1; then
    log_error "Nuclei is not installed or not in PATH"
    exit 1
  fi

  local target_file="" dir="" output_dir="" target_name=""

  # Handle URL mode (single URL, no subdomain enum)
  if [[ -n "$url" ]]; then
    log_info "Single URL mode: $url"
    target_name="$url"

    # Extract domain from URL for directory structure
    local extracted_domain=$(echo "$url" | awk -F[/:] '{print $4}')
    dir="$(results_dir "$extracted_domain")"
    output_dir="$dir/vulnerabilities"
    ensure_dir "$output_dir"

    # Create temporary URL file
    target_file="$dir/temp-url.txt"
    echo "$url" > "$target_file"

    # Send scan start notification
    discord_send "**Nuclei scan started for:** \`$url\` (mode: \`$mode\`)"

    log_info "Running Nuclei in $mode mode on single URL"
    run_nuclei_scan "$target_file" "$output_dir" "$mode" "$threads" "$target_name"

    # Cleanup
    rm -f "$target_file"

  # Handle domain mode
  else
    log_info "Domain mode: $domain"
    target_name="$domain"
    dir="$(results_dir "$domain")"
    output_dir="$dir/vulnerabilities"
    ensure_dir "$output_dir"

    # Always perform subdomain enumeration and live-host detection for domain scans
    log_info "Performing subdomain enumeration and live-host detection for $domain using livehosts module"
    ensure_dir "$dir/subs"

    local livehosts_script="$ROOT_DIR/modules/livehosts.sh"

    if [[ -f "$livehosts_script" ]]; then
      # Use the livehosts module to enumerate subdomains and detect live hosts.
      # This will produce $dir/subs/all-subs.txt and $dir/subs/live-subs.txt
      log_info "Invoking livehosts module: $livehosts_script get -d $domain -t $threads"
      # Run in subshell to avoid set -e causing exit on non-zero; livehosts.sh already handles failures gracefully.
      "$livehosts_script" get -d "$domain" -t "$threads" || log_warn "livehosts module exited with non-zero status"
    else
      log_warn "livehosts module not found at $livehosts_script. This project centralizes subdomain enumeration & live-host detection in that module; please ensure it exists."
    fi

    # Report counts if files exist
    if [[ -s "$dir/subs/all-subs.txt" ]]; then
      local sub_count=$(wc -l < "$dir/subs/all-subs.txt")
      log_success "Found $sub_count unique subdomains (post-enum)"
    fi

    if [[ -s "$dir/subs/live-subs.txt" ]]; then
      local live_count=$(wc -l < "$dir/subs/live-subs.txt")
      log_success "Found $live_count live hosts (post-enum)"
    fi

    # Ensure live hosts exist
    target_file="$dir/subs/live-subs.txt"

    if [[ ! -s "$target_file" ]]; then
      log_warn "No live hosts file found, trying to get from database..."
      ensure_dir "$dir/subs"

      # Try to get live hosts from database
      if ! ensure_live_hosts "$domain" "$target_file"; then
        log_error "Failed to get live hosts for $domain"
        log_info "Subdomain/livehost enumeration is automatic for domain scans"
        exit 1
      fi
    fi

    if [[ ! -s "$target_file" ]]; then
      log_error "No targets found to scan"
      exit 1
    fi

    local target_count=$(wc -l < "$target_file")
    log_info "Running Nuclei in $mode mode on $target_count targets"

    # Send scan start notification
    discord_send "**Nuclei scan started for:** \`$domain\` (mode: \`$mode\`, targets: \`$target_count\`)"

    run_nuclei_scan "$target_file" "$output_dir" "$mode" "$threads" "$target_name"
  fi

  log_success "Nuclei scan completed successfully!"
  discord_send "**Nuclei scan completed successfully for:** \`$target_name\` (mode: \`$mode\`)"
}

run_nuclei_scan() {
  local target_file="$1"
  local output_dir="$2"
  local mode="$3"
  local threads="$4"
  local target_name="$5"

  ensure_dir "$output_dir"

  case "$mode" in
    full)
      run_full_scan "$target_file" "$output_dir" "$threads" "$target_name"
      ;;
    cves)
      run_cves_scan "$target_file" "$output_dir" "$threads" "$target_name"
      ;;
    panels)
      run_panels_scan "$target_file" "$output_dir" "$threads" "$target_name"
      ;;
    default-logins)
      run_default_logins_scan "$target_file" "$output_dir" "$threads" "$target_name"
      ;;
    vulnerabilities)
      run_vulnerabilities_scan "$target_file" "$output_dir" "$threads" "$target_name"
      ;;
  esac
}

run_full_scan() {
  local target_file="$1"
  local output_dir="$2"
  local threads="$3"
  local target_name="$4"

  log_info "=== Running FULL scan mode ==="
  log_info "This includes all custom and public templates (and will also run CVEs and Panels scans)"

  local results=()

  # 1. Scan with custom templates (nuclei_templates/vulns)
  if [[ -d "$ROOT_DIR/nuclei_templates/vulns" ]]; then
    log_info "Scanning with custom templates (nuclei_templates/vulns)..."
    local custom_out="$output_dir/nuclei-custom-others.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei_templates/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$custom_out" \
      2>/dev/null || true

    if [[ -s "$custom_out" ]]; then
      local count=$(wc -l < "$custom_out")
      log_success "Found $count findings with custom templates"
      results+=("$custom_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_full_$(date +%s)}"
      discord_send_file "$custom_out" "**Nuclei Full Scan - Custom Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No findings with custom templates"
    fi
  fi

  # 2. Scan with public HTTP templates (nuclei-templates/http)
  if [[ -d "$ROOT_DIR/nuclei-templates/http" ]]; then
    log_info "Scanning with public HTTP templates (nuclei-templates/http)..."
    local public_out="$output_dir/nuclei-public-http.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei-templates/http/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$public_out" \
      2>/dev/null || true

    if [[ -s "$public_out" ]]; then
      local count=$(wc -l < "$public_out")
      log_success "Found $count findings with public HTTP templates"
      results+=("$public_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_full_$(date +%s)}"
      discord_send_file "$public_out" "**Nuclei Full Scan - Public HTTP Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No findings with public HTTP templates"
    fi
  fi

  # Summary
  if [[ ${#results[@]} -gt 0 ]]; then
    log_success "Full scan completed with ${#results[@]} result file(s)"
  else
    log_info "Full scan completed with no findings"
  fi
}

run_cves_scan() {
  local target_file="$1"
  local output_dir="$2"
  local threads="$3"
  local target_name="$4"

  log_info "=== Running CVEs scan mode ==="
  log_info "This includes custom and public CVE templates"

  local results=()

  # 1. Scan with custom CVE templates
  if [[ -d "$ROOT_DIR/nuclei_templates/cves" ]]; then
    log_info "Scanning with custom CVE templates (nuclei_templates/cves)..."
    local custom_cves_out="$output_dir/nuclei-custom-cves.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei_templates/cves/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$custom_cves_out" \
      2>/dev/null || true

    if [[ -s "$custom_cves_out" ]]; then
      local count=$(wc -l < "$custom_cves_out")
      log_success "Found $count CVE findings with custom templates"
      results+=("$custom_cves_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_cves_$(date +%s)}"
      discord_send_file "$custom_cves_out" "**Nuclei CVEs - Custom Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No CVE findings with custom templates"
    fi
  else
    log_warn "Custom CVE templates directory not found: nuclei_templates/cves"
  fi

  # 2. Scan with public CVE templates
  if [[ -d "$ROOT_DIR/nuclei-templates/http/cves" ]]; then
    log_info "Scanning with public CVE templates (nuclei-templates/http/cves)..."
    local public_cves_out="$output_dir/nuclei-public-cves.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei-templates/http/cves/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$public_cves_out" \
      2>/dev/null || true

    if [[ -s "$public_cves_out" ]]; then
      local count=$(wc -l < "$public_cves_out")
      log_success "Found $count CVE findings with public templates"
      results+=("$public_cves_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_cves_$(date +%s)}"
      discord_send_file "$public_cves_out" "**Nuclei CVEs - Public Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No CVE findings with public templates"
    fi
  else
    log_warn "Public CVE templates directory not found: nuclei-templates/http/cves"
  fi

  # Summary
  if [[ ${#results[@]} -gt 0 ]]; then
    log_success "CVEs scan completed with ${#results[@]} result file(s)"
  else
    log_info "CVEs scan completed with no findings"
  fi
}

run_panels_scan() {
  local target_file="$1"
  local output_dir="$2"
  local threads="$3"

  log_info "=== Running Panels Discovery scan mode ==="

  local results=()

  # 1. Scan with custom panels templates (nuclei_templates/panels)
  if [[ -d "$ROOT_DIR/nuclei_templates/panels" ]]; then
    log_info "Scanning with custom panel templates (nuclei_templates/panels - 1019+ templates)..."
    local custom_panels_out="$output_dir/nuclei-custom-panels.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei_templates/panels/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$custom_panels_out" \
      2>/dev/null || true

    if [[ -s "$custom_panels_out" ]]; then
      local count=$(wc -l < "$custom_panels_out")
      log_success "Found $count panels with custom templates"
      results+=("$custom_panels_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_panels_$(date +%s)}"
      discord_send_file "$custom_panels_out" "**Nuclei Panels Discovery - Custom Templates (1019+ Panels)**" "$scan_id"
    else
      log_info "No panels found with custom templates"
    fi
  else
    log_warn "Custom panels templates directory not found: nuclei_templates/panels"
  fi

  # 2. Scan with public exposed-panels templates
  if [[ -d "$ROOT_DIR/nuclei-templates/http/exposed-panels" ]]; then
    log_info "Scanning with public exposed panels templates (nuclei-templates/http/exposed-panels)..."
    local public_panels_out="$output_dir/nuclei-public-panels.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei-templates/http/exposed-panels/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$public_panels_out" \
      2>/dev/null || true

    if [[ -s "$public_panels_out" ]]; then
      local count=$(wc -l < "$public_panels_out")
      log_success "Found $count exposed panels with public templates"
      results+=("$public_panels_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_panels_$(date +%s)}"
      discord_send_file "$public_panels_out" "**Nuclei Panels Discovery - Public Templates**" "$scan_id"
    else
      log_info "No exposed panels found with public templates"
    fi
  else
    log_warn "Public exposed panels templates directory not found: nuclei-templates/http/exposed-panels"
  fi

  # Summary
  if [[ ${#results[@]} -gt 0 ]]; then
    log_success "Panels scan completed with ${#results[@]} result file(s)"
  else
    log_info "Panels scan completed with no findings"
  fi
}

run_default_logins_scan() {
  local target_file="$1"
  local output_dir="$2"
  local threads="$3"
  local target_name="$4"

  log_info "=== Running Default Logins scan ==="

  local results=()

  # 1. Scan with custom default logins templates
  if [[ -d "$ROOT_DIR/nuclei_templates/default-logins" ]]; then
    log_info "Scanning with custom default logins templates (nuclei_templates/default-logins)..."
    local custom_logins_out="$output_dir/nuclei-custom-default-logins.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei_templates/default-logins/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$custom_logins_out" \
      2>/dev/null || true

    if [[ -s "$custom_logins_out" ]]; then
      local count=$(wc -l < "$custom_logins_out")
      log_success "Found $count default login findings with custom templates"
      results+=("$custom_logins_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_logins_$(date +%s)}"
      discord_send_file "$custom_logins_out" "**Nuclei Default Logins - Custom Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No default login findings with custom templates"
    fi
  else
    log_warn "Custom default logins templates directory not found: nuclei_templates/default-logins"
  fi

  # 2. Scan with public default logins templates
  if [[ -d "$ROOT_DIR/nuclei-templates/http/default-logins" ]]; then
    log_info "Scanning with public default logins templates (nuclei-templates/http/default-logins)..."
    local public_logins_out="$output_dir/nuclei-public-default-logins.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei-templates/http/default-logins/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$public_logins_out" \
      2>/dev/null || true

    if [[ -s "$public_logins_out" ]]; then
      local count=$(wc -l < "$public_logins_out")
      log_success "Found $count default login findings with public templates"
      results+=("$public_logins_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_logins_$(date +%s)}"
      discord_send_file "$public_logins_out" "**Nuclei Default Logins - Public Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No default login findings with public templates"
    fi
  else
    log_warn "Public default logins templates directory not found: nuclei-templates/http/default-logins"
  fi

  # Summary
  if [[ ${#results[@]} -gt 0 ]]; then
    log_success "Default logins scan completed with ${#results[@]} result file(s)"
  else
    log_info "Default logins scan completed with no findings"
  fi
}

run_vulnerabilities_scan() {
  local target_file="$1"
  local output_dir="$2"
  local threads="$3"
  local target_name="$4"

  log_info "=== Running Generic Vulnerabilities scan mode ==="
  log_info "This includes custom and public vulnerability templates"

  local results=()

  # 1. Scan with custom vulnerability templates (nuclei_templates/vulns)
  if [[ -d "$ROOT_DIR/nuclei_templates/vulns" ]]; then
    log_info "Scanning with custom vulnerability templates (nuclei_templates/vulns)..."
    local custom_vulns_out="$output_dir/nuclei-custom-vulnerabilities.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei_templates/vulns/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$custom_vulns_out" \
      2>/dev/null || true

    if [[ -s "$custom_vulns_out" ]]; then
      local count=$(wc -l < "$custom_vulns_out")
      log_success "Found $count vulnerability findings with custom templates"
      results+=("$custom_vulns_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_vulns_$(date +%s)}"
      discord_send_file "$custom_vulns_out" "**Nuclei Vulnerabilities - Custom Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No vulnerability findings with custom templates"
    fi
  else
    log_warn "Custom vulnerability templates directory not found: nuclei_templates/vulns"
  fi

  # 2. Scan with public vulnerability templates (nuclei-templates/http/vulnerabilities)
  if [[ -d "$ROOT_DIR/nuclei-templates/http/vulnerabilities" ]]; then
    log_info "Scanning with public vulnerability templates (nuclei-templates/http/vulnerabilities)..."
    local public_vulns_out="$output_dir/nuclei-public-vulnerabilities.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei-templates/http/vulnerabilities/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$public_vulns_out" \
      2>/dev/null || true

    if [[ -s "$public_vulns_out" ]]; then
      local count=$(wc -l < "$public_vulns_out")
      log_success "Found $count vulnerability findings with public templates"
      results+=("$public_vulns_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_vulns_$(date +%s)}"
      discord_send_file "$public_vulns_out" "**Nuclei Vulnerabilities - Public Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No vulnerability findings with public templates"
    fi
  else
    log_warn "Public vulnerability templates directory not found: nuclei-templates/http/vulnerabilities"
  fi

  # 3. Scan with DAST vulnerability templates (nuclei-templates/dast/vulnerabilities)
  if [[ -d "$ROOT_DIR/nuclei-templates/dast/vulnerabilities" ]]; then
    log_info "Scanning with DAST vulnerability templates (nuclei-templates/dast/vulnerabilities)..."
    local dast_vulns_out="$output_dir/nuclei-dast-vulnerabilities.txt"

    nuclei -l "$target_file" \
      -t "$ROOT_DIR/nuclei-templates/dast/vulnerabilities/" \
      -c "$threads" \
      -silent \
      -duc \
      -o "$dast_vulns_out" \
      2>/dev/null || true

    if [[ -s "$dast_vulns_out" ]]; then
      local count=$(wc -l < "$dast_vulns_out")
      log_success "Found $count vulnerability findings with DAST templates"
      results+=("$dast_vulns_out")
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-nuclei_vulns_$(date +%s)}"
      discord_send_file "$dast_vulns_out" "**Nuclei Vulnerabilities - DAST Templates (\`$target_name\`)**" "$scan_id"
    else
      log_info "No vulnerability findings with DAST templates"
    fi
  else
    log_warn "DAST vulnerability templates directory not found: nuclei-templates/dast/vulnerabilities"
  fi

  # Summary
  if [[ ${#results[@]} -gt 0 ]]; then
    log_success "Vulnerabilities scan completed with ${#results[@]} result file(s)"
  else
    log_info "Vulnerabilities scan completed with no findings"
  fi
}

case "${1:-}" in
  run) shift; nuclei_run "$@" ;;
  -h|--help|help) usage; exit 0;;
  *) usage; exit 1;;
esac
