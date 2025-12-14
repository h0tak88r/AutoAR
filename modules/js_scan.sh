#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load environment variables first
if [[ -f "$ROOT_DIR/.env" ]]; then
  source "$ROOT_DIR/.env"
fi

source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"
source "$ROOT_DIR/lib/db.sh"

usage() { echo "Usage: js scan -d <domain> [-s <subdomain>]"; }

ensure_phase_time_remaining() {
  local remaining
  remaining=$(phase_time_remaining)
  # Ensure remaining is numeric before comparison
  if [[ -n "$remaining" ]] && [[ "$remaining" =~ ^[0-9]+$ ]] && [[ "$remaining" -le 0 ]]; then
    log_warn "Phase timeout reached for JavaScript scanning; skipping remaining JS tasks."
    return 1
  fi
  return 0
}

run_js_with_phase_timeout() {
  local description="$1"
  shift
  if ! run_with_phase_timeout "$description" "$@"; then
    local status=$?
    if [[ $status -eq 124 ]]; then
      log_warn "$description exceeded the configured phase timeout for this lite phase."
    fi
    return $status
  fi
  return 0
}

js_scan() {
  local domain="" sub=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -s|--subdomain) sub="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" && -z "$sub" ]] && { usage; exit 1; }

  local target_dir; target_dir="$(results_dir "${sub:-$domain}")"
  local urls_file="$target_dir/urls/js-urls.txt"
  ensure_dir "$(dirname "$urls_file")"

  # Try to ensure URLs exist, but don't fail if it doesn't work
  set +e
  ensure_urls "${sub:-$domain}" "$urls_file" || log_warn "Failed to get URLs for ${sub:-$domain}, continuing anyway..."
  set -e

  # If URLs file doesn't exist, try to create it from existing results
  if [[ ! -s "$urls_file" ]]; then
    log_warn "No JS URLs file found, checking for existing results..."
    local results_dir="$(dirname "$(dirname "$urls_file")")"
    local js_urls_file="$results_dir/urls/js-urls.txt"
    if [[ -s "$js_urls_file" ]]; then
      log_info "Using existing JS URLs from previous scan"
      cp "$js_urls_file" "$urls_file"
    fi
  fi

  local out_dir="$target_dir/vulnerabilities/js"; ensure_dir "$out_dir"

  # Only run JS analysis if URLs file exists and has content
  if [[ -s "$urls_file" ]]; then
    if ! ensure_phase_time_remaining; then
      return 0
    fi

    # === Nuclei Template Scanning ===
    log_info "Running Nuclei template scans on JavaScript files"

    # Check if nuclei is available
    if command -v nuclei >/dev/null 2>&1; then
      local nuclei_found=false

      # 1. Scan with all custom JS templates (including tokens)
      if [[ -d "$ROOT_DIR/nuclei_templates/js" ]]; then
        log_info "Scanning with all custom JS templates (including all tokens)"
        local custom_status=0
        if ! run_js_with_phase_timeout "Custom JS Nuclei templates" \
        nuclei -l "$urls_file" \
          -t "$ROOT_DIR/nuclei_templates/js/" \
          -silent \
          -duc \
          -o "$out_dir/nuclei-custom-js.txt" \
          2>/dev/null; then
          custom_status=$?
          if [[ $custom_status -eq 124 ]]; then
            return 0
          fi
          log_warn "Custom JS Nuclei scan exited with status $custom_status, continuing..."
        fi

        if [[ -s "$out_dir/nuclei-custom-js.txt" ]]; then
          local custom_count=$(wc -l < "$out_dir/nuclei-custom-js.txt")
          log_success "Found $custom_count matches with all custom JS templates"
          cat "$out_dir/nuclei-custom-js.txt"
          nuclei_found=true
        else
          log_info "No matches found with all custom JS templates"
        fi
      fi

      # 2. Scan with all public Nuclei exposure templates
      if [[ -d "$ROOT_DIR/nuclei-templates/http/exposures" ]]; then
        log_info "Scanning with all public Nuclei exposure templates"
        local public_status=0
        if ! run_js_with_phase_timeout "Public exposure Nuclei templates" \
        nuclei -l "$urls_file" \
          -t "$ROOT_DIR/nuclei-templates/http/exposures/" \
          -silent \
          -duc \
          -o "$out_dir/nuclei-public-exposures.txt" \
          2>/dev/null; then
          public_status=$?
          if [[ $public_status -eq 124 ]]; then
            return 0
          fi
          log_warn "Public exposure Nuclei scan exited with status $public_status, continuing..."
        fi

        if [[ -s "$out_dir/nuclei-public-exposures.txt" ]]; then
          local public_count=$(wc -l < "$out_dir/nuclei-public-exposures.txt")
          log_success "Found $public_count matches with public exposure templates"
          cat "$out_dir/nuclei-public-exposures.txt"
          nuclei_found=true
        else
          log_info "No matches found with public exposure templates"
        fi
      fi



      if [[ "$nuclei_found" == false ]]; then
        log_info "No Nuclei findings detected"
      fi
    else
      log_warn "Nuclei not found in PATH, skipping Nuclei template scans"
    fi

    # === JSLeak Regex Analysis ===
    log_info "Running JS regex analysis with jsleak"

    if command -v jsleak >/dev/null 2>&1; then
      if ! ensure_phase_time_remaining; then
        return 0
      fi
      log_info "Scanning with trufflehog-v3 patterns"
      local truffle_status=0
      if ! run_js_with_phase_timeout "trufflehog regex scan" \
        jsleak -t "$ROOT_DIR/regexes/trufflehog-v3.yaml" -s -c 20 < "$urls_file" > "$out_dir/trufflehog.txt" 2>/dev/null; then
        truffle_status=$?
        if [[ $truffle_status -eq 124 ]]; then
          return 0
        fi
        log_warn "trufflehog regex scan exited with status $truffle_status, continuing..."
      fi

      # Show results if any found
      if [[ -s "$out_dir/trufflehog.txt" ]]; then
        log_success "Found $(wc -l < "$out_dir/trufflehog.txt") trufflehog matches"
        cat "$out_dir/trufflehog.txt"
      else
        log_info "No trufflehog matches found"
      fi
    fi

    if [[ -d "$ROOT_DIR/regexes" ]]; then
      for f in "$ROOT_DIR"/regexes/*.yaml; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f" .yaml)"
        if [[ "$base" != "trufflehog-v3" ]]; then
          if ! ensure_phase_time_remaining; then
            return 0
          fi
          log_info "Scanning with $base patterns"
          local regex_status=0
          if ! run_js_with_phase_timeout "$base regex scan" \
            jsleak -t "$f" -s -c 20 < "$urls_file" > "$out_dir/$base.txt" 2>/dev/null; then
            regex_status=$?
            if [[ $regex_status -eq 124 ]]; then
              return 0
            fi
            log_warn "$base regex scan exited with status $regex_status, continuing..."
          fi

          # Show results if any found
          if [[ -s "$out_dir/$base.txt" ]]; then
            log_success "Found $(wc -l < "$out_dir/$base.txt") $base matches"
            cat "$out_dir/$base.txt"
          else
            log_info "No $base matches found"
          fi
        fi
      done
    fi

    # Save JS files to database
    log_info "Saving JS files to database"
    if db_ensure_connection; then
      # Initialize schema if needed
      db_init_schema 2>/dev/null || true
      local count=0
      while IFS= read -r js_url; do
        if [[ -n "$js_url" ]]; then
          if db_insert_js_file "$domain" "$js_url"; then
            ((count++))
          fi
        fi
      done < "$urls_file"
      log_success "Saved $count JS files to database"
    else
      log_warn "Database connection failed, skipping database save"
    fi
  else
    log_warn "No JS URLs file found at $urls_file"
  fi

  # Send all findings files to Discord
  log_info "Preparing to send results to Discord"
  local files_sent=0

  for findings_file in "$out_dir"/*.txt; do
    if [[ -s "$findings_file" ]]; then
      base="$(basename "$findings_file" .txt)"
      # Send final results via bot (webhook used for logging)
      local scan_id="${AUTOAR_CURRENT_SCAN_ID:-js_scan_$(date +%s)}"
      case "$base" in
        nuclei-custom-js)
          discord_send_file "$findings_file" "🔍 JS Scan - All Custom Templates (JS + 144+ Tokens)" "$scan_id"
          ((files_sent++))
          ;;
        nuclei-public-exposures)
          discord_send_file "$findings_file" "🌐 JS Scan - Public Nuclei Exposure Templates (All)" "$scan_id"
          ((files_sent++))
          ;;
        *)
          discord_send_file "$findings_file" "JS scan matches ($base)" "$scan_id"
          ((files_sent++))
          ;;
      esac
    fi
  done

  if [[ $files_sent -gt 0 ]]; then
    log_success "Sent $files_sent result files to Discord"
  else
    log_info "No findings to send to Discord"
  fi

  log_success "JavaScript scanning completed for ${sub:-$domain}"
  return 0
}

case "${1:-}" in
  scan) shift; js_scan "$@" ;;
  *) usage; exit 1;;
esac
