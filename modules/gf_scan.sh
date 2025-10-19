#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: gf scan -d <domain>"; }

gf_scan() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir="$(results_dir "$domain")"
  local urls="$dir/urls/all-urls.txt"
  local base="$dir/vulnerabilities"
  ensure_dir "$base"
  
  # Check if URLs file is corrupted (contains binary content)
  if [[ -f "$urls" ]] && file "$urls" | grep -q "data"; then
    log_warn "URLs file appears corrupted (binary content detected), regenerating..."
    mv "$urls" "${urls}.corrupted"
    
    if command -v urlfinder >/dev/null 2>&1; then
      log_info "Regenerating clean URLs with urlfinder"
      urlfinder -d "$domain" -all -silent -pc "${AUTOAR_CONFIG_FILE}" > "$urls" 2>/dev/null || true
      log_success "Regenerated URLs: $(wc -l < "$urls" 2>/dev/null || echo 0) lines"
    else
      log_warn "urlfinder not available, cannot regenerate URLs"
    fi
  fi
  
  # Check if URLs exist, if not run fastlook first
  if [[ ! -s "$urls" ]]; then
    log_info "No URLs found for $domain, running fastlook first"
    discord_send_progress "🔄 **No URLs found for $domain, running fastlook first**"
    
    set +e
    "$ROOT_DIR/modules/fastlook.sh" run -d "$domain"
    local fastlook_exit_code=$?
    set -e
    
    if [[ $fastlook_exit_code -ne 0 ]]; then
      log_warn "Failed to run fastlook for $domain (exit code: $fastlook_exit_code), continuing anyway..."
    fi
    
    # Check if URLs exist after fastlook
    if [[ ! -s "$urls" ]]; then
      log_warn "Still no URLs found for $domain after fastlook"
      exit 1
    fi
  fi
  
  log_info "Found URLs file: $urls ($(wc -l < "$urls") lines)"

  if command -v gf >/dev/null 2>&1; then
    log_info "Running GF patterns on $(wc -l < "$urls") URLs"
    local total_matches=0
    
    for pattern in debug_logic idor iext img-traversal iparams isubs jsvar lfi rce redirect sqli ssrf ssti xss; do
      local out="$base/$pattern/gf-results.txt"
      ensure_dir "$(dirname "$out")"
      
      set +e
      cat "$urls" | gf "$pattern" > "$out" 2>/dev/null
      local gf_exit_code=$?
      set -e
      
      if [[ $gf_exit_code -eq 0 && -s "$out" ]]; then
        local match_count=$(wc -l < "$out")
        log_success "GF $pattern: Found $match_count matches"
        total_matches=$((total_matches + match_count))
        discord_file "$out" "GF $pattern matches for $domain ($match_count matches)"
      else
        log_info "GF $pattern: No matches found"
      fi
    done
    
    log_success "GF scan completed: $total_matches total matches across all patterns"
  else
    log_warn "GF tool not found, skipping GF pattern scanning"
  fi
}

case "${1:-}" in
  scan) shift; gf_scan "$@" ;;
  *) usage; exit 1;;
esac


