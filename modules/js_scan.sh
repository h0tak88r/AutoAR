#!/usr/bin/env bash
set -euo pipefail

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

  local out_dir="$target_dir/vulnerabilities/js"; ensure_dir "$out_dir"

  # Only run JS analysis if URLs file exists and has content
  if [[ -s "$urls_file" ]]; then
    if command -v jsleak >/dev/null 2>&1; then
      jsleak -t "$ROOT_DIR/regexes/trufflehog-v3.yaml" -s -c 20 < "$urls_file" > "$out_dir/trufflehog.txt" 2>/dev/null || true
    fi
    if [[ -d "$ROOT_DIR/regexes" ]]; then
      for f in "$ROOT_DIR"/regexes/*.yaml; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f" .yaml)"
        jsleak -t "$f" -s -c 20 < "$urls_file" > "$out_dir/$base.txt" 2>/dev/null || true
      done
    fi

    # Save JS files to database
    log_info "Saving JS files to database"
    local count=0
    while IFS= read -r js_url; do
      if [[ -n "$js_url" ]]; then
        if "$ROOT_DIR/db_handler.py" insert-js-file "$domain" "$js_url"; then
          ((count++))
        fi
      fi
    done < "$urls_file"
    log_info "Saved $count JS files to database"
  else
    log_warn "No JS URLs file found at $urls_file"
  fi

  if [[ -s "$out_dir/trufflehog.txt" ]]; then
    discord_send_file "$out_dir/trufflehog.txt" "JS scan matches (trufflehog)"
  fi
  
  log_success "JavaScript scanning completed for ${sub:-$domain}"
}

case "${1:-}" in
  scan) shift; js_scan "$@" ;;
  *) usage; exit 1;;
esac


