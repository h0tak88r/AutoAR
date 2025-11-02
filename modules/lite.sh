#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: lite run -d <domain> [--skip-js]"; }

lite_run() {
  local domain=""
  local skip_js=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      --skip-js) skip_js=1; shift;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  # Calculate total steps (4 if skipping JS, 5 otherwise)
  local total_steps=$((skip_js ? 4 : 5))

  # Send initial progress notification
  discord_send "**Lite Scan started for:** \`$domain\`"

  log_info "Step 1/$total_steps: Live host filtering"
  discord_send "**[1/$total_steps] Live host filtering:** \`$domain\`"
  "$ROOT_DIR/modules/livehosts.sh" get -d "$domain" || log_warn "Live host filtering failed, continuing..."

  log_info "Step 2/$total_steps: Reflection scanning"
  discord_send "**[2/$total_steps] Reflection scanning:** \`$domain\`"
  "$ROOT_DIR/modules/reflection.sh" scan -d "$domain" || log_warn "Reflection scanning failed, continuing..."

  # JavaScript scanning (skippable)
  if [[ $skip_js -eq 0 ]]; then
    log_info "Step 3/$total_steps: JavaScript scanning"
    discord_send "**[3/$total_steps] JavaScript scanning:** \`$domain\`"
    "$ROOT_DIR/modules/js_scan.sh" scan -d "$domain" || log_warn "JavaScript scanning failed, continuing..."

    # Send all JS scan results to Discord if they exist
    local js_results_dir
    js_results_dir="$(results_dir "$domain")/vulnerabilities/js"
    if [[ -d "$js_results_dir" ]]; then
      local any_js_file_sent=0
      for findings_file in "$js_results_dir"/*.txt; do
        if [[ -s "$findings_file" ]]; then
          base="$(basename "$findings_file" .txt)"
          discord_file "$findings_file" "**JavaScript Scan Matches (\`$base\`) for \`$domain\`**"
          any_js_file_sent=1
        fi
      done
      if [[ $any_js_file_sent -eq 1 ]]; then
        discord_send "**JavaScript scan results posted above for** \`$domain\`"
      fi
    fi
  else
    log_info "Skipping JavaScript scanning (--skip-js flag set)"
  fi

  local nuclei_step=$((skip_js ? 3 : 4))
  log_info "Step $nuclei_step/$total_steps: Nuclei scanning"
  discord_send "**[$nuclei_step/$total_steps] Nuclei vulnerability scan:** \`$domain\`"
  "$ROOT_DIR/modules/nuclei.sh" run -d "$domain" || log_warn "Nuclei scanning failed, continuing..."

  log_info "Step $total_steps/$total_steps: Lite scan completed"
  discord_send "**Lite Scan completed for:** \`$domain\`"
}

case "${1:-}" in
  run) shift; lite_run "$@" ;;
  *) usage; exit 1;;
esac


