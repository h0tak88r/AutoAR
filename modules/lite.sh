#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat <<'EOF'
Usage: lite run -d <domain> [--skip-js] [--phase-timeout <duration>]
                 [--timeout-livehosts <duration>]
                 [--timeout-reflection <duration>]
                 [--timeout-js <duration>]
                 [--timeout-nuclei <duration>]

Durations accept plain seconds (e.g. 3600) or shorthand (e.g. 15m, 2h).
Use 0/none/off to disable the timeout for a phase.
EOF
}

parse_timeout_value() {
  local raw="$1"
  [[ -n "$raw" ]] || return 1

  case "$raw" in
    none|off|disable|disabled|0)
      echo 0
      return 0
      ;;
  esac

  if [[ "$raw" =~ ^([0-9]+)([smhdSMHD]?)$ ]]; then
    local value=${BASH_REMATCH[1]}
    local unit=${BASH_REMATCH[2]}
    case "$unit" in
      ''|'s'|'S') echo "$value" ;;
      'm'|'M') echo $((value * 60)) ;;
      'h'|'H') echo $((value * 3600)) ;;
      'd'|'D') echo $((value * 86400)) ;;
      *) echo "$value" ;;
    esac
    return 0
  fi

  log_warn "Invalid timeout value '$raw'. Expected seconds or suffixed value like 30m/2h."
  return 1
}

format_timeout_value() {
  local seconds="${1:-0}"
  if [[ -z "$seconds" || "$seconds" -le 0 ]]; then
    echo "no limit"
    return
  fi

  local hrs=$((seconds / 3600))
  local mins=$(((seconds % 3600) / 60))
  local secs=$((seconds % 60))
  local parts=()

  if (( hrs > 0 )); then
    parts+=("${hrs}h")
  fi
  if (( mins > 0 )); then
    parts+=("${mins}m")
  fi
  if (( hrs == 0 && mins == 0 )); then
    parts+=("${secs}s")
  fi

  echo "${parts[*]}"
}

run_phase() {
  local phase_key="$1"
  local step="$2"
  local total="$3"
  local description="$4"
  local timeout_seconds="$5"
  local target_label="$6"
  shift 6

  [[ -n "$phase_key" ]] || return 1

  # Ensure timeout_seconds is numeric, default to 0 if empty/invalid
  if [[ -z "$timeout_seconds" || ! "$timeout_seconds" =~ ^[0-9]+$ ]]; then
    timeout_seconds=0
  fi

  local timeout_label=""
  if [[ "$timeout_seconds" -gt 0 ]]; then
    timeout_label=" (timeout: $(format_timeout_value "$timeout_seconds"))"
  fi

  log_info "Step $step/$total: $description"
  discord_send "**[$step/$total] $description:** \`$target_label\`${timeout_label}"

  export AUTOAR_PHASE_KEY="$phase_key"
  export AUTOAR_PHASE_LABEL="$description"
  export AUTOAR_PHASE_TIMEOUT="$timeout_seconds"
  export AUTOAR_PHASE_START_TS="$(date +%s)"

  local phase_status=0
  if [[ "$timeout_seconds" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    set +e
    timeout --preserve-status --signal TERM --kill-after=30 "$timeout_seconds" "$@"
    phase_status=$?
    set -e
  elif [[ "$timeout_seconds" -gt 0 ]]; then
    log_warn "'timeout' command not available; running $phase_key without enforcement"
    set +e
    "$@"
    phase_status=$?
    set -e
  else
    set +e
    "$@"
    phase_status=$?
    set -e
  fi

  unset AUTOAR_PHASE_KEY AUTOAR_PHASE_LABEL AUTOAR_PHASE_TIMEOUT AUTOAR_PHASE_START_TS

  if [[ $phase_status -eq 124 ]]; then
    log_warn "$description timed out after $(format_timeout_value "$timeout_seconds")."
    discord_send "**[$step/$total] $description** timed out after $(format_timeout_value "$timeout_seconds"). Continuing..."
    return 124
  elif [[ $phase_status -ne 0 ]]; then
    log_warn "$description exited with status $phase_status. Continuing with next phase."
    return $phase_status
  fi

  log_success "$description completed"
  return 0
}

lite_run() {
  local domain=""
  local skip_js=0
  local env_default_timeout="${LITE_PHASE_TIMEOUT_DEFAULT:-3600}"
  local default_phase_timeout
  if ! default_phase_timeout=$(parse_timeout_value "$env_default_timeout"); then
    default_phase_timeout=7200
  fi

  declare -A phase_timeouts=(
    [livehosts]="__unset"
    [reflection]="__unset"
    [js]="__unset"
    [nuclei]="__unset"
  )

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      --skip-js) skip_js=1; shift;;
      --phase-timeout)
        if parsed=$(parse_timeout_value "$2"); then
          default_phase_timeout="$parsed"
        else
          log_warn "Unable to parse phase timeout '$2'; keeping existing default."
        fi
        shift 2;;
      --timeout-livehosts)
        if parsed=$(parse_timeout_value "$2"); then
          phase_timeouts[livehosts]="$parsed"
        fi
        shift 2;;
      --timeout-reflection)
        if parsed=$(parse_timeout_value "$2"); then
          phase_timeouts[reflection]="$parsed"
        fi
        shift 2;;
      --timeout-js)
        if parsed=$(parse_timeout_value "$2"); then
          phase_timeouts[js]="$parsed"
        fi
        shift 2;;
      --timeout-nuclei)
        if parsed=$(parse_timeout_value "$2"); then
          phase_timeouts[nuclei]="$parsed"
        fi
        shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  for key in "${!phase_timeouts[@]}"; do
    local value="${phase_timeouts[$key]}"
    if [[ "$value" == "__unset" || -z "$value" ]]; then
      phase_timeouts[$key]="$default_phase_timeout"
    fi
  done

  # Calculate total steps (4 if skipping JS, 5 otherwise)
  local total_steps=$((skip_js ? 4 : 5))

  # Send initial progress notification
  discord_send "**Lite Scan started for:** \`$domain\`"

  local current_step=1
  run_phase "livehosts" "$current_step" "$total_steps" "Live host filtering" "${phase_timeouts[livehosts]}" "$domain" \
    "$ROOT_DIR/modules/livehosts.sh" get -d "$domain" || true
  ((current_step++))

  run_phase "reflection" "$current_step" "$total_steps" "Reflection scanning" "${phase_timeouts[reflection]}" "$domain" \
    "$ROOT_DIR/modules/reflection.sh" scan -d "$domain" || true
  ((current_step++))

  # JavaScript scanning (skippable)
  if [[ $skip_js -eq 0 ]]; then
    run_phase "js" "$current_step" "$total_steps" "JavaScript scanning" "${phase_timeouts[js]}" "$domain" \
      "$ROOT_DIR/modules/js_scan.sh" scan -d "$domain" || true
    ((current_step++))

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

  run_phase "nuclei" "$current_step" "$total_steps" "Nuclei vulnerability scan" "${phase_timeouts[nuclei]}" "$domain" \
    "$ROOT_DIR/modules/nuclei.sh" run -d "$domain" || true
  ((current_step++))

  log_info "Step $total_steps/$total_steps: Lite scan completed"
  discord_send "**Lite Scan completed for:** \`$domain\`"
}

case "${1:-}" in
  run) shift; lite_run "$@" ;;
  *) usage; exit 1;;
esac


