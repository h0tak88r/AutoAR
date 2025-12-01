#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat <<EOF
Usage: 
  jwt scan -t <url> [--cookie <name=value>] [--header <name: value>] [-M <mode>]
  jwt query <query_id>

Examples:
  # Send JWT via cookie
  jwt scan -t https://www.ticarpi.com/ --cookie auth=JWT_TOKEN -M at

  # Send JWT via header
  jwt scan -t https://www.ticarpi.com/ --header "Authorization: Bearer JWT_TOKEN" -M pb

  # Query a log entry by ID
  jwt query jwttool_4e7d0ae3c2bb25dfa4d765d9bb3f8317

Notes:
  - This is a thin wrapper around ticarpi/jwt_tool.
  - You must provide either --cookie or --header (not both).
  - Cookie format: name=value
  - Header format: name: value
EOF
}

jwt_scan() {
  local target="" mode="pb"
  local cookie=""
  local header=""
  local canary=""
  local post_data=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target) target="$2"; shift 2;;
      --cookie)    cookie="$2"; shift 2;;
      --header)    header="$2"; shift 2;;
      -M|--mode)   mode="$2"; shift 2;;
      --canary)    canary="$2"; shift 2;;
      --post-data) post_data="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done

  if [[ -z "$target" ]]; then
    usage
    exit 1
  fi

  if [[ -z "$cookie" && -z "$header" ]]; then
    log_error "You must provide either --cookie or --header"
    usage
    exit 1
  fi

  if [[ -n "$cookie" && -n "$header" ]]; then
    log_error "You cannot provide both --cookie and --header. Choose one."
    usage
    exit 1
  fi

  # Check both possible locations: python/jwt_tool.py (file) or python/jwt_tool/jwt_tool.py (directory)
  local tool_script=""
  if [[ -f "$ROOT_DIR/python/jwt_tool.py" ]]; then
    tool_script="$ROOT_DIR/python/jwt_tool.py"
  elif [[ -f "$ROOT_DIR/python/jwt_tool/jwt_tool.py" ]]; then
    tool_script="$ROOT_DIR/python/jwt_tool/jwt_tool.py"
  else
    log_error "jwt_tool not found. Expected at:"
    log_error "  $ROOT_DIR/python/jwt_tool.py"
    log_error "  or"
    log_error "  $ROOT_DIR/python/jwt_tool/jwt_tool.py"
    log_error "Please ensure jwt_tool.py is located in one of these locations"
    log_error "and install deps:"
    log_error "  python3 -m pip install termcolor cprint pycryptodomex requests ratelimit"
    exit 1
  fi

  local domain
  domain="$(echo "$target" | awk -F/ '{print $3}')"
  [[ -z "$domain" ]] && domain="jwt-scan"
  local out_dir
  out_dir="$(results_dir "$domain")/vulnerabilities/jwt"
  ensure_dir "$out_dir"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local out_file="$out_dir/jwt_tool_${ts}.txt"

  local via=""
  local rh_arg="" rc_arg="" cv_arg="" data_arg=""
  
  if [[ -n "$cookie" ]]; then
    via="cookie"
    rc_arg="-rc"
    log_info "Running jwt_tool against $target with mode '$mode' (via cookie)"
    log_info "Using cookie: $cookie"
  else
    via="header"
    rh_arg="-rh"
    log_info "Running jwt_tool against $target with mode '$mode' (via header)"
    log_info "Using header: $header"
  fi

  log_info "Results will be saved to $out_file"

  if [[ -n "$canary" ]]; then
    cv_arg="-cv"
  fi
  if [[ -n "$post_data" ]]; then
    data_arg="--data"
  fi

  set +e
  if [[ "$via" == "header" ]]; then
    python3 "$tool_script" \
      -t "$target" \
      -np \
      -y \
      $rh_arg "$header" \
      ${cv_arg:+$cv_arg "$canary"} \
      ${data_arg:+$data_arg "$post_data"} \
      -M "$mode" | tee "$out_file"
  else
    python3 "$tool_script" \
      -t "$target" \
      -np \
      -y \
      $rc_arg "$cookie" \
      ${cv_arg:+$cv_arg "$canary"} \
      ${data_arg:+$data_arg "$post_data"} \
      -M "$mode" | tee "$out_file"
  fi
  local status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_warn "jwt_tool exited with status $status"
  else
    log_success "jwt_tool completed (exit code 0)"
  fi

  if [[ -s "$out_file" ]]; then
    discord_file "$out_file" "🔐 JWT security test results for $target (mode: $mode)"
  fi

  return 0
}

jwt_query() {
  local query_id="$1"

  if [[ -z "$query_id" ]]; then
    log_error "Query ID is required"
    usage
    exit 1
  fi

  # Check both possible locations: python/jwt_tool.py (file) or python/jwt_tool/jwt_tool.py (directory)
  local tool_script=""
  if [[ -f "$ROOT_DIR/python/jwt_tool.py" ]]; then
    tool_script="$ROOT_DIR/python/jwt_tool.py"
  elif [[ -f "$ROOT_DIR/python/jwt_tool/jwt_tool.py" ]]; then
    tool_script="$ROOT_DIR/python/jwt_tool/jwt_tool.py"
  else
    log_error "jwt_tool not found. Expected at:"
    log_error "  $ROOT_DIR/python/jwt_tool.py"
    log_error "  or"
    log_error "  $ROOT_DIR/python/jwt_tool/jwt_tool.py"
    exit 1
  fi

  log_info "Querying JWT tool log for ID: $query_id"
  
  python3 "$tool_script" -Q "$query_id"
  local status=$?

  if [[ $status -ne 0 ]]; then
    log_warn "jwt_tool query exited with status $status"
    return 1
  fi

  return 0
}

case "${1:-}" in
  scan) shift; jwt_scan "$@" ;;
  query) shift; jwt_query "$@" ;;
  *) usage; exit 1;;
esac


