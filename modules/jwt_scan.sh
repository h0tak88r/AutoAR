#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat <<EOF
Usage: jwt scan -t <url> --jwt <token> [--via header|cookie]
                [--header-name <name>] [--cookie-name <name>]
                [-M <mode>] [--canary <value>] [--post-data <data>]

Examples:
  # Send JWT via Authorization header (default)
  jwt scan -t https://www.ticarpi.com/ --jwt JWT_HERE -M pb

  # Send JWT via cookie named "jwt"
  jwt scan -t https://www.ticarpi.com/ --jwt JWT_HERE --via cookie --cookie-name jwt -M er

Notes:
  - This is a thin wrapper around ticarpi/jwt_tool.
  - The JWT is automatically placed in either a request header (-rh) or cookie (-rc).
EOF
}

jwt_scan() {
  local target="" jwt="" mode="pb"
  local via="header"
  local header_name="Authorization"
  local cookie_name="jwt"
  local canary=""
  local post_data=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target) target="$2"; shift 2;;
      --jwt)       jwt="$2"; shift 2;;
      --via)       via="$2"; shift 2;;
      --header-name) header_name="$2"; shift 2;;
      --cookie-name) cookie_name="$2"; shift 2;;
      -M|--mode)   mode="$2"; shift 2;;
      --canary)    canary="$2"; shift 2;;
      --post-data) post_data="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done

  if [[ -z "$target" || -z "$jwt" ]]; then
    usage
    exit 1
  fi

  local tool_dir="$ROOT_DIR/tools/jwt_tool"
  local tool_script="$tool_dir/jwt_tool.py"

  if [[ ! -f "$tool_script" ]]; then
    log_error "jwt_tool not found at $tool_script"
    log_error "Please clone it with:"
    log_error "  git clone https://github.com/ticarpi/jwt_tool \"$tool_dir\""
    log_error "and install deps:"
    log_error "  python3 -m pip install termcolor cprint pycryptodomex requests"
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

  log_info "Running jwt_tool against $target with mode '$mode' (via $via)"
  log_info "Results will be saved to $out_file"

  local rh_arg="" rc_arg="" cv_arg="" data_arg=""
  if [[ "$via" == "header" ]]; then
    local header_value
    if [[ "$header_name" =~ [Aa]uthorization ]]; then
      header_value="$header_name: Bearer $jwt"
    else
      header_value="$header_name: $jwt"
    fi
    rh_arg="-rh"
    rc_arg=""
    log_info "Using header: $header_value"
  else
    local cookie_value="${cookie_name}=${jwt}"
    rc_arg="-rc"
    rh_arg=""
    log_info "Using cookie: $cookie_value"
  fi

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
      $rh_arg "$header_value" \
      ${cv_arg:+$cv_arg "$canary"} \
      ${data_arg:+$data_arg "$post_data"} \
      -M "$mode" | tee "$out_file"
  else
    python3 "$tool_script" \
      -t "$target" \
      $rc_arg "$cookie_value" \
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

case "${1:-}" in
  scan) shift; jwt_scan "$@" ;;
  *) usage; exit 1;;
esac


