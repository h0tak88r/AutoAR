#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat <<EOF
Usage: jwt scan -t <url> -c "<cookie_string>" [-M <mode>]

Examples:
  jwt scan -t https://www.ticarpi.com/ -c "jwt=JWT_HERE;anothercookie=test" -M pb

Notes:
  - This is a thin wrapper around ticarpi/jwt_tool.
  - The cookie string is passed as a raw cookie via -rc.
EOF
}

jwt_scan() {
  local target="" cookie="" mode="pb"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target) target="$2"; shift 2;;
      -c|--cookie) cookie="$2"; shift 2;;
      -M|--mode)   mode="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done

  if [[ -z "$target" || -z "$cookie" ]]; then
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

  log_info "Running jwt_tool against $target with mode '$mode'"
  log_info "Results will be saved to $out_file"

  set +e
  python3 "$tool_script" \
    -t "$target" \
    -rc "$cookie" \
    -M "$mode" \
    | tee "$out_file"
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


