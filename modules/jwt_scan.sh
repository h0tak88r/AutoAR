#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() {
  cat <<EOF
Usage: 
  jwt scan -t <url> [--cookie <name=value>] [--header <name: value>] [OPTIONS]
  jwt query <query_id>

Examples:
  # Full scan via cookie
  jwt scan -t https://www.example.com/ --cookie auth=JWT_TOKEN

  # Scan via header (skip secret cracking for faster results)
  jwt scan -t https://www.example.com/ --header "Authorization: Bearer JWT_TOKEN" --skip-crack

  # Scan with custom wordlist
  jwt scan -t https://www.example.com/ --cookie auth=JWT_TOKEN -w /path/to/wordlist.txt

  # Scan with limited crack attempts
  jwt scan -t https://www.example.com/ --cookie auth=JWT_TOKEN --max-crack-attempts 50

Options:
  -t, --target <url>          Target URL
  --cookie <name=value>       JWT token via cookie (format: name=JWT_TOKEN)
  --header <name: value>      JWT token via header (format: "Authorization: Bearer JWT_TOKEN")
  --skip-crack                Skip secret cracking for faster results
  --skip-payloads             Skip payload generation
  -w, --wordlist <file>       Custom wordlist for weak secret detection
  --max-crack-attempts <num>  Limit secret testing attempts

Notes:
  - This uses jwt-hack (https://github.com/hahwul/jwt-hack) instead of jwt_tool.py
  - You must provide either --cookie or --header (not both).
  - Cookie format: name=JWT_TOKEN
  - Header format: "Authorization: Bearer JWT_TOKEN" or "Authorization: JWT_TOKEN"
EOF
}

jwt_scan() {
  local target="" mode="scan"
  local cookie=""
  local header=""
  local skip_crack=""
  local skip_payloads=""
  local wordlist=""
  local max_crack_attempts=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t|--target) target="$2"; shift 2;;
      --cookie)    cookie="$2"; shift 2;;
      --header)    header="$2"; shift 2;;
      -M|--mode)   mode="$2"; shift 2;;
      --skip-crack) skip_crack="--skip-crack"; shift;;
      --skip-payloads) skip_payloads="--skip-payloads"; shift;;
      -w|--wordlist) wordlist="$2"; shift 2;;
      --max-crack-attempts) max_crack_attempts="$2"; shift 2;;
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

  # Check if jwt-hack is available
  if ! command -v jwt-hack >/dev/null 2>&1; then
    log_error "jwt-hack not found. Please install it:"
    log_error "  cargo install jwt-hack"
    log_error "  or"
    log_error "  brew install jwt-hack"
    log_error "  or"
    log_error "  docker pull ghcr.io/hahwul/jwt-hack:latest"
    exit 1
  fi

  # Extract JWT token from cookie or header
  local jwt_token=""
  if [[ -n "$cookie" ]]; then
    # Cookie format: name=JWT_TOKEN
    jwt_token=$(echo "$cookie" | cut -d'=' -f2-)
    log_info "Running jwt-hack scan against $target (via cookie)"
    log_info "Using cookie: $cookie"
  else
    # Header format: "Authorization: Bearer JWT_TOKEN" or "Authorization: JWT_TOKEN"
    jwt_token=$(echo "$header" | sed -E 's/^[^:]+:\s*(Bearer\s+)?//')
    log_info "Running jwt-hack scan against $target (via header)"
    log_info "Using header: $header"
  fi

  if [[ -z "$jwt_token" ]]; then
    log_error "Failed to extract JWT token from cookie/header"
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
  local out_file="$out_dir/jwt_hack_${ts}.txt"

  log_info "Results will be saved to $out_file"

  # Build jwt-hack command - default to scan mode
  local cmd_args=("scan" "$jwt_token")
  
  # Map old mode parameter to jwt-hack options (for backward compatibility)
  case "$mode" in
    scan|pb|at)
      # Full scan mode (default)
      ;;
    decode)
      cmd_args=("decode" "$jwt_token")
      ;;
    verify)
      log_warn "Verify mode requires --secret parameter (not yet implemented in wrapper)"
      cmd_args=("decode" "$jwt_token")
      ;;
    *)
      # Default to scan
      ;;
  esac

  # Add optional flags if provided
  [[ -n "$skip_crack" ]] && cmd_args+=("--skip-crack")
  [[ -n "$skip_payloads" ]] && cmd_args+=("--skip-payloads")
  [[ -n "$wordlist" ]] && cmd_args+=("-w" "$wordlist")
  [[ -n "$max_crack_attempts" ]] && cmd_args+=("--max-crack-attempts" "$max_crack_attempts")

  set +e
  jwt-hack "${cmd_args[@]}" | tee "$out_file"
  local status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_warn "jwt-hack exited with status $status"
  else
    log_success "jwt-hack completed (exit code 0)"
  fi

  if [[ -s "$out_file" ]]; then
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-jwt_scan_$(date +%s)}"
    discord_send_file "$out_file" "🔐 JWT security test results for $target (mode: $mode)" "$scan_id"
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

  log_warn "jwt-hack does not support query mode like jwt_tool.py"
  log_warn "Query ID: $query_id"
  log_warn "Please use jwt-hack scan/decode/verify commands directly"
  
  return 1
}

case "${1:-}" in
  scan) shift; jwt_scan "$@" ;;
  query) shift; jwt_query "$@" ;;
  *) usage; exit 1;;
esac


