#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/
# lib/discord.sh functionality in gomodules/ - functionality in gomodules/

usage() {
  cat <<EOF
Usage: 
  jwt scan --token <JWT_TOKEN> [OPTIONS]

Examples:
  # Full scan including weak secret detection and payload generation
  jwt scan --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

  # Skip secret cracking for faster results
  jwt scan --token JWT_TOKEN --skip-crack

  # Skip payload generation
  jwt scan --token JWT_TOKEN --skip-payloads

  # Use custom wordlist for weak secret detection
  jwt scan --token JWT_TOKEN -w /path/to/wordlist.txt

  # Limit secret testing attempts
  jwt scan --token JWT_TOKEN --max-crack-attempts 50

Options:
  --token <JWT_TOKEN>         JWT token to scan (required)
  --skip-crack                Skip secret cracking for faster results
  --skip-payloads             Skip payload generation
  -w, --wordlist <file>       Custom wordlist for weak secret detection
  --max-crack-attempts <num>  Limit secret testing attempts

Notes:
  - This uses jwt-hack (https://github.com/hahwul/jwt-hack)
  - Simply provide the JWT token directly - no URL, cookie, or header needed
EOF
}

jwt_scan() {
  local jwt_token=""
  local skip_crack=""
  local skip_payloads=""
  local wordlist=""
  local max_crack_attempts=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --token) jwt_token="$2"; shift 2;;
      --skip-crack) skip_crack="--skip-crack"; shift;;
      --skip-payloads) skip_payloads="--skip-payloads"; shift;;
      -w|--wordlist) wordlist="$2"; shift 2;;
      --max-crack-attempts) max_crack_attempts="$2"; shift 2;;
      *) 
        # Unknown option - show usage but don't exit immediately if token is provided
        if [[ -z "$jwt_token" ]]; then
          usage
          exit 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$jwt_token" ]]; then
    log_error "JWT token is required"
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

  # Create output directory
  local out_dir
  out_dir="$(results_dir "jwt-scan")/vulnerabilities/jwt"
  ensure_dir "$out_dir"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local out_file="$out_dir/jwt_hack_${ts}.txt"

  log_info "Running jwt-hack scan on JWT token"
  log_info "Results will be saved to $out_file"

  # Build jwt-hack command - default to scan mode
  local cmd_args=("scan" "$jwt_token")

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
    discord_send_file "$out_file" "🔐 JWT security scan results" "$scan_id"
  fi

  return 0
}

case "${1:-}" in
  scan) shift; jwt_scan "$@" ;;
  *) usage; exit 1;;
esac


