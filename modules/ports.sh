#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: ports scan -d <domain> [-t <threads>]"
  echo "  -d, --domain     Target domain to scan"
  echo "  -t, --threads    Number of threads for naabu (default: 100)"
}

ports_scan() {
  local domain="" threads="100"; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -t|--threads) threads="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  echo "[INFO] Starting ports scan for domain: $domain"
  
  local dir="$(results_dir "$domain")"
  local subs="$dir/subs/live-subs.txt"
  local out="$dir/ports/ports.txt"
  
  echo "[INFO] Results directory: $dir"
  echo "[INFO] Subdomains file: $subs"
  echo "[INFO] Output file: $out"
  
  ensure_dir "$(dirname "$out")"
  echo "[INFO] Created output directory: $(dirname "$out")"
  
  # Ensure live hosts exist (from DB or live host check)
  echo "[INFO] Ensuring live hosts exist..."
  if ! ensure_live_hosts "$domain" "$subs"; then
    echo "[ERROR] Failed to get live hosts for $domain"
    exit 1
  fi
  echo "[INFO] Live hosts check completed"

  if command -v naabu >/dev/null 2>&1; then
    echo "[INFO] Running naabu port scan with $threads threads..."
    if naabu -l "$subs" -tp "$threads" -ec -c 500 -Pn --silent -rate "$threads" -o "$out"; then
      echo "[SUCCESS] Naabu scan completed successfully"
    else
      echo "[WARN] Naabu scan completed with warnings"
    fi
  else
    echo "[ERROR] naabu not found, skipping port scan"
  fi
  
  if [[ -s "$out" ]]; then
    echo "[SUCCESS] Port scan results saved to: $out"
    echo "[INFO] File size: $(wc -l < "$out") lines"
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-ports_$(date +%s)}"
    discord_send_file "$out" "Port scan results for $domain" "$scan_id"
  else
    echo "[WARN] No port scan results generated"
  fi
}

case "${1:-}" in
  scan) shift; ports_scan "$@" ;;
  *) usage; exit 1;;
esac


