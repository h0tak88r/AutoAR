#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: dns takeover -d <domain>"; }

dns_takeover() {
  local domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$domain" ]] && { usage; exit 1; }

  local dir subs finding
  dir="$(results_dir "$domain")"
  subs="$dir/subs/all-subs.txt"
  ensure_dir "$dir/vulnerabilities/dns-takeover"
  finding="$dir/vulnerabilities/dns-takeover/dns-takeover-summary.txt"
  : > "$finding"
  
  # Ensure subdomains exist (from DB or enumeration)
  ensure_subdomains "$domain" "$subs" || { log_warn "Failed to get subdomains for $domain"; exit 1; }

  if [[ -s "$subs" && -d "$ROOT_DIR/nuclei-templates/http/takeovers" && -x "$(command -v nuclei || echo /bin/false)" ]]; then
    nuclei -l "$subs" -t nuclei-templates/http/takeovers/ -o "$dir/vulnerabilities/dns-takeover/nuclei-takeover-public.txt" >/dev/null 2>&1 || true
  fi

  [[ -s "$dir/vulnerabilities/dns-takeover/nuclei-takeover-public.txt" ]] && discord_send_file "$dir/vulnerabilities/dns-takeover/nuclei-takeover-public.txt" "Nuclei takeover findings"

  echo "DNS takeover scan completed for $domain" >> "$finding"
  discord_send_file "$finding" "DNS takeover summary for $domain"
}

case "${1:-}" in
  takeover) shift; dns_takeover "$@" ;;
  *) usage; exit 1;;
esac


