#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: s3 scan -b <bucket> [-r <region>] [--no-sign] | s3 enum -b <root-domain>"; }

s3_scan() {
  local bucket="" region="" no_sign=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -b|--bucket) bucket="$2"; shift 2;;
      -r|--region) region="$2"; shift 2;;
      -n|--no-sign|--no-sign-request) no_sign=true; shift;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$bucket" ]] && { usage; exit 1; }

  local dir; dir="$(results_dir "s3_$bucket")"
  local out="$dir/vulnerabilities/s3/s3-scan-results.txt"
  ensure_dir "$(dirname "$out")"

  local base_url="https://$bucket.s3.amazonaws.com/"
  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 3 "$base_url" || true)

  {
    echo "S3 BUCKET SCAN RESULTS"
    echo "Bucket: $bucket"
    echo "Region: ${region:-default}"
    echo "Base HTTP: $http_code"
  } > "$out"

  discord_file "$out" "S3 scan results for $bucket"
}

S3_MUTATIONS_DEFAULT=( "" "-files" "-data" "-backup" "-static" "-uploads" "-assets" "-media" "-images" "-docs" "-api" "-storage" "-logs" "-tmp" "-web" "-admin" )

s3_enum() {
  local root_domain=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -b|--bucket) root_domain="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  [[ -z "$root_domain" ]] && { usage; exit 1; }

  # normalize
  root_domain=$(echo "$root_domain" | sed 's/\..*$//' | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')

  local dir; dir="$(results_dir "s3_enum_$root_domain")"
  local out="$dir/vulnerabilities/s3/enum-put.txt"
  ensure_dir "$(dirname "$out")"
  : > "$out"

  local mutations_file="$ROOT_DIR/Wordlists/s3.txt"
  local -a mutations
  if [[ -f "$mutations_file" ]]; then
    mapfile -t mutations < <(grep -v '^#' "$mutations_file" | sed '/^$/d')
  else
    mutations=("${S3_MUTATIONS_DEFAULT[@]}")
  fi

  local -a bucket_names; bucket_names+=("$root_domain")
  for m in "${mutations[@]}"; do
    [[ -z "$m" ]] && continue
    bucket_names+=("${root_domain}${m}")
    [[ "$m" =~ ^[a-z] ]] && bucket_names+=("${m}${root_domain}")
  done

  log_info "Generated ${#bucket_names[@]} candidate buckets"

  local exists_count=0 vulnerable_count=0
  for b in "${bucket_names[@]}"; do
    local base="https://$b.s3.amazonaws.com/"
    local code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 1 --max-time 2 "$base" || true)
    if [[ "$code" =~ ^(200|301|302|403)$ ]]; then
      echo "[EXISTS] $base ($code)" >> "$out"
      ((exists_count++))
      # attempt simple PUT test
      local test_url="${base%/}/autoar-test-$(date +%s).txt"
      local put_resp=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 2 --max-time 3 -X PUT --data "autoar-test" "$test_url" || true)
      if [[ "$put_resp" == "200" || "$put_resp" == "201" ]]; then
        echo "[VULNERABLE] $test_url ($put_resp)" >> "$out"
        ((vulnerable_count++))
      fi
    fi
  done

  {
    echo "S3 ENUM SUMMARY"
    echo "Root: $root_domain"
    echo "Candidates: ${#bucket_names[@]}"
    echo "Existing: $exists_count"
    echo "Writable: $vulnerable_count"
  } >> "$out"

  discord_file "$out" "S3 enum results for $root_domain (exist: $exists_count, writable: $vulnerable_count)"
}

case "${1:-}" in
  scan) shift; s3_scan "$@" ;;
  enum) shift; s3_enum "$@" ;;
  *) usage; exit 1;;
esac


