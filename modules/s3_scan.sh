#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load compatibility functions (replaces lib/ functions)
if [[ -f "$ROOT_DIR/gomodules/compat.sh" ]]; then
  source "$ROOT_DIR/gomodules/compat.sh"
else
  # Minimal fallback functions
  log_info()    { printf "[INFO] %s\n" "$*"; }
  log_warn()    { printf "[WARN] %s\n" "$*"; }
  log_error()   { printf "[ERROR] %s\n" "$*" 1>&2; }
  log_success() { printf "[OK] %s\n" "$*"; }
  ensure_dir() { mkdir -p "$1"; }
  results_dir() { echo "${AUTOAR_RESULTS_DIR:-new-results}/$1"; }
  discord_send_file() { log_info "File will be sent by Discord bot: $2"; }
fi

usage() { echo "Usage: s3 scan -b <bucket> [-r <region>] [--no-sign] | s3 enum -b <root-domain>"; exit 0; }

# S3 test file variables
S3_TEST_FILE="s3_test_file.txt"
S3_LOCAL_FILE="/tmp/$S3_TEST_FILE"

# Function to check S3 permissions with AWS CLI
check_s3_permission() {
    local perm_name="$1"
    local aws_command="$2"
    log_info "Checking ${perm_name} permission..."
    if eval "$aws_command" &>/dev/null; then
        log_success "✅ ${perm_name}: ALLOWED"
        return 0
    else
        log_warn "❌ ${perm_name}: DENIED"
        return 1
    fi
}

# Function to get all possible S3 URLs for a given bucket/object
get_all_s3_urls() {
    local object="$1"
    local bucket="$2"
    local region="$3"
    local urls=()

    # Standard S3 URLs (try these first - most common)
    urls+=("https://$bucket.s3.amazonaws.com/$object")
    urls+=("https://s3.amazonaws.com/$bucket/$object")

    # Regional URLs (if specific region provided)
    if [[ -n "$region" ]]; then
        urls+=("https://$bucket.s3.$region.amazonaws.com/$object")
        urls+=("https://s3.$region.amazonaws.com/$bucket/$object")
    fi

    # Virtual hosted style
    urls+=("https://$bucket.s3-website.amazonaws.com/$object")
    if [[ -n "$region" ]]; then
        urls+=("https://$bucket.s3-website-$region.amazonaws.com/$object")
    fi

    printf '%s\n' "${urls[@]}"
}

# Function to get all S3 URLs including all regions (for comprehensive scanning)
get_all_s3_urls_with_all_regions() {
    local object="$1"
    local bucket="$2"
    local urls=()

    # Common AWS regions
    local regions=(
        "us-east-1" "us-east-2" "us-west-1" "us-west-2"
        "eu-west-1" "eu-west-2" "eu-west-3" "eu-central-1" "eu-north-1"
        "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ap-northeast-2"
        "ap-south-1" "ca-central-1" "sa-east-1"
    )

    # Standard S3 URLs (try these first)
    urls+=("https://$bucket.s3.amazonaws.com/$object")
    urls+=("https://s3.amazonaws.com/$bucket/$object")
    urls+=("https://$bucket.s3-website.amazonaws.com/$object")

    # All regional URLs
    for region in "${regions[@]}"; do
        urls+=("https://$bucket.s3.$region.amazonaws.com/$object")
        urls+=("https://s3.$region.amazonaws.com/$bucket/$object")
        urls+=("https://$bucket.s3-website-$region.amazonaws.com/$object")
    done

    printf '%s\n' "${urls[@]}"
}

# Function to check permissions with curl for all S3 URL styles
check_s3_curl_permission_all_styles() {
    local perm_name="$1"
    local method="$2"
    local object="$3"
    local file="$4" # For PUT
    local output_file="$5"
    local bucket="$6"
    local region="$7"
    local test_all_regions="${8:-false}"
    local urls
    local url
    local found_vulnerable=false

    # Phase 1: Try standard URLs first (no region specified)
    if [[ -z "$region" ]]; then
        log_info "Phase 1: Testing standard S3 URLs (no region)"
        urls=$(get_all_s3_urls "$object" "$bucket" "") || true
    else
        log_info "Phase 1: Testing with specified region: $region"
        urls=$(get_all_s3_urls "$object" "$bucket" "$region") || true
    fi

    [[ -z "$urls" ]] && { log_warn "No URLs generated for testing"; return 0; }

    for url in $urls; do
        log_info "Testing ${perm_name} at $url"
        local result="000"
        if [[ "$method" == "GET" ]]; then
            result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null || echo "000")
        elif [[ "$method" == "PUT" ]]; then
            if [[ -f "$file" ]]; then
                result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -X PUT --data-binary "@$file" "$url" 2>/dev/null || echo "000")
            else
                result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -X PUT --data "test" "$url" 2>/dev/null || echo "000")
            fi
        elif [[ "$method" == "DELETE" ]]; then
            result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -X DELETE "$url" 2>/dev/null || echo "000")
        fi

        if [[ "$result" =~ ^(200|201|204)$ ]]; then
            echo "[ALLOWED] ${perm_name} at $url ($result)" >> "$output_file"
            found_vulnerable=true
            log_success "Found vulnerable endpoint: $url"
        else
            echo "[DENIED] ${perm_name} at $url ($result)" >> "$output_file"
        fi
    done

    # Phase 2: If no region specified and no vulnerabilities found, try all regions
    if [[ -z "$region" && "$found_vulnerable" == false && "$test_all_regions" == true ]]; then
        log_info "Phase 2: No vulnerabilities found in standard URLs, testing all regions..."
        urls=$(get_all_s3_urls_with_all_regions "$object" "$bucket") || true
        
        [[ -z "$urls" ]] && { log_warn "No URLs generated for Phase 2 testing"; return 0; }

        for url in $urls; do
            log_info "Testing ${perm_name} at $url"
            local result="000"
            if [[ "$method" == "GET" ]]; then
                result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null || echo "000")
            elif [[ "$method" == "PUT" ]]; then
                if [[ -f "$file" ]]; then
                    result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -X PUT --data-binary "@$file" "$url" 2>/dev/null || echo "000")
                else
                    result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -X PUT --data "test" "$url" 2>/dev/null || echo "000")
                fi
            elif [[ "$method" == "DELETE" ]]; then
                result=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 -X DELETE "$url" 2>/dev/null || echo "000")
            fi

            if [[ "$result" =~ ^(200|201|204)$ ]]; then
                echo "[ALLOWED] ${perm_name} at $url ($result)" >> "$output_file"
                found_vulnerable=true
                log_success "Found vulnerable endpoint: $url"
            else
                echo "[DENIED] ${perm_name} at $url ($result)" >> "$output_file"
            fi
        done
    fi

    if [[ "$found_vulnerable" == true ]]; then
        return 0
    else
        return 0  # Always return 0 to prevent script exit due to set -e
    fi
}

s3_scan() {
  local bucket="" region="" no_sign=false verbose=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -b|--bucket) bucket="$2"; shift 2;;
      -r|--region) region="$2"; shift 2;;
      -n|--no-sign|--no-sign-request) no_sign=true; shift;;
      -v|--verbose) verbose=true; shift;;
      -h|--help) usage; exit 0;;
      *) log_error "Unknown option: $1"; usage; exit 1;;
    esac
  done
  [[ -z "$bucket" ]] && { log_error "Bucket name is required"; usage; exit 1; }

  log_info "Starting comprehensive S3 bucket scan for: $bucket"

  local dir; dir="$(results_dir "s3_$bucket")"
  local s3_dir="$dir/vulnerabilities/s3"
  ensure_dir "$s3_dir"

  # Create output files
  local aws_results="$s3_dir/aws-cli-results.txt"
  local curl_results="$s3_dir/curl-results.txt"
  local public_results="$s3_dir/public-access-results.txt"
  local summary_file="$s3_dir/s3-scan-summary.txt"

  # Create empty files
  touch "$aws_results" "$curl_results" "$public_results" "$summary_file"

  # Create a temporary local file for testing write permissions
  echo "AutoAR S3 test file - $(date)" > "$S3_LOCAL_FILE"

  # Set AWS command flags
  local aws_flags=""
  if [[ "$no_sign" == true ]]; then
      aws_flags="--no-sign-request"
  fi
  if [[ -n "$region" ]]; then
      aws_flags="$aws_flags --region $region"
  fi

  log_info "Testing S3 bucket permissions for: $bucket"
  if [[ -n "$region" ]]; then
      log_info "Region: $region"
  fi

  # Check if AWS CLI is available and configured
  if command -v aws >/dev/null 2>&1; then
      # Check if AWS credentials are configured
      if aws sts get-caller-identity >/dev/null 2>&1 || [[ "$no_sign" == true ]]; then
          # Run permission checks (AWS CLI)
          log_info "Running AWS CLI permission checks..."
          {
              echo "AWS CLI PERMISSIONS:"
              echo "Bucket: $bucket"
              echo "Region: ${region:-'default'}"
              echo "Authentication: $([ "$no_sign" == true ] && echo "Public access only" || echo "Authenticated")"
              echo ""
          } >> "$aws_results"

          # Check each permission and log results
          if check_s3_permission "Read" "aws s3 ls s3://$bucket $aws_flags"; then
              echo "[ALLOWED] Read permission" >> "$aws_results"
          else
              echo "[DENIED] Read permission" >> "$aws_results"
          fi

          if check_s3_permission "Write" "aws s3 cp $S3_LOCAL_FILE s3://$bucket/$S3_TEST_FILE $aws_flags && aws s3 rm s3://$bucket/$S3_TEST_FILE $aws_flags"; then
              echo "[ALLOWED] Write permission" >> "$aws_results"
          else
              echo "[DENIED] Write permission" >> "$aws_results"
          fi

          if check_s3_permission "READ_ACP" "aws s3api get-bucket-acl --bucket $bucket $aws_flags"; then
              echo "[ALLOWED] READ_ACP permission" >> "$aws_results"
          else
              echo "[DENIED] READ_ACP permission" >> "$aws_results"
          fi

          if check_s3_permission "WRITE_ACP" "aws s3api put-bucket-acl --bucket $bucket --acl private $aws_flags"; then
              echo "[ALLOWED] WRITE_ACP permission" >> "$aws_results"
          else
              echo "[DENIED] WRITE_ACP permission" >> "$aws_results"
          fi

          if check_s3_permission "FULL_CONTROL" "aws s3api put-bucket-acl --bucket $bucket --acl private $aws_flags && aws s3 cp $S3_LOCAL_FILE s3://$bucket/$S3_TEST_FILE $aws_flags && aws s3 rm s3://$bucket/$S3_TEST_FILE $aws_flags && aws s3 ls s3://$bucket $aws_flags"; then
              echo "[ALLOWED] FULL_CONTROL permission" >> "$aws_results"
          else
              echo "[DENIED] FULL_CONTROL permission" >> "$aws_results"
          fi
      else
          log_warn "AWS CLI available but no credentials configured. Skipping AWS CLI tests."
          {
              echo "AWS CLI PERMISSIONS:"
              echo "Bucket: $bucket"
              echo "Region: ${region:-'default'}"
              echo "Status: SKIPPED - No AWS credentials configured"
              echo "Note: Use --no-sign flag for public access testing only"
              echo ""
          } >> "$aws_results"
      fi
  else
      log_warn "AWS CLI not available. Skipping AWS CLI tests."
      {
          echo "AWS CLI PERMISSIONS:"
          echo "Bucket: $bucket"
          echo "Region: ${region:-'default'}"
          echo "Status: SKIPPED - AWS CLI not installed"
          echo "Note: Install AWS CLI for comprehensive permission testing"
          echo ""
      } >> "$aws_results"
  fi

  # Run curl-based permission checks for all S3 URL styles
  log_info "Running curl-based permission checks..."
  {
      echo "CURL PERMISSIONS:"
      echo "Bucket: $bucket"
      echo "Region: ${region:-'default'}"
      echo ""
  } >> "$curl_results"

  # Test different operations (Phase 1: Standard URLs, Phase 2: All regions if no region specified)
  check_s3_curl_permission_all_styles "List (GET /)" "GET" "" "" "$curl_results" "$bucket" "$region" "true" || true
  check_s3_curl_permission_all_styles "Download (GET /$S3_TEST_FILE)" "GET" "$S3_TEST_FILE" "" "$curl_results" "$bucket" "$region" "true" || true
  check_s3_curl_permission_all_styles "Upload (PUT /$S3_TEST_FILE)" "PUT" "$S3_TEST_FILE" "$S3_LOCAL_FILE" "$curl_results" "$bucket" "$region" "true" || true
  check_s3_curl_permission_all_styles "Delete (DELETE /$S3_TEST_FILE)" "DELETE" "$S3_TEST_FILE" "" "$curl_results" "$bucket" "$region" "true" || true

  # Test public/anonymous access
  log_info "Testing public/anonymous access..."
  {
      echo "PUBLIC ACCESS:"
      echo "Bucket: $bucket"
      echo "Region: ${region:-'default'}"
      echo ""
  } >> "$public_results"

  # Set AWS_FLAGS for public checks
  local public_aws_flags="--no-sign-request"
  if [[ -n "$region" ]]; then
      public_aws_flags="$public_aws_flags --region $region"
  fi

  # Repeat permission checks with no-sign-request (AWS CLI) - only if AWS CLI is available
  if command -v aws >/dev/null 2>&1; then
      if check_s3_permission "Read (public)" "aws s3 ls s3://$bucket $public_aws_flags"; then
          echo "[ALLOWED] Read permission (public)" >> "$public_results"
      else
          echo "[DENIED] Read permission (public)" >> "$public_results"
      fi

      if check_s3_permission "Write (public)" "aws s3 cp $S3_LOCAL_FILE s3://$bucket/$S3_TEST_FILE $public_aws_flags && aws s3 rm s3://$bucket/$S3_TEST_FILE $public_aws_flags"; then
          echo "[ALLOWED] Write permission (public)" >> "$public_results"
      else
          echo "[DENIED] Write permission (public)" >> "$public_results"
      fi
  else
      echo "[SKIPPED] AWS CLI not available for public access testing" >> "$public_results"
  fi

  # Repeat curl-based permission checks for all S3 URL styles (public) - Phase 1: Standard, Phase 2: All regions
  check_s3_curl_permission_all_styles "List (GET /, public)" "GET" "" "" "$public_results" "$bucket" "$region" "true" || true
  check_s3_curl_permission_all_styles "Download (GET /$S3_TEST_FILE, public)" "GET" "$S3_TEST_FILE" "" "$public_results" "$bucket" "$region" "true" || true
  check_s3_curl_permission_all_styles "Upload (PUT /$S3_TEST_FILE, public)" "PUT" "$S3_TEST_FILE" "$S3_LOCAL_FILE" "$public_results" "$bucket" "$region" "true" || true
  check_s3_curl_permission_all_styles "Delete (DELETE /$S3_TEST_FILE, public)" "DELETE" "$S3_TEST_FILE" "" "$public_results" "$bucket" "$region" "true" || true

  # Generate simple summary
  {
      echo "=== S3 BUCKET SCAN RESULTS ==="
      echo "Bucket: $bucket"
      echo "Region: ${region:-'default'}"
      echo "Scan Date: $(date)"
      echo ""
  } > "$summary_file"

  # Clean up local test file
  rm -f "$S3_LOCAL_FILE"

  # Combine all results into a single comprehensive file
  local combined_results="$s3_dir/s3-scan-results.txt"
  {
      echo "S3 BUCKET SCAN RESULTS"
      echo "======================"
      echo "Bucket: $bucket"
      echo "Region: ${region:-'default'}"
      echo "Date: $(date)"
      echo ""

      if [[ -s "$aws_results" ]]; then
          echo "AWS CLI PERMISSIONS:"
          echo "-------------------"
          grep -E "\[(ALLOWED|DENIED)\]" "$aws_results" || echo "No AWS CLI results"
          echo ""
      fi

      if [[ -s "$curl_results" ]]; then
          echo "CURL PERMISSIONS:"
          echo "----------------"
          grep -E "\[(ALLOWED|DENIED)\]" "$curl_results" || echo "No curl results"
          echo ""
      fi

      if [[ -s "$public_results" ]]; then
          echo "PUBLIC ACCESS:"
          echo "--------------"
          grep -E "\[(ALLOWED|DENIED)\]" "$public_results" || echo "No public access results"
          echo ""
      fi

  } > "$combined_results"

  log_success "S3 bucket scan completed for $bucket"
  log_info "Results saved in: $s3_dir"

  # Send results to Discord
  local scan_id="${AUTOAR_CURRENT_SCAN_ID:-s3_scan_$(date +%s)}"
  if [[ -s "$combined_results" ]]; then
      discord_send "✅ S3 scan completed for bucket: $bucket. Results attached."
      discord_send_file "$combined_results" "S3 Scan Results for $bucket" "$scan_id"
  else
      discord_send "ℹ️ S3 scan completed for bucket: $bucket. No findings."
  fi
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

  local scan_id="${AUTOAR_CURRENT_SCAN_ID:-s3_enum_$(date +%s)}"
  discord_send_file "$out" "S3 enum results for $root_domain (exist: $exists_count, writable: $vulnerable_count)" "$scan_id"
}

case "${1:-}" in
  scan) shift; s3_scan "$@" ;;
  enum) shift; s3_enum "$@" ;;
  *) usage; exit 1;;
esac
