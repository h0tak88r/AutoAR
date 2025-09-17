#!/bin/bash

# Function to display usage
usage() {
    echo -e "Usage: $0 -b <bucket_name> [-r <region>] [-n]"
    echo -e "  -b <bucket_name>  : Specify the S3 bucket name"
    echo -e "  -r <region>       : Specify the AWS region (optional)" 
    echo -e "  -n                : Use --no-sign-request (for public buckets)"
    exit 1
}

# Default values
BUCKET_NAME=""
TEST_FILE="s3_test_file.txt"
LOCAL_FILE="/tmp/$TEST_FILE"
NO_SIGN_REQUEST=false
REGION=""

# Colors for output
GREEN="\033[1;32m"
RED="\033[1;31m"
BLUE="\033[1;34m"
NC="\033[0m" # No color

# Parse command-line arguments
while getopts "b:r:n" opt; do
    case "${opt}" in
        b) BUCKET_NAME="${OPTARG}" ;;
        r) REGION="${OPTARG}" ;;
        n) NO_SIGN_REQUEST=true ;;
        *) usage ;;
    esac
done

# Check if bucket name is provided
if [[ -z "$BUCKET_NAME" ]]; then
    usage
fi

# Set AWS command flags
AWS_FLAGS=""
if [[ "$NO_SIGN_REQUEST" == true ]]; then
    AWS_FLAGS="--no-sign-request"
fi
if [[ -n "$REGION" ]]; then
    AWS_FLAGS="$AWS_FLAGS --region $REGION"
fi

# =====================
# Function Definitions
# =====================

# Function to check permissions with AWS CLI
check_permission() {
    local perm_name="$1"
    local aws_command="$2"
    echo -ne "🔍 Checking ${perm_name} permission... ⏳ "
    if eval "$aws_command" &>/dev/null; then
        echo -e "✅ ${GREEN}ALLOWED${NC}"
    else
        echo -e "❌ ${RED}DENIED${NC}"
    fi
}

# Function to get all possible S3 URLs for a given bucket/object
get_all_s3_urls() {
    local object="$1"
    local urls=()
    # Virtual-hosted–style (global)
    urls+=("https://${BUCKET_NAME}.s3.amazonaws.com/${object}")
    # Virtual-hosted–style (regional)
    if [[ -n "$REGION" ]]; then
        urls+=("https://${BUCKET_NAME}.s3.${REGION}.amazonaws.com/${object}")
    fi
    # Path-style (global)
    urls+=("https://s3.amazonaws.com/${BUCKET_NAME}/${object}")
    # Path-style (regional)
    if [[ -n "$REGION" ]]; then
        urls+=("https://s3.${REGION}.amazonaws.com/${BUCKET_NAME}/${object}")
        urls+=("https://s3-${REGION}.amazonaws.com/${BUCKET_NAME}/${object}")
    fi
    printf '%s\n' "${urls[@]}"
}

# Function to check permissions with curl for all S3 URL styles
check_curl_permission_all_styles() {
    local perm_name="$1"
    local method="$2"
    local object="$3"
    local file="$4" # For PUT
    local urls
    urls=$(get_all_s3_urls "$object")
    local url
    for url in $urls; do
        echo -ne "🔍 [curl] Checking ${perm_name} at $url ... ⏳ "
        local result
        if [[ "$method" == "GET" ]]; then
            result=$(curl -s -o /dev/null -w "%{http_code}" "$url")
            [[ "$result" == "200" ]] && echo -e "✅ ${GREEN}ALLOWED${NC}" || echo -e "❌ ${RED}DENIED${NC}"
        elif [[ "$method" == "PUT" ]]; then
            result=$(curl -s -o /dev/null -w "%{http_code}" -T "$file" "$url")
            [[ "$result" =~ ^2 ]] && echo -e "✅ ${GREEN}ALLOWED${NC}" || echo -e "❌ ${RED}DENIED${NC}"
        elif [[ "$method" == "DELETE" ]]; then
            result=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$url")
            [[ "$result" =~ ^2 ]] && echo -e "✅ ${GREEN}ALLOWED${NC}" || echo -e "❌ ${RED}DENIED${NC}"
        fi
    done
}

# =====================
# Main Execution Logic
# =====================

# Create a temporary local file for testing write permissions
echo "This is a test file." > "$LOCAL_FILE"

# Display header
echo -e "\n📊 ${BLUE}Testing S3 Bucket Permissions: ${BUCKET_NAME}${NC}"
if [[ -n "$REGION" ]]; then
    echo -e "🌍 Region: ${BLUE}$REGION${NC}"
fi
echo ""

# Run permission checks (AWS CLI)
check_permission "Read" "aws s3 ls s3://$BUCKET_NAME $AWS_FLAGS"
check_permission "Write" "aws s3 cp $LOCAL_FILE s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS && aws s3 rm s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS"
check_permission "READ_ACP" "aws s3api get-bucket-acl --bucket $BUCKET_NAME $AWS_FLAGS"
check_permission "WRITE_ACP" "aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private $AWS_FLAGS"
check_permission "FULL_CONTROL" "aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private $AWS_FLAGS && aws s3 cp $LOCAL_FILE s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS && aws s3 rm s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS && aws s3 ls s3://$BUCKET_NAME $AWS_FLAGS"

# Run curl-based permission checks for all S3 URL styles
check_curl_permission_all_styles "List (GET /)" "GET" ""
check_curl_permission_all_styles "Download (GET /$TEST_FILE)" "GET" "$TEST_FILE"
check_curl_permission_all_styles "Upload (PUT /$TEST_FILE)" "PUT" "$TEST_FILE" "$LOCAL_FILE"
check_curl_permission_all_styles "Delete (DELETE /$TEST_FILE)" "DELETE" "$TEST_FILE"

# Separator and message for public/anonymous checks
printf "\n==============================\n"
echo -e "${BLUE}Now testing with --no-sign-request (public/anonymous access)...${NC}"
printf "==============================\n\n"

# Set AWS_FLAGS for public checks
AWS_FLAGS="--no-sign-request"

# Repeat permission checks with no-sign-request (AWS CLI)
check_permission "Read (public)" "aws s3 ls s3://$BUCKET_NAME $AWS_FLAGS"
check_permission "Write (public)" "aws s3 cp $LOCAL_FILE s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS && aws s3 rm s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS"
check_permission "READ_ACP (public)" "aws s3api get-bucket-acl --bucket $BUCKET_NAME $AWS_FLAGS"
check_permission "WRITE_ACP (public)" "aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private $AWS_FLAGS"
check_permission "FULL_CONTROL (public)" "aws s3api put-bucket-acl --bucket $BUCKET_NAME --acl private $AWS_FLAGS && aws s3 cp $LOCAL_FILE s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS && aws s3 rm s3://$BUCKET_NAME/$TEST_FILE $AWS_FLAGS && aws s3 ls s3://$BUCKET_NAME $AWS_FLAGS"

# Repeat curl-based permission checks for all S3 URL styles (public)
check_curl_permission_all_styles "List (GET /, public)" "GET" ""
check_curl_permission_all_styles "Download (GET /$TEST_FILE, public)" "GET" "$TEST_FILE"
check_curl_permission_all_styles "Upload (PUT /$TEST_FILE, public)" "PUT" "$TEST_FILE" "$LOCAL_FILE"
check_curl_permission_all_styles "Delete (DELETE /$TEST_FILE, public)" "DELETE" "$TEST_FILE"

# Clean up local test file
rm "$LOCAL_FILE"

# Final message
echo -e "\n✅ ${GREEN}Permission check complete.${NC}\n"