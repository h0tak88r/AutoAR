#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/db.sh"

usage() {
    echo "Usage: keyskit list | keyskit search <query> | keyskit validate <provider> <api_key>"
    echo ""
    echo "Commands:"
    echo "  list                - List all available API key validation templates"
    echo "  search <query>     - Search for API key validation templates by name"
    echo "  validate <provider> <api_key> - Generate validation command for a provider"
    echo ""
    echo "Examples:"
    echo "  keyskit list"
    echo "  keyskit search stripe"
    echo "  keyskit search aws"
    echo "  keyskit validate Stripe sk_live_abc123"
}

# Function to list all templates
keyskit_list() {
    log_info "Fetching all templates from database..."
    
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    local templates
    templates=$(db_list_keyskit_templates)
    
    if [[ -z "$templates" ]]; then
        log_warn "No templates found in database"
        log_info "Run the import script first: ./scripts/import_keyskit_templates.sh"
        return 1
    fi
    
    local count=$(echo "$templates" | wc -l)
    log_success "Found $count template(s):"
    echo ""
    
    echo "$templates" | sed 's/^/  - /'
    echo ""
    
    return 0
}

# Function to search for templates matching a query
keyskit_search() {
    local query="$1"
    
    if [[ -z "$query" ]]; then
        log_error "Search query is required"
        usage
        return 1
    fi
    
    log_info "Searching for templates matching: $query"
    
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    # Search in database - escape query and use db_query directly
    local escaped_query
    escaped_query=$(echo "$query" | sed "s/'/''/g")
    
    # Use db_query and filter out any log messages
    local results
    results=$(db_query "SELECT keyname, command_template, method, url, header, body, note, description FROM keyskit_templates WHERE keyname ILIKE '%$escaped_query%' OR description ILIKE '%$escaped_query%' ORDER BY keyname LIMIT 50;" 2>/dev/null | grep -v "^\[" | grep -v "^$" | grep .)
    
    # Check if we have actual data (must contain pipe separator)
    if [[ -z "$results" ]] || [[ ! "$results" =~ \| ]]; then
        log_warn "No templates found matching: $query"
        return 1
    fi
    
    # Parse results (pipe-separated from psql: keyname|command_template|method|url|header|body|note|description)
    local count=0
    while IFS='|' read -r keyname command_template method url header body note description; do
        # Skip empty lines or lines that don't look like data
        if [[ -z "$keyname" ]] || [[ "$keyname" =~ ^\[ ]]; then
            continue
        fi
        ((count++))
        
        echo "  📋 $keyname"
        if [[ -n "$description" ]]; then
            local desc_preview="${description:0:100}"
            if [[ ${#description} -gt 100 ]]; then
                desc_preview="${desc_preview}..."
            fi
            echo "     Description: $desc_preview"
        fi
        echo "     Method: $method"
        echo "     URL: $url"
        echo ""
    done <<< "$results"
    
    log_success "Found $count matching template(s)"
    
    return 0
}

# Function to generate validation command for a provider
keyskit_validate() {
    local provider="$1"
    local api_key="${2:-}"
    
    if [[ -z "$provider" ]]; then
        log_error "Provider name is required"
        usage
        return 1
    fi
    
    if [[ -z "$api_key" ]]; then
        log_error "API key is required"
        usage
        return 1
    fi
    
    log_info "Generating validation command for: $provider"
    
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    # Get template from database
    local template_data
    template_data=$(db_get_keyskit_template "$provider")
    
    if [[ -z "$template_data" ]]; then
        log_error "Template not found for provider: $provider"
        log_info "Use 'keyskit search $provider' to find available templates"
        return 1
    fi
    
    # Parse pipe-separated result from psql: keyname|command_template|method|url|header|body|note|description
    IFS='|' read -r keyname command_template method url header body note description <<< "$template_data"
    
    if [[ -z "$keyname" ]] || [[ -z "$url" ]]; then
        log_error "Invalid template data for provider: $provider"
        return 1
    fi
    
    # Parse command_template (JSON) and replace variables using Python
    local processed_data=$(python3 -c "
import json
import sys
import re
import base64

command_template = sys.argv[1]
api_key = sys.argv[2]

# Parse the stored JSON template
try:
    template = json.loads(command_template)
except json.JSONDecodeError:
    print('ERROR: Invalid JSON template', file=sys.stderr)
    sys.exit(1)

name = template.get('name', 'Unknown')
method = template.get('method', 'GET')
header = template.get('header', '')
url = template.get('url', '')
body = template.get('body', '')
note = template.get('note', '')
description = template.get('description', '')

if not url:
    print('ERROR: Missing URL', file=sys.stderr)
    sys.exit(1)

# Encode API key for Basic Auth
encoded_key = base64.b64encode(f'{api_key}:'.encode()).decode()

# Replace variables in URL
url = re.sub(r'\$[A-Za-z_][A-Za-z0-9_-]*', api_key, url)

# Replace variables in header
if header:
    # Replace Basic_Auth with encoded key first
    header = header.replace('\$Basic_Auth', encoded_key)
    # Replace all other \$VARIABLE patterns
    header = re.sub(r'\$[A-Za-z_][A-Za-z0-9_-]*', api_key, header)

# Replace variables in body
if body:
    body = re.sub(r'\$[A-Za-z_][A-Za-z0-9_-]*', api_key, body)

# Output as JSON for easy parsing
result = {
    'name': name,
    'method': method,
    'header': header,
    'url': url,
    'body': body,
    'note': note,
    'description': description
}
print(json.dumps(result))
" "$command_template" "$api_key" 2>/dev/null)
    
    if [[ -z "$processed_data" ]] || [[ "$processed_data" == ERROR* ]]; then
        log_error "Failed to process template"
        return 1
    fi
    
    # Extract values from Python output
    set +u
    local name=$(echo "$processed_data" | jq -r '.name // "Unknown"' 2>/dev/null || echo "Unknown")
    local method=$(echo "$processed_data" | jq -r '.method // "GET"' 2>/dev/null || echo "GET")
    local header_raw=$(echo "$processed_data" | jq -r '.header // ""' 2>/dev/null || echo "")
    local header=$(echo "$header_raw" | sed "s/\$Access_Token/$api_key/g" | sed "s/\$API_KEY/$api_key/g" | sed "s/\$API_Key/$api_key/g" | sed "s/\$api_key/$api_key/g" | sed "s/\$API_TOKEN/$api_key/g" | sed "s/\$api_token/$api_key/g")
    local url=$(echo "$processed_data" | jq -r '.url // ""' 2>/dev/null || echo "")
    local body=$(echo "$processed_data" | jq -r '.body // ""' 2>/dev/null || echo "")
    local note=$(echo "$processed_data" | jq -r '.note // ""' 2>/dev/null || echo "")
    local description=$(echo "$processed_data" | jq -r '.description // ""' 2>/dev/null || echo "")
    set -u
    
    # Build curl command
    local curl_cmd="curl"
    
    # Add method
    if [[ "$method" == "POST" ]]; then
        curl_cmd="$curl_cmd -X POST"
    else
        curl_cmd="$curl_cmd -X GET"
    fi
    
    # Add headers
    if [[ -n "$header" ]]; then
        # Parse header string (format: 'Header-Key':'Value','Another-Header':'AnotherValue')
        local header_cmd=$(python3 -c "
import sys
import re
header = sys.argv[1]
if not header or header.strip() == '':
    sys.exit(0)
# Match pattern: 'key':'value'
pattern = r\"'([^']+)':'([^']+)'\"
matches = re.findall(pattern, header)
if matches:
    result = ' '.join([f\"-H '{k}: {v}'\" for k, v in matches])
    print(result)
" "$header" 2>/dev/null)
        
        if [[ -n "$header_cmd" ]]; then
            curl_cmd="$curl_cmd $header_cmd"
        fi
    fi
    
    # Add body for POST requests
    if [[ "$method" == "POST" ]] && [[ -n "$body" ]]; then
        curl_cmd="$curl_cmd -d \"$body\""
    fi
    
    # Add URL
    curl_cmd="$curl_cmd \"$url\""
    
    # Output results
    echo ""
    log_success "Validation command for $name:"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Provider: $name"
    if [[ -n "$description" ]]; then
        echo "Description: $description"
    fi
    echo "Method: $method"
    echo ""
    echo "Command:"
    echo "$curl_cmd"
    echo ""
    if [[ -n "$note" ]]; then
        echo "Note: $note"
        echo ""
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Also output as JSON for API/Discord
    local output_file=$(mktemp)
    cat > "$output_file" <<EOF
{
  "provider": "$name",
  "method": "$method",
  "url": "$url",
  "command": "$curl_cmd",
  "description": "$description",
  "note": "$note"
}
EOF
    echo "$output_file"
    
    return 0
}

# Main function
main() {
    local cmd="${1:-}"
    shift || true
    
    case "$cmd" in
        list)
            keyskit_list "$@"
            ;;
        search)
            if [[ $# -lt 1 ]]; then
                log_error "Usage: keyskit search <query>"
                return 1
            fi
            keyskit_search "$1"
            ;;
        validate)
            if [[ $# -lt 2 ]]; then
                log_error "Usage: keyskit validate <provider> <api_key>"
                return 1
            fi
            keyskit_validate "$1" "$2"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
