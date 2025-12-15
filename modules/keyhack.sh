#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# lib/logging.sh functionality in gomodules/ - functionality in gomodules/
# lib/utils.sh functionality in gomodules/ - functionality in gomodules/

# Load database functions (prefer Go wrapper, fallback to bash)
if [[ -f "$ROOT_DIR/gomodules/db/wrapper.sh" ]]; then
  source "$ROOT_DIR/gomodules/db/wrapper.sh"
elif [[ -f "$ROOT_DIR/lib/db.sh" ]]; then
  # lib/db.sh functionality in gomodules/ - functionality in gomodules/
fi

usage() {
    echo "Usage: keyhack list | keyhack search <query> | keyhack validate <provider> <api_key> | keyhack add <keyname> <command> <description> [notes]"
    echo ""
    echo "Commands:"
    echo "  list                - List all available API key validation templates"
    echo "  search <query>     - Search for API key validation templates by name"
    echo "  validate <provider> <api_key> - Generate validation command for a provider"
    echo "  add <keyname> <command> <description> [notes] - Add a new template"
    echo ""
    echo "Examples:"
    echo "  keyhack list"
    echo "  keyhack search stripe"
    echo "  keyhack search aws"
    echo "  keyhack validate Stripe sk_live_abc123"
    echo "  keyhack add 'Slack' 'curl -H \"Authorization: Bearer \$API_KEY\" https://slack.com/api/auth.test' 'Slack API validation' 'Requires Bearer token'"
}

# Function to list all templates
keyhack_list() {
    log_info "Fetching all templates from database..."
    
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    local templates
    templates=$(db_list_keyhack_templates)
    
    if [[ -z "$templates" ]]; then
        log_warn "No templates found in database"
        log_info "Add templates using: keyhack add <keyname> <command> <description> [notes]"
        log_info "Or use Discord command: /keyhack_add"
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
keyhack_search() {
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
    
    # Use the db_search_keyhack_templates function from db.sh
    # This function handles escaping and returns pipe-separated results
    # Redirect stderr to /dev/null to suppress log messages, then filter out any remaining log lines
    local results
    results=$(db_search_keyhack_templates "$query" 2>/dev/null | grep -v "^\[" | grep -v "^$" | grep -F "|")
    
    # Check if we have actual data (must contain pipe separator and not be empty)
    if [[ -z "$results" ]] || [[ ! "$results" =~ \| ]]; then
        log_warn "No templates found matching: $query"
        return 1
    fi
    
    # Debug: Check if we have results
    local result_count=$(echo "$results" | wc -l)
    if [[ $result_count -eq 0 ]]; then
        log_warn "No templates found matching: $query"
        return 1
    fi
    
    # Parse results and generate curl commands using Python
    # psql outputs pipe-separated: keyname|command_template|method|url|header|body|note|description
    # Process all results at once using Python for better handling
    # Use here-document to prevent bash variable expansion
    # Write to temp file to ensure Python gets all data correctly
    local temp_file=$(mktemp)
    echo "$results" > "$temp_file"
    TEMP_FILE="$temp_file" python3 <<'PYTHON_SCRIPT'
import json
import sys
import re
import base64
import os

# Read from temp file (passed via environment variable)
temp_file = os.environ.get('TEMP_FILE', '')
if not temp_file:
    # Fallback: read from stdin
    lines = sys.stdin.readlines()
else:
    with open(temp_file, 'r') as f:
        lines = f.readlines()

count = 0

for line in lines:
    line = line.strip()
    if not line or '|' not in line:
        continue
    
    # Split by pipe (max 8 parts)
    parts = line.split('|', 7)
    if len(parts) < 8:
        parts.extend([''] * (8 - len(parts)))
    
    keyname = parts[0].strip()
    command_template_json = parts[1]
    method = parts[2].strip()
    url = parts[3].strip()
    header = parts[4].strip()
    body = parts[5].strip()
    note = parts[6].strip()
    description = parts[7].strip()
    
    if not keyname or keyname.startswith('['):
        continue
    
    # Parse JSON template
    try:
        template = json.loads(command_template_json)
    except:
        # Fallback to direct values if JSON parsing fails
        template = {
            'method': method or 'GET',
            'url': url or '',
            'header': header or '',
            'body': body or '',
            'note': note or '',
            'description': description or ''
        }
    
    method = template.get('method', method or 'GET')
    url_template = template.get('url', url or '')
    header_template = template.get('header', header or '')
    body_template = template.get('body', body or '')
    note = template.get('note', note or '')
    description = template.get('description', description or '')
    
    # Handle SHELL commands (like AWS)
    if method.upper() == 'SHELL':
        # For AWS, show the shell command format
        if 'AWS' in keyname.upper():
            curl_cmd = 'AWS_ACCESS_KEY_ID=$ACCESS_KEY AWS_SECRET_ACCESS_KEY=$SECRET_KEY aws sts get-caller-identity'
        else:
            curl_cmd = 'Shell command (see note for details)'
    else:
        # Build curl command with placeholders for HTTP methods
        curl_parts = ['curl']
        
        # Add method
        if method.upper() == 'POST':
            curl_parts.append('-X POST')
        elif method.upper() != 'GET':
            curl_parts.append(f'-X {method.upper()}')
        
        # Add headers (keep placeholders like $API_KEY, $Basic_Auth, etc.)
        if header_template:
            # Parse header format: 'Header-Key':'Value'
            pattern = r"'([^']+)':'([^']+)'"
            matches = re.findall(pattern, header_template)
            for key, value in matches:
                curl_parts.append(f"-H '{key}: {value}'")
        
        # Add body for POST requests
        if method.upper() == 'POST' and body_template:
            curl_parts.append(f"-d '{body_template}'")
        
        # Add URL
        curl_parts.append(f"'{url_template}'")
        
        curl_cmd = ' '.join(curl_parts)
    
    # Output formatted result
    print(f'📋 {keyname}')
    if description:
        desc_preview = description[:100] + ('...' if len(description) > 100 else '')
        print(f'   Description: {desc_preview}')
    print(f'   Command:')
    print(f'   {curl_cmd}')
    if note:
        print(f'   Note: {note}')
    print()
    count += 1

if count == 0:
    sys.exit(1)
PYTHON_SCRIPT
    local python_exit=$?
    rm -f "$temp_file"
    
    if [[ $python_exit -ne 0 ]]; then
        log_warn "No templates found matching: $query"
        return 1
    fi
    
    # Count total results for success message
    count=$(echo "$results" | awk -F'|' 'NF >= 8 && $1 != "" && $1 !~ /^\[/ {count++} END {print count+0}')
    
    log_success "Found $count matching template(s)"
    
    return 0
}

# Function to generate validation command for a provider
keyhack_validate() {
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
    template_data=$(db_get_keyhack_template "$provider")
    
    if [[ -z "$template_data" ]]; then
        log_error "Template not found for provider: $provider"
        log_info "Use 'keyhack search $provider' to find available templates"
        return 1
    fi
    
    # Parse pipe-separated result from psql: keyname|command_template|method|url|header|body|note|description
    IFS='|' read -r keyname command_template method url header body note description <<< "$template_data"
    
    if [[ -z "$keyname" ]]; then
        log_error "Invalid template data for provider: $provider"
        return 1
    fi
    
    # For SHELL commands, URL can be empty
    if [[ "$method" != "SHELL" ]] && [[ -z "$url" ]]; then
        log_error "Invalid template data for provider: $provider (missing URL)"
        return 1
    fi
    
    # Parse command_template (JSON) and replace variables using Python
    # For AWS and similar, api_key might be in format: ACCESS_KEY_ID:SECRET_KEY
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

# Handle SHELL commands (like AWS)
if method == 'SHELL':
    # For AWS, api_key format is ACCESS_KEY_ID:SECRET_KEY
    if ':' in api_key:
        access_key, secret_key = api_key.split(':', 1)
        # Replace ACCESS_KEY and SECRET_KEY placeholders
        note = note.replace('\$ACCESS_KEY', access_key) if note else ''
        note = note.replace('\$SECRET_KEY', secret_key) if note else ''
        shell_cmd = f'AWS_ACCESS_KEY_ID={access_key} AWS_SECRET_ACCESS_KEY={secret_key} aws sts get-caller-identity'
    else:
        # Single key - use as is
        shell_cmd = api_key
    
    result = {
        'name': name,
        'method': 'SHELL',
        'header': '',
        'url': '',
        'body': '',
        'shell_command': shell_cmd,
        'note': note,
        'description': description
    }
    print(json.dumps(result))
    sys.exit(0)

# HTTP-based validation (original logic)
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
    local shell_cmd=$(echo "$processed_data" | jq -r '.shell_command // ""' 2>/dev/null || echo "")
    local header_raw=$(echo "$processed_data" | jq -r '.header // ""' 2>/dev/null || echo "")
    # Only process header if not SHELL command and header exists
    local header=""
    if [[ "$method" != "SHELL" ]] && [[ -n "$header_raw" ]]; then
        header=$(echo "$header_raw" | sed "s/\$Access_Token/$api_key/g" | sed "s/\$API_KEY/$api_key/g" | sed "s/\$API_Key/$api_key/g" | sed "s/\$api_key/$api_key/g" | sed "s/\$API_TOKEN/$api_key/g" | sed "s/\$api_token/$api_key/g")
    fi
    local url=$(echo "$processed_data" | jq -r '.url // ""' 2>/dev/null || echo "")
    local body=$(echo "$processed_data" | jq -r '.body // ""' 2>/dev/null || echo "")
    local note=$(echo "$processed_data" | jq -r '.note // ""' 2>/dev/null || echo "")
    local description=$(echo "$processed_data" | jq -r '.description // ""' 2>/dev/null || echo "")
    set -u
    
    # Handle SHELL commands (like AWS)
    if [[ "$method" == "SHELL" ]] && [[ -n "$shell_cmd" ]]; then
        # Output results for shell command
        echo ""
        log_success "Validation command for $name:"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Provider: $name"
        if [[ -n "$description" ]]; then
            echo "Description: $description"
        fi
        echo "Method: Shell Command"
        echo ""
        echo "Command:"
        echo "$shell_cmd"
        echo ""
        if [[ -n "$note" ]]; then
            echo "Note:"
            echo -e "$note" | sed 's/\\n/\n/g'
            echo ""
        fi
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        # Also output as JSON for API/Discord
        local output_file=$(mktemp)
        cat > "$output_file" <<EOF
{
  "provider": "$name",
  "method": "SHELL",
  "command": "$shell_cmd",
  "description": "$description",
  "note": "$(echo "$note" | sed 's/"/\\"/g' | sed 's/$/\\n/' | tr -d '\n')"
}
EOF
        echo "$output_file"
        return 0
    fi
    
    # Build curl command for HTTP-based validation
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

# Function to add a new template
keyhack_add() {
    local keyname="$1"
    local command="$2"
    local description="$3"
    local notes="${4:-}"
    
    if [[ -z "$keyname" ]] || [[ -z "$command" ]] || [[ -z "$description" ]]; then
        log_error "Usage: keyhack add <keyname> <command> <description> [notes]"
        return 1
    fi
    
    log_info "Adding new template: $keyname"
    
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    # Determine method from command
    local method="GET"
    local url=""
    local header=""
    local body=""
    
    # Parse command to extract method, URL, headers, body
    if echo "$command" | grep -qi "curl"; then
        # Extract method
        if echo "$command" | grep -qiE "\-X\s+(POST|PUT|DELETE|PATCH)"; then
            method=$(echo "$command" | grep -oiE "\-X\s+(POST|PUT|DELETE|PATCH)" | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
        elif echo "$command" | grep -qi "\-d\s"; then
            method="POST"
        fi
        
        # Extract URL (last quoted string or last argument)
        url=$(echo "$command" | grep -oE "['\"](https?://[^'\"]+)['\"]" | head -1 | tr -d "'\"")
        if [[ -z "$url" ]]; then
            url=$(echo "$command" | awk '{for(i=NF;i>=1;i--) if($i ~ /^https?:\/\//) {print $i; exit}}')
        fi
        
        # Extract headers
        header=$(echo "$command" | grep -oE "\-H\s+['\"]([^'\"]+)['\"]" | sed "s/-H //g" | tr -d "'\"" | head -1)
        
        # Extract body
        if echo "$command" | grep -qi "\-d\s"; then
            body=$(echo "$command" | grep -oE "\-d\s+['\"]([^'\"]+)['\"]" | sed "s/-d //g" | tr -d "'\"")
        fi
    elif echo "$command" | grep -qiE "^(AWS_|SHELL|shell)"; then
        # Shell command
        method="SHELL"
        url=""
    else
        # Try to extract URL from command
        url=$(echo "$command" | grep -oE "https?://[^\s]+" | head -1)
    fi
    
    # Create JSON template
    local template_json=$(python3 -c "
import json
import sys

keyname = sys.argv[1]
method = sys.argv[2]
url = sys.argv[3]
header = sys.argv[4]
body = sys.argv[5]
notes = sys.argv[6]
description = sys.argv[7]

template = {
    'name': keyname,
    'method': method,
    'url': url,
    'header': header,
    'body': body,
    'note': notes,
    'description': description
}

print(json.dumps(template))
" "$keyname" "$method" "$url" "$header" "$body" "$notes" "$description" 2>/dev/null)
    
    if [[ -z "$template_json" ]]; then
        log_error "Failed to create template JSON"
        return 1
    fi
    
    # Insert into database
    local insert_result
    insert_result=$(db_insert_keyhack_template "$keyname" "$template_json" "$method" "$url" "$header" "$body" "$notes" "$description" 2>&1)
    local insert_exit=$?
    
    # PostgreSQL returns "INSERT 0 1" on success, SQLite returns nothing but exit code 0
    if [[ $insert_exit -eq 0 ]] && (echo "$insert_result" | grep -qE "INSERT|UPDATE" || [[ -z "$insert_result" ]]); then
        log_success "Template '$keyname' added successfully"
        return 0
    elif echo "$insert_result" | grep -qi "duplicate\|already exists\|constraint"; then
        log_warn "Template '$keyname' already exists (updated)"
        return 0
    else
        log_error "Failed to add template '$keyname'"
        if [[ -n "$insert_result" ]]; then
            log_error "Error: $insert_result"
        fi
        return 1
    fi
}

# Main function
main() {
    local cmd="${1:-}"
    shift || true
    
    case "$cmd" in
        list)
            keyhack_list "$@"
            ;;
        search)
            if [[ $# -lt 1 ]]; then
                log_error "Usage: keyhack search <query>"
                return 1
            fi
            keyhack_search "$1"
            ;;
        validate)
            if [[ $# -lt 2 ]]; then
                log_error "Usage: keyhack validate <provider> <api_key>"
                return 1
            fi
            keyhack_validate "$1" "$2"
            ;;
        add)
            if [[ $# -lt 3 ]]; then
                log_error "Usage: keyhack add <keyname> <command> <description> [notes]"
                return 1
            fi
            keyhack_add "$1" "$2" "$3" "${4:-}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
