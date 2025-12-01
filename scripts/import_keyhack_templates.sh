#!/usr/bin/env bash
# One-time script to import KeyHack templates into the database
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/db.sh"

TEMPLATES_DIR="$ROOT_DIR/keyhack_templates"

main() {
    log_info "Starting KeyHack templates import..."
    
    if [[ ! -d "$TEMPLATES_DIR" ]]; then
        log_error "Templates directory not found: $TEMPLATES_DIR"
        return 1
    fi
    
    # Ensure database connection
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    # Initialize schema (creates table if not exists)
    db_init_schema
    
    local count=0
    local failed=0
    
    # Disable exit on error for the loop to continue processing even if one fails
    set +e
    
    # Process each JSON template file
    for template_file in "$TEMPLATES_DIR"/*.json; do
        if [[ ! -f "$template_file" ]]; then
            continue
        fi
        
        local filename=$(basename "$template_file" .json)
        
        # Parse template using Python to handle JSON properly
        local template_data=$(python3 -c "
import json
import sys

try:
    with open('$template_file', 'r') as f:
        template = json.load(f)
    
    # Extract fields
    name = template.get('name', '$filename')
    method = template.get('method', 'GET')
    url = template.get('url', '')
    header = template.get('header', '')
    body = template.get('body', '')
    note = template.get('note', '')
    description = template.get('description', '')
    
    # Store full template as command_template (JSON string)
    command_template = json.dumps(template)
    
    # Output as tab-separated values for bash parsing
    print(f\"{name}\t{command_template}\t{method}\t{url}\t{header}\t{body}\t{note}\t{description}\")
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1)
        
        if [[ -z "$template_data" ]] || [[ "$template_data" == ERROR* ]] || [[ "$template_data" == *"ERROR:"* ]]; then
            log_warn "Failed to parse template: $filename"
            ((failed++))
            continue
        fi
        
        # Parse tab-separated values
        IFS=$'\t' read -r keyname command_template method url header body note description <<< "$template_data"
        
        if [[ -z "$keyname" ]] || [[ -z "$url" ]]; then
            log_warn "Skipping template with missing keyname or URL: $filename"
            ((failed++))
            continue
        fi
        
        # Insert into database (suppress errors to continue)
        db_insert_keyhack_template "$keyname" "$command_template" "$method" "$url" "$header" "$body" "$note" "$description" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            ((count++))
            if [[ $((count % 50)) -eq 0 ]]; then
                log_info "Imported $count templates..."
            fi
        else
            log_warn "Failed to insert template: $keyname"
            ((failed++))
        fi
    done
    
    # Re-enable exit on error
    set -e
    
    log_success "Import completed: $count templates imported"
    if [[ $failed -gt 0 ]]; then
        log_warn "$failed templates failed to import"
    fi
    
    # Show total count in database
    local total_count
    if [[ "$DB_TYPE" == "postgresql" ]]; then
        total_count=$(db_query "SELECT COUNT(*) FROM keyhack_templates;" | tr -d ' ')
    else
        total_count=$(db_query "SELECT COUNT(*) FROM keyhack_templates;" | tr -d ' ')
    fi
    
    log_info "Total templates in database: $total_count"
}

main "$@"

