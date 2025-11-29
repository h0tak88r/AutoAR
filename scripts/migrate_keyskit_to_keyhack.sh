#!/usr/bin/env bash
# Script to migrate KeysKit templates from keyskit_templates to keyhack_templates table
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/db.sh"

main() {
    log_info "Migrating KeysKit templates to keyhack_templates table..."
    
    if ! db_ensure_connection; then
        log_error "Database connection failed. Please check your DB configuration."
        return 1
    fi
    
    # Initialize schema (ensures keyhack_templates table exists)
    db_init_schema
    
    # Check if keyskit_templates table exists
    local keyskit_exists
    if [[ "$DB_TYPE" == "postgresql" ]]; then
        keyskit_exists=$(db_query "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'keyskit_templates');" 2>&1 | grep -v '^\[.*\]' | grep -v '^$' | tr -d ' ' | head -1)
    else
        keyskit_exists=$(db_query "SELECT name FROM sqlite_master WHERE type='table' AND name='keyskit_templates';" 2>&1 | grep -c "keyskit_templates" || echo "0")
    fi
    
    if [[ "$keyskit_exists" != "t" ]] && [[ "$keyskit_exists" != "1" ]] && [[ "$keyskit_exists" != "true" ]]; then
        log_warn "keyskit_templates table not found. Nothing to migrate."
        return 0
    fi
    
    # Count templates in keyskit_templates
    local keyskit_count
    keyskit_count=$(db_query "SELECT COUNT(*) FROM keyskit_templates;" 2>&1 | grep -v '^\[.*\]' | grep -v '^$' | tr -d ' ')
    
    if [[ -z "$keyskit_count" ]] || [[ "$keyskit_count" == "0" ]]; then
        log_warn "No templates found in keyskit_templates table"
        return 0
    fi
    
    log_info "Found $keyskit_count templates in keyskit_templates table"
    
    # Get all templates from keyskit_templates and insert into keyhack_templates
    # Use SQL to copy data directly
    if [[ "$DB_TYPE" == "postgresql" ]]; then
        log_info "Copying templates from keyskit_templates to keyhack_templates..."
        
        # Use INSERT ... ON CONFLICT to avoid duplicates
        db_exec "INSERT INTO keyhack_templates (keyname, command_template, method, url, header, body, note, description)
                 SELECT keyname, command_template, method, url, header, body, note, description
                 FROM keyskit_templates
                 ON CONFLICT (keyname) DO UPDATE SET
                     command_template = EXCLUDED.command_template,
                     method = EXCLUDED.method,
                     url = EXCLUDED.url,
                     header = EXCLUDED.header,
                     body = EXCLUDED.body,
                     note = EXCLUDED.note,
                     description = EXCLUDED.description,
                     updated_at = NOW();" 2>&1 | grep -v '^\[.*\]' | head -5
        
        local migrated_count
        migrated_count=$(db_query "SELECT COUNT(*) FROM keyhack_templates;" 2>&1 | grep -v '^\[.*\]' | grep -v '^$' | tr -d ' ')
        
        log_success "Migration completed! Total templates in keyhack_templates: $migrated_count"
    else
        # SQLite version
        log_info "Copying templates from keyskit_templates to keyhack_templates..."
        
        db_exec "INSERT OR REPLACE INTO keyhack_templates (keyname, command_template, method, url, header, body, note, description)
                 SELECT keyname, command_template, method, url, header, body, note, description
                 FROM keyskit_templates;" 2>&1 | grep -v '^\[.*\]' | head -5
        
        local migrated_count
        migrated_count=$(db_query "SELECT COUNT(*) FROM keyhack_templates;" 2>&1 | grep -v '^\[.*\]' | grep -v '^$' | tr -d ' ')
        
        log_success "Migration completed! Total templates in keyhack_templates: $migrated_count"
    fi
    
    return 0
}

main "$@"

