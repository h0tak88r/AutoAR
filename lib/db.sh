#!/usr/bin/env bash
# Database library for AutoAR (PostgreSQL + SQLite support)
# Provides database connection, schema management, and CRUD operations

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh" 2>/dev/null || true
source "$ROOT_DIR/lib/config.sh" 2>/dev/null || true

# Database configuration
DB_TYPE=${DB_TYPE:-postgresql}

# Parse PostgreSQL connection string if provided
if [[ -n "${DB_HOST:-}" && "$DB_HOST" =~ ^postgresql:// ]]; then
  # Extract connection details from PostgreSQL URL
  DB_TYPE="postgresql"
  DB_URL="$DB_HOST"
  # Parse the URL to extract components
  if [[ "$DB_HOST" =~ postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+) ]]; then
    DB_USER="${BASH_REMATCH[1]}"
    DB_PASSWORD="${BASH_REMATCH[2]}"
    DB_HOST_IP="${BASH_REMATCH[3]}"
    DB_PORT="${BASH_REMATCH[4]}"
    DB_NAME="${BASH_REMATCH[5]}"
    # Keep original DB_HOST for connection string
    DB_HOST="$DB_HOST_IP"
  fi
else
  # Use individual environment variables
  DB_HOST=${DB_HOST:-localhost}
  DB_PORT=${DB_PORT:-5432}
  DB_USER=${DB_USER:-autoar}
  DB_PASSWORD=${DB_PASSWORD:-}
  DB_NAME=${DB_NAME:-autoar}
fi

# Connection string based on DB type
# Set up PostgreSQL connection
DB_CONNECTION_STRING="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
DB_CLIENT="psql"

# Export environment variables for psql
export PGPASSWORD="$DB_PASSWORD"

die() { echo "$1" >&2; exit 1; }

# Check if required database client is available
require_db_client() {
  command -v psql >/dev/null 2>&1 || die "psql is not installed. Install postgresql-client."
}

# Execute SQL query
db_exec() {
  local query="$1"
  require_db_client
  
  PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A -c "$query" 2>/dev/null || true
}

# Execute SQL query and return results
db_query() {
  local query="$1"
  require_db_client
  
  PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -A -c "$query" 2>/dev/null || true
}

# Initialize database schema
db_init_schema() {
  log_info "Initializing database schema..."
  if ! db_ensure_connection; then
    log_warn "Database not available, skipping schema initialization"
    return 1
  fi
  require_db_client
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    # PostgreSQL schema
    db_exec "
    CREATE TABLE IF NOT EXISTS domains (
      id SERIAL PRIMARY KEY,
      domain VARCHAR(255) UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE TABLE IF NOT EXISTS subdomains (
      id SERIAL PRIMARY KEY,
      domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
      subdomain VARCHAR(255) UNIQUE NOT NULL,
      is_live BOOLEAN DEFAULT FALSE,
      http_url VARCHAR(512),
      https_url VARCHAR(512),
      http_status INTEGER,
      https_status INTEGER,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE TABLE IF NOT EXISTS js_files (
      id SERIAL PRIMARY KEY,
      subdomain_id INTEGER REFERENCES subdomains(id) ON DELETE CASCADE,
      js_url VARCHAR(1024) UNIQUE NOT NULL,
      content_hash VARCHAR(64),
      last_scanned TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    
    CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
    CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
    CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
    "
  else
    # SQLite schema
    db_exec "
    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS subdomains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
      subdomain TEXT UNIQUE NOT NULL,
      is_live BOOLEAN DEFAULT 0,
      http_url TEXT,
      https_url TEXT,
      http_status INTEGER,
      https_status INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS js_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subdomain_id INTEGER REFERENCES subdomains(id) ON DELETE CASCADE,
      js_url TEXT UNIQUE NOT NULL,
      content_hash TEXT,
      last_scanned DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_subdomains_domain_id ON subdomains(domain_id);
    CREATE INDEX IF NOT EXISTS idx_subdomains_is_live ON subdomains(is_live);
    CREATE INDEX IF NOT EXISTS idx_js_files_subdomain_id ON js_files(subdomain_id);
    "
  fi
  
  log_success "Database schema initialized"
}

# Insert or get domain ID
db_insert_domain() {
  local domain="$1"
  local domain_id
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    domain_id=$(db_query "INSERT INTO domains (domain) VALUES ('$domain') ON CONFLICT (domain) DO UPDATE SET updated_at = NOW() RETURNING id;" | head -1)
  else
    domain_id=$(db_query "INSERT OR IGNORE INTO domains (domain) VALUES ('$domain'); SELECT id FROM domains WHERE domain = '$domain';" | head -1)
  fi
  
  echo "$domain_id"
}

# Insert or update subdomain
db_insert_subdomain() {
  local domain="$1"
  local subdomain="$2"
  local is_live="${3:-false}"
  local http_url="${4:-}"
  local https_url="${5:-}"
  local http_status="${6:-}"
  local https_status="${7:-}"
  
  local domain_id
  domain_id=$(db_insert_domain "$domain")
  
  # Use simple INSERT for now (PostgreSQL only)
  log_info "Inserting subdomain: $subdomain for domain_id: $domain_id"
  db_exec "INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status) 
           VALUES ($domain_id, '$subdomain', $is_live, '$http_url', '$https_url', '$http_status', '$https_status');"
}

# Batch insert subdomains (much faster for large datasets)
db_batch_insert_subdomains() {
  local domain="$1"
  local subdomains_file="$2"
  local is_live="${3:-false}"
  
  if [[ ! -f "$subdomains_file" ]]; then
    log_error "Subdomains file not found: $subdomains_file"
    return 1
  fi
  
  local domain_id
  domain_id=$(db_insert_domain "$domain")
  
  log_info "Batch inserting subdomains for $domain (domain_id: $domain_id)"
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    # Use individual INSERTs for better compatibility
    local count=0
    local failed=0
    while IFS= read -r subdomain; do
      if [[ -n "$subdomain" ]]; then
        if db_exec "INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status) 
                    VALUES ($domain_id, '$subdomain', $is_live, '', '', 0, 0)
                    ON CONFLICT (subdomain) DO UPDATE SET 
                    domain_id = EXCLUDED.domain_id,
                    is_live = EXCLUDED.is_live,
                    updated_at = NOW();"; then
          ((count++))
        else
          ((failed++))
          log_warn "Failed to insert subdomain: $subdomain"
        fi
      fi
    done < "$subdomains_file"
    
    if [[ $count -gt 0 ]]; then
      log_success "Batch inserted $count subdomains"
    fi
    if [[ $failed -gt 0 ]]; then
      log_warn "Failed to insert $failed subdomains"
    fi
  else
    # SQLite batch insert using VALUES clause
    local values=""
    local count=0
    
    while IFS= read -r subdomain; do
      if [[ -n "$subdomain" ]]; then
        if [[ -n "$values" ]]; then
          values="$values,"
        fi
        values="$values($domain_id, '$subdomain', $is_live, '', '', '', '')"
        ((count++))
        
        # Insert in batches of 1000 to avoid SQL limits
        if [[ $count -eq 1000 ]]; then
          db_exec "INSERT OR REPLACE INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status) VALUES $values;"
          values=""
          count=0
        fi
      fi
    done < "$subdomains_file"
    
    # Insert remaining values
    if [[ -n "$values" ]]; then
      db_exec "INSERT OR REPLACE INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status) VALUES $values;"
    fi
    
    log_success "Batch inserted subdomains"
  fi
}

# Get all subdomains for a domain
db_get_subdomains() {
  local domain="$1"
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    db_query "SELECT s.subdomain FROM subdomains s 
              JOIN domains d ON s.domain_id = d.id 
              WHERE d.domain = '$domain' 
              ORDER BY s.subdomain;"
  else
    db_query "SELECT s.subdomain FROM subdomains s 
              JOIN domains d ON s.domain_id = d.id 
              WHERE d.domain = '$domain' 
              ORDER BY s.subdomain;"
  fi
}

# Get live subdomains for a domain
db_get_live_subdomains() {
  local domain="$1"
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    db_query "SELECT s.subdomain FROM subdomains s 
              JOIN domains d ON s.domain_id = d.id 
              WHERE d.domain = '$domain' AND s.is_live = true 
              ORDER BY s.subdomain;"
  else
    db_query "SELECT s.subdomain FROM subdomains s 
              JOIN domains d ON s.domain_id = d.id 
              WHERE d.domain = '$domain' AND s.is_live = 1 
              ORDER BY s.subdomain;"
  fi
}

# Insert JS file
db_insert_js_file() {
  local domain="$1"
  local js_url="$2"
  local content_hash="${3:-}"
  
  # Extract subdomain from URL
  local subdomain
  subdomain=$(echo "$js_url" | sed -E 's|^https?://([^/]+).*|\1|')
  
  
  local subdomain_id
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    subdomain_id=$(db_query "SELECT s.id FROM subdomains s JOIN domains d ON s.domain_id = d.id WHERE d.domain = '$domain' AND s.subdomain = '$subdomain';")
  else
    subdomain_id=$(db_query "SELECT s.id FROM subdomains s JOIN domains d ON s.domain_id = d.id WHERE d.domain = '$domain' AND s.subdomain = '$subdomain';")
  fi
  
  
  if [[ -n "$subdomain_id" ]]; then
    if [[ "$DB_TYPE" == "postgresql" ]]; then
      db_exec "INSERT INTO js_files (subdomain_id, js_url, content_hash, last_scanned) 
               VALUES ($subdomain_id, '$js_url', '$content_hash', NOW())
               ON CONFLICT (js_url) DO UPDATE SET 
               content_hash = EXCLUDED.content_hash,
               last_scanned = NOW(),
               updated_at = NOW();"
    else
      db_exec "INSERT OR REPLACE INTO js_files (subdomain_id, js_url, content_hash, last_scanned) 
               VALUES ($subdomain_id, '$js_url', '$content_hash', datetime('now'));"
    fi
  else
    # Subdomain not found, try to create it
    local domain_id
    domain_id=$(db_insert_domain "$domain")
    
    # Insert the subdomain
    if [[ "$DB_TYPE" == "postgresql" ]]; then
      subdomain_id=$(db_query "INSERT INTO subdomains (domain_id, subdomain, is_live, http_url, https_url, http_status, https_status) 
                               VALUES ($domain_id, '$subdomain', false, '', '', 0, 0)
                               ON CONFLICT (subdomain) DO UPDATE SET 
                               domain_id = EXCLUDED.domain_id,
                               updated_at = NOW()
                               RETURNING id;")
    fi
    
    if [[ -n "$subdomain_id" ]]; then
      # Now insert the JS file
      if [[ "$DB_TYPE" == "postgresql" ]]; then
        db_exec "INSERT INTO js_files (subdomain_id, js_url, content_hash, last_scanned) 
                 VALUES ($subdomain_id, '$js_url', '$content_hash', NOW())
                 ON CONFLICT (js_url) DO UPDATE SET 
                 content_hash = EXCLUDED.content_hash,
                 last_scanned = NOW(),
                 updated_at = NOW();"
      fi
      return 0
    else
      return 1
    fi
  fi
  
  return 0
}

# Get JS files for a domain
db_get_js_files() {
  local domain="$1"
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    db_query "SELECT jf.js_url FROM js_files jf 
              JOIN subdomains s ON jf.subdomain_id = s.id 
              JOIN domains d ON s.domain_id = d.id 
              WHERE d.domain = '$domain' 
              ORDER BY jf.js_url;"
  else
    db_query "SELECT jf.js_url FROM js_files jf 
              JOIN subdomains s ON jf.subdomain_id = s.id 
              JOIN domains d ON s.domain_id = d.id 
              WHERE d.domain = '$domain' 
              ORDER BY jf.js_url;"
  fi
}

# List all domains
db_list_domains() {
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    db_query "SELECT domain FROM domains ORDER BY domain;"
  else
    db_query "SELECT domain FROM domains ORDER BY domain;"
  fi
}

# Test database connection
db_test_connection() {
  require_db_client
  
  PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" >/dev/null 2>&1
}

# Ensure PostgreSQL connection
db_ensure_connection() {
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    if ! db_test_connection; then
      log_warn "PostgreSQL connection failed. Database operations will be skipped."
      log_info "DB_HOST: $DB_HOST"
      log_info "DB_PORT: $DB_PORT"
      log_info "DB_USER: $DB_USER"
      log_info "DB_NAME: $DB_NAME"
      return 1
    fi
  else
    log_error "Only PostgreSQL is supported. Please set DB_TYPE=postgresql"
    return 1
  fi
}

# Export subdomains to file
db_export_subdomains() {
  local domain="$1"
  local output_file="$2"
  
  mkdir -p "$(dirname "$output_file")"
  db_get_subdomains "$domain" > "$output_file"
  
  if [[ -s "$output_file" ]]; then
    local count=$(wc -l < "$output_file")
    log_success "Exported $count subdomains to $output_file"
    
    # Send to Discord if webhook is configured
    if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
      source "$ROOT_DIR/lib/discord.sh" 2>/dev/null || true
      command -v send_file_to_discord >/dev/null 2>&1 && send_file_to_discord "$output_file" "DB subdomains for $domain"
    fi
  else
    log_warn "No subdomains found for $domain"
  fi
}
