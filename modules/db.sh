#!/usr/bin/env bash
# Database CLI module for AutoAR (PostgreSQL + SQLite)
# Provides read/list/export helpers using lib/db.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load environment variables first
if [[ -f "$ROOT_DIR/.env" ]]; then
  source "$ROOT_DIR/.env"
fi

# lib/logging.sh removed - functionality in gomodules/ 2>/dev/null || true
# lib/utils.sh removed - functionality in gomodules/ 2>/dev/null || true

# Load database functions (prefer Go wrapper, fallback to bash)
if [[ -f "$ROOT_DIR/gomodules/db/wrapper.sh" ]]; then
  source "$ROOT_DIR/gomodules/db/wrapper.sh"
elif [[ -f "$ROOT_DIR/lib/db.sh" ]]; then
  # lib/db.sh removed - functionality in gomodules/ || { echo "ERROR: Failed to load database functions" >&2; exit 1; }
else
  echo "ERROR: No database functions available" >&2
  exit 1
fi

# lib/discord.sh removed - functionality in gomodules/ 2>/dev/null || true

die() { echo "$1" >&2; exit 1; }

# Send database results to Discord
send_db_result_to_discord() {
  local command="$1"
  local result="$2"
  local domain="${3:-}"
  
  if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
    local message="**Database Command:** \`$command\`"
    if [[ -n "$domain" ]]; then
      message="$message
**Domain:** \`$domain\`"
    fi
    message="$message
**Result:**
\`\`\`
$result
\`\`\`"
    
    discord_send "$message" >/dev/null 2>&1 || true
  fi
}

db_domains_list() {
  # Use the existing db_list_domains function from lib/db.sh
  db_ensure_connection
  local result=$(db_list_domains)
  echo "$result"
  
  # Send domains list to Discord
  send_db_result_to_discord "db domains list" "$result"
  
  # Create a file with domains and send via Discord webhook
  if [[ -n "$result" ]]; then
    local results_dir="${AUTOAR_RESULTS_DIR}/db_domains_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$results_dir"
    local domains_file="$results_dir/all_domains.txt"
    
    echo "# AutoAR Database - All Domains" > "$domains_file"
    echo "# Generated: $(date)" >> "$domains_file"
    echo "" >> "$domains_file"
    echo "$result" >> "$domains_file"
    
    # Send final results via bot (webhook used for logging)
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-db_domains_$(date +%s)}"
    discord_send_file "$domains_file" "All domains from database" "$scan_id"
    
    echo "Domains exported to: $domains_file"
  else
    echo "No domains found in database"
    send_db_result_to_discord "db domains list" "No domains found in database"
  fi
}

db_subdomains_list() {
  local domain=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  db_ensure_connection
  local result=$(db_get_subdomains "$domain")
  echo "$result"
  
  # Create a file with subdomains and send via Discord webhook
  if [[ -n "$result" ]]; then
    local results_dir="${AUTOAR_RESULTS_DIR}/db_subdomains_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$results_dir"
    local subdomains_file="$results_dir/${domain}_subdomains.txt"
    
    echo "# AutoAR Database - Subdomains for $domain" > "$subdomains_file"
    echo "# Generated: $(date)" >> "$subdomains_file"
    echo "" >> "$subdomains_file"
    echo "$result" >> "$subdomains_file"
    
    # Send final results via bot
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-db_subdomains_$(date +%s)}"
    discord_send_file "$subdomains_file" "Subdomains for $domain from database" "$scan_id"
    
    echo "Subdomains exported to: $subdomains_file"
  else
    echo "No subdomains found for $domain"
    send_db_result_to_discord "db subdomains list" "No subdomains found for $domain" "$domain"
  fi
}

db_subdomains_export() {
  local domain="" out=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -o|--out) out="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  [[ -z "$out" ]] && out="$ROOT_DIR/new-results/$domain/subs/db-subdomains.txt"
  db_export_subdomains "$domain" "$out"
}

# Get all subdomains from all domains
db_all_subdomains_list() {
  db_ensure_connection
  
  if [[ "$DB_TYPE" == "postgresql" ]]; then
    local result=$(db_query "SELECT s.subdomain FROM subdomains s 
              JOIN domains d ON s.domain_id = d.id 
              ORDER BY d.domain, s.subdomain;")
  else
    local result=$(db_query "SELECT s.subdomain FROM subdomains s 
              JOIN domains d ON s.domain_id = d.id 
              ORDER BY d.domain, s.subdomain;")
  fi
  
  echo "$result"
  
  # Send all subdomains list to Discord
  send_db_result_to_discord "db all subdomains list" "$result"
  
  # Create a file with all subdomains and send via Discord webhook
  if [[ -n "$result" ]]; then
    local results_dir="${AUTOAR_RESULTS_DIR}/db_all_subdomains_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$results_dir"
    local all_subdomains_file="$results_dir/all_subdomains.txt"
    
    echo "# AutoAR Database - All Subdomains" > "$all_subdomains_file"
    echo "# Generated: $(date)" >> "$all_subdomains_file"
    echo "" >> "$all_subdomains_file"
    echo "$result" >> "$all_subdomains_file"
    
    # Send final results via bot
    local scan_id="${AUTOAR_CURRENT_SCAN_ID:-db_all_subdomains_$(date +%s)}"
    discord_send_file "$all_subdomains_file" "All subdomains from database" "$scan_id"
    
    echo "All subdomains exported to: $all_subdomains_file"
  else
    echo "No subdomains found in database"
    send_db_result_to_discord "db all subdomains list" "No subdomains found in database"
  fi
}

db_js_list() {
  local domain=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  db_ensure_connection
  local result=$(db_get_js_files "$domain")
  echo "$result"
  send_db_result_to_discord "db js list" "$result" "$domain"
}

db_domain_delete() {
  local domain=""
  local force=false
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain) domain="$2"; shift 2;;
      -f|--force) force=true; shift;;
      *) shift;;
    esac
  done
  [[ -z "$domain" ]] && die "--domain is required"
  
  db_ensure_connection
  
  # Get domain ID first
  local domain_id
  domain_id=$(db_query "SELECT id FROM domains WHERE domain = '$domain';")
  
  if [[ -z "$domain_id" ]]; then
    echo "Domain '$domain' not found in database"
    send_db_result_to_discord "db domains delete" "Domain '$domain' not found in database" "$domain"
    return 1
  fi
  
  # Get counts for confirmation
  local subdomain_count=$(db_query "SELECT COUNT(*) FROM subdomains WHERE domain_id = $domain_id;")
  local js_count=$(db_query "SELECT COUNT(*) FROM js_files WHERE subdomain_id IN (SELECT id FROM subdomains WHERE domain_id = $domain_id);")
  
  echo "Domain: $domain (ID: $domain_id)"
  echo "Subdomains: $subdomain_count"
  echo "JS files: $js_count"
  
  if [[ "$force" != "true" ]]; then
    echo ""
    echo "This will delete the domain and ALL related data:"
    echo "- $subdomain_count subdomains"
    echo "- $js_count JS files"
    echo ""
    read -p "Are you sure you want to continue? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
      echo "Operation cancelled"
      return 0
    fi
  fi
  
  echo "Deleting domain '$domain' and all related data..."
  
  # Delete in correct order (foreign key constraints)
  # 1. Delete JS files first
  if [[ $js_count -gt 0 ]]; then
    echo "Deleting $js_count JS files..."
    db_exec "DELETE FROM js_files WHERE subdomain_id IN (SELECT id FROM subdomains WHERE domain_id = $domain_id);"
  fi
  
  # 2. Delete subdomains
  if [[ $subdomain_count -gt 0 ]]; then
    echo "Deleting $subdomain_count subdomains..."
    db_exec "DELETE FROM subdomains WHERE domain_id = $domain_id;"
  fi
  
  # 3. Delete domain
  echo "Deleting domain..."
  db_exec "DELETE FROM domains WHERE id = $domain_id;"
  
  echo "✅ Domain '$domain' and all related data deleted successfully"
  local result="Successfully deleted domain '$domain' and all related data:\n- Subdomains: $subdomain_count\n- JS files: $js_count"
  send_db_result_to_discord "db domains delete" "$result" "$domain"
}

# Get database statistics
db_stats() {
  db_ensure_connection
  
  local domain_count=$(db_query "SELECT COUNT(*) FROM domains;")
  local subdomain_count=$(db_query "SELECT COUNT(*) FROM subdomains;")
  local js_count=$(db_query "SELECT COUNT(*) FROM js_files;")
  local live_subdomain_count=$(db_query "SELECT COUNT(*) FROM subdomains WHERE is_live = true;")
  
  echo "📊 AutoAR Database Statistics"
  echo "================================"
  echo "Domains: $domain_count"
  echo "Subdomains: $subdomain_count"
  echo "Live Subdomains: $live_subdomain_count"
  echo "JS Files: $js_count"
  echo ""
  
  # Top domains by subdomain count
  echo "Top 10 domains by subdomain count:"
  echo "----------------------------------"
  db_query "SELECT d.domain, COUNT(s.id) as subdomain_count 
            FROM domains d 
            LEFT JOIN subdomains s ON d.id = s.domain_id 
            GROUP BY d.id, d.domain 
            ORDER BY subdomain_count DESC 
            LIMIT 10;" | while IFS='|' read -r domain count; do
    printf "%-30s %s\n" "$domain" "$count"
  done
  
  # Send stats to Discord
  local stats="📊 AutoAR Database Statistics\n"
  stats+="Domains: $domain_count\n"
  stats+="Subdomains: $subdomain_count\n"
  stats+="Live Subdomains: $live_subdomain_count\n"
  stats+="JS Files: $js_count"
  send_db_result_to_discord "db stats" "$stats"
}

# Clean up old data
db_cleanup() {
  local days=30
  local dry_run=false
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--days) days="$2"; shift 2;;
      --dry-run) dry_run=true; shift;;
      *) shift;;
    esac
  done
  
  db_ensure_connection
  
  echo "🧹 AutoAR Database Cleanup"
  echo "=========================="
  echo "Removing data older than $days days"
  echo "Mode: $([ "$dry_run" = "true" ] && echo "DRY RUN" || echo "LIVE")"
  echo ""
  
  # Count old domains
  local old_domains=$(db_query "SELECT COUNT(*) FROM domains WHERE created_at < NOW() - INTERVAL '$days days';")
  local old_subdomains=$(db_query "SELECT COUNT(*) FROM subdomains WHERE created_at < NOW() - INTERVAL '$days days';")
  local old_js=$(db_query "SELECT COUNT(*) FROM js_files WHERE created_at < NOW() - INTERVAL '$days days';")
  
  echo "Data to be removed:"
  echo "- Domains: $old_domains"
  echo "- Subdomains: $old_subdomains"
  echo "- JS files: $old_js"
  echo ""
  
  if [[ "$dry_run" = "true" ]]; then
    echo "DRY RUN: No data was actually removed"
    return 0
  fi
  
  if [[ $old_domains -eq 0 && $old_subdomains -eq 0 && $old_js -eq 0 ]]; then
    echo "No old data found to clean up"
    return 0
  fi
  
  echo "Proceeding with cleanup..."
  
  # Delete old JS files first
  if [[ $old_js -gt 0 ]]; then
    echo "Deleting $old_js old JS files..."
    db_exec "DELETE FROM js_files WHERE created_at < NOW() - INTERVAL '$days days';"
  fi
  
  # Delete old subdomains
  if [[ $old_subdomains -gt 0 ]]; then
    echo "Deleting $old_subdomains old subdomains..."
    db_exec "DELETE FROM subdomains WHERE created_at < NOW() - INTERVAL '$days days';"
  fi
  
  # Delete old domains
  if [[ $old_domains -gt 0 ]]; then
    echo "Deleting $old_domains old domains..."
    db_exec "DELETE FROM domains WHERE created_at < NOW() - INTERVAL '$days days';"
  fi
  
  echo "✅ Cleanup completed successfully"
  
  local result="Database cleanup completed:\n- Removed $old_domains domains\n- Removed $old_subdomains subdomains\n- Removed $old_js JS files"
  send_db_result_to_discord "db cleanup" "$result"
}

usage() {
  cat <<EOF
Usage: db <resource> <action> [options]

Resources & actions:
  domains list                             List distinct domains in DB
  domains delete   -d <domain> [-f]        Delete domain and all related data (use -f to skip confirmation)
  subdomains list   -d <domain>            List subdomains for a domain
  subdomains export -d <domain> [-o file]  Export subdomains to file (and Discord if configured)
  subdomains all                           List all subdomains from all domains
  js list          -d <domain>             List JS files for a domain
  stats                                    Show database statistics
  cleanup          [-d days] [--dry-run]   Clean up old data (default: 30 days, use --dry-run to preview)

Options:
  --db <path>       Override DB path (default: $AUTOAR_DB)
EOF
}

# Entry
main() {
  [[ $# -lt 1 ]] && { usage; exit 1; }
  
  # Handle special case for stats and cleanup commands
  if [[ "$1" == "stats" ]]; then
    shift
    db_stats "$@"
    return
  fi
  
  if [[ "$1" == "cleanup" ]]; then
    shift
    db_cleanup "$@"
    return
  fi
  
  [[ $# -lt 2 ]] && { usage; exit 1; }
  local resource="$1"; shift
  local action="$1"; shift

  # Allow overriding DB path
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --db) AUTOAR_DB="$2"; shift 2;;
      *) break;;
    esac
  done

  case "$resource:$action" in
    domains:list)      db_domains_list "$@" ;;
    domains:delete)    db_domain_delete "$@" ;;
    subdomains:list)   db_subdomains_list "$@" ;;
    subdomains:export) db_subdomains_export "$@" ;;
    subdomains:all)    db_all_subdomains_list "$@" ;;
    js:list)           db_js_list "$@" ;;
    *) usage; exit 1;;
  esac
}

main "$@"


