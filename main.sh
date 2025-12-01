#!/usr/bin/env bash
set -euo pipefail

# Root dir resolution
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables first
if [[ -f "$ROOT_DIR/.env" ]]; then
  source "$ROOT_DIR/.env"
fi

# Include libraries
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/config.sh"
source "$ROOT_DIR/lib/discord.sh"

print_usage() {
  cat <<EOF
Usage: main.sh <command> <action> [options]

Commands:
  subdomains get      -d <domain>
  livehosts get       -d <domain>
  cnames get          -d <domain>
  urls collect        -d <domain>
  js scan             -d <domain> [-s <subdomain>]
  reflection scan     -d <domain>
  nuclei run          -d <domain>
  tech detect         -d <domain>
  ports scan          -d <domain>
  gf scan             -d <domain>
  sqlmap run          -d <domain>
  dalfox run          -d <domain>
  
  monitor updates add    -u <url> [--strategy ...] [--pattern <regex>]
  monitor updates remove -u <url>
  monitor updates start  [--interval <sec>] [--daemon] [--all]
  monitor updates stop   [--all]
  monitor updates list
  wpDepConf scan      -d <domain> | -l <live_hosts_file>
  dns takeover        -d <domain>     (comprehensive scan)
  dns cname           -d <domain>     (CNAME takeover only)
  dns ns              -d <domain>     (NS takeover only)
  dns azure-aws       -d <domain>     (Azure/AWS takeover only)
  dns dnsreaper       -d <domain>     (DNSReaper scan only)
  dns all             -d <domain>     (comprehensive scan)
  s3 scan             -b <bucket> [-r <region>]
  s3 enum             -b <root_domain>
  github scan         -r <owner/repo>
  github org          -o <org> [-m <max-repos>]
  github depconfusion -r <owner/repo>
  github experimental -r <owner/repo>
  github-wordlist scan -o <github_org> [-t <github_token>]
  backup scan            -d <domain> [-o <output_dir>] [-t <threads>] [-d <delay>]
  backup scan            -l <live_hosts_file> [-o <output_dir>] [-t <threads>] [-d <delay>]
  depconfusion scan <file>                    Scan local dependency file
  depconfusion github repo <owner/repo>       Scan GitHub repository
  depconfusion github org <org>               Scan GitHub organization
  depconfusion web <url> [url2] [url3]...     Scan web targets
  depconfusion web-file <file>                Scan targets from file
  misconfig scan <target> [service] [delay]   Scan for misconfigurations
  misconfig service <target> <service-id>     Scan specific service
  misconfig list                              List available services
  misconfig update                            Update templates
  keyhack list                                List all API key validation templates
  keyhack search <query>                      Search API key validation templates
  keyhack validate <provider> <api_key>       Generate validation command for API key
  keyhack add <keyname> <command> <desc> [notes] Add a new template
  jwt scan             -t <url> [--cookie|--header] [-M <mode>]   Test JWT security using jwt_tool
  jwt query            <query_id>                                   Query JWT tool log by ID

Workflows:
  lite run            -d <domain>
  fastlook run        -d <domain>
  domain run          -d <domain>

Database:
  db domains list
  db domains delete   -d <domain>
  db subdomains list  -d <domain>
  db subdomains export -d <domain> [-o file]
  db js list          -d <domain>

Utilities:
  cleanup run         --domain <domain> [--keep]
  check-tools
  help
EOF
}

# Dispatch helpers
cmd_subdomains() { "$ROOT_DIR/modules/subdomains.sh" "$@"; }
cmd_livehosts()  { "$ROOT_DIR/modules/livehosts.sh"  "$@"; }
cmd_cnames()     { "$ROOT_DIR/modules/cnames.sh"     "$@"; }
cmd_urls()       { "$ROOT_DIR/modules/urls.sh"       "$@"; }
cmd_js()         { "$ROOT_DIR/modules/js_scan.sh"    "$@"; }
cmd_lite()       { "$ROOT_DIR/modules/lite.sh"       "$@"; }
cmd_s3()         { "$ROOT_DIR/modules/s3_scan.sh"     "$@"; }
cmd_domain()     { "$ROOT_DIR/modules/domain.sh"      "$@"; }
cmd_cleanup()    { "$ROOT_DIR/modules/cleanup.sh"     "$@"; }
cmd_db()         { "$ROOT_DIR/modules/db.sh"          "$@"; }
cmd_checktools() { "$ROOT_DIR/modules/check_tools.sh"  "$@"; }
cmd_reflection() { "$ROOT_DIR/modules/reflection.sh"  "$@"; }
cmd_nuclei()     { "$ROOT_DIR/modules/nuclei.sh"      "$@"; }
cmd_tech()       { "$ROOT_DIR/modules/tech.sh"        "$@"; }
cmd_ports()      { "$ROOT_DIR/modules/ports.sh"       "$@"; }
cmd_gf()         { "$ROOT_DIR/modules/gf_scan.sh"     "$@"; }
cmd_sqlmap()     { "$ROOT_DIR/modules/sqlmap.sh"      "$@"; }
cmd_dalfox()     { "$ROOT_DIR/modules/dalfox.sh"      "$@"; }
cmd_updates()    { "$ROOT_DIR/modules/updates.sh"     "$@"; }
cmd_dns()        { "$ROOT_DIR/modules/dns_takeover.sh" "$@"; }
cmd_github()     { "$ROOT_DIR/modules/github_scan.sh"    "$@"; }
cmd_github_wordlist() { python3 "$ROOT_DIR/python/github_wordlist.py" "$1"; }
cmd_backup()     { "$ROOT_DIR/modules/backup_scan.sh"    "$@"; }
cmd_depconfusion() { "$ROOT_DIR/modules/depconfusion.sh" "$@"; }
cmd_misconfig()  { "$ROOT_DIR/modules/misconfig.sh"     "$@"; }
cmd_fastlook()   { "$ROOT_DIR/modules/fastlook.sh"      "$@"; }
cmd_keyhack()    { "$ROOT_DIR/modules/keyhack.sh"       "$@"; }
cmd_jwt()        { "$ROOT_DIR/modules/jwt_scan.sh"      "$@"; }
cmd_help()       { print_usage; }
cmd_wpdepconf()  { "$ROOT_DIR/modules/wp_plugin_confusion.sh" "$@" ; }

main() {
  if [[ $# -lt 1 ]]; then
    print_usage; exit 1
  fi

  local cmd="$1"; shift || true
  case "$cmd" in
    subdomains) cmd_subdomains "$@" ;;
    livehosts)  cmd_livehosts  "$@" ;;
    cnames)     cmd_cnames     "$@" ;;
    urls)       cmd_urls       "$@" ;;
    js)         cmd_js         "$@" ;;
    s3)         cmd_s3         "$@" ;;
    domain)     cmd_domain     "$@" ;;
    cleanup)    cmd_cleanup    "$@" ;;
    db)         cmd_db         "$@" ;;
    check-tools) cmd_checktools "$@" ;;
    lite)       cmd_lite       "$@" ;;
    reflection) cmd_reflection "$@" ;;
    nuclei)     cmd_nuclei     "$@" ;;
    tech)       cmd_tech       "$@" ;;
    ports)      cmd_ports      "$@" ;;
    gf)         cmd_gf         "$@" ;;
    sqlmap)     cmd_sqlmap     "$@" ;;
    dalfox)     cmd_dalfox     "$@" ;;
    
    monitor)
      local sub="$1"; shift || true
      case "$sub" in
        updates)
          local action="$1"; shift || true
          case "$action" in
            add)    cmd_updates add "$@" ;;
            remove) cmd_updates remove "$@" ;;
            start)  cmd_updates monitor start "$@" ;;
            stop)   cmd_updates monitor stop  "$@" ;;
            list)   cmd_updates monitor list  "$@" ;;
            *) print_usage; exit 1;;
          esac
        ;;
        *) print_usage; exit 1;;
      esac
    ;;
  dns)        cmd_dns        "$@" ;;
  github)     cmd_github     "$@" ;;
  github-wordlist) cmd_github_wordlist "$@" ;;
  backup)     cmd_backup     "$@" ;;
  depconfusion) cmd_depconfusion "$@" ;;
  misconfig)   cmd_misconfig   "$@" ;;
  fastlook)    cmd_fastlook    "$@" ;;
  keyhack)     cmd_keyhack     "$@" ;;
  jwt)         cmd_jwt         "$@" ;;
  help)        cmd_help        "$@" ;;
  wpDepConf)   cmd_wpdepconf   "$@" ;;
  --help|-h)  print_usage ;;
  *) log_error "Unknown command: $cmd"; print_usage; exit 1 ;;
  esac
}

main "$@"


