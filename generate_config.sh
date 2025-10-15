#!/bin/bash

# Generate autoar.yaml from environment variables
cat > /app/autoar.yaml << EOF
# AutoAR Configuration - Generated from Environment Variables
WORDPRESS: [${WORDPRESS_API_KEY:-}]
bevigil: [${BEVIGIL_API_KEY:-}]
binaryedge: [${BINARYEDGE_API_KEY:-}]
urlscan: [${URLSCAN_API_KEY:-}]
bufferoverflow: []
c99: []
censys: [${CENSYS_API_ID:-}${CENSYS_API_SECRET:+:${CENSYS_API_SECRET}}]
certspotter: [${CERTSPOTTER_API_KEY:-}]
chaos: [${CHAOS_API_KEY:-}]
chinaz: []
dnsdb: []
fofa: [${FOFA_EMAIL:-}${FOFA_KEY:+:${FOFA_KEY}}]
fullhunt: [${FULLHUNT_API_KEY:-}]
github: [${GITHUB_TOKEN:-}]
intelx: [${INTELX_API_KEY:-}]
passivetotal: [${PASSIVETOTAL_USERNAME:-}${PASSIVETOTAL_API_KEY:+:${PASSIVETOTAL_API_KEY}}]
quake: [${QUAKE_USERNAME:-}${QUAKE_PASSWORD:+:${QUAKE_PASSWORD}}]
robtex: []
securitytrails: [${SECURITYTRAILS_API_KEY:-}]
shodan: [${SHODAN_API_KEY:-}]
threatbook: [${THREATBOOK_API_KEY:-}]
virustotal: [${VIRUSTOTAL_API_KEY:-}]
whoisxmlapi: [${WHOISXMLAPI_API_KEY:-}]
zoomeye: [${ZOOMEYE_USERNAME:-}${ZOOMEYE_PASSWORD:+:${ZOOMEYE_PASSWORD}}]
zoomeyeapi: [${ZOOMEYEAPI_API_KEY:-}]
dnsrepo: []
hunter: [${HUNTER_API_KEY:-}]
H1_API_KEY: "${H1_API_KEY:-}"
INTEGRITI_API_KEY: "${INTEGRITI_API_KEY:-}"
DISCORD_WEBHOOK: "${DISCORD_WEBHOOK:-}"
SAVE_TO_DB: ${SAVE_TO_DB:-true}
VERBOSE: ${VERBOSE:-true}
DB_NAME: "${DB_NAME:-autoar}"
DOMAINS_COLLECTION: "${DOMAINS_COLLECTION:-domains}"
SUBDOMAINS_COLLECTION: "${SUBDOMAINS_COLLECTION:-subdomains}"
openrouter_api: "${OPENROUTER_API_KEY:-}"

# GitLab storage configuration
gitlab:
  project_url: "${GITLAB_PROJECT_URL:-}"
  username: "${GITLAB_USERNAME:-}"
  access_token: "${GITLAB_ACCESS_TOKEN:-}"
  branch: "${GITLAB_BRANCH:-main}"
  use_gitlab_storage: ${USE_GITLAB_STORAGE:-false}

# Tool configuration
tools:
  nuclei:
    templates_path: "${NUCLEI_TEMPLATES_PATH:-/app/nuclei_templates}"
    rate_limit: ${NUCLEI_RATE_LIMIT:-150}
    concurrency: ${NUCLEI_CONCURRENCY:-25}
  
  ffuf:
    wordlist_path: "${FFUF_WORDLIST_PATH:-/app/Wordlists/quick_fuzz.txt}"
    threads: ${FFUF_THREADS:-50}
  
  subfinder:
    config_path: "${AUTOAR_CONFIG_FILE:-/app/autoar.yaml}"
    threads: ${SUBFINDER_THREADS:-10}
  
  github_scan:
    max_repos: ${GITHUB_MAX_REPOS:-50}
    parallel_jobs: ${GITHUB_PARALLEL_JOBS:-3}
    html_reports: ${GITHUB_HTML_REPORTS:-true}
    scan_types: ["${GITHUB_SCAN_TYPES:-github_org_scan}"]

# Storage configuration
storage:
  type: "${STORAGE_TYPE:-local}"
  local_path: "${LOCAL_PATH:-/app/new-results}"
  gitlab:
    project_url: "${GITLAB_PROJECT_URL:-}"
    username: "${GITLAB_USERNAME:-}"
    access_token: "${GITLAB_ACCESS_TOKEN:-}"
    branch: "${GITLAB_BRANCH:-main}"
EOF

echo "Generated autoar.yaml with environment variables"
