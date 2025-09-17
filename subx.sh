#!/bin/bash

# Minimal subdomain enumeration script using HackerTarget with proxychains
# Usage: cat domains.txt | ./subx.sh [--silent]

# Parse arguments
SILENT=false
for arg in "$@"; do
    case $arg in
        --silent)
            SILENT=true
            shift
            ;;
    esac
done

# Function to print messages only if not in silent mode
log() {
    if [[ "$SILENT" == "false" ]]; then
        echo "$1" >&2
    fi
}

# Function to check if we can reach the API
check_api() {
    local test_domain="example.com"
    log "Testing API connection..."
    local response=$(proxychains4 -q curl -s "https://api.hackertarget.com/hostsearch/?q=$test_domain" 2>/dev/null)
    if [[ -z "$response" ]]; then
        log "Error: Could not reach HackerTarget API. Check your proxy configuration."
        exit 1
    fi
    if [[ "$response" == *"API count exceeded"* ]]; then
        log "Error: API quota exceeded. Try a different proxy."
        exit 1
    fi
    log "API connection successful!"
}

# Check API connectivity first
check_api

# Process input domains
while IFS= read -r domain || [[ -n "$domain" ]]; do
    # Skip empty lines and comments
    if [[ -z "$domain" || "$domain" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    # Trim whitespace
    domain=$(echo "$domain" | tr -d ' \t\r\n')
    
    # Skip if still empty after trimming
    if [[ -z "$domain" ]]; then
        continue
    fi
    
    # Query HackerTarget and output subdomains
    log "Checking domain: $domain"
    proxychains4 -q curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" 2>/dev/null | cut -d',' -f1
    
    # Add a small delay to avoid overwhelming the proxy
    sleep 2
    
done | sort -u | grep -v '^$' 