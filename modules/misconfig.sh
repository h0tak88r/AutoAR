#!/bin/bash

# AutoAR Misconfig Scanner Module
# Uses misconfig-mapper to detect security misconfigurations in third-party services

set -euo pipefail

# Source common functions
source "$(dirname "$0")/../lib/logging.sh"
source "$(dirname "$0")/../lib/discord.sh"
source "$(dirname "$0")/../lib/utils.sh"

# Tool configuration
MISCONFIG_BIN="misconfig-mapper"

# Check if misconfig-mapper is available
check_misconfig_mapper() {
    if ! command -v "$MISCONFIG_BIN" &> /dev/null; then
        # Try common Go binary paths
        if [[ -f "/home/sallam/go/bin/$MISCONFIG_BIN" ]]; then
            MISCONFIG_BIN="/home/sallam/go/bin/$MISCONFIG_BIN"
        elif [[ -f "/usr/local/bin/$MISCONFIG_BIN" ]]; then
            MISCONFIG_BIN="/usr/local/bin/$MISCONFIG_BIN"
        else
            log_error "misconfig-mapper not found. Please install it with: go install github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest"
            exit 1
        fi
    fi
}

# List available services
list_services() {
    log_info "Listing available services..."
    "$MISCONFIG_BIN" -list-services
}

# Scan for misconfigurations
scan_misconfig() {
    local target="$1"
    local service="${2:-*}"
    local delay="${3:-1000}"
    local skip_checks="${4:-false}"
    local verbose="${5:-1}"
    local output_json="${6:-false}"
    
    log_info "Scanning for misconfigurations on target: $target"
    discord_send_progress "🔍 **Scanning for misconfigurations: $target**"
    
    # Set output directory
    local output_dir="$(results_dir "misconfig-$(date +%Y%m%d-%H%M%S)")"
    ensure_dir "$output_dir"
    
    # Build command
    local cmd=("$MISCONFIG_BIN" "-target" "$target" "-service" "$service" "-delay" "$delay" "-verbose" "$verbose")
    
    if [[ "$skip_checks" == "true" ]]; then
        cmd+=("-skip-misconfiguration-checks" "true")
    fi
    
    if [[ "$output_json" == "true" ]]; then
        cmd+=("-output-json")
    fi
    
    # Run scan
    if "${cmd[@]}" > "$output_dir/misconfig-scan.txt" 2>&1; then
        log_success "Misconfiguration scan completed"
        
        # Check for findings
        if grep -q "VULNERABLE\|MISCONFIGURED\|FOUND" "$output_dir/misconfig-scan.txt"; then
            log_warn "Security misconfigurations found!"
            discord_send_progress "⚠️ **Found security misconfigurations!**"
        else
            log_success "No security misconfigurations found"
            discord_send_progress "✅ **No security misconfigurations found**"
        fi
        
        # Send results to Discord
        discord_file "$output_dir/misconfig-scan.txt" "Misconfiguration scan results for $target"
    else
        log_error "Misconfiguration scan failed"
        discord_send_progress "❌ **Misconfiguration scan failed**"
        exit 1
    fi
}

# Scan specific service
scan_service() {
    local target="$1"
    local service_id="$2"
    local delay="${3:-1000}"
    local verbose="${4:-1}"
    
    log_info "Scanning service ID $service_id on target: $target"
    discord_send_progress "🔍 **Scanning service $service_id: $target**"
    
    # Set output directory
    local output_dir="$(results_dir "misconfig-service-$(date +%Y%m%d-%H%M%S)")"
    ensure_dir "$output_dir"
    
    # Build command
    local cmd=("$MISCONFIG_BIN" "-target" "$target" "-service" "$service_id" "-delay" "$delay" "-verbose" "$verbose")
    
    # Run scan
    if "${cmd[@]}" > "$output_dir/misconfig-service-scan.txt" 2>&1; then
        log_success "Service misconfiguration scan completed"
        
        # Check for findings
        if grep -q "VULNERABLE\|MISCONFIGURED\|FOUND" "$output_dir/misconfig-service-scan.txt"; then
            log_warn "Security misconfigurations found in service $service_id!"
            discord_send_progress "⚠️ **Found misconfigurations in service $service_id!**"
        else
            log_success "No security misconfigurations found in service $service_id"
            discord_send_progress "✅ **No misconfigurations found in service $service_id**"
        fi
        
        # Send results to Discord
        discord_file "$output_dir/misconfig-service-scan.txt" "Service $service_id misconfiguration scan results for $target"
    else
        log_error "Service misconfiguration scan failed"
        discord_send_progress "❌ **Service $service_id scan failed**"
        exit 1
    fi
}

# Update templates
update_templates() {
    log_info "Updating misconfig-mapper templates..."
    discord_send_progress "🔄 **Updating misconfig-mapper templates...**"
    
    if "$MISCONFIG_BIN" -update-templates; then
        log_success "Templates updated successfully"
        discord_send_progress "✅ **Templates updated successfully**"
    else
        log_error "Failed to update templates"
        discord_send_progress "❌ **Failed to update templates**"
        exit 1
    fi
}

# Usage information
usage() {
    echo "Usage: misconfig <command> [options]"
    echo ""
    echo "Commands:"
    echo "  scan <target> [service] [delay] [skip-checks] [verbose] [json]"
    echo "                    Scan for misconfigurations"
    echo "  service <target> <service-id> [delay] [verbose]"
    echo "                    Scan specific service by ID"
    echo "  list              List available services"
    echo "  update            Update templates"
    echo ""
    echo "Options:"
    echo "  target            Company/organization name or domain"
    echo "  service           Service ID or '*' for all (default: '*')"
    echo "  delay             Delay between requests in ms (default: 1000)"
    echo "  skip-checks       Skip misconfiguration checks (default: false)"
    echo "  verbose           Verbosity level 0-2 (default: 1)"
    echo "  json              Output in JSON format (default: false)"
    echo ""
    echo "Examples:"
    echo "  misconfig scan yourcompany"
    echo "  misconfig scan yourcompany.com -as-domain"
    echo "  misconfig service yourcompany 1"
    echo "  misconfig list"
    echo "  misconfig update"
}

# Main function
main() {
    check_misconfig_mapper
    
    # Handle help flags
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        usage
        exit 0
    fi
    
    case "${1:-}" in
        scan)
            shift
            if [[ $# -lt 1 ]]; then
                log_error "Target required for scan command"
                usage
                exit 1
            fi
            scan_misconfig "$@"
            ;;
        service)
            shift
            if [[ $# -lt 2 ]]; then
                log_error "Target and service ID required for service command"
                usage
                exit 1
            fi
            scan_service "$@"
            ;;
        list)
            list_services
            ;;
        update)
            update_templates
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
