#!/usr/bin/env bash
# Dependency Confusion Scanner using Confused tool
# Scans GitHub organization repositories for dependency confusion vulnerabilities

set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/.env" 2>/dev/null || true
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { 
  echo "Usage: depconfusion scan -o <github_org> [-t <github_token>] [-m <max_repos>]"
  echo "  -o, --org        GitHub organization name"
  echo "  -t, --token      GitHub token (optional, can use GITHUB_TOKEN env var)"
  echo "  -m, --max-repos  Maximum number of repositories to scan (default: 50)"
}

depconfusion_scan() {
  local org="" token="" max_repos="50"
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--org) org="$2"; shift 2;;
      -t|--token) token="$2"; shift 2;;
      -m|--max-repos) max_repos="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  
  [[ -z "$org" ]] && { usage; exit 1; }
  
  # Set default output directory
  local output_dir="$(results_dir "github-$org")/dependency-confusion"
  ensure_dir "$output_dir"
  
  log_info "Starting dependency confusion scan for GitHub organization: $org"
  discord_send_progress "🔍 **Starting dependency confusion scan for $org**"
  
  # Check if confused tool is installed
  if ! command -v confused >/dev/null 2>&1; then
    log_error "Confused tool not found. Please install it with: go install github.com/visma-prodsec/confused@latest"
    discord_send_progress "❌ **Confused tool not found. Please install it first.**"
    exit 1
  fi
  
  # Use token from parameter or environment
  token="${token:-${GITHUB_TOKEN:-}}"
  
  if [[ -z "$token" ]]; then
    log_warn "No GitHub token provided. Using unauthenticated requests (rate limited)"
    discord_send_progress "⚠️ **No GitHub token provided. Using unauthenticated requests**"
  fi
  
  log_info "Fetching repositories for organization: $org"
  discord_send_progress "📦 **Fetching repositories for $org**"
  
  # Fetch repositories using Python script
  local repos_file="$output_dir/repositories.txt"
  if ! python3 "$ROOT_DIR/python/github_dep_scanner.py" "$org" "$token" "$max_repos" > "$repos_file" 2>"$output_dir/github-output.log"; then
    log_error "Failed to fetch repositories for $org"
    discord_send_progress "❌ **Failed to fetch repositories for $org**"
    exit 1
  fi
  
  local repo_count=$(wc -l < "$repos_file")
  log_success "Found $repo_count repositories"
  
  if [[ $repo_count -eq 0 ]]; then
    log_warn "No repositories found for organization: $org"
    discord_send_progress "⚠️ **No repositories found for $org**"
    exit 0
  fi
  
  log_info "Scanning repositories for dependency files..."
  discord_send_progress "🔍 **Scanning $repo_count repositories for dependency files**"
  
  # Scan each repository
  local total_scanned=0
  local total_vulnerable=0
  local vulnerable_repos=()
  
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    
    log_info "Scanning repository: $repo"
    
    # Create repo-specific output directory
    local repo_dir="$output_dir/$(echo "$repo" | tr '/' '-')"
    ensure_dir "$repo_dir"
    
    # Download dependency files for this repository
    if python3 "$ROOT_DIR/python/github_dep_scanner.py" download-files "$repo" "$token" "$repo_dir" > "$repo_dir/download.log" 2>&1; then
      local files_found=$(find "$repo_dir" -name "*.txt" -o -name "*.json" -o -name "*.xml" -o -name "*.lock" | wc -l)
      
      if [[ $files_found -gt 0 ]]; then
        log_success "Found $files_found dependency files in $repo"
        
        # Scan each dependency file with confused
        local repo_vulnerable=false
        
        for dep_file in "$repo_dir"/*.{txt,json,xml,lock}; do
          [[ ! -f "$dep_file" ]] && continue
          
          local filename=$(basename "$dep_file")
          local file_ext="${filename##*.}"
          local language=""
          
          # Determine language based on file extension
          case "$file_ext" in
            txt) language="pip" ;;
            json) 
              if [[ "$filename" == "package.json" ]]; then
                language="npm"
              elif [[ "$filename" == "composer.json" ]]; then
                language="composer"
              else
                continue
              fi
              ;;
            xml) language="mvn" ;;
            lock)
              if [[ "$filename" == "Gemfile.lock" ]]; then
                language="rubygems"
              else
                continue
              fi
              ;;
            *) continue ;;
          esac
          
          log_info "Scanning $filename with confused ($language)"
          
          # Run confused tool
          local confused_output="$repo_dir/confused-${filename%.*}.txt"
          if confused -l "$language" "$dep_file" > "$confused_output" 2>&1; then
            # Check if vulnerabilities were found
            if grep -q "Issues found" "$confused_output"; then
              log_warn "Dependency confusion vulnerabilities found in $repo/$filename"
              repo_vulnerable=true
              total_vulnerable=$((total_vulnerable + 1))
            else
              log_success "No vulnerabilities found in $repo/$filename"
            fi
          else
            log_warn "Failed to scan $repo/$filename with confused"
          fi
        done
        
        if [[ "$repo_vulnerable" == true ]]; then
          vulnerable_repos+=("$repo")
        fi
        
        total_scanned=$((total_scanned + 1))
      else
        log_info "No dependency files found in $repo"
      fi
    else
      log_warn "Failed to download dependency files for $repo"
    fi
    
  done < "$repos_file"
  
  # Generate summary report
  generate_depconfusion_summary "$org" "$output_dir" "$total_scanned" "$total_vulnerable" "${vulnerable_repos[@]}"
  
  # Send results to Discord
  if [[ $total_vulnerable -gt 0 ]]; then
    discord_file "$output_dir/dependency-confusion-summary.txt" "Dependency confusion scan results for $org ($total_vulnerable vulnerabilities found)"
    
    # Send individual vulnerable repo reports
    for repo in "${vulnerable_repos[@]}"; do
      local repo_dir="$output_dir/$(echo "$repo" | tr '/' '-')"
      for report in "$repo_dir"/confused-*.txt; do
        [[ -f "$report" ]] && discord_file "$report" "Dependency confusion report for $repo"
      done
    done
    
    discord_send_progress "⚠️ **Dependency confusion scan completed for $org - Found $total_vulnerable vulnerabilities in ${#vulnerable_repos[@]} repositories**"
  else
    discord_file "$output_dir/dependency-confusion-summary.txt" "Dependency confusion scan results for $org (no vulnerabilities found)"
    discord_send_progress "✅ **Dependency confusion scan completed for $org - No vulnerabilities found**"
  fi
  
  log_success "Dependency confusion scan completed for $org"
}

generate_depconfusion_summary() {
  local org="$1"
  local output_dir="$2"
  local total_scanned="$3"
  local total_vulnerable="$4"
  shift 4
  local vulnerable_repos=("$@")
  
  local summary_file="$output_dir/dependency-confusion-summary.txt"
  
  {
    echo "Dependency Confusion Scan Summary for $org"
    echo "============================================="
    echo "Scan Date: $(date)"
    echo "Organization: $org"
    echo "Total Repositories Scanned: $total_scanned"
    echo "Total Vulnerabilities Found: $total_vulnerable"
    echo ""
    
    if [[ $total_vulnerable -gt 0 ]]; then
      echo "Vulnerable Repositories:"
      echo "======================="
      for repo in "${vulnerable_repos[@]}"; do
        echo "- $repo"
      done
      echo ""
      
      echo "Vulnerability Details:"
      echo "====================="
      for repo in "${vulnerable_repos[@]}"; do
        local repo_dir="$output_dir/$(echo "$repo" | tr '/' '-')"
        echo ""
        echo "Repository: $repo"
        echo "----------------------------------------"
        
        for report in "$repo_dir"/confused-*.txt; do
          if [[ -f "$report" ]]; then
            local filename=$(basename "$report" .txt | sed 's/confused-//')
            echo "File: $filename"
            cat "$report" | grep -A 20 "Issues found" || echo "No detailed output available"
            echo ""
          fi
        done
      done
    else
      echo "No dependency confusion vulnerabilities found."
      echo ""
      echo "This means all package names referenced in dependency files"
      echo "are either available in public repositories or properly secured."
    fi
    
    echo ""
    echo "Scan completed using Confused tool:"
    echo "https://github.com/visma-prodsec/confused"
  } > "$summary_file"
  
  log_info "Generated dependency confusion summary: $summary_file"
}

case "${1:-}" in
  scan) shift; depconfusion_scan "$@" ;;
  *) usage; exit 1;;
esac
