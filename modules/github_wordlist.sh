#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/lib/logging.sh"
source "$ROOT_DIR/lib/utils.sh"
source "$ROOT_DIR/lib/discord.sh"

usage() { echo "Usage: github_wordlist scan -o <github_org> [-t <github_token>]"; }

# Check if GitHub token is available
check_github_token() {
  local token="$1"
  if [[ -z "$token" ]]; then
    log_error "GitHub token is required. Set GITHUB_TOKEN environment variable or use -t flag"
    return 1
  fi
  return 0
}

# Get all repositories for a GitHub organization
get_org_repos() {
  local org="$1"
  local token="$2"
  local page=1
  local repos_file=$(mktemp)
  
  log_info "Fetching repositories for GitHub organization: $org"
  
  while true; do
    local url="https://api.github.com/orgs/$org/repos?per_page=100&page=$page&type=all"
    local response=$(curl -s -H "Authorization: token $token" \
                          -H "Accept: application/vnd.github.v3+json" \
                          "$url" 2>/dev/null)
    
    if [[ $? -ne 0 ]]; then
      log_error "Failed to fetch repositories from GitHub API"
      rm -f "$repos_file"
      return 1
    fi
    
    # Check if we got any repositories
    local repo_count=$(echo "$response" | grep -c '"name"' 2>/dev/null || echo "0")
    if [[ "$repo_count" -eq 0 ]]; then
      break
    fi
    
    # Extract repository names
    echo "$response" | grep '"name"' | sed 's/.*"name": *"\([^"]*\)".*/\1/' >> "$repos_file"
    
    log_info "Fetched $repo_count repositories from page $page"
    ((page++))
    
    # Rate limiting - small delay between requests
    sleep 0.5
  done
  
  local total_repos=$(wc -l < "$repos_file" 2>/dev/null || echo "0")
  log_success "Found $total_repos total repositories for $org"
  
  echo "$repos_file"
}

# Download ignore files from a repository
download_ignore_files() {
  local org="$1"
  local repo="$2"
  local token="$3"
  local output_dir="$4"
  
  # List of ignore files to look for
  local ignore_files=(
    ".gitignore"
    ".eslintignore"
    ".dockerignore"
    ".npmignore"
    ".prettierignore"
    ".stylelintignore"
    ".coverageignore"
    ".nycrc"
    ".eslintrc"
    ".eslintrc.js"
    ".eslintrc.json"
    ".eslintrc.yml"
    ".eslintrc.yaml"
    ".prettierrc"
    ".prettierrc.js"
    ".prettierrc.json"
    ".prettierrc.yml"
    ".prettierrc.yaml"
    ".stylelintrc"
    ".stylelintrc.js"
    ".stylelintrc.json"
    ".stylelintrc.yml"
    ".stylelintrc.yaml"
    ".dockerignore"
    ".babelignore"
    ".flowconfig"
    ".gitattributes"
    ".hgignore"
    ".svnignore"
    ".bzrignore"
    ".darcsignore"
    ".fossilignore"
    ".monotoneignore"
    ".pijulignore"
    ".jshintignore"
    ".jscsrc"
    ".jscs.json"
    ".editorconfig"
    ".gitmodules"
    ".gitkeep"
    ".gitattributes"
    ".htaccess"
    ".htpasswd"
    ".env.example"
    ".env.template"
    ".env.local.example"
    ".env.development.example"
    ".env.production.example"
    ".env.staging.example"
    ".env.test.example"
  )
  
  local found_files=0
  
  for ignore_file in "${ignore_files[@]}"; do
    local url="https://api.github.com/repos/$org/$repo/contents/$ignore_file"
    local response=$(curl -s -H "Authorization: token $token" \
                          -H "Accept: application/vnd.github.v3+json" \
                          "$url" 2>/dev/null)
    
    if echo "$response" | grep -q '"type": "file"'; then
      # File exists, download it
      local download_url=$(echo "$response" | grep '"download_url"' | sed 's/.*"download_url": *"\([^"]*\)".*/\1/')
      
      if [[ -n "$download_url" ]]; then
        local file_content=$(curl -s "$download_url" 2>/dev/null)
        if [[ -n "$file_content" ]]; then
          echo "$file_content" > "$output_dir/${repo}_${ignore_file}"
          ((found_files++))
        fi
      fi
    fi
    
    # Small delay to avoid rate limiting
    sleep 0.1
  done
  
  echo "$found_files"
}

# Extract patterns from ignore files
extract_patterns() {
  local input_dir="$1"
  local output_file="$2"
  
  log_info "Extracting patterns from ignore files"
  
  > "$output_file"
  
  for file in "$input_dir"/*; do
    if [[ -f "$file" ]]; then
      # Extract various types of patterns
      # 1. Direct file/directory names
      grep -v '^#' "$file" | grep -v '^$' | grep -v '^!' | \
      sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | \
      grep -v '^$' >> "$output_file"
      
      # 2. Extract from comments (sometimes patterns are in comments)
      grep '^#' "$file" | sed 's/^#[[:space:]]*//' | \
      grep -E '^[a-zA-Z0-9_./-]+' >> "$output_file"
      
      # 3. Extract from complex patterns (remove wildcards for base patterns)
      grep -v '^#' "$file" | grep -v '^$' | grep -v '^!' | \
      sed 's/\*//g' | sed 's/\?//g' | sed 's/\[.*\]//g' | \
      sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | \
      grep -E '^[a-zA-Z0-9_./-]+$' >> "$output_file"
    fi
  done
  
  # Clean up and deduplicate
  sort -u "$output_file" > "${output_file}.tmp"
  mv "${output_file}.tmp" "$output_file"
  
  local pattern_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
  log_success "Extracted $pattern_count unique patterns"
}

# Generate wordlist from patterns
generate_wordlist() {
  local patterns_file="$1"
  local output_file="$2"
  
  log_info "Generating comprehensive wordlist from patterns"
  
  > "$output_file"
  
  while IFS= read -r pattern; do
    [[ -z "$pattern" ]] && continue
    
    # Add the pattern itself
    echo "$pattern" >> "$output_file"
    
    # Add variations
    if [[ "$pattern" == *"/"* ]]; then
      # Extract directory names from paths
      echo "$pattern" | cut -d'/' -f1 >> "$output_file"
      echo "$pattern" | cut -d'/' -f2 >> "$output_file" 2>/dev/null || true
      echo "$pattern" | cut -d'/' -f3 >> "$output_file" 2>/dev/null || true
    fi
    
    # Add file extensions
    if [[ "$pattern" == *"."* ]]; then
      echo "$pattern" | sed 's/.*\.//' >> "$output_file"
    fi
    
    # Add base names (without extensions)
    if [[ "$pattern" == *"."* ]]; then
      echo "$pattern" | sed 's/\.[^.]*$//' >> "$output_file"
    fi
    
  done < "$patterns_file"
  
  # Clean up and deduplicate
  sort -u "$output_file" > "${output_file}.tmp"
  mv "${output_file}.tmp" "$output_file"
  
  local wordlist_count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
  log_success "Generated $wordlist_count unique words for wordlist"
}

github_wordlist_scan() {
  local org="" token=""; while [[ $# -gt 0 ]]; do
    case "$1" in
      -o|--org) org="$2"; shift 2;;
      -t|--token) token="$2"; shift 2;;
      *) usage; exit 1;;
    esac
  done
  
  [[ -z "$org" ]] && { usage; exit 1; }
  
  # Use token from parameter or environment variable
  token="${token:-${GITHUB_TOKEN:-}}"
  check_github_token "$token" || exit 1
  
  local dir="$(results_dir "github-$org")"
  local base="$dir/wordlists"
  ensure_dir "$base"
  
  log_info "Starting GitHub Target Based Wordlist generation for organization: $org"
  discord_send_progress "🔍 **Generating GitHub wordlist for organization: $org**"
  
  # Get all repositories
  local repos_file=$(get_org_repos "$org" "$token")
  if [[ $? -ne 0 ]]; then
    log_error "Failed to fetch repositories"
    exit 1
  fi
  
  local total_repos=$(wc -l < "$repos_file" 2>/dev/null || echo "0")
  if [[ "$total_repos" -eq 0 ]]; then
    log_warn "No repositories found for organization: $org"
    discord_send_progress "⚠️ **No repositories found for organization: $org**"
    rm -f "$repos_file"
    exit 1
  fi
  
  # Create temporary directory for ignore files
  local temp_dir=$(mktemp -d)
  local processed_repos=0
  local total_ignore_files=0
  
  log_info "Downloading ignore files from $total_repos repositories"
  
  # Download ignore files from each repository
  while IFS= read -r repo; do
    [[ -z "$repo" ]] && continue
    
    log_info "Processing repository: $repo"
    local found_files=$(download_ignore_files "$org" "$repo" "$token" "$temp_dir")
    total_ignore_files=$((total_ignore_files + found_files))
    ((processed_repos++))
    
    # Progress update every 10 repositories
    if [[ $((processed_repos % 10)) -eq 0 ]]; then
      discord_send_progress "🔄 **Processed $processed_repos/$total_repos repositories, found $total_ignore_files ignore files**"
    fi
    
  done < "$repos_file"
  
  # Clean up repositories file
  rm -f "$repos_file"
  
  log_success "Downloaded $total_ignore_files ignore files from $processed_repos repositories"
  
  if [[ "$total_ignore_files" -eq 0 ]]; then
    log_warn "No ignore files found in any repositories"
    discord_send_progress "⚠️ **No ignore files found in repositories for organization: $org**"
    rm -rf "$temp_dir"
    exit 1
  fi
  
  # Extract patterns and generate wordlist
  local patterns_file="$base/github-patterns.txt"
  local wordlist_file="$base/github-wordlist.txt"
  
  extract_patterns "$temp_dir" "$patterns_file"
  generate_wordlist "$patterns_file" "$wordlist_file"
  
  # Clean up temporary directory
  rm -rf "$temp_dir"
  
  # Send results to Discord
  local pattern_count=$(wc -l < "$patterns_file" 2>/dev/null || echo "0")
  local wordlist_count=$(wc -l < "$wordlist_file" 2>/dev/null || echo "0")
  
  log_success "GitHub wordlist generation completed"
  log_info "Organization: $org"
  log_info "Repositories processed: $processed_repos"
  log_info "Ignore files found: $total_ignore_files"
  log_info "Unique patterns extracted: $pattern_count"
  log_info "Wordlist entries generated: $wordlist_count"
  
  # Send files to Discord
  discord_file "$patterns_file" "GitHub ignore patterns for $org ($pattern_count patterns from $processed_repos repos)"
  discord_file "$wordlist_file" "GitHub target wordlist for $org ($wordlist_count words)"
  
  discord_send_progress "✅ **GitHub wordlist generation completed for $org**"
}

case "${1:-}" in
  scan) shift; github_wordlist_scan "$@" ;;
  *) usage; exit 1;;
esac
