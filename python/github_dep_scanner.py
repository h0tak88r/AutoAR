#!/usr/bin/env python3
"""
GitHub Dependency File Scanner
Downloads dependency files from GitHub repositories for dependency confusion scanning
"""

import os
import sys
import requests
import json
import time
from pathlib import Path
from typing import List, Dict, Optional

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def load_env():
    """Load environment variables from .env file"""
    env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

def get_github_token() -> Optional[str]:
    """Get GitHub token from environment or command line"""
    return os.environ.get('GITHUB_TOKEN')

def get_org_repos(org: str, token: Optional[str], max_repos: int = 50) -> List[str]:
    """Fetch all repositories for a GitHub organization"""
    print(f"🔍 Fetching repositories for organization: {org}", file=sys.stderr)
    
    headers = {}
    if token:
        headers['Authorization'] = f'token {token}'
    
    repos = []
    page = 1
    per_page = min(100, max_repos)
    
    while len(repos) < max_repos:
        url = f"https://api.github.com/orgs/{org}/repos"
        params = {
            'page': page,
            'per_page': per_page,
            'sort': 'updated',
            'direction': 'desc'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 401:
                print("❌ Error: Bad credentials. Please check your GitHub token.")
                sys.exit(1)
            elif response.status_code == 404:
                print(f"❌ Error: Organization '{org}' not found.")
                sys.exit(1)
            elif response.status_code == 403:
                print("❌ Error: Rate limit exceeded. Please wait or use a token.")
                sys.exit(1)
            elif response.status_code != 200:
                print(f"❌ Error fetching repositories: {response.status_code}")
                sys.exit(1)
            
            data = response.json()
            
            if not data:
                break
            
            for repo in data:
                if len(repos) >= max_repos:
                    break
                repos.append(repo['full_name'])
            
            print(f"📦 Fetched {len(data)} repositories from page {page}", file=sys.stderr)
            
            if len(data) < per_page:
                break
            
            page += 1
            
            # Rate limiting
            if not token:
                time.sleep(1)
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching repositories: {e}", file=sys.stderr)
            sys.exit(1)
    
    print(f"✅ Found {len(repos)} total repositories for {org}", file=sys.stderr)
    return repos[:max_repos]

def download_dependency_files(repo: str, token: Optional[str], output_dir: str) -> bool:
    """Download dependency files from a GitHub repository"""
    print(f"📥 Downloading dependency files from {repo}", file=sys.stderr)
    
    headers = {}
    if token:
        headers['Authorization'] = f'token {token}'
    
    # List of dependency files to look for
    dependency_files = [
        'requirements.txt',
        'package.json',
        'composer.json',
        'pom.xml',
        'Gemfile.lock',
        'yarn.lock',
        'package-lock.json',
        'Pipfile',
        'Pipfile.lock',
        'go.mod',
        'go.sum',
        'Cargo.toml',
        'Cargo.lock'
    ]
    
    downloaded_files = []
    
    for filename in dependency_files:
        url = f"https://raw.githubusercontent.com/{repo}/main/{filename}"
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                # Save the file
                file_path = os.path.join(output_dir, filename)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                downloaded_files.append(filename)
                print(f"  ✅ Downloaded {filename}", file=sys.stderr)
            elif response.status_code == 404:
                # Try other branches
                for branch in ['master', 'develop', 'dev']:
                    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{filename}"
                    try:
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            file_path = os.path.join(output_dir, filename)
                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(response.text)
                            downloaded_files.append(filename)
                            print(f"  ✅ Downloaded {filename} from {branch} branch", file=sys.stderr)
                            break
                    except requests.exceptions.RequestException:
                        continue
            elif response.status_code == 403:
                print(f"  ⚠️ Rate limited for {filename}", file=sys.stderr)
                time.sleep(2)
            else:
                print(f"  ❌ Failed to download {filename}: {response.status_code}", file=sys.stderr)
                
        except requests.exceptions.RequestException as e:
            print(f"  ❌ Error downloading {filename}: {e}", file=sys.stderr)
    
    if downloaded_files:
        print(f"📁 Downloaded {len(downloaded_files)} dependency files from {repo}", file=sys.stderr)
        return True
    else:
        print(f"⚠️ No dependency files found in {repo}", file=sys.stderr)
        return False

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print("  python3 github_dep_scanner.py <org> [token] [max_repos]", file=sys.stderr)
        print("  python3 github_dep_scanner.py download-files <repo> [token] <output_dir>", file=sys.stderr)
        sys.exit(1)
    
    # Load environment
    load_env()
    
    if sys.argv[1] == "download-files":
        # Download files for a specific repository
        if len(sys.argv) < 5:
            print("Usage: python3 github_dep_scanner.py download-files <repo> [token] <output_dir>", file=sys.stderr)
            sys.exit(1)
        
        repo = sys.argv[2]
        token = sys.argv[3] if len(sys.argv) > 4 else get_github_token()
        output_dir = sys.argv[4] if len(sys.argv) > 4 else sys.argv[3]
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        success = download_dependency_files(repo, token, output_dir)
        sys.exit(0 if success else 1)
    
    else:
        # Fetch repositories for an organization
        org = sys.argv[1]
        token = sys.argv[2] if len(sys.argv) > 2 else get_github_token()
        max_repos = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        
        print(f"🚀 Starting GitHub dependency scanner for organization: {org}", file=sys.stderr)
        
        repos = get_org_repos(org, token, max_repos)
        
        # Output repositories to stdout (for shell script to read)
        for repo in repos:
            print(repo)
        
        print(f"🎉 Found {len(repos)} repositories for {org}", file=sys.stderr)

if __name__ == "__main__":
    main()
