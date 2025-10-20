#!/usr/bin/env python3
"""
GitHub Target Based Wordlist Generator
A Python script to generate wordlists from GitHub organization ignore files
"""

import os
import sys
import json
import requests
import time
import tempfile
from pathlib import Path
from typing import List, Dict, Set
import re

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def load_env():
    """Load environment variables from .env file"""
    env_file = os.path.join(os.path.dirname(__file__), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

def get_github_token():
    """Get GitHub token from environment"""
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print("❌ Error: GITHUB_TOKEN not found in environment")
        sys.exit(1)
    return token

def get_org_repos(org: str, token: str) -> List[str]:
    """Get all repositories for a GitHub organization"""
    print(f"🔍 Fetching repositories for organization: {org}")
    
    repos = []
    page = 1
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    while True:
        url = f"https://api.github.com/orgs/{org}/repos?per_page=100&page={page}&type=all"
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if not data:
                break
                
            for repo in data:
                repos.append(repo['name'])
            
            print(f"📦 Fetched {len(data)} repositories from page {page}")
            page += 1
            
            # Rate limiting
            time.sleep(0.5)
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching repositories: {e}")
            break
    
    print(f"✅ Found {len(repos)} total repositories for {org}")
    return repos

def download_ignore_file(org: str, repo: str, ignore_file: str, token: str) -> str:
    """Download content of an ignore file from a GitHub repository"""
    url = f"https://api.github.com/repos/{org}/{repo}/contents/{ignore_file}"
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3.raw'
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 404:
            return None
        else:
            print(f"⚠️ Warning: HTTP {response.status_code} for {org}/{repo}/{ignore_file}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"⚠️ Warning: Failed to fetch {org}/{repo}/{ignore_file}: {e}")
        return None

def extract_patterns(content: str) -> Set[str]:
    """Extract patterns from ignore file content"""
    patterns = set()
    
    for line in content.split('\n'):
        line = line.strip()
        
        # Skip empty lines and comments
        if not line or line.startswith('#'):
            continue
            
        # Skip negation patterns
        if line.startswith('!'):
            continue
            
        # Clean up the pattern
        pattern = line.strip()
        
        # Add the pattern itself
        patterns.add(pattern)
        
        # Extract variations
        if '/' in pattern:
            # Extract directory names from paths
            parts = pattern.split('/')
            for part in parts:
                if part and not part.startswith('*'):
                    patterns.add(part)
        
        # Extract file extensions
        if '.' in pattern:
            ext = pattern.split('.')[-1]
            if ext and not ext.startswith('*'):
                patterns.add(ext)
        
        # Extract base names from wildcards
        if '*' in pattern:
            base = pattern.replace('*', '').replace('?', '')
            if base:
                patterns.add(base)
    
    return patterns

def generate_wordlist(patterns: Set[str]) -> List[str]:
    """Generate comprehensive wordlist from patterns"""
    wordlist = set()
    
    for pattern in patterns:
        # Add the pattern itself
        wordlist.add(pattern)
        
        # Add variations
        if '/' in pattern:
            parts = pattern.split('/')
            for part in parts:
                if part and not part.startswith('*'):
                    wordlist.add(part)
        
        # Add file extensions
        if '.' in pattern:
            ext = pattern.split('.')[-1]
            if ext and not ext.startswith('*'):
                wordlist.add(ext)
        
        # Add base names
        if '*' in pattern:
            base = pattern.replace('*', '').replace('?', '')
            if base:
                wordlist.add(base)
    
    return sorted(list(wordlist))

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python3 github_wordlist.py <organization>")
        sys.exit(1)
    
    org = sys.argv[1]
    
    # Load environment
    load_env()
    token = get_github_token()
    
    print(f"🚀 Starting GitHub Target Based Wordlist generation for organization: {org}")
    
    # Get repositories
    repos = get_org_repos(org, token)
    if not repos:
        print("❌ No repositories found")
        sys.exit(1)
    
    # Limit to first 20 repositories for performance
    repos = repos[:20]
    print(f"📊 Processing first {len(repos)} repositories")
    
    # Define ignore files to check
    ignore_files = [
        '.gitignore',
        '.eslintignore', 
        '.dockerignore',
        '.npmignore',
        '.prettierignore',
        '.stylelintignore',
        '.eslintrc',
        '.eslintrc.js',
        '.eslintrc.json',
        '.prettierrc',
        '.prettierrc.js',
        '.prettierrc.json',
        '.gitattributes',
        '.editorconfig'
    ]
    
    # Download ignore files and extract patterns
    all_patterns = set()
    processed_repos = 0
    total_files = 0
    
    print(f"📥 Downloading ignore files from {len(repos)} repositories")
    
    for repo in repos:
        print(f"🔍 Processing repository: {repo}")
        repo_patterns = set()
        
        for ignore_file in ignore_files:
            content = download_ignore_file(org, repo, ignore_file, token)
            if content:
                patterns = extract_patterns(content)
                repo_patterns.update(patterns)
                total_files += 1
                print(f"  ✅ Found {ignore_file}")
            
            # Small delay to avoid rate limiting
            time.sleep(0.05)
        
        all_patterns.update(repo_patterns)
        processed_repos += 1
        
        if processed_repos % 5 == 0:
            print(f"📊 Processed {processed_repos}/{len(repos)} repositories, found {total_files} ignore files")
    
    print(f"✅ Downloaded {total_files} ignore files from {processed_repos} repositories")
    
    # Generate wordlist
    print("🔧 Generating wordlist from patterns...")
    wordlist = generate_wordlist(all_patterns)
    
    # Create output directory
    output_dir = Path(f"new-results/github-{org}/wordlists")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save patterns and wordlist
    patterns_file = output_dir / "github-patterns.txt"
    wordlist_file = output_dir / "github-wordlist.txt"
    
    with open(patterns_file, 'w') as f:
        for pattern in sorted(all_patterns):
            f.write(f"{pattern}\n")
    
    with open(wordlist_file, 'w') as f:
        for word in wordlist:
            f.write(f"{word}\n")
    
    print(f"✅ Generated wordlist with {len(wordlist)} unique words")
    print(f"📁 Patterns saved to: {patterns_file}")
    print(f"📁 Wordlist saved to: {wordlist_file}")
    
    # Send to Discord using shell command
    try:
        print("📤 Sending results to Discord...")
        
        # Use the shell discord_file function
        import subprocess
        
        # Send patterns file
        cmd1 = f'bash -c "cd {os.path.dirname(__file__)} && source lib/discord.sh && discord_file \\"{patterns_file}\\" \\"GitHub patterns for {org} ({len(all_patterns)} patterns from {total_files} files)\\""'
        subprocess.run(cmd1, shell=True, check=True)
        
        # Send wordlist file
        cmd2 = f'bash -c "cd {os.path.dirname(__file__)} && source lib/discord.sh && discord_file \\"{wordlist_file}\\" \\"GitHub wordlist for {org} ({len(wordlist)} words)\\""'
        subprocess.run(cmd2, shell=True, check=True)
        
        print("✅ Results sent to Discord")
        
    except Exception as e:
        print(f"⚠️ Discord integration failed: {e}")
        print("📁 Files saved locally")
    
    print("🎉 GitHub Target Based Wordlist generation completed!")

if __name__ == "__main__":
    main()
