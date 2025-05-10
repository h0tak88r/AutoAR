#!/usr/bin/env python3

import sys
import tldextract
import re
from typing import Set, List

def should_skip_line(line: str) -> bool:
    """Check if a line should be skipped based on various criteria."""
    # Skip empty lines or comments
    if not line or line.startswith('#'):
        return True
        
    # Skip common non-domain entries
    skip_patterns = [
        r'^https://play\.google\.com',  # Google Play links
        r'^https://apps\.apple\.com',   # App Store links
        r'^https://github\.com',        # GitHub links
        r'^https://itunes\.apple\.com', # iTunes links
        r'Backend related to',          # Description lines
        r'Device:',                     # Device descriptions
        r'Special scenarios',           # Documentation lines
        r'Source Code',                 # Documentation lines
        r'System Specification',        # Documentation lines
        r'Native K8S',                  # Technical descriptions
        r'OIDC-based',                 # Technical descriptions
        r'Hardware found',             # Hardware descriptions
        r'GitLab and GitHub',          # Repository references
        r'In-Scope',                   # Scope descriptions
        r'Specific scenarios',         # Documentation
        r'Core Product',               # Product descriptions
        r'Software packages',          # Package descriptions
        r'buffered-reader',           # Package names
        r'cargo-',                    # Package prefixes
        r'\.apk$',                    # APK files
        r'\.ipa$',                    # IPA files
    ]
    
    for pattern in skip_patterns:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    
    return False

def is_valid_domain(domain: str) -> bool:
    """Validate if a string is a valid domain name."""
    if not domain or len(domain) < 4:
        return False
    if not "." in domain:
        return False
    
    # Skip invalid TLDs
    invalid_tlds = {'apk', 'ipa', 'exe', 'js', 'php', 'html', 'aspx'}
    if domain.split('.')[-1].lower() in invalid_tlds:
        return False
        
    # Basic domain validation regex
    pattern = r"^[a-z0-9][a-z0-9-]*[a-z0-9]\.[a-z]{2,}$"
    return bool(re.match(pattern, domain))

def extract_domains(input_lines: List[str]) -> Set[str]:
    """Extract valid domain names from a list of URLs or domain strings."""
    domains = set()
    invalid_entries = {
        "js", "js's", "com", "net", "org", "x", "fd", 
        "au)", "th)", "tr)", "ua)", "ua))", "{fd"
    }
    
    for line in input_lines:
        try:
            line = line.strip().lower()
            
            # Skip invalid or non-domain lines
            if not line or line in invalid_entries or should_skip_line(line):
                continue
            
            # Handle wildcard domains
            if line.startswith('*.'):
                line = line[2:]
            
            # Handle URL patterns
            if "//" in line:
                line = line.split("//")[-1].split("/")[0]
            
            # Handle domain patterns like (com|se|ee|dk)
            if line.startswith('(') and line.endswith(')'):
                continue
                
            # Extract domain
            ext = tldextract.extract(line)
            if ext.domain and ext.suffix:
                domain = f"{ext.domain}.{ext.suffix}"
                if is_valid_domain(domain):
                    domains.add(domain)
        except Exception as e:
            continue
    
    return domains

def main():
    """Main function to process input from stdin and output domains to stdout."""
    try:
        input_lines = sys.stdin.readlines()
        domains = extract_domains(input_lines)
        
        # Output sorted domains
        for domain in sorted(domains):
            print(domain)
            
    except Exception as e:
        sys.stderr.write(f"Error: {str(e)}\n")
        sys.exit(1)

if __name__ == "__main__":
    main() 