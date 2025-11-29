#!/usr/bin/env python3
"""
Generate HTML report from TruffleHog JSON output
Uses the new secrets parser for better extraction and duplicate removal
"""
import sys
from pathlib import Path

# Import the new parser
sys.path.insert(0, str(Path(__file__).parent))
from github_secrets_parser import parse_secrets, remove_duplicates, generate_html_table, SecretFinding


def generate_html_report(json_file, html_file, repo_name, org_name, secret_count):
    """Generate HTML report from JSON secrets file using the new parser"""
    
    # Use the new parser to extract and deduplicate secrets
    findings = parse_secrets(json_file)
    unique_findings = remove_duplicates(findings)
    
    # Generate HTML table using the new parser
    html_content = generate_html_table(unique_findings, repo_name, org_name)
    
    # Write HTML file
    try:
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report generated: {html_file} (found {len(unique_findings)} unique secrets)")
        return 0
    except Exception as e:
        print(f"Error writing HTML file: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    if len(sys.argv) != 6:
        print(f"Usage: {sys.argv[0]} <json_file> <html_file> <repo_name> <org_name> <secret_count>", file=sys.stderr)
        sys.exit(1)
    
    json_file = sys.argv[1]
    html_file = sys.argv[2]
    repo_name = sys.argv[3]
    org_name = sys.argv[4]
    secret_count = int(sys.argv[5])
    
    sys.exit(generate_html_report(json_file, html_file, repo_name, org_name, secret_count))

