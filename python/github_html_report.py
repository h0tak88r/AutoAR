#!/usr/bin/env python3
"""
Generate HTML report from TruffleHog JSON output
"""
import json
import sys
import html
from datetime import datetime
from pathlib import Path


def escape_html(text):
    """Escape HTML special characters"""
    if text is None:
        return "N/A"
    return html.escape(str(text))


def extract_field(secret, *paths, default="N/A"):
    """Extract field from nested JSON structure with fallback paths"""
    for path in paths:
        keys = path.split('.')
        value = secret
        try:
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    value = None
                if value is None:
                    break
            if value is not None and value != "":
                return value
        except (AttributeError, TypeError, KeyError):
            continue
    return default


def generate_html_report(json_file, html_file, repo_name, org_name, secret_count):
    """Generate HTML report from JSON secrets file"""
    
    # Read JSON file
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            secrets = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading JSON file: {e}", file=sys.stderr)
        secrets = []
    
    if not isinstance(secrets, list):
        secrets = []
    
    # HTML template
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Secrets Scan Report - {escape_html(repo_name)}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }}
        .header p {{
            margin: 5px 0;
            font-size: 1.1em;
        }}
        .timestamp {{
            font-style: italic;
            opacity: 0.9;
        }}
        .summary {{
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}
        .summary h2 {{
            color: #667eea;
            margin-top: 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #666;
            margin-top: 5px;
        }}
        .secrets-section {{
            padding: 30px;
        }}
        .secret-item {{
            background: #fff;
            border: 1px solid #e1e5e9;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }}
        .secret-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e1e5e9;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .secret-title {{
            font-weight: bold;
            color: #333;
            font-size: 1.1em;
        }}
        .severity {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }}
        .severity.high {{
            background: #ffebee;
            color: #c62828;
        }}
        .severity.medium {{
            background: #fff3e0;
            color: #ef6c00;
        }}
        .severity.low {{
            background: #e8f5e8;
            color: #2e7d32;
        }}
        .secret-content {{
            padding: 20px;
        }}
        .secret-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }}
        .meta-item {{
            display: flex;
            flex-direction: column;
        }}
        .meta-label {{
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        .meta-value {{
            color: #333;
            word-break: break-all;
        }}
        .secret-value {{
            background: #f8f9fa;
            border: 1px solid #e1e5e9;
            border-radius: 4px;
            padding: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            word-break: break-all;
            margin: 10px 0;
        }}
        .no-secrets {{
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }}
        .no-secrets h3 {{
            color: #2e7d32;
            margin-bottom: 10px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e1e5e9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 GitHub Secrets Scan Report</h1>
            <p>Repository: <strong>{escape_html(repo_name)}</strong></p>
            <p>Organization: <strong>{escape_html(org_name)}</strong></p>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        
        <div class="summary">
            <h2>📊 Scan Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{secret_count}</div>
                    <div class="stat-label">Secrets Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{datetime.now().strftime('%Y-%m-%d')}</div>
                    <div class="stat-label">Scan Date</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">TruffleHog</div>
                    <div class="stat-label">Scanner Used</div>
                </div>
            </div>
        </div>
        
        <div class="secrets-section">
            <h2>🔐 Detected Secrets</h2>
"""
    
    # Generate secret items
    if secret_count > 0 and secrets:
        for secret in secrets:
            if not isinstance(secret, dict):
                continue
            
            # Extract fields with proper fallbacks
            detector_name = extract_field(secret, 'SourceMetadata.DetectorName', 'DetectorName', default='Unknown')
            severity = extract_field(secret, 'SourceMetadata.Severity', 'Severity', default='medium')
            verified = extract_field(secret, 'SourceMetadata.Verified', 'Verified', default='false')
            redacted = extract_field(secret, 'Redacted', default='')
            is_canary = extract_field(secret, 'SourceMetadata.Canary', 'Canary', default='false')
            
            # Extract GitHub-specific metadata
            file_path = extract_field(secret, 
                'SourceMetadata.Data.Github.file', 
                'SourceMetadata.Data.Git.file', 
                'File', 
                default='N/A')
            line_num = extract_field(secret,
                'SourceMetadata.Data.Github.line',
                'SourceMetadata.Data.Git.line',
                'Line',
                default='N/A')
            commit = extract_field(secret,
                'SourceMetadata.Data.Github.commit',
                'SourceMetadata.Data.Git.commit',
                'Commit',
                default='N/A')
            link = extract_field(secret,
                'SourceMetadata.Data.Github.link',
                'SourceMetadata.Data.Git.link',
                'Link',
                default='N/A')
            
            # Skip invalid entries
            if detector_name == 'Unknown' or not detector_name:
                continue
            
            # Escape HTML
            detector_name = escape_html(detector_name)
            file_path = escape_html(file_path)
            line_num = escape_html(line_num)
            commit = escape_html(commit)
            link = escape_html(link)
            redacted = escape_html(redacted)
            
            # Generate HTML for this secret
            html_content += f"""
            <div class="secret-item">
                <div class="secret-header">
                    <div class="secret-title">{detector_name}</div>
                    <div class="severity {severity}">{severity}</div>
                </div>
                <div class="secret-content">
                    <div class="secret-meta">
                        <div class="meta-item"><span class="meta-label">File:</span> <span class="meta-value">{file_path}</span></div>
                        <div class="meta-item"><span class="meta-label">Line:</span> <span class="meta-value">{line_num}</span></div>
                        <div class="meta-item"><span class="meta-label">Commit:</span> <span class="meta-value">{commit}</span></div>
                        <div class="meta-item"><span class="meta-label">Verified:</span> <span class="meta-value">{verified}</span></div>
"""
            
            if is_canary == 'true' or is_canary is True:
                html_content += """                        <div class="meta-item"><span class="meta-label">⚠️ Canary Token:</span> <span class="meta-value">Yes</span></div>
"""
            
            if link != 'N/A' and link != 'null' and link:
                html_content += f"""                        <div class="meta-item"><span class="meta-label">Link:</span> <span class="meta-value"><a href="{link}" target="_blank">View in GitHub</a></span></div>
"""
            
            html_content += """                    </div>
"""
            
            if redacted and redacted != 'null' and redacted != '':
                html_content += f"""                    <div class="secret-value">{redacted}</div>
"""
            
            html_content += """                </div>
            </div>
"""
    else:
        html_content += """            <div class="no-secrets">
                <h3>✅ No Secrets Found</h3>
                <p>Great! No secrets were detected in this repository.</p>
            </div>
"""
    
    # Close HTML
    html_content += f"""        </div>
        
        <div class="footer">
            <p>Generated by AutoAR GitHub Secrets Scanner | Powered by TruffleHog</p>
            <p>Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML file
    try:
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML report generated: {html_file}")
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

