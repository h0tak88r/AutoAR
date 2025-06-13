# autoAr

An automated reconnaissance and vulnerability scanning tool that combines multiple tools for comprehensive web application security assessment, with integrated SQLite storage for findings.

## Features

- Subdomain enumeration using multiple sources and APIs
- SQLite database integration for persistent storage of findings
- Live host detection and technology fingerprinting
- Port scanning
- URL discovery and JavaScript analysis
- Vulnerability scanning with nuclei
- Pattern matching using GF tool for:
  - Debug logic
  - IDOR
  - LFI
  - RCE
  - Redirects
  - SQL Injection
  - SSRF
  - SSTI
  - XSS
  - And more...
- Fuzzing capabilities
- SQL injection scanning
- XSS detection with Dalfox
- JavaScript security analysis
- Subdomain takeover detection
- PUT method scanning
- Discord integration for notifications
- SecurityTrails API integration (optional)
- Company monitoring integration
- JavaScript file monitoring
- Fast reconnaissance mode
- Customizable scan modes

## Setup Instructions

1. **Clone the repository and enter the directory:**
   ```bash
   git clone https://github.com/h0tak88r/autoar.git
   cd autoar
   ```

2. **Run the setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Download regex patterns for secrets detection:**
   ```bash
   mkdir -p regexes
   # Download and place regex patterns from:
   # https://github.com/mazen160/secrets-patterns-db
   # Required patterns:
   # - trufflehog-v3.yaml
   # - nuclei-regexes.yaml
   # - nuclei-generic.yaml
   # - pii-regexes.yaml
   # - risky-regexes.yaml
   # - rules-regexes.yaml
   ```

## Configuration

Create a file named `autoar.yaml` in the project root with the following content:

```yaml
WORDPRESS: []
bevigil: []
binaryedge: []
urlscan: []
bufferoverflow: []
c99: []
censys: []
certspotter: []
chaos: []
chinaz: []
dnsdb: []
fofa: []
fullhunt: []
github: []
intelx: []
passivetotal: []
quake: []
robtex: []
securitytrails: []
shodan: []
threatbook: []
virustotal: []
whoisxmlapi: []
zoomeye: []
zoomeyeapi: []
dnsrepo: []
hunter: []
H1_API_KEY: ""
INTEGRITI_API_KEY: ""
MONGO_URI:  ""
DISCORD_WEBHOOK:  ""
SAVE_TO_DB: true
VERBOSE: true
DB_NAME:  "autoar"
DOMAINS_COLLECTION:  ""
SUBDOMAINS_COLLECTION:  ""
```

- The script will automatically load `autoar.yaml` from the project root
- The `discord.webhook` variable is used for Discord notifications if not set via command line
- `save_to_db` and `verbose` can be set to control database saving and verbosity
- All secrets and API keys should be placed in this file for secure and centralized configuration

## Database Management

The project uses SQLite for data storage. You can manage the database using the `sqlite_db_handler.py` script:

```bash
# Add a domain
./sqlite_db_handler.py add_domain example.com

# Add subdomains from a file
./sqlite_db_handler.py add_subdomains_file example.com subs.txt

# List all domains with stats
./sqlite_db_handler.py list_domains_stats

# Get all subdomains for a domain
./sqlite_db_handler.py get_subdomains example.com

# Manage JS files
./sqlite_db_handler.py add_jsfiles example.com jsfiles.json
./sqlite_db_handler.py list_jsfiles example.com
```

## Usage

### Available Subcommands:

```bash
domain      Full scan mode (customizable with skip flags)
subdomain   Scan a single subdomain
liteScan    Quick scan (subdomains, CNAME, live hosts, URLs, JS, nuclei)
fastLook    Fast look (subenum, live subdomains, collect urls, tech detect, cname checker)
jsMonitor   Monitor JS files for a domain or single subdomain and alert on changes
monitor     Run the Python monitoring script
help        Show help message
```

### Basic Usage:
```bash
./autoAr.sh domain -d example.com
```

### Single Subdomain Scan:
```bash
./autoAr.sh subdomain -s subdomain.example.com
```

### Lite Mode (Quick Scan):
```bash
./autoAr.sh liteScan -d example.com
```

### Fast Look Mode:
```bash
./autoAr.sh fastLook -d example.com
```

### JavaScript Monitoring:
```bash
./autoAr.sh jsMonitor -d example.com
# or for a single subdomain
./autoAr.sh jsMonitor -s sub.example.com
```

### Available Options:
```bash
Options:
    -l, --lite                  Run in lite mode (subdomains, CNAME, live hosts, URLs, JS, nuclei)
    -h, --help                  Show help message
    -d, --domain               Target domain (e.g., example.com)
    -s, --subdomain            Single subdomain to scan (e.g., sub.example.com)
    -v, --verbose              Enable verbose output
    -sp, --skip-port           Skip port scanning
    -sf, --skip-fuzzing        Skip fuzzing scans
    -ss, --skip-sqli           Skip SQL injection scanning
    -sd, --skip-dalfox         Skip Dalfox XSS scanning
    -dw, --discord-webhook     Discord webhook URL for notifications
    -sk, --securitytrails-key  SecurityTrails API key for additional subdomain enumeration
```

## Company Monitoring Integration

AutoAR supports integration with custom company monitoring scripts. You can create your own Python script to monitor specific companies and integrate it with AutoAR. The monitoring script should:

1. Be placed in the project root directory
2. Follow the naming convention `monitor-*.py`
3. Implement Discord webhook integration for notifications
4. Use the configuration from `autoar.yaml`

Example monitoring script structure:
```python
#!/usr/bin/env python3
import requests
import time
import sys
import os
import logging
from bs4 import BeautifulSoup
import json
import argparse

# Use the same config file as AutoAR
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "autoar.yaml")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_discord_webhook():
    # Load from autoar.yaml
    try:
        import yaml
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r") as f:
                config = yaml.safe_load(f)
                return config.get("DISCORD_WEBHOOK")
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return None

def send_discord_message(content):
    webhook_url = get_discord_webhook()
    if not webhook_url:
        logging.error("Discord webhook not configured")
        return
    data = {"content": content}
    try:
        requests.post(webhook_url, json=data)
    except Exception as e:
        logging.error(f"Failed to send Discord message: {e}")

# Your monitoring logic here
def monitor_company():
    # Implement your monitoring logic
    pass

if __name__ == "__main__":
    monitor_company()
```

To use your custom monitoring script:
```bash
./autoAr.sh monitor
# or for specific company
./autoAr.sh monitor -c company_name
# or monitor all companies
./autoAr.sh monitor --all
```

## Output Structure

Results are organized in the following directory structure:
```
results/
└── example.com/
    ├── subs/
    │   ├── all-subs.txt
    │   ├── live-subs.txt
    │   ├── apis-subs.txt
    │   ├── tech-detect.txt
    │   └── cname-records.txt
    ├── urls/
    │   ├── all-urls.txt
    │   └── js-urls.txt
    ├── vulnerabilities/
    │   ├── debug_logic/
    │   ├── idor/
    │   ├── lfi/
    │   ├── rce/
    │   ├── redirect/
    │   ├── sqli/
    │   ├── ssrf/
    │   ├── ssti/
    │   ├── xss/
    │   └── js/
    ├── fuzzing/
    │   ├── ffufGet.txt
    │   └── ffufPost.txt
    └── ports/
        └── ports.txt
```

## JavaScript Analysis

The tool performs comprehensive JavaScript analysis using multiple approaches:
1. URL discovery using URLFinder
2. JavaScript file discovery using JSFinder
3. Secrets detection using multiple regex patterns
4. Endpoint extraction
5. Security vulnerability scanning

## Discord Integration

To enable Discord notifications:
```bash
./autoAr.sh -d example.com -dw "your-discord-webhook-url"
```

The tool will send:
- Discovered subdomains
- Live hosts and technology detection results
- JavaScript analysis results
- Vulnerability findings
- Port scan results
- Fuzzing results
- Company monitoring alerts

## Notes
- All log and status messages appear in your terminal with color and emoji formatting
- Only data files (not log messages) are sent to Discord when webhook is configured
- Keep your regex patterns up to date from [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db)
- For best results, run full scans with all options enabled
- Use lite mode (-l) for quick reconnaissance
- Consider using skip flags for targeted scanning
- SQLite database provides persistent storage of findings
- SecurityTrails API integration enhances subdomain discovery (API key required)
- GF patterns provide efficient vulnerability pattern matching
- Create custom monitoring scripts to track specific companies
- Use the fast look mode for quick initial reconnaissance
- JavaScript monitoring helps track changes in JS files 