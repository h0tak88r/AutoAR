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
api_keys:
  securitytrails: ""
  ywh: ""
  h1_token: ""
  h1_username: "0x88"

discord:
  webhook: ""

tool_config:
  save_to_db: true
  verbose: true
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

### Basic Usage:
```bash
./autoAr.sh -d example.com
```

### Single Subdomain Scan:
```bash
./autoAr.sh -s subdomain.example.com
```

### Lite Mode (Quick Scan):
```bash
./autoAr.sh -d example.com -l
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