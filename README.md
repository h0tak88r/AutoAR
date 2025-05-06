# autoAr

An automated reconnaissance and vulnerability scanning tool that combines multiple tools for comprehensive web application security assessment.

## Features

- Subdomain enumeration using multiple sources
- Live host detection
- Port scanning
- URL discovery and JavaScript analysis
- Vulnerability scanning with nuclei
- Fuzzing capabilities
- SQL injection scanning
- XSS detection
- Parameter discovery
- JavaScript security analysis
- Subdomain takeover detection
- PUT method scanning
- Discord integration for notifications

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
    -l, --lite              Run in lite mode (subdomains, CNAME, live hosts, URLs, JS, nuclei)
    -h, --help             Show help message
    -d, --domain           Target domain (e.g., example.com)
    -s, --subdomain        Single subdomain to scan (e.g., sub.example.com)
    -v, --verbose          Enable verbose output
    -sp, --skip-port       Skip port scanning
    -sf, --skip-fuzzing    Skip fuzzing scans
    -ss, --skip-sqli       Skip SQL injection scanning
    -spx, --skip-paramx    Skip ParamX scanning
    -sd, --skip-dalfox     Skip Dalfox XSS scanning
    -dw, --discord-webhook Discord webhook URL for notifications
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
    │   └── cname-records.txt
    ├── urls/
    │   ├── all-urls.txt
    │   └── js-urls.txt
    ├── vulnerabilities/
    │   ├── xss/
    │   ├── sqli/
    │   ├── ssrf/
    │   ├── ssti/
    │   ├── lfi/
    │   ├── rce/
    │   ├── idor/
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
- Live hosts
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
