# autoAr - Automated Attack and Reconnaissance Tool

```
 ▗▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▖  ▗▄▖ ▗▄▄▖ 
▐▌ ▐▌▐▌ ▐▌  █ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌
▐▛▀▜▌▐▌ ▐▌  █ ▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖
▐▌ ▐▌▝▚▄▞▘  █ ▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌
                              By: h0tak88r
```

autoAr is a comprehensive automated reconnaissance and vulnerability scanning tool designed for security researchers and penetration testers. It combines multiple security tools to perform thorough domain analysis and vulnerability assessment.

## Features

- Subdomain Enumeration
- URL Discovery and Analysis
- Port Scanning
- Parameter Discovery and Analysis
- JavaScript File Analysis
- Vulnerability Scanning
- Discord Integration for Notifications
- Customizable Scanning Options

## Prerequisites

The following tools need to be installed:

- subfinder
- httpx
- waymore
- subov88r
- nuclei
- naabu
- kxss
- qsreplace
- paramx
- dalfox
- ffuf
- interlace
- urldedupe

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd autoAr
```

2. Install required tools:
```bash
# Example installation commands for some tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/cyinnove/paramx/cmd/paramx@latest
# ... Install other required tools
```

3. Make the script executable:
```bash
chmod +x autoAr.sh
```

## Usage

Basic usage:
```bash
./autoAr.sh -d example.com
```

### Options

- `-d DOMAIN` : Single target domain
- `-l FILE` : File containing list of domains
- `-s SUBDOMAIN` : Single subdomain to scan
- `-w WEBHOOK` : Discord webhook URL for notifications
- `-o DIR` : Output directory (default: results)
- `-t DIR` : ParamX templates directory (default: paramx-templates)
- `-v` : Verbose output
- `--skip-ports` : Skip port scanning
- `--skip-fuzz` : Skip fuzzing
- `--skip-sqli` : Skip SQL injection scanning
- `--skip-paramx` : Skip ParamX scanning

### Examples

1. Scan a single domain:
```bash
./autoAr.sh -d example.com
```

2. Scan multiple domains from a file:
```bash
./autoAr.sh -l domains.txt -w https://discord.webhook.url
```

3. Scan with specific options:
```bash
./autoAr.sh -d example.com -s sub.example.com --skip-ports --skip-sqli
```

4. Use custom ParamX templates:
```bash
./autoAr.sh -d example.com -t /path/to/paramx/templates
```

## Output Structure

Results are organized in the following directory structure:
```
results/
└── domain.com/
    ├── subs/
    ├── urls/
    ├── vulnerabilities/
    │   ├── xss/
    │   ├── sqli/
    │   ├── ssrf/
    │   ├── ssti/
    │   ├── lfi/
    │   ├── rce/
    │   └── idor/
    ├── fuzzing/
    └── ports/
```

## Features in Detail

1. **Subdomain Enumeration**
   - Uses multiple tools and sources
   - Includes passive and active enumeration
   - Subdomain takeover checks

2. **URL Discovery**
   - Crawls and discovers URLs
   - Filters live endpoints
   - Organizes by functionality

3. **Vulnerability Scanning**
   - XSS Detection
   - SQL Injection
   - SSRF
   - Template Injection
   - Local File Inclusion
   - Remote Code Execution
   - IDOR

4. **JavaScript Analysis**
   - Extracts JavaScript files
   - Analyzes for sensitive information
   - Checks for potential vulnerabilities

5. **Reporting**
   - Organized output structure
   - Discord notifications
   - Detailed logging

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

Created by h0tak88r

## License

This project is licensed under the MIT License - see the LICENSE file for details
