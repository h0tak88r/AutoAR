# AutoAR (Automated Attack Reconnaissance) 🚀
 
AutoAR is a comprehensive, modular security automation toolkit designed for bug bounty hunters, penetration testers, and security researchers. It provides **three operational modes**: Discord bot, REST API, or both simultaneously, powered by a **pure Go implementation** that orchestrates automated reconnaissance, vulnerability scanning, and attack surface analysis.

## ✨ Features

### 🔍 **Reconnaissance & Discovery**
- **Subdomain Enumeration**: Multiple engines (Subfinder, Amass, Assetfinder, etc.)
- **Live Host Detection**: Fast HTTP/HTTPS validation with custom timeouts
- **CNAME Analysis**: CNAME record extraction and analysis
- **URL Collection**: Comprehensive URL gathering from multiple sources
- **Technology Detection**: Web technology stack identification
- **DNS Takeover Detection**: Comprehensive DNS takeover vulnerability scanning

### 🛡️ **Vulnerability Scanning**
- **Nuclei Integration**: 1000+ vulnerability templates with custom rate limiting
- **React2Shell Scanner**: React Server Components RCE detection (CVE-2025-55182) with WAF bypass methods, source code exposure checks, and DoS testing
- **WordPress Plugin Confusion**: Automated WP plugin/theme confusion attack detection
- **Dependency Confusion**: GitHub repository dependency confusion scanning
- **S3 Bucket Enumeration**: AWS S3 bucket discovery and analysis (pure Go via AWS SDK v2, no aws CLI required)
- **SQL Injection Testing**: SQLMap integration for automated SQLi testing
- **XSS Detection**: Dalfox integration for cross-site scripting detection
- **Backup File Discovery**: Automated backup file and sensitive file discovery

### 🎯 **Specialized Scanners**
- **JavaScript Analysis**: JS file collection and secret extraction
- **JavaScript Monitoring**: Continuous monitoring of JavaScript files for changes
- **GitHub Reconnaissance**: Organization and repository scanning with secrets detection
- **GitHub Wordlist Generation**: Automated wordlist creation from organization files
- **Port Scanning**: Nmap integration for port discovery
- **Reflection Testing**: HTTP parameter reflection analysis
- **Gf Pattern Matching**: Custom pattern matching for various vulnerabilities
- **KeyHack API Key Validation**: 778+ API key validation templates for testing and validating discovered keys

### 📊 **Monitoring & Tracking**
- **Target Monitoring**: Database-backed continuous monitoring of web targets
- **JavaScript Monitoring**: Track changes in JavaScript files and detect new secrets
- **Multi-Strategy Detection**: Support for hash, size, headers, and regex-based change detection
- **Update Notifications**: Real-time Discord webhooks for detected changes
- **Persistent State Management**: Database storage for monitored targets and events
- **Flexible Intervals**: Configurable monitoring intervals per target
- **Daemon Mode**: Background monitoring with automated restarts

### 🤖 **Multi-Interface Support**
- **Discord Bot Mode**: Interactive bot with slash commands and real-time notifications
- **REST API Mode**: Full-featured API with Swagger/OpenAPI documentation
- **Hybrid Mode**: Run both Discord bot and API server simultaneously
- **Real-time Notifications**: Live scan progress and results (Discord)
- **File Sharing**: Automatic result file uploads
- **API Documentation**: Interactive API docs at `/docs` endpoint
- **Async Scanning**: Background scan execution with status tracking
- **Progress Tracking**: Real-time scan status updates across both interfaces

### 🗄️ **Database Support**
- **PostgreSQL Integration**: Full database support for results storage
- **SQLite Fallback**: Lightweight database option
- **Data Export**: Easy data export and analysis
- **Result Management**: Organized result storage and retrieval

### ⚡ **Performance & Threading**
- **Configurable Threading**: All scanning tools support custom thread counts (default: 100)
- **Parallel Processing**: Optimized for multi-core systems with concurrent operations
- **Resource Management**: Intelligent thread allocation based on tool capabilities
- **Performance Tuning**: Easy adjustment of thread counts via Discord commands or CLI flags

**Supported Tools with Threading:**
- **Subdomain Enumeration**: Subfinder with configurable thread pools
- **Live Host Detection**: Httpx with parallel HTTP probing
- **Vulnerability Scanning**: Nuclei with concurrent template execution
- **Port Scanning**: Naabu with high-speed parallel port discovery
- **XSS Detection**: Dalfox with concurrent payload testing
- **SQL Injection Testing**: SQLMap with Interlace for parallel testing
- **Technology Detection**: Httpx with parallel technology fingerprinting
- **URL Collection**: Urlfinder and JSFinder with concurrent crawling
- **Backup File Discovery**: Fuzzuli with parallel backup file enumeration

## 🚀 Quick Start

### Docker Compose (Recommended)

1. **Clone the repository**:
```bash
git clone https://github.com/h0tak88r/AutoAR.git
cd AutoAR
```

2. **Set up environment variables**:
```bash
cp env.example .env
# Edit .env with your configuration
```

3. **Required Environment Variables**:
```bash
DISCORD_BOT_TOKEN=your_discord_bot_token
DISCORD_WEBHOOK=your_discord_webhook_url
```

4. **Optional API Keys** (for enhanced functionality):
```bash
SECURITYTRAILS_API_KEY=your_key
SHODAN_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
GITHUB_TOKEN=your_token
# ... and many more (see docker-compose.yml for full list)
```

5. **Build and run**:
```bash
docker compose build
docker compose up -d
```

6. **Verify installation**:
```bash
docker logs autoar-discord
```

### Manual Installation

1. **Install Go** (1.23 or later):
```bash
# Install Go from https://golang.org/dl/
# Or use package manager
sudo apt install golang-go  # Ubuntu/Debian
```

2. **Install security tools**  
Only required if you run AutoAR **directly on your host**.  
The official Docker images install these automatically.  
Most scanners are still invoked as external binaries; several tools like `next88`, `apkX`,
`confused2`, `fuzzuli`, `dalfox`, `gf`, `urlfinder`, `jsfinder`, `kxss`, `naabu`, `misconfig-mapper`,
and the JWT engine (`jwthack`) are embedded as Go libraries and do **not** need separate installation.
```bash
# Go-based tools (external binaries AutoAR still calls via CLI)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# System packages (for Naabu/pcap when building locally on Linux)
sudo apt-get update && sudo apt-get install -y libpcap-dev

# Decompiler used by embedded apkX engine
curl -L "https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip" -o /tmp/jadx.zip
sudo mkdir -p /opt/jadx
sudo unzip -q /tmp/jadx.zip -d /opt/jadx
sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
rm /tmp/jadx.zip
```

**Note on AWS integration**

- S3 enumeration and scanning are implemented in pure Go using **AWS SDK for Go v2**.  
- You **do not** need the `aws` CLI; just configure standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or IAM role / shared config).

3. **Build AutoAR**:
```bash
# Clone repository
git clone https://github.com/h0tak88r/AutoAR.git
cd AutoAR

# Build the binary
go build -o autoar ./cmd/autoar

# Or install globally
go install ./cmd/autoar
```

4. **Configure and run**:
```bash
# Set up environment
cp env.example .env
# Edit .env with your configuration

# Run AutoAR
export AUTOAR_MODE=discord
export DISCORD_BOT_TOKEN=your_token_here
./autoar bot  # Start Discord bot
# or
./autoar api  # Start REST API
# or
./autoar both # Start both
```

## 📖 Usage

### CLI Commands

AutoAR provides a unified **pure Go CLI** (`autoar`) with all functionality implemented in Go:

```bash
# Basic usage
autoar <command> <action> [options]

# Examples
autoar subdomains get -d example.com
autoar livehosts get -d example.com -t 100
autoar cnames get -d example.com
autoar urls collect -d example.com
autoar nuclei run -d example.com -m full
autoar reflection scan -d example.com
autoar dalfox run -d example.com
autoar sqlmap run -d example.com
autoar ports scan -d example.com
autoar tech detect -d example.com
autoar gf scan -d example.com
autoar github-wordlist scan -o orgname
autoar apkx scan -i /path/to/app.apk    # Analyze APK/IPA with embedded apkX engine
autoar bot    # Start Discord bot
autoar api    # Start REST API server
autoar both   # Start both bot and API

# See all commands
autoar help
```

### Operational Modes

AutoAR supports three operational modes to fit your workflow:

### 🎯 Operational Modes

#### 1. Discord Bot Mode (Default)
```bash
# Using Docker Compose
docker-compose up autoar-discord

# Without Docker
export AUTOAR_MODE=discord
export DISCORD_BOT_TOKEN=your_token_here
autoar bot
```

#### 2. REST API Mode
```bash
# Using Docker Compose
docker-compose --profile api up autoar-api

# Without Docker
export AUTOAR_MODE=api
export API_HOST=0.0.0.0
export API_PORT=8000
./autoar api
```
Access API documentation at: `http://localhost:8000/docs`

#### 3. Both Discord Bot AND API (Hybrid Mode)
```bash
# Using Docker Compose
docker-compose --profile full up autoar-full

# Without Docker
export AUTOAR_MODE=both
export DISCORD_BOT_TOKEN=your_token_here
export API_HOST=0.0.0.0
export API_PORT=8000
./autoar both
```

---

### Discord Commands

Once the bot is running, use these slash commands in Discord:

#### Basic Reconnaissance
- `/subdomains domain:example.com [threads:100]` - Enumerate subdomains
- `/livehosts domain:example.com [threads:100]` - Find live hosts
- `/cnames domain:example.com` - Extract CNAME records
- `/urls domain:example.com [threads:100]` - Collect URLs
- `/tech domain:example.com [threads:100]` - Detect technologies

#### Vulnerability Scanning
- `/nuclei domain:example.com [threads:100]` - Run Nuclei scans
- `/react2shell_scan domain:example.com [threads:100] [enable_source_exposure:false] [dos_test:false]` - Scan domain hosts for React Server Components RCE (CVE-2025-55182) using next88 smart scan (sequential: normal → WAF bypass → Vercel WAF → paths)
- `/react2shell url:https://example.com [verbose:false]` - Test single URL for React Server Components RCE using next88 smart scan
- `/jwt_scan token:<JWT_TOKEN> [skip_crack:false] [skip_payloads:false] [wordlist:] [max_crack_attempts:]` - JWT token vulnerability scanning using jwt-hack
- `/wpdepconf domain:example.com` - WordPress plugin confusion
- `/dalfox domain:example.com [threads:100]` - XSS detection
- `/sqlmap domain:example.com [threads:100]` - SQL injection testing
- `/backup_scan domain:example.com [threads:100] [full:false]` - Backup file discovery
- `/apkx_scan file:<APK_OR_IPA_ATTACHMENT> [mitm:false]` - Analyze Android APK or iOS IPA with embedded apkX engine and return structured report

#### Specialized Scans
- `/js domain:example.com` - JavaScript analysis
- `/github scan repo:owner/repo` - GitHub repository secrets scanning
- `/github org:company` - GitHub organization reconnaissance
- `/github-wordlist org:company` - Generate wordlists from GitHub org
- `/s3 bucket:example-bucket` - S3 bucket scanning
- `/dns domain:example.com` - DNS takeover detection
- `/ports domain:example.com [threads:100]` - Port scanning

#### KeyHack API Key Validation
- `/keyhack_list` - List all available API key validation templates (778+ templates)
- `/keyhack_search query:stripe` - Search for API key validation templates by name
- `/keyhack_validate provider:Stripe api_key:sk_live_abc123` - Generate validation command for an API key
- `/keyhack_add keyname:Slack command:"curl -H 'Authorization: Bearer \$API_KEY' https://slack.com/api/auth.test" description:"Slack API validation" notes:"Requires Bearer token"` - Add a new API key validation template

#### GitHub Reconnaissance
- `/github scan repo:microsoft/PowerShell` - Scan specific repository for secrets
- `/github org:microsoft` - Scan entire organization (50 repos max)
- `/github-wordlist org:microsoft` - Generate wordlists from organization files

#### Workflows
- `/lite domain:example.com` - Light reconnaissance
- `/fastlook domain:example.com` - Quick scan
- `/domain domain:example.com` - Full domain analysis

#### Updates Monitoring
- New simplified commands (database-backed):
  - `/monitor_updates_add url:<URL> [strategy:hash|size|headers|regex] [pattern:<regex>]`
  - `/monitor_updates_remove url:<URL>`
  - `/monitor_updates_start [interval:900]` (starts monitors for all targets from DB)
  - `/monitor_updates_stop`
  - `/monitor_updates_list`

### CLI Usage

Access the container and use the CLI directly:

```bash
# Enter the container
docker exec -it autoar-discord bash

# Basic reconnaissance (with threading)
autoar subdomains get -d example.com -t 100
autoar livehosts get -d example.com -t 100 -s
autoar cnames get -d example.com
autoar urls collect -d example.com -t 100
autoar tech detect -d example.com -t 100

# Vulnerability scanning
autoar nuclei run -d example.com -m full -t 100
autoar nuclei run -u https://example.com -m cves
autoar reflection scan -d example.com
autoar dalfox run -d example.com -t 100
autoar sqlmap run -d example.com -t 100
autoar ports scan -d example.com -t 100
autoar gf scan -d example.com

# Specialized scans
autoar wpDepConf scan -d example.com

# Workflows
autoar fastlook run -d example.com
autoar lite run -d example.com --skip-js
autoar domain run -d example.com

# Database operations
autoar db domains list
autoar db subdomains list -d example.com
autoar db subdomains export -d example.com -o results.txt
autoar db js list -d example.com
```

## 🔑 KeyHack API Key Validation

AutoAR includes **KeyHack**, a comprehensive API key validation system with **778+ templates** for testing and validating discovered API keys across hundreds of services.

### Features

- **📋 778+ Templates**: Comprehensive collection of API key validation templates from KeysKit and custom additions
- **🔍 Smart Search**: Search templates by provider name or description
- **✅ Quick Validation**: Generate ready-to-use validation commands (curl or shell)
- **➕ Extensible**: Add custom validation templates via Discord or CLI
- **🌐 Multi-Format Support**: Supports HTTP-based (curl) and shell-based (AWS CLI, etc.) validation methods

### Usage Examples

#### List All Templates
```bash
# CLI (when implemented)
autoar keyhack list

# Discord
/keyhack_list
```

#### Search for Templates
```bash
# CLI (when implemented)
autoar keyhack search stripe

# Discord
/keyhack_search query:stripe
```

#### Validate an API Key
```bash
# CLI (when implemented)
autoar keyhack validate Stripe sk_live_abc123

# Discord
/keyhack_validate provider:Stripe api_key:sk_live_abc123
```

#### Add Custom Template
```bash
# CLI (when implemented)
autoar keyhack add "MyService" "curl -H 'Authorization: Bearer \$API_KEY' https://api.myservice.com/v1/test" "GET" "https://api.myservice.com/v1/test" "Authorization: Bearer \$API_KEY" "" "Requires Bearer token" "MyService API validation"

# Discord
/keyhack_add keyname:MyService command:"curl -H 'Authorization: Bearer \$API_KEY' https://api.myservice.com/v1/test" description:"MyService API validation" notes:"Requires Bearer token"
```

### Supported Services

KeyHack includes validation templates for 778+ services including:
- **Payment Processors**: Stripe, PayPal, Square
- **Cloud Providers**: AWS, Azure, GCP, DigitalOcean
- **Communication**: Slack, Discord, Telegram, Twilio
- **Development**: GitHub, GitLab, Bitbucket, npm
- **APIs**: Twitter, Facebook, Google, Microsoft
- **And 700+ more services**

### Database Storage

All templates are stored in PostgreSQL/SQLite database (`keyhack_templates` table) for:
- Fast search and retrieval
- Easy template management
- Persistent storage across restarts
- Version control and updates

### Template Format

Templates support multiple validation methods:
- **HTTP GET/POST**: Standard curl commands with headers
- **Basic Auth**: Base64-encoded credentials
- **Bearer Tokens**: OAuth-style token authentication
- **Shell Commands**: AWS CLI, gcloud, etc.

### Integration with GitHub Scanning

KeyHack seamlessly integrates with GitHub scanning:
1. Scan repositories for exposed API keys
2. Use KeyHack to validate discovered keys
3. Determine key permissions and scope
4. Report findings with validation results

## 🔍 GitHub Scanning Features

AutoAR includes powerful GitHub reconnaissance capabilities for discovering secrets and generating targeted wordlists.

### GitHub Repository Scanning
Scan individual repositories for exposed secrets and sensitive information:

```bash
# Scan a specific repository (when implemented in Go)
autoar github scan -r owner/repository

# Example: Scan Microsoft's PowerShell repository
autoar github scan -r microsoft/PowerShell
```

**Features:**
- 🔍 **Secrets Detection**: Finds API keys, passwords, tokens, and other sensitive data
- 📊 **HTML Reports**: Generates detailed HTML reports with findings
- 🎯 **Pattern Matching**: Uses advanced regex patterns to identify secrets
- 📁 **File Analysis**: Scans all files in the repository

### GitHub Organization Scanning
Scan entire organizations to discover repositories and their secrets:

```bash
# Scan an organization (when implemented in Go)
autoar github org -o microsoft -m 50

# Scan with custom repository limit
autoar github org -o microsoft -m 100
```

**Features:**
- 🏢 **Organization-wide Scan**: Discovers all public repositories
- 🔍 **Bulk Secret Detection**: Scans multiple repositories in parallel
- 📈 **Progress Tracking**: Real-time progress updates via Discord
- 📊 **Summary Reports**: Consolidated findings across all repositories

### GitHub Wordlist Generation
Generate targeted wordlists from organization's ignore files and patterns:

```bash
# Generate wordlist from organization
autoar github-wordlist scan -o microsoft

# With custom GitHub token
autoar github-wordlist scan -o microsoft -t your_github_token
```

**Features:**
- 📝 **Ignore File Analysis**: Extracts patterns from .gitignore files
- 🎯 **Targeted Wordlists**: Creates organization-specific wordlists
- 🔄 **Pattern Extraction**: Finds common file patterns and extensions
- 📁 **Multiple Sources**: Analyzes various ignore file formats

### GitHub Scan Results
All GitHub scans generate comprehensive results:

```
new-results/
├── github-microsoft/
│   ├── dependency-confusion/
│   │   ├── microsoft-powershell/
│   │   ├── microsoft-vscode/
│   │   └── dependency-confusion-summary.txt
│   └── wordlists/
│       ├── github-patterns.txt
│       ├── github-wordlist.txt
│       └── corser_gitignore.txt
```

### Required Configuration
Set up your GitHub token for enhanced functionality:

```bash
# In your .env file or environment
GITHUB_TOKEN=your_github_personal_access_token
```

**Token Permissions Required:**
- `repo` - Access to repository contents
- `read:org` - Read organization membership
- `read:user` - Read user profile information

## ⚡ Threading Configuration

AutoAR supports configurable threading across all scanning tools for optimal performance:

### Discord Commands
All Discord commands support optional `threads` parameter (default: 100):
```
/subdomains domain:example.com threads:200
/nuclei domain:example.com threads:50
/ports domain:example.com threads:500
```

### CLI Commands
All CLI commands support `-t` or `--threads` flag (where applicable):
```bash
# High-performance scanning
autoar subdomains get -d example.com  # Threads configurable via module flags
autoar nuclei run -d example.com
autoar ports scan -d example.com

# Note: Thread counts are typically configured via environment variables or module-specific flags
# See individual module documentation for thread configuration options
```

### Performance Guidelines
- **High-end systems**: 200-500 threads for maximum speed
- **Standard systems**: 100 threads (default) for balanced performance
- **Resource-constrained**: 25-50 threads to avoid overwhelming the system
- **Network-limited**: Lower thread counts to avoid rate limiting

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DISCORD_BOT_TOKEN` | Discord bot token | Required |
| `DISCORD_WEBHOOK` | Discord webhook URL | Required |
| `DISCORD_ONLY` | Discord-only mode (no local files) | `false` |
| `SAVE_TO_DB` | Save results to database | `true` |
| `DB_TYPE` | Database type (postgresql/sqlite) | `postgresql` |
| `DB_HOST` | Database host | Required for PostgreSQL |
| `VERBOSE` | Verbose logging | `true` |

### API Keys

Configure these for enhanced functionality:

- **SecurityTrails**: `SECURITYTRAILS_API_KEY`
- **Shodan**: `SHODAN_API_KEY`
- **VirusTotal**: `VIRUSTOTAL_API_KEY`
- **GitHub**: `GITHUB_TOKEN`
- **AWS**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- **And 20+ more** (see docker-compose.yml)

### Customization

- **Nuclei Templates**: Place custom templates in `nuclei_templates/`
- **Wordlists**: Add custom wordlists to `Wordlists/`
- **Regex Patterns**: Customize patterns in `regexes/`
- **Rate Limits**: Adjust `NUCLEI_RATE_LIMIT` and `NUCLEI_CONCURRENCY`

## 📁 Project Structure

```
AutoAR/
├── cmd/
│   └── autoar/
│       └── main.go        # Main CLI entry point (pure Go)
├── internal/
│   ├── modules/           # Internal Go modules (business logic)
│   │   ├── gobot/         # Discord bot + API server
│   │   ├── db/            # Database operations (PostgreSQL/SQLite)
│   │   ├── subdomains/    # Subdomain enumeration
│   │   ├── livehosts/     # Live host detection
│   │   ├── urls/          # URL collection
│   │   ├── cnames/        # CNAME analysis
│   │   ├── nuclei/        # Nuclei integration (CLI-wrapper)
│   │   ├── dalfox/        # XSS detection (CLI-wrapper)
│   │   ├── sqlmap/        # SQL injection testing (CLI-wrapper)
│   │   ├── ports/         # Port scanning
│   │   ├── tech/          # Technology detection
│   │   ├── gf/            # Pattern matching
│   │   ├── reflection/    # Reflection testing
│   │   ├── dns/           # DNS takeover detection
│   │   ├── lite/          # Lite scan workflow
│   │   ├── fastlook/      # Fast look workflow
│   │   ├── domain/        # Full domain scan workflow
│   │   ├── github-wordlist/ # GitHub wordlist generator
│   │   ├── wp-confusion/  # WordPress confusion scanner
│   │   ├── entrypoint/    # Docker entrypoint (Go binary)
│   │   ├── config/        # Configuration management
│   │   └── utils/         # Utility functions
│   └── tools/             # Tool integrations / vendored engines (pure Go)
│       ├── confused2/         # Dependency confusion scanner (Go library)
│       ├── next88/            # React2Shell/Next.js RCE scanner (Go library)
│       ├── fuzzuli/           # Backup file discovery (Go library)
│       ├── dalfox/            # XSS detection (Go library integration)
│       ├── naabu/             # Port scanning (Go library integration)
│       ├── urlfinder/         # Passive URL collection (native Go)
│       ├── jsfinder/          # JS URL extraction (native Go)
│       ├── kxss/              # Reflection/XSS helper (native Go)
│       ├── gf/                # Pattern matching engine (native Go)
│       ├── jwthack/           # JWT vulnerability engine (native Go)
│       ├── misconfigmapper/   # Cloud misconfiguration engine (vendored)
│       └── apkx/              # Embedded apkX Android/iOS analysis engine
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── nuclei_templates/      # Nuclei vulnerability templates (cloned)
├── nuclei-templates/       # Public Nuclei templates (cloned)
├── Wordlists/             # Wordlists (cloned)
├── regexes/               # Custom regex patterns
├── templates/             # Template files
├── docker-compose.yml     # Docker configuration
├── Dockerfile             # Multi-stage Docker build
└── README.md              # This file
```

**Key Points:**
- **Pure Go Implementation**: All functionality is implemented in Go. No bash scripts remain.
- **Standard Go Layout**: Following Go community best practices with `cmd/` for binaries
- **Modular Design**: Each scanner/workflow is a separate Go module
- **Docker-First**: Optimized for containerized deployment

## 🛠️ Advanced Usage

### Custom Workflows

Create custom scanning workflows by combining modules:

```bash
# Custom reconnaissance workflow
autoar subdomains get -d example.com
autoar livehosts get -d example.com -s
autoar urls collect -d example.com
autoar nuclei run -d example.com -m full
autoar dalfox run -d example.com
```

### Database Management

```bash
# List all domains
autoar db domains list

# Export subdomains for a domain
autoar db subdomains export -d example.com -o subdomains.txt

# List subdomains for a domain
autoar db subdomains list -d example.com

# List JS files for a domain
autoar db js list -d example.com
```

### Batch Processing

```bash
# Process multiple domains from a file
while read domain; do
  autoar domain run -d "$domain"
done < domains.txt
```

## 🔒 Security Considerations

- **API Keys**: Store sensitive API keys in environment variables
- **Rate Limiting**: Respect API rate limits to avoid service disruption
- **Rate Limiting**: Configure rate limits for external APIs to avoid blocking
- **Legal Compliance**: Ensure you have permission to scan target domains
- **Data Privacy**: Be mindful of sensitive data in scan results

## 🌐 REST API Usage

AutoAR now includes a full-featured REST API! Access all scanning capabilities programmatically for integration with CI/CD, custom dashboards, and automation workflows.

### API Quick Start

#### Start API Server
```bash
# Using Docker Compose
docker-compose --profile api up autoar-api

# Without Docker
export AUTOAR_MODE=api
export API_HOST=0.0.0.0
export API_PORT=8000
./autoar api
```

#### Access Interactive Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### API Endpoints Overview

#### Reconnaissance Scans
```bash
# Subdomain Enumeration
curl -X POST "http://localhost:8000/scan/subdomains" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Live Hosts Discovery
curl -X POST "http://localhost:8000/scan/livehosts" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# URL Collection
curl -X POST "http://localhost:8000/scan/urls" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Technology Detection
curl -X POST "http://localhost:8000/scan/tech" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Port Scanning
curl -X POST "http://localhost:8000/scan/ports" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### Vulnerability Scans
```bash
# Nuclei Vulnerability Scanner
curl -X POST "http://localhost:8000/scan/nuclei" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# DNS Takeover Check
curl -X POST "http://localhost:8000/scan/dns-takeover" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# APK/IPA Static Analysis (apkX engine)
curl -X POST "http://localhost:8000/scan/apkx" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/absolute/path/to/app.apk"}'

# Reflection Vulnerabilities
curl -X POST "http://localhost:8000/scan/reflection" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

#### Specialized Scans
```bash
# JavaScript Analysis
curl -X POST "http://localhost:8000/scan/js" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "subdomain": "api.example.com"}'

# S3 Bucket Security
curl -X POST "http://localhost:8000/scan/s3" \
  -H "Content-Type: application/json" \
  -d '{"bucket": "my-bucket", "region": "us-east-1"}'

# GitHub Repository Secrets
curl -X POST "http://localhost:8000/scan/github" \
  -H "Content-Type: application/json" \
  -d '{"repo": "owner/repository"}'

# GitHub Organization Scanning
curl -X POST "http://localhost:8000/scan/github_org" \
  -H "Content-Type: application/json" \
  -d '{"org": "organization", "max_repos": 50}'
```

#### KeyHack API Key Validation
```bash
# Search for templates
curl -X POST "http://localhost:8000/keyhack/search" \
  -H "Content-Type: application/json" \
  -d '{"query": "stripe"}'

# Validate an API key
curl -X POST "http://localhost:8000/keyhack/validate" \
  -H "Content-Type: application/json" \
  -d '{"provider": "Stripe", "api_key": "sk_live_abc123"}'
```

**Note**: Use the CLI or Discord commands for listing all templates, as the API focuses on search and validation operations.

#### Scan Management
```bash
# Check scan status
curl "http://localhost:8000/scan/{scan_id}/status"

# Get scan results
curl "http://localhost:8000/scan/{scan_id}/results"

# Download results as file
curl -O "http://localhost:8000/scan/{scan_id}/download"

# List all scans
curl "http://localhost:8000/scans"
```

### Python API Client Example

```python
import requests
import time

API_BASE = "http://localhost:8000"

# Start a scan
response = requests.post(
    f"{API_BASE}/scan/subdomains",
    json={"domain": "example.com"}
)
scan_data = response.json()
scan_id = scan_data["scan_id"]
print(f"Scan started: {scan_id}")

# Wait for completion
while True:
    status = requests.get(f"{API_BASE}/scan/{scan_id}/status").json()
    if status["status"] in ["completed", "failed"]:
        break
    time.sleep(5)

# Get results
results = requests.get(f"{API_BASE}/scan/{scan_id}/results").json()
print(f"Output: {results['output']}")
```

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

async function runScan() {
  // Start scan
  const { data } = await axios.post('http://localhost:8000/scan/subdomains', {
    domain: 'example.com'
  });
  
  const scanId = data.scan_id;
  console.log(`Scan started: ${scanId}`);
  
  // Wait for completion
  let status;
  do {
    const statusResponse = await axios.get(
      `http://localhost:8000/scan/${scanId}/status`
    );
    status = statusResponse.data.status;
    await new Promise(resolve => setTimeout(resolve, 5000));
  } while (status === 'running');
  
  // Get results
  const results = await axios.get(
    `http://localhost:8000/scan/${scanId}/results`
  );
  console.log('Results:', results.data);
}
```

### CI/CD Integration (GitHub Actions)

```yaml
name: Security Scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run AutoAR Scan
        run: |
          RESPONSE=$(curl -X POST "${{ secrets.AUTOAR_API }}/scan/nuclei" \
            -H "Content-Type: application/json" \
            -d '{"domain": "example.com"}')
          SCAN_ID=$(echo $RESPONSE | jq -r '.scan_id')
          
          # Wait for completion
          while true; do
            STATUS=$(curl -s "${{ secrets.AUTOAR_API }}/scan/$SCAN_ID/status" | jq -r '.status')
            if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
              break
            fi
            sleep 10
          done
          
          # Download results
          curl -o results.txt "${{ secrets.AUTOAR_API }}/scan/$SCAN_ID/download"
```

### Available Modes

AutoAR supports three operational modes:

#### 1. Discord Bot Only (Default)
```bash
docker-compose up autoar-discord
# or
export AUTOAR_MODE=discord
export DISCORD_BOT_TOKEN=your_token_here
./autoar bot
```

#### 2. REST API Only
```bash
docker-compose --profile api up autoar-api
# or
export AUTOAR_MODE=api
export API_HOST=0.0.0.0
export API_PORT=8000
./autoar api
```

#### 3. Hybrid Mode (Both Discord + API)
```bash
docker-compose --profile full up autoar-full
# or
export AUTOAR_MODE=both
export DISCORD_BOT_TOKEN=your_token_here
export API_HOST=0.0.0.0
export API_PORT=8000
./autoar both
```

### API Response Format

All scan endpoints return a scan ID for tracking:
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "started",
  "message": "Scan started successfully",
  "command": "autoar subdomains get -d example.com"
}
```

Check status:
```json
{
  "scan_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": "running|completed|failed",
  "started_at": "2024-01-15T10:00:00.000000",
  "completed_at": "2024-01-15T10:05:00.000000",
  "output": "scan output...",
  "error": null
}
```

### Testing the API

Test the API using curl or any HTTP client:
```bash
# Health check
curl http://localhost:8000/health

# Start a scan
curl -X POST "http://localhost:8000/scan/subdomains" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Check scan status
curl "http://localhost:8000/scan/{scan_id}/status"
```

### API Security Considerations

**Current Implementation**: No authentication (designed for localhost/internal use)

**For Production**:
1. **Add Authentication**: Implement API keys or JWT tokens
2. **Use HTTPS**: Deploy behind reverse proxy (nginx, traefik) with SSL/TLS
3. **Rate Limiting**: Prevent abuse and resource exhaustion
4. **Firewall Rules**: Restrict access by IP address
5. **Network Isolation**: Use Docker networks or VPNs

Example nginx reverse proxy with SSL:
```nginx
server {
    listen 443 ssl http2;
    server_name api.autoar.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for amazing tools
- [Nuclei](https://nuclei.projectdiscovery.io/) for vulnerability templates
- [Subfinder](https://github.com/projectdiscovery/subfinder) for subdomain enumeration
- [Httpx](https://github.com/projectdiscovery/httpx) for HTTP probing
- All the open-source security tools that make this project possible

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/h0tak88r/AutoAR/issues)
- **Discussions**: [GitHub Discussions](https://github.com/h0tak88r/AutoAR/discussions)
- **Discord**: Join our Discord server for real-time support

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Always ensure you have proper authorization before scanning any target. The authors are not responsible for any misuse of this tool.