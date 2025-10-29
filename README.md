# AutoAR (Automated Attack Reconnaissance) 🚀

AutoAR is a comprehensive, modular security automation toolkit designed for bug bounty hunters, penetration testers, and security researchers. It combines a Discord bot frontend with a powerful bash-based CLI backend, providing automated reconnaissance, vulnerability scanning, and attack surface analysis.

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
- **WordPress Plugin Confusion**: Automated WP plugin/theme confusion attack detection
- **Dependency Confusion**: GitHub repository dependency confusion scanning
- **S3 Bucket Enumeration**: AWS S3 bucket discovery and analysis
- **SQL Injection Testing**: SQLMap integration for automated SQLi testing
- **XSS Detection**: Dalfox integration for cross-site scripting detection
- **Backup File Discovery**: Automated backup file and sensitive file discovery

### 🎯 **Specialized Scanners**
- **JavaScript Analysis**: JS file collection and secret extraction
- **GitHub Reconnaissance**: Organization and repository scanning with secrets detection
- **GitHub Wordlist Generation**: Automated wordlist creation from organization files
- **Port Scanning**: Nmap integration for port discovery
- **Reflection Testing**: HTTP parameter reflection analysis
- **Gf Pattern Matching**: Custom pattern matching for various vulnerabilities

### 🤖 **Discord Integration**
- **Real-time Notifications**: Live scan progress and results
- **File Sharing**: Automatic result file uploads
- **Slash Commands**: Easy-to-use Discord commands
- **Progress Tracking**: Real-time scan status updates
- **Configurable Threading**: All tools support custom thread counts for optimal performance

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
git clone https://github.com/yourusername/AutoAR.git
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
docker logs autoar-bot
```

### Manual Installation

1. **Install dependencies**:
```bash
# Python dependencies
pip install -r requirements.txt

# System dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y subfinder amass assetfinder httpx nuclei nmap sqlmap dalfox ffuf gobuster dirb dirbuster wafw00f whatweb wpscan nikto masscan naabu naabu-probe httpx-probe

# Additional tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

2. **Configure the system**:
```bash
chmod +x *.sh modules/*.sh
cp env.example .env
# Edit .env with your configuration
```

3. **Run the Discord bot**:
```bash
python discord_bot.py
```

## 📖 Usage

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
- `/wpdepconf domain:example.com` - WordPress plugin confusion
- `/dalfox domain:example.com [threads:100]` - XSS detection
- `/sqlmap domain:example.com [threads:100]` - SQL injection testing
- `/backup_scan domain:example.com [threads:100] [full:false]` - Backup file discovery

#### Specialized Scans
- `/js domain:example.com` - JavaScript analysis
- `/github scan repo:owner/repo` - GitHub repository secrets scanning
- `/github org:company` - GitHub organization reconnaissance
- `/github-wordlist org:company` - Generate wordlists from GitHub org
- `/s3 bucket:example-bucket` - S3 bucket scanning
- `/dns domain:example.com` - DNS takeover detection
- `/ports domain:example.com [threads:100]` - Port scanning

#### GitHub Reconnaissance
- `/github scan repo:microsoft/PowerShell` - Scan specific repository for secrets
- `/github org:microsoft` - Scan entire organization (50 repos max)
- `/github-wordlist org:microsoft` - Generate wordlists from organization files

#### Workflows
- `/lite domain:example.com` - Light reconnaissance
- `/fastlook domain:example.com` - Quick scan
- `/domain domain:example.com` - Full domain analysis

#### Updates Monitoring
- `/updates_add url:<URL> [strategy:hash|size|headers|regex] [pattern:<regex>]`
- `/updates_list` - List configured targets
- `/updates_check [url:<URL>]` - One-off check for all or a specific URL
- `/updates_monitor_start [interval:900]` - Start monitors for all targets
- `/updates_monitor_stop` - Stop all monitors
- `/updates_monitor_list` - List running monitors

### CLI Usage

Access the container and use the CLI directly:

```bash
# Enter the container
docker exec -it autoar-bot bash

# Basic reconnaissance (with threading)
/app/main.sh subdomains get -d example.com -t 100
/app/main.sh livehosts get -d example.com -t 100
/app/main.sh cnames get -d example.com
/app/main.sh urls collect -d example.com -t 100
/app/main.sh tech detect -d example.com -t 100

# Vulnerability scanning (with threading)
/app/main.sh nuclei run -d example.com -t 100
/app/main.sh dalfox run -d example.com -t 100
/app/main.sh sqlmap run -d example.com -t 100
/app/main.sh ports scan -d example.com -t 100
/app/main.sh backup scan -d example.com -t 100 --full
/app/main.sh wpDepConf scan -d example.com

# Specialized scans
/app/main.sh js scan -d example.com
/app/main.sh github scan -r owner/repo
/app/main.sh github org -o company -m 50
/app/main.sh github-wordlist scan -o company
/app/main.sh s3 scan -b bucket-name
/app/main.sh dns takeover -d example.com

# Workflows
/app/main.sh lite run -d example.com
/app/main.sh fastlook run -d example.com
/app/main.sh domain run -d example.com

# Updates Monitoring (CLI)
/app/main.sh updates add -u https://example.com --strategy hash
/app/main.sh updates add -u https://site/blog --strategy regex --pattern '([A-Z][a-z]{2,8} [0-9]{1,2}, [0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})'
/app/main.sh updates list
/app/main.sh updates check
/app/main.sh updates check -u https://site/blog
/app/main.sh updates monitor start --all --interval 900 --daemon
/app/main.sh updates monitor list
/app/main.sh updates monitor stop --all

# Database operations
/app/main.sh db domains list
/app/main.sh db subdomains list -d example.com
/app/main.sh db subdomains export -d example.com -o results.txt
```

## 🔍 GitHub Scanning Features

AutoAR includes powerful GitHub reconnaissance capabilities for discovering secrets and generating targeted wordlists.

### GitHub Repository Scanning
Scan individual repositories for exposed secrets and sensitive information:

```bash
# Scan a specific repository
/app/main.sh github scan -r owner/repository

# Example: Scan Microsoft's PowerShell repository
/app/main.sh github scan -r microsoft/PowerShell
```

**Features:**
- 🔍 **Secrets Detection**: Finds API keys, passwords, tokens, and other sensitive data
- 📊 **HTML Reports**: Generates detailed HTML reports with findings
- 🎯 **Pattern Matching**: Uses advanced regex patterns to identify secrets
- 📁 **File Analysis**: Scans all files in the repository

### GitHub Organization Scanning
Scan entire organizations to discover repositories and their secrets:

```bash
# Scan an organization (default: 50 repos max)
/app/main.sh github org -o microsoft

# Scan with custom repository limit
/app/main.sh github org -o microsoft -m 100
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
/app/main.sh github-wordlist scan -o microsoft

# With custom GitHub token
/app/main.sh github-wordlist scan -o microsoft -t your_github_token
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
All CLI commands support `-t` or `--threads` flag:
```bash
# High-performance scanning
./modules/subdomains.sh get -d example.com -t 200
./modules/nuclei.sh run -d example.com -t 50
./modules/ports.sh scan -d example.com -t 500

# Conservative scanning (lower resource usage)
./modules/subdomains.sh get -d example.com -t 25
./modules/nuclei.sh run -d example.com -t 10
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
├── modules/                 # Core scanning modules
│   ├── subdomains.sh       # Subdomain enumeration
│   ├── livehosts.sh        # Live host detection
│   ├── nuclei.sh           # Nuclei integration
│   ├── wp_plugin_confusion.sh # WordPress scanning
│   └── ...                 # Other modules
├── python/                 # Python utilities
│   ├── discord_bot.py      # Discord bot
│   ├── db_handler.py       # Database operations
│   └── wp_update_confusion.py # WP confusion scanner
├── lib/                    # Shared libraries
│   ├── logging.sh          # Logging utilities
│   ├── utils.sh            # Common utilities
│   └── discord.sh          # Discord integration
├── nuclei_templates/       # Nuclei vulnerability templates
├── Wordlists/             # Wordlists and patterns
├── regexes/               # Custom regex patterns
├── docker-compose.yml     # Docker configuration
├── Dockerfile            # Container definition
└── main.sh               # CLI entry point
```

## 🛠️ Advanced Usage

### Custom Workflows

Create custom scanning workflows by combining modules:

```bash
# Custom reconnaissance workflow
/app/main.sh subdomains get -d example.com
/app/main.sh livehosts get -d example.com
/app/main.sh urls collect -d example.com
/app/main.sh nuclei run -d example.com
/app/main.sh dalfox run -d example.com
```

### Database Management

```bash
# List all domains
/app/main.sh db domains list

# Export subdomains for a domain
/app/main.sh db subdomains export -d example.com -o subdomains.txt

# Clean up old data
/app/main.sh cleanup run --domain example.com
```

### Batch Processing

```bash
# Process multiple domains from a file
while read domain; do
  /app/main.sh domain run -d "$domain"
done < domains.txt
```

## 🔒 Security Considerations

- **API Keys**: Store sensitive API keys in environment variables
- **Rate Limiting**: Respect API rate limits to avoid service disruption
- **Legal Compliance**: Ensure you have permission to scan target domains
- **Data Privacy**: Be mindful of sensitive data in scan results

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

- **Issues**: [GitHub Issues](https://github.com/yourusername/AutoAR/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/AutoAR/discussions)
- **Discord**: Join our Discord server for real-time support

---

**⚠️ Disclaimer**: This tool is for educational and authorized testing purposes only. Always ensure you have proper authorization before scanning any target. The authors are not responsible for any misuse of this tool.