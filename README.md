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
- **GitHub Reconnaissance**: Organization and repository scanning
- **Port Scanning**: Nmap integration for port discovery
- **Reflection Testing**: HTTP parameter reflection analysis
- **Gf Pattern Matching**: Custom pattern matching for various vulnerabilities

### 🤖 **Discord Integration**
- **Real-time Notifications**: Live scan progress and results
- **File Sharing**: Automatic result file uploads
- **Slash Commands**: Easy-to-use Discord commands
- **Progress Tracking**: Real-time scan status updates

### 🗄️ **Database Support**
- **PostgreSQL Integration**: Full database support for results storage
- **SQLite Fallback**: Lightweight database option
- **Data Export**: Easy data export and analysis
- **Result Management**: Organized result storage and retrieval

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
- `/subdomains domain:example.com` - Enumerate subdomains
- `/livehosts domain:example.com` - Find live hosts
- `/cnames domain:example.com` - Extract CNAME records
- `/urls domain:example.com` - Collect URLs
- `/tech domain:example.com` - Detect technologies

#### Vulnerability Scanning
- `/nuclei domain:example.com` - Run Nuclei scans
- `/wpdepconf domain:example.com` - WordPress plugin confusion
- `/dalfox domain:example.com` - XSS detection
- `/sqlmap domain:example.com` - SQL injection testing
- `/backup domain:example.com` - Backup file discovery

#### Specialized Scans
- `/js domain:example.com` - JavaScript analysis
- `/github org:company` - GitHub reconnaissance
- `/s3 bucket:example-bucket` - S3 bucket scanning
- `/dns domain:example.com` - DNS takeover detection
- `/ports domain:example.com` - Port scanning

#### Workflows
- `/lite domain:example.com` - Light reconnaissance
- `/fastlook domain:example.com` - Quick scan
- `/domain domain:example.com` - Full domain analysis

### CLI Usage

Access the container and use the CLI directly:

```bash
# Enter the container
docker exec -it autoar-bot bash

# Basic reconnaissance
/app/main.sh subdomains get -d example.com
/app/main.sh livehosts get -d example.com
/app/main.sh cnames get -d example.com
/app/main.sh urls collect -d example.com

# Vulnerability scanning
/app/main.sh nuclei run -d example.com
/app/main.sh wpDepConf scan -d example.com
/app/main.sh dalfox run -d example.com
/app/main.sh sqlmap run -d example.com

# Specialized scans
/app/main.sh js scan -d example.com
/app/main.sh github scan -r owner/repo
/app/main.sh s3 scan -b bucket-name
/app/main.sh dns takeover -d example.com

# Workflows
/app/main.sh lite run -d example.com
/app/main.sh fastlook run -d example.com
/app/main.sh domain run -d example.com

# Database operations
/app/main.sh db domains list
/app/main.sh db subdomains list -d example.com
/app/main.sh db subdomains export -d example.com -o results.txt
```

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