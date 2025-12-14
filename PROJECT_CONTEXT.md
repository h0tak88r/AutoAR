# AutoAR Project Context

## Overview

AutoAR (Automated Attack Reconnaissance) is a comprehensive, modular security automation toolkit designed for bug bounty hunters, penetration testers, and security researchers. It provides three operational modes: Discord bot, REST API, or both simultaneously, all powered by a robust bash-based CLI backend.

## Project Structure

```
AutoAR/
├── main.sh                    # Main entry point, dispatches commands to modules
├── modules/                   # Individual scanning modules (bash scripts)
│   ├── github_scan.sh        # GitHub secrets scanning (repos & orgs)
│   ├── subdomains.sh         # Subdomain enumeration
│   ├── livehosts.sh          # Live host detection
│   ├── nuclei.sh             # Vulnerability scanning
│   ├── js_scan.sh            # JavaScript analysis
│   └── ...                   # Many more modules
├── lib/                      # Shared library functions
│   ├── logging.sh            # Logging utilities
│   ├── utils.sh              # Common utilities
│   ├── config.sh             # Configuration management
│   └── discord.sh            # Discord integration
├── python/                    # Python utility scripts (for specific tools)
│   ├── jwt_tool.py           # JWT scanning tool
│   ├── wp_update_confusion.py # WordPress confusion scanner
│   ├── github_wordlist.py    # GitHub wordlist generator
│   └── db_handler.py         # Database operations
├── go-bot/                    # Go implementation (Discord bot + API server)
│   ├── main.go               # Entry point
│   ├── api.go                # REST API server
│   ├── react2shell.go        # React2Shell scanning
│   └── commands*.go          # Discord command handlers
├── Dockerfile                # Docker build configuration
├── docker-compose.yml        # Docker Compose configuration
├── requirements.txt          # Python dependencies
└── regexes/                  # Regex patterns for secret detection
```

## Core Architecture

### 1. Command Dispatch System (`main.sh`)

The main script acts as a router, dispatching commands to appropriate modules:

```bash
./main.sh <command> <action> [options]
```

**Example Commands:**
- `github scan -r owner/repo` - Scan GitHub repository
- `github org -o organization` - Scan GitHub organization
- `subdomains get -d domain.com` - Enumerate subdomains
- `nuclei run -d domain.com` - Run Nuclei vulnerability scan

### 2. Module System

Each module is a standalone bash script in `modules/` that:
- Handles its own argument parsing
- Uses shared libraries from `lib/`
- Outputs results to standardized directories
- Integrates with Discord for notifications

### 3. GitHub Secrets Scanning

**Location:** `modules/github_scan.sh`

**Key Features:**
- Uses TruffleHog for secret detection
- Supports repository and organization scanning
- Extracts unique secrets using `jq`
- Generates formatted tables using `jtbl` (if available)
- Sends results to Discord

**Functions:**
- `github_scan()` - Scan individual repository
- `github_org_scan()` - Scan entire organization
- `extract_unique_secrets()` - Extract detector name + raw secret value
- `generate_secrets_table()` - Create formatted table (uses jtbl)

**Output Files:**
1. `*_secrets.json` - Raw TruffleHog JSON output
2. `*_secrets.txt` - Unique secrets in format: `DetectorName: secret_value`
3. `*_secrets_table.txt` - Formatted table (if jtbl available)

**Dependencies:**
- `trufflehog` - Secret scanning tool
- `jq` - JSON processing
- `jtbl` - Table formatting (optional, falls back to plain text)

### 4. Discord Bot Integration

**Location:** `python/discord_bot.py`

**Features:**
- Slash commands for all scanning operations
- Real-time progress notifications
- File uploads for scan results
- Background task execution
- Database integration

**Key Commands:**
- `/github_scan` - Scan GitHub repository or organization
- `/subdomain_scan` - Enumerate subdomains
- `/nuclei_scan` - Run vulnerability scan
- `/monitor_add` - Add target for monitoring

### 5. REST API Server

**Location:** `go-bot/api.go`

**Framework:** FastAPI

**Endpoints:**
- `POST /scan/{scan_type}` - Start a scan
- `GET /scan/{scan_id}/status` - Get scan status
- `GET /scan/{scan_id}/results` - Download results
- `GET /scans` - List all scans
- `GET /health` - Health check

**Features:**
- Async background scanning
- Status tracking
- File downloads
- Swagger documentation at `/docs`

### 6. Database Integration

**Supported Databases:**
- PostgreSQL (primary)
- SQLite (fallback)

**Storage:**
- Scan results
- Monitored targets
- Subdomain data
- JavaScript findings

**Location:** `python/db_handler.py`, `lib/db.sh`

## Key Technologies & Tools

### Security Tools (Go-based)
- **Subfinder** - Subdomain enumeration
- **Nuclei** - Vulnerability scanning
- **Httpx** - HTTP probing
- **Naabu** - Port scanning
- **Dalfox** - XSS detection
- **SQLMap** - SQL injection testing
- **TruffleHog** - Secret scanning
- **Confused** - Dependency confusion detection
- **Misconfig-mapper** - Misconfiguration detection

### Utilities
- **jq** - JSON processing
- **jtbl** - JSON to table conversion
- **yq** - YAML processing
- **git** - Version control operations

### Python Libraries
- **discord.py** - Discord bot framework
- **fastapi** - REST API framework
- **psycopg2** - PostgreSQL adapter
- **pyyaml** - YAML parsing

## Docker Configuration

### Dockerfile Structure

1. **Builder Stage** (Go tools):
   - Installs Go-based security tools
   - Installs TruffleHog
   - Compiles all tools

2. **Runtime Stage** (Python):
   - Base: `python:3.11-slim`
   - Installs system dependencies
   - Installs Python packages
   - Copies Go tools from builder
   - Sets up non-root user

### Key Docker Features

- **Multi-stage build** for smaller image size
- **Non-root user** for security
- **Health checks** for monitoring
- **Volume mounts** for persistent data
- **Environment variable** configuration

### Installing jtbl

jtbl is installed via pip in the Dockerfile:
```dockerfile
RUN pip3 install --no-cache-dir jtbl
```

If installation fails, the script falls back to plain text format.

## GitHub Secrets Scanning Workflow

1. **Scan Execution:**
   ```bash
   ./main.sh github org -o organization
   ```

2. **TruffleHog Execution:**
   - Scans organization/repository
   - Outputs NDJSON (newline-delimited JSON)
   - Each line is a secret finding

3. **JSON Processing:**
   - Converts NDJSON to JSON array
   - Filters valid findings (has DetectorName)

4. **Secret Extraction:**
   - Uses `jq` to extract:
     - Detector name (from `SourceMetadata.DetectorName` or `DetectorName`)
     - Raw secret value (from `Raw` or `SourceMetadata.Raw`)
   - Falls back to `Redacted` if `Raw` unavailable
   - Removes duplicates using `sort -u`

5. **Output Generation:**
   - **JSON file**: Raw TruffleHog output
   - **Text file**: `DetectorName: secret_value` format
   - **Table file**: Formatted table (if jtbl available)

6. **Discord Notification:**
   - Sends summary message
   - Uploads JSON file
   - Uploads text file with unique secrets
   - Uploads table file (if generated)

## Configuration

### Environment Variables

**Required:**
- `DISCORD_BOT_TOKEN` - Discord bot token
- `DISCORD_WEBHOOK` - Discord webhook URL

**Database:**
- `DB_HOST` - Database host
- `DB_PORT` - Database port (default: 5432)
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name

**GitHub:**
- `GITHUB_TOKEN` - GitHub personal access token (for rate limits)

**API Keys (Optional):**
- `SECURITYTRAILS_API_KEY`
- `SHODAN_API_KEY`
- `VIRUSTOTAL_API_KEY`
- And many more...

### Configuration File

**Location:** `autoar.yaml`

Contains tool-specific settings, API keys, and scan configurations.

## Results Storage

**Directory:** `/app/new-results` (configurable via `AUTOAR_RESULTS_DIR`)

**Structure:**
```
new-results/
├── github_org_organization/
│   └── vulnerabilities/
│       └── github/
│           ├── org_secrets.json
│           ├── org_secrets.txt
│           └── org_secrets_table.txt
└── github_repo_name/
    └── vulnerabilities/
        └── github/
            ├── repo_secrets.json
            ├── repo_secrets.txt
            └── repo_secrets_table.txt
```

## Error Handling

- All modules use `set -euo pipefail` for strict error handling
- Logging via `lib/logging.sh` with levels: INFO, WARN, ERROR, SUCCESS
- Discord notifications for errors
- Graceful fallbacks (e.g., jtbl → plain text)

## KeyHack Integration

**Location:** `modules/keyhack.sh`, `keyhack_templates/`

**Features:**
- Search through 750+ API key validation templates
- Generate ready-to-use curl commands for API key validation
- Support for multiple authentication methods (Bearer, Basic Auth, API Key headers, etc.)
- Automatic variable replacement in URLs, headers, and request bodies
- Special handling for Basic Auth (automatic base64 encoding)

**Usage:**

**CLI:**
```bash
# Search for templates
./main.sh keyhack search stripe

# Generate validation command
./main.sh keyhack validate Stripe sk_live_abc123
```

**API:**
```bash
# Search
POST /keyhack/search
{"query": "stripe"}

# Validate
POST /keyhack/validate
{"provider": "Stripe", "api_key": "sk_live_abc123"}
```

**Discord:**
- `/keyhack_search <query>` - Search for templates
- `/keyhack_validate <provider> <api_key>` - Generate validation command

**Templates:**
- Located in `keyhack_templates/` directory
- 750+ templates from [KeysKit project](https://github.com/MrMax4o4/KeysKit)
- Each template contains: name, method, header, url, body, note, description

**Template Structure:**
```json
{
  "name": "Provider Name",
  "method": "GET or POST",
  "header": "'Header-Key':'Value'",
  "url": "https://api.provider.com/endpoint",
  "body": "param1=$API_KEY&param2=value",
  "note": "Optional notes",
  "description": "Provider description"
}
```

## Recent Changes

### KeyHack Integration (2025-11-29)
- Added KeyHack integration for API key validation
- Integrated 750+ validation templates
- Added CLI, API, and Discord bot support
- Automatic variable replacement and Basic Auth encoding

### GitHub Secrets Scanning Improvements

1. **Removed Python Dependencies:**
   - Removed `github_html_report.py`
   - Removed `github_secrets_parser.py`
   - Now uses pure bash + jq

2. **Added jtbl Support:**
   - Installed in Dockerfile
   - Generates formatted tables
   - Falls back to plain text if unavailable

3. **Simplified Output:**
   - JSON file (raw TruffleHog output)
   - Text file (unique secrets: `DetectorName: secret_value`)
   - Table file (formatted, optional)

4. **Better Duplicate Removal:**
   - Uses `sort -u` on detector name + secret value
   - Handles multiple JSON path variations

5. **Organization Detection:**
   - Detects if input is org vs repo
   - Shows helpful error messages
   - Suggests correct command

## Development Guidelines

### Adding New Modules

1. Create script in `modules/`
2. Source shared libraries: `source "$ROOT_DIR/lib/logging.sh"`
3. Add command handler in `main.sh`
4. Follow existing patterns for:
   - Argument parsing
   - Error handling
   - Result storage
   - Discord integration

### Testing

- Test locally before Docker
- Check logs: `docker-compose logs -f`
- Verify Discord notifications
- Test with small targets first

### Debugging

- Enable verbose mode: `VERBOSE=true`
- Check module logs
- Review Discord messages
- Inspect result files

## Common Issues & Solutions

### jtbl Not Found
- **Solution**: Falls back to plain text automatically
- **Fix**: Ensure pip install succeeds in Dockerfile

### TruffleHog Errors
- **Check**: GitHub token is set
- **Check**: Repository/organization exists
- **Check**: Rate limits not exceeded

### JSON Parsing Errors
- **Cause**: Invalid JSON from TruffleHog
- **Solution**: Script handles this gracefully with fallbacks

### Discord Notifications Not Working
- **Check**: `DISCORD_BOT_TOKEN` and `DISCORD_WEBHOOK` are set
- **Check**: Bot has proper permissions
- **Check**: Webhook URL is valid

## API Integration

### Starting API Server

```bash
docker-compose --profile api up autoar-api
```

### API Endpoints

- **Health**: `GET /health`
- **Start Scan**: `POST /scan/{scan_type}`
- **Get Status**: `GET /scan/{scan_id}/status`
- **Get Results**: `GET /scan/{scan_id}/results`
- **List Scans**: `GET /scans`
- **Docs**: `GET /docs` (Swagger UI)

### Example API Usage

```bash
# Start GitHub org scan
curl -X POST "http://localhost:8000/scan/github_org" \
  -H "Content-Type: application/json" \
  -d '{"org": "organization"}'

# Check status
curl "http://localhost:8000/scan/{scan_id}/status"

# Download results
curl "http://localhost:8000/scan/{scan_id}/results" -o results.zip
```

## Monitoring System

### Adding Targets

```bash
./main.sh monitor updates add -u https://example.com
```

### Monitoring Strategies

- **hash** - Detect changes via content hash
- **size** - Detect changes via file size
- **headers** - Detect changes via HTTP headers
- **pattern** - Detect changes via regex pattern

### Daemon Mode

```bash
./main.sh monitor updates start --daemon
```

Runs in background, automatically restarts on failure.

## Best Practices

1. **Always use GitHub token** for organization scans
2. **Start with small targets** for testing
3. **Monitor rate limits** for API keys
4. **Use Docker** for consistent environment
5. **Check logs regularly** for errors
6. **Backup results** before cleanup
7. **Use database** for persistent storage
8. **Enable verbose mode** for debugging

## Future Enhancements

- [ ] Support for more secret scanners
- [ ] Enhanced duplicate detection algorithms
- [ ] Real-time secret verification
- [ ] Integration with secret management systems
- [ ] Advanced filtering options
- [ ] Custom report formats
- [ ] Webhook integrations
- [ ] Scheduled scanning

## Support & Contribution

- **Issues**: Report bugs and feature requests
- **Pull Requests**: Welcome contributions
- **Documentation**: Keep this file updated
- **Testing**: Test thoroughly before submitting

## License

[Add license information here]

---

**Last Updated:** 2025-11-29
**Version:** 1.0.0
**Maintainer:** [Your Name/Team]

