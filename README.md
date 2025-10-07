# AutoAR

An automated reconnaissance and vulnerability scanning tool with a powerful REST API for programmatic access. Combines multiple tools for comprehensive web application security assessment with integrated SQLite storage for findings.

## 🚀 What's New (v2.0.0) - API-First Architecture

- **🌐 REST API**: Complete programmatic access to all AutoAR functionality
- **⚡ Async Processing**: Non-blocking scan execution with real-time status updates
- **📊 Structured Results**: JSON-formatted results with comprehensive summaries
- **🔧 Easy Integration**: Simple HTTP endpoints for any programming language
- **📁 File Downloads**: Direct access to all generated result files
- **🔄 Job Management**: Track, monitor, and manage scan jobs
- **📚 Auto Documentation**: Interactive API docs at `/docs`

## 🏃 Quick Start

### 1. Start the API Server

```bash
# Start the API server
./start_api.sh

# Or manually
python3 api.py
```

The API will be available at:
- **API Server**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

### 2. Run Scans via API

```bash
# Quick scan
python3 client.py example.com

# Full scan
python3 client.py example.com liteScan

# Subdomain scan
python3 client.py sub.example.com subdomain
```

### 3. Direct API Usage

```bash
# Start a scan
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "fastLook"}'

# Check status
curl "http://localhost:8000/status/{job_id}"

# Get results
curl "http://localhost:8000/results/{job_id}"
```

## 📚 Available Scan Types

- **`fastLook`**: Quick reconnaissance (subdomains, live hosts, URLs, tech detection, CNAME)
- **`liteScan`**: Comprehensive scan (includes vulnerability scanning)
- **`domain`**: Full domain scan with all features
- **`subdomain`**: Scan a single subdomain
- **`jsMonitor`**: Monitor JavaScript files for changes
- **`github_single_repo`**: Scan a single GitHub repository for secrets
- **`github_org_scan`**: Scan a GitHub organization for secrets
- **`github_wordlist`**: Generate a wordlist from an org’s ignore files

## 🔧 CLI Usage (Original)

The original CLI interface is still available:

```bash
./autoAr.sh liteScan -d example.com
./autoAr.sh fastLook -d example.com
./autoAr.sh domain   -d example.com
./autoAr.sh subdomain -s sub.example.com
./autoAr.sh jsMonitor -d example.com
# GitHub wordlist from org ignore files
./autoAr.sh github-wordlist -o organization-name
./autoAr.sh github-wordlist -o org -m 300 --files ".gitignore,.npmignore,.dockerignore"
```

## 🐍 Python Integration

```python
from client import AutoARClient

# Initialize client
client = AutoARClient("http://localhost:8000")

# Start a scan
scan_response = client.start_scan("example.com", "fastLook")
job_id = scan_response['job_id']

# Wait for completion and get results
results = client.wait_for_completion(job_id)

# Print summary
print(f"Found {results['summary']['total_subdomains']} subdomains")
print(f"Found {results['summary']['total_urls']} URLs")
print(f"Found {results['summary']['js_files']} JS files")
```

## 🧰 GitHub Wordlist Generation

Generates a deduplicated wordlist from an organization’s ignore files (e.g., `.gitignore`, `.npmignore`). It filters comments, empties, HTML/404 bodies, normalizes trailing slashes, enforces a safe charset, and sends the final list to Discord if configured.

- Prerequisite: GitHub CLI (`gh`) recommended. Falls back to REST API when unavailable.

CLI examples:

```bash
# Default file set, up to 200 repos
./autoAr.sh github-wordlist -o ORG

# Custom files and repo limit
./autoAr.sh github-wordlist -o ORG -m 300 --files ".gitignore,.npmignore,.dockerignore"
```

API example:

```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "ORG",
    "scan_type": "github_wordlist",
    "max_repos": 300,
    "wordlist_files_csv": ".gitignore,.npmignore,.dockerignore"
  }'
```

## 📊 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Start a new scan |
| `GET` | `/status/{job_id}` | Get job status |
| `GET` | `/results/{job_id}` | Get scan results |
| `GET` | `/download/{job_id}/{file_path}` | Download result files |
| `GET` | `/jobs` | List recent jobs |
| `DELETE` | `/jobs/{job_id}` | Delete job and results |
| `GET` | `/config` | Get current configuration |
| `PUT` | `/config` | Update configuration |
| `GET` | `/health` | Health check |

## 🛠️ Installation

### Prerequisites

- Python 3.7+
- AutoAR dependencies (subfinder, httpx, nuclei, etc.)

### Setup

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Make scripts executable
chmod +x autoAr.sh start_api.sh

# Start the API
./start_api.sh
```

## 🔧 Configuration

Edit `autoar.yaml` to configure:

```yaml
# Database configuration
DB_NAME: "autoar"
SAVE_TO_DB: true
VERBOSE: false

# Discord webhook for notifications
DISCORD_WEBHOOK: ""

# SecurityTrails API key
securitytrails:
  - ""

# GitHub token
github:
  - ""
```

## 📁 Project Structure

```
AutoAR/
├── api.py              # FastAPI server
├── client.py           # Python client
├── autoAr.sh           # Main AutoAR script
├── sqlite_db_handler.py # Database handler
├── autoar.yaml         # Configuration
├── requirements.txt    # Python dependencies
├── start_api.sh        # API startup script
├── new-results/        # Scan results directory
├── Wordlists/          # Wordlists for fuzzing
├── nuclei_templates/   # Nuclei templates
├── regexes/            # Regex patterns
└── API-README.md       # Detailed API documentation
```

## 🔒 Security & Secrets

- Real secrets live in `autoar.yaml` (ignored by git)
- A sanitized `autoar.sample.yaml` shows the schema
- CI uses gitleaks to prevent accidental secret commits
- API runs on localhost by default (change for production)

## 📈 Performance

- Jobs run asynchronously in the background
- Multiple scans can run concurrently
- Results are cached until job deletion
- Use Redis for job storage in production

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License. 