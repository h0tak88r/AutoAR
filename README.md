# autoAr

An automated reconnaissance and vulnerability scanning tool that combines multiple tools for comprehensive web application security assessment, with integrated MongoDB storage for findings.

## Features

- Subdomain enumeration using multiple sources and APIs
- MongoDB integration for persistent storage of findings
- Live host detection and technology fingerprinting
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

4. **Configure MongoDB (Optional):**
   - Update the MongoDB connection string in `mongo_db_handler.py`
   - Test the connection:
   ```bash
   ./mongo_db_handler.py help
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

### With MongoDB Storage:
```bash
./autoAr.sh -d example.com --save-to-db
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
    -spx, --skip-paramx        Skip ParamX scanning
    -sd, --skip-dalfox         Skip Dalfox XSS scanning
    -dw, --discord-webhook     Discord webhook URL for notifications
    -st, --save-to-db          Save results to MongoDB database
    -sk, --securitytrails-key  SecurityTrails API key for additional subdomain enumeration
```

## MongoDB Integration

The tool supports MongoDB integration for persistent storage of domains and subdomains. To use this feature, you'll need to create your own MongoDB database handler.

### Setting Up MongoDB Integration

1. **Create a MongoDB Database:**
   - Set up a MongoDB instance (local or cloud service like MongoDB Atlas/Railway)
   - Create a database named `autoar` (or your preferred name)
   - Create collections: `domains` and `subdomains`

2. **Create Your Database Handler:**
   Create a Python script named `mongo_db_handler.py` with this structure:

   ```python
   #!/usr/bin/env python3
   from pymongo import MongoClient, UpdateOne
   import sys
   import os
   
   # Your MongoDB connection details
   MONGO_URI = "your_mongodb_connection_string"
   DB_NAME = "your_database_name"
   DOMAINS_COLLECTION = "domains"
   SUBDOMAINS_COLLECTION = "subdomains"
   
   class DatabaseHandler:
       def __init__(self):
           self.client = MongoClient(MONGO_URI)
           self.db = self.client[DB_NAME]
   
       def add_domain(self, domain: str) -> bool:
           # Implementation for adding a domain
           pass
   
       def add_subdomain(self, domain: str, subdomain: str) -> bool:
           # Implementation for adding a subdomain
           pass
   
       def add_subdomains_from_file(self, domain: str, file_path: str) -> None:
           # Implementation for adding subdomains from file
           pass
   
       def list_domains(self) -> None:
           # Implementation for listing domains
           pass
   
       def get_subdomains(self, domain: str) -> None:
           # Implementation for getting subdomains
           pass
   
   # Command-line interface implementation
   ```

3. **Required Functions:**
   Your handler should implement these commands:
   ```bash
   ./mongo_db_handler.py add_domain <domain>                # Add a single domain
   ./mongo_db_handler.py add_subdomain <domain> <subdomain> # Add a single subdomain
   ./mongo_db_handler.py list_domains                       # List all domains
   ./mongo_db_handler.py get_subdomains <domain>           # Get subdomains for domain
   ./mongo_db_handler.py add_subdomains_file <domain> <file> # Add subdomains from file
   ```

4. **Security Best Practices:**
   - Store your MongoDB URI in an environment variable
   - Use strong authentication
   - Implement proper error handling
   - Add input validation for domains and subdomains
   - Use indexes for better performance

5. **Enable MongoDB Storage:**
   Once your handler is set up, use the `--save-to-db` flag:
   ```bash
   ./autoAr.sh -d example.com --save-to-db
   ```

### Database Schema

Recommended schema for your MongoDB collections:

```javascript
// domains collection
{
    "_id": ObjectId,
    "domain": String  // indexed, unique
}

// subdomains collection
{
    "_id": ObjectId,
    "domain_id": ObjectId,  // reference to domains collection
    "subdomain": String     // indexed
}
```

For a complete implementation example or assistance, please open an issue on the GitHub repository.

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
- MongoDB integration provides persistent storage of findings
- SecurityTrails API integration enhances subdomain discovery (API key required) 