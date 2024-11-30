# AutoAR - Automated Attack and Reconnaissance Tool

```
 ▗▄▖ ▗▖ ▗▖▗▄▄▄▖▗▄▖  ▗▄▖ ▗▄▄▖ 
▐▌ ▐▌▐▌ ▐▌  █ ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌
▐▛▀▜▌▐▌ ▐▌  █ ▐▌ ▐▌▐▛▀▜▌▐▛▀▚▖
▐▌ ▐▌▝▚▄▞▘  █ ▝▚▄▞▘▐▌ ▐▌▐▌ ▐▌
                              By: h0tak88r
```

AutoAR is a comprehensive web-based security scanning and vulnerability management platform that automates the process of reconnaissance and vulnerability assessment across multiple domains.

## Core Features

### Command Line Tool
- Subdomain Enumeration
- URL Discovery and Analysis
- Port Scanning
- Parameter Discovery and Analysis
- JavaScript File Analysis
- Vulnerability Scanning
- Discord Integration for Notifications
- Customizable Scanning Options

### Web Interface Components
1. **Dashboard**
   - Vulnerability statistics
   - Scan overview
   - Recent scan tracking

2. **Vulnerabilities Page**
   - Detailed vulnerability listing
   - Filtering by severity and status
   - Comprehensive vulnerability details

3. **Attack Surface Page**
   - Endpoint discovery
   - Subdomain tracking
   - Technology stack identification

4. **Settings Page**
   - Tool configuration management
   - Notification settings
   - Scan default preferences

5. **Best Practices Page**
   - Security recommendations
   - Categorized best practices
   - Severity-based guidance

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

## Technology Stack

### Backend
- Flask (Python)
- Flask-CORS
- Virtual Environment

### Frontend
- Next.js
- TypeScript
- Tailwind CSS
- React

## Project Structure
```
autoAR/
├── autoAr.sh              # Main command line tool
├── autoAR-web/           # Web interface
│   ├── backend/
│   │   ├── app.py
│   │   └── venv/
│   ├── frontend/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── styles/
│   │   └── public/
│   └── README.md
└── results/              # Scan results directory
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/h0tak88r/AutoAR.git
cd AutoAR
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

### Command Line Interface (CLI)

The tool can be run directly from the command line with various options:

```bash
# Basic usage with a single domain
./autoAr.sh -d example.com

# Scan multiple domains from a file
./autoAr.sh -l domains.txt

# Scan a specific subdomain
./autoAr.sh -s subdomain.example.com

# Full scan with all modules
./autoAr.sh -d example.com --full

# Custom scan with specific modules
./autoAr.sh -d example.com --subdomains --urls --ports

# Silent mode (no banner)
./autoAr.sh -d example.com --silent

# Specify custom output directory
./autoAr.sh -d example.com -o /path/to/output
```

Available CLI Options:
- `-d, --domain` : Single target domain
- `-l, --list` : File containing list of domains
- `-s, --subdomain` : Single subdomain to scan
- `-o, --output` : Custom output directory
- `--full` : Run all scanning modules
- `--subdomains` : Run only subdomain enumeration
- `--urls` : Run only URL discovery
- `--ports` : Run only port scanning
- `--params` : Run only parameter discovery
- `--js` : Run only JavaScript analysis
- `--vulns` : Run only vulnerability scanning
- `--silent` : Run without banner and minimal output
- `--notify` : Enable Discord notifications
- `--help` : Show help message

### Web Interface (GUI)

The web interface provides a user-friendly way to manage and visualize scans:

1. Start the Backend Server:
```bash
cd autoAR-web/backend
source venv/bin/activate  # On Unix/macOS
# or
.\venv\Scripts\activate  # On Windows
python app.py
```
The backend API will be available at `http://localhost:5000`

2. Start the Frontend Server:
```bash
cd autoAR-web/frontend
npm install  # Only needed first time
npm run dev
```
The web interface will be accessible at `http://localhost:3000`

3. Using the Web Interface:
   - Navigate to `http://localhost:3000` in your browser
   - Use the dashboard to:
     - Start new scans
     - Monitor ongoing scans
     - View scan results
     - Configure scan settings
     - Manage notifications
     - Export reports

4. API Endpoints (for developers):
```bash
# Start a new scan
curl -X POST http://localhost:5000/api/scan -d '{"domain": "example.com"}'

# Get scan status
curl http://localhost:5000/api/scan/status/<scan_id>

# Get scan results
curl http://localhost:5000/api/scan/results/<scan_id>
```

## Features in Development
- Backend API integration for real data
- Persistent configuration storage
- Advanced error handling
- Authentication mechanism
- Comprehensive result parsing
- Machine learning-based vulnerability prediction
- Advanced reporting capabilities
- Integration with external security platforms
- Containerization support
- CI/CD pipeline integration

## Security Considerations
- Input validation
- Secure header implementation
- Rate limiting
- Webhook notification security
- Configurable tool options

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
