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

### Command Line Tool

Basic usage:
```bash
./autoAr.sh -d example.com
```

Options:
- `-d DOMAIN` : Single target domain
- `-l FILE` : File containing list of domains
- `-s SUBDOMAIN` : Single subdomain to scan

### Web Interface Setup

1. Backend Setup:
```bash
cd autoAR-web/backend
python3 -m venv venv
source venv/bin/activate  # On Unix/macOS
pip install flask flask-cors
python app.py
```
The backend will run on http://localhost:5000

2. Frontend Setup:
```bash
cd autoAR-web/frontend
npm install
npm run dev
```
The frontend will run on http://localhost:3000

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
