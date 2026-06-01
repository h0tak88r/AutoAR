# IPA Auditor

<p align="center">
  <img src="https://github.com/user-attachments/assets/4ae2b72d-6d10-4a39-95ab-bc167728b034" alt="IPA Auditor Logo" width="120">
</p>

<p align="center">
  <strong>iOS Static Security Analysis Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Web-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Checks-50%2B%20OWASP%20MASVS-green?style=flat-square" alt="Security Checks">
  <img src="https://img.shields.io/badge/Privacy-100%25%20Client--Side-purple?style=flat-square" alt="Privacy">
</p>


<p align="center">
  <a href="https://ipaauditor.com"> Live Demo</a>
</p>

---

### Overview

IPA Auditor is a browser-based static security analysis tool for iOS applications. It performs comprehensive security scanning of IPA files based on OWASP MASVS guidelines without requiring any server-side processing or file uploads.

** 100% Client-Side** - All analysis happens in your browser. Your IPA files are never uploaded anywhere.

## Features

| Feature | Description |
|---------|-------------|
|  **Static Analysis** | 50+ security checks based on OWASP MASVS guidelines |
|  **Binary Security** | PIE, ARC, Stack Canary, and encryption verification |
|  **File Explorer** | Browse IPA contents with syntax highlighting |
|  **Secret Detection** | Find hardcoded API keys, tokens, and credentials |
|  **Plist Analysis** | Parse and analyze Info.plist and embedded plists |
|  **Permission Audit** | Review app permissions and privacy descriptions |
|  **URL Scheme Analysis** | Identify custom URL schemes and deep links |
|  **Tracker Detection** | Identify embedded analytics and tracking SDKs |
|  **PDF Reports** | Export detailed security assessment reports |

## Screenshots

![ipa auditor 1](https://github.com/user-attachments/assets/6ec121f7-b6e4-44e4-af15-c61e9e4f0492)

---

###  iOS Security Analysis Dashboard

![dashbord](https://github.com/user-attachments/assets/2af0c96d-f113-4c51-ae6f-1329e6551f88)


---

###  Security Findings & Vulnerability Analysis
Comprehensive security findings categorized by severity with detailed remediation guidance based on OWASP MASVS.

![ipa 2](https://github.com/user-attachments/assets/71e94d65-3df9-4bb5-bf5d-732164600a09)

---

###  IPA File Explorer with Hex Viewer
Full-featured file browser with syntax highlighting, hex viewer, and string extraction for binary analysis.

![ipa aud 3](https://github.com/user-attachments/assets/0420a915-5351-4d77-87eb-be20d61ab1ee)



##  Security Checks

IPA Auditor performs **50+ security checks** across multiple categories:

###  Data Storage
- NSUserDefaults Insecure Storage
- CoreData Unencrypted Storage
- Realm Database Encryption
- SQLite Database Usage
- Keychain Secure Storage
- Plist File Write Operations

###  Cryptography
- Weak Hash Algorithms (MD5, SHA1)
- Weak Encryption (DES/3DES)
- ECB Mode Encryption
- Insecure Random Generator
- Hardcoded Secrets/Passwords

###  Network Security
- Insecure HTTP URLs
- SSL/TLS Validation Disabled
- SSL Pinning Implementation
- ATS Configuration Analysis
- Weak TLS Versions

###  App Security
- Jailbreak Detection
- Anti-Debug Protection
- PIE (Position Independent Executable)
- Stack Canary Protection
- ARC (Automatic Reference Counting)

###  Platform Security
- Deprecated UIWebView Usage
- JavaScript in WebView
- Custom URL Scheme Handlers
- Universal Links Validation
- Clipboard/Pasteboard Access

###  Cloud & APIs
- AWS S3 Bucket Exposure
- Firebase Database URLs
- Google API Key Exposure
- Hardcoded Tokens/Bearer

###  Privacy & Tracking
- Location Tracking
- Contacts Access
- Camera/Microphone Access
- Debug Logging
- Tracker/SDK Detection

##  Usage

### Online Version
Visit [ipaauditor.com](https://ipaauditor.com) to use the tool directly in your browser.

### Local Setup

```bash
# Clone the repository
git clone https://github.com/thecybersandeep/ipaauditor.git

# Navigate to the directory
cd ipaauditor
```

#### Option 1: Direct File Opening (Simplest) 

Simply double-click `index.html` to open it in your browser. **It works offline!**

```bash
# Windows
start index.html

# macOS
open index.html

# Linux
xdg-open index.html
```

#### Option 2: Local Server (For Development)

If you prefer using a local server:

**Python:**
```bash
python -m http.server 8000
# Open http://localhost:8000
```

**Node.js:**
```bash
npx serve .
# Open http://localhost:3000
```

**VS Code:** Install "Live Server" extension → Right-click `index.html` → "Open with Live Server"

### How to Use
1. **Drop or Select** your IPA file
2. **Wait** for the analysis to complete
3. **Review** findings across different tabs:
   - **Overview**: App info, permissions, trackers
   - **Findings**: Security issues grouped by severity
   - **Binary**: Checksec results and libraries
   - **Explorer**: Browse and inspect all files

4. **Export** a detailed PDF report

##  Privacy

**Your data never leaves your device.**

-  100% client-side processing
-  No server uploads
-  No data collection
-  No tracking
-  Works offline (after initial load)

##  Report Export

Generate professional PDF reports containing:
- Application metadata
- Security score
- All findings with severity levels
- Binary security checks
- Permissions analysis
- Detected trackers/SDKs
- CWE and OWASP references

##  Project Structure

```
ipaauditor/
├── index.html          # Main application page
├── ipa-analyzer.js     # Core analysis engine
├── lib/                # Third-party libraries
│   ├── jszip.min.js    # ZIP file processing
│   ├── plist.min.js    # Property list parsing
│   └── jspdf.umd.min.js # PDF generation
├── start-server.bat    # Windows server launcher
├── start-server.sh     # Mac/Linux server launcher
├── README.md           # This file
├── LICENSE             # CC BY-NC-ND 4.0
└── CNAME               # Custom domain config
```

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before analyzing any application. The authors are not responsible for any misuse of this tool.

**Note:** This is an automated pattern-matching scanner, NOT a comprehensive security audit. Results are indicative only and require manual verification by a qualified security professional.

##  Built With

- **JSZip** - ZIP file processing
- **plist.js** - Property list parsing
- **jsPDF** - PDF report generation
- **Vanilla JS** - No framework dependencies

## Author

**Sandeep**

- LinkedIn: [@sandeepwawdane](https://www.linkedin.com/in/sandeepwawdane/)
- GitHub: [@thecybersandeep](https://github.com/thecybersandeep)


##  Related Projects

- [ADB Auditor](https://adbauditor.com) - Android Security Analysis Tool
