# ADB Auditor

<p align="center">
  <img src="img/logo.svg" alt="ADB Auditor Logo" width="120">
</p>

<p align="center">
  <strong>Android Security Auditing Platform</strong>
</p>

<p align="center">
  <a href="https://adbauditor.com/">Live</a> •
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#documentation">Documentation</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Web-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Protocol-WebUSB%20%2B%20ADB-green?style=flat-square" alt="Protocol">
  <img src="https://img.shields.io/badge/Privacy-100%25%20Client--Side-purple?style=flat-square" alt="Privacy">
  <img src="https://img.shields.io/github/license/thecybersandeep/adbauditor?style=flat-square" alt="License">
</p>

---

## Overview

ADB Auditor is a browser-based Android security auditing tool designed for penetration testers, security researchers, and cybersecurity professionals. It connects to Android devices via WebUSB and provides comprehensive security analysis capabilities without requiring any server-side processing.

**🔒 100% Client-Side** - All data processing happens in your browser. No data is ever uploaded to any server.

## Features

| Feature | Description |
|---------|-------------|
| 📱 **App Analysis** | List installed applications, extract APK files, analyze permissions and signatures |
| 📂 **File Browser** | Navigate device filesystem with root support, upload/download files |
| 🗄️ **Storage Audit** | Analyze SharedPreferences, SQLite databases, identify sensitive data exposure |
| 💻 **Shell Access** | Direct ADB shell with command history and autocomplete |
| 📸 **Screenshot** | Capture device screen for documentation and evidence |
| 🔐 **Security Scan** | Automated security checks for common vulnerabilities |
| 📊 **Device Info** | Comprehensive device information and system properties |

## Screenshots

### 🔐 Android Security Auditing Dashboard
Modern, client-side Android security auditing interface with WebUSB + ADB support. Connect devices securely and perform deep analysis without uploading data.
  
![ADB Auditor Dashboard](https://github.com/user-attachments/assets/eab09ce1-ce31-44cd-b02d-131fa14d5faa)

---

### 🧩 Local Storage & App Data Analysis (Root)
Analyze application storage with root access, including SharedPreferences, databases, and internal files for advanced security assessments.
  
![ADB File Browser](https://github.com/user-attachments/assets/75fa83b4-e195-488b-9fdc-5fa248cb2e30)
---

### 📁 Root File Browser via ADB
Full-featured file browser powered by ADB with optional root mode, enabling navigation, upload, download, and inspection of device file systems.
  
![Root Storage Analysis](https://github.com/user-attachments/assets/fbd571d0-3790-4f85-b3bd-807c878087f9)


## Requirements

### Browser Support
- Google Chrome 89+
- Microsoft Edge 89+
- Opera 75+

> ⚠️ **Note:** Firefox and Safari do not support WebUSB API

### Device Requirements
- Android device with USB Debugging enabled
- USB data cable (not charge-only)
- For full analysis: Rooted device (optional but recommended)


## Installation

### Option 1: Use Online (Recommended)
Visit [https://adbauditor.com/](https://adbauditor.com/)

### Option 2: Run Locally (No Hosting Required)

```bash
# Clone the repository
git clone https://github.com/thecybersandeep/adbauditor.git

# Navigate to directory
cd adbauditor

# Open directly in browser (recommended)
google-chrome index.html
```

### Option 3: Self-Host

```
# Clone the repository
git clone https://github.com/thecybersandeep/adbauditor.git

# Navigate to directory
cd adbauditor

# Serve with any static server
python -m http.server 8080
# or
npx serve .
# or
php -S localhost:8080
```

### Option 4: Docker

```
# Using Docker Compose
docker-compose up -d

# Or using Docker directly
docker build -t adbauditor .
docker run -p 8080:80 adbauditor
```

Access at `http://localhost:8080`

## Usage

### Quick Start

1. **Enable USB Debugging** on your Android device:
   - Go to `Settings` → `About Phone`
   - Tap `Build Number` 7 times to enable Developer Options
   - Go to `Settings` → `Developer Options`
   - Enable `USB Debugging`

2. **Connect your device** via USB cable

3. **Open ADB Auditor** in Chrome/Edge

4. **Click "Connect"** and select your device from the browser popup

5. **Accept the USB debugging prompt** on your device


## Documentation

### File Structure

```
adbauditor/
├── js/
│   ├── adb-core.js         # ADB protocol implementation
│   ├── app.js              # Main application logic
│   └── security-auditor.js # Security scanning module
├── img/
│   └── logo.svg            # Application logo
├── docs/
│   ├── API.md              # API documentation
│   └── SECURITY.md         # Security considerations
├── index.html              # Main application
├── 404.html                # Error page
├── robots.txt              # SEO robots file
├── sitemap.xml             # SEO sitemap
├── LICENSE                 # MIT License
└── README.md               # This file
```

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + 1-6` | Switch between tabs |
| `Ctrl + R` | Refresh current view |
| `Ctrl + D` | Disconnect device |
| `↑ / ↓` | Navigate shell history |

## Privacy & Security

- **Zero Data Upload**: All processing is done locally in your browser
- **No Tracking**: No analytics, telemetry, or tracking of any kind
- **No Account Required**: Use immediately without registration
- **Open Source**: Full source code available for audit

## Troubleshooting

### Device Not Detected

1. Try a different USB cable (ensure it's a data cable)
2. Try a different USB port
3. Revoke USB debugging authorizations and re-authorize
4. Restart ADB on device: `adb kill-server && adb start-server`

### Connection Lost

1. Check USB cable connection
2. Disable battery optimization for USB debugging
3. Keep device screen on during transfer

### Permission Denied

1. Enable Root toggle for protected directories
2. Grant root access on device when prompted
3. Some system files may still be inaccessible



## License

This project is licensed under the License: CC BY-NC-ND 4.0



## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any device. The authors are not responsible for any misuse of this tool.

## Author

**Sandeep Wawdane**

- LinkedIn: [@sandeepwawdane](https://www.linkedin.com/in/sandeepwawdane/)
- GitHub: [@thecybersandeep](https://github.com/thecybersandeep)

---

<p align="center">
  Made with ❤️ for the Security Community
</p>

<p align="center">
  <a href="https://github.com/thecybersandeep/adbauditor/stargazers">⭐ Star this repo</a> if you find it useful!
</p>
