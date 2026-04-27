# APK Auditor

[![JavaScript](https://img.shields.io/badge/JavaScript-Client--Side-F7DF1E?style=flat&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)](../../releases)

Android APK security analysis tool that runs in the browser. Drop an APK file, it decompiles the DEX, parses the manifest, scans for issues, and lets you browse the code. Nothing gets uploaded anywhere.

<img width="1547" height="853" alt="image" src="https://github.com/user-attachments/assets/983ac4c4-b1d3-4b07-9c51-1c28b60318fb" />


## What It Does

**DEX Decompiler** : reads DEX bytecode and converts it to Java pseudocode and Smali disassembly. Class trees, method signatures, field listings, string extraction.

**Security Scanner** : 80+ rules covering hardcoded secrets, weak crypto, insecure HTTP, exported components, WebView vulns, intent issues, SQL injection, certificate pinning bypasses, and more. Findings tagged with CWE, OWASP Mobile Top 10, MASVS.

**Manifest Parser** : decodes binary AXML. Exported components, permissions, SDK versions, backup flags, deep link schemes, task hijacking, custom permissions.

**Certificate Analysis** : reads signing certs from the APK

**Component Inspector** : lists all exported activities, services, receivers, providers with intent filters and permissions. Generates ADB commands to test each one.

<img width="1725" height="806" alt="image" src="https://github.com/user-attachments/assets/c0460bd6-5ce5-440c-9bbb-93f991370470" />


**Tracker Detection** : identifies 38+ ad SDKs, analytics, crash reporters, payment libs from DEX strings.

**File Explorer** : browse APK contents. XML, JSON, images, databases, .so files with syntax highlighting or hex view.

**PDF Export** : findings report with all instances.

## Use It

Go to [apkauditor.com](https://apkauditor.com) and drop an APK.

## Run Locally

Open `index.html` in Chrome, Firefox, or Edge. Or serve it:

```bash
python -m http.server 8000
```

## Quick Start

Open the page, drag and drop an APK onto the drop zone. Wait for analysis to finish. Browse the five tabs: Overview, Findings, Code & Explorer, Components, Manifest.

Click any finding to jump to the source. Use the sidebar search to find classes, methods, strings across all decompiled code.

## Security Rules

| Category | What it checks |
|----------|---------------|
| Storage | World-readable/writable files, external storage, SharedPreferences, SQLite raw queries |
| Crypto | Weak hashes (MD5, SHA-1), hardcoded keys, ECB mode, static IVs, no padding, deprecated ciphers |
| Network | Cleartext HTTP, missing cert pinning, custom TrustManagers, hostname verifier bypasses |
| Components | Exported without permissions, intent redirection, pending intent mutability, deep link hijacking |
| WebView | JavaScript enabled, file access, debug mode, content provider access, mixed content |
| Secrets | API keys (Google, AWS, Firebase, Stripe, Twilio, etc.), hardcoded passwords and tokens |
| Code | Reflection, dynamic class loading, native libs, clipboard access, screenshot flags |

## Multi-DEX Support

Handles APKs with multiple DEX files (classes.dex through classes9.dex). All get parsed and scanned.

## Project Structure

```
index.html         - UI and styling
apk-analyzer.js    - all analysis logic
lib/
  jszip.min.js     - ZIP extraction (MIT)
  jspdf.umd.min.js - PDF export (MIT)
```

## How It Works

Everything runs client-side in JavaScript. The APK is extracted with JSZip, DEX files are parsed from binary, bytecode is translated to Java pseudocode through register tracking and pattern matching, binary XML is decoded from AXML format, and certificates are parsed from PKCS#7/DER. No server, no uploads, no external calls.

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

For authorized security testing and educational use only. Get permission before analyzing APKs you don't own.

## Author

[Sandeep Wawdane](https://www.linkedin.com/in/sandeepwawdane/)
