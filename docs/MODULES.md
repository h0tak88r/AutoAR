# AutoAR Modules Reference

This document outlines the exhaustive list of modules embedded directly within AutoAR, including how they map explicitly to user interface panels and what artifact outputs they generate.

## 1. Mock Data / Test Targets
AutoAR includes a hard-routed demo trap-door configured for local developer testing. Submitting any of the following targets intercepts actual system tools and initiates an immediate generation of synthetic mock payloads to validate your UI state natively across every artifact:
*   `keyword.com`
*   `0x88.autoar`
*   `demo.autoar.com`

### Generated Mock Payloads
The following items explicitly describe what is returned when the internal test suite fires.

| UI Tab | Module Name | Mock Target Output | Vulnerability Type / Finding | Severity |
| :--- | :--- | :--- | :--- | :--- |
| **Links** | **URL-Enum** | `https://0x88.autoar/api`<br>`https://0x88.autoar/admin`<br>`https://0x88.autoar/test` | *URL-Enum* | **INFO** |
| **Links** | **JS-Enum** | `https://0x88.autoar/main.js`<br>`https://0x88.autoar/vendor.chunk.js` | *JS-Enum* | **INFO** |
| **Vulnerabilities** | **Nuclei** | `https://0x88.autoar/api` | `cve-2023-1000` | **HIGH** |
| **Vulnerabilities** | **S3 Scan** | `0x88.autoar-bucket` | `s3-scan-open` | **CRITICAL** |
| **Vulnerabilities** | **Backup Files** | `https://0x88.autoar/backup.zip` | `backup-detection` | **HIGH** |
| **Vulnerabilities** | **Port Scan** | `0x88.autoar` | `Open Port 8080 (http-alt)` | **INFO** |
| **Vulnerabilities** | **JS Analysis** | `https://0x88.autoar/main.js` | `[AWS API Key]: AKIA1234567890` | **HIGH** |
| **Vulnerabilities** | **ZeroDays** | `https://0x88.autoar` | `CVE-2024-XXXX Node.js Remote Code Execution` | **CRITICAL** |
| **Vulnerabilities** | **AEM Scan** | `https://0x88.autoar/aem` | `AEM Default Credentials` | **CRITICAL** |
| **Vulnerabilities** | **Misconfig** | `https://0x88.autoar/.git` | `Exposed Git Directory` | **MEDIUM** |
| **Vulnerabilities** | **Dep Confusion** | `https://0x88.autoar/wp-content` | `WordPress Missing Theme` | **MEDIUM** |
| **Vulnerabilities** | **Dep Confusion** | `package.json` | `Dependency Confusion in 'internal-core'` | **HIGH** |

---

## 2. Active Production Modules (Not Mocked)
These modules are invoked dynamically during legitimate attack surface mapping. They do not trigger artificial simulation results on the demo endpoints, but evaluate payloads rigorously across production targets:

| Module Identifier | System Role / Engine | Principal UI Mapping |
| :--- | :--- | :--- |
| **Subdomain Enum** | `subfinder` & active bruteforce variants | **Assets** |
| **Tech Detect** | `wappalyzer` HTTP structure scanning | **Assets** |
| **FFuf Fuzzing** | `ffuf` (dictionary enumeration / recursion) | **Vulnerabilities** *(paths/secrets)* |
| **XSS Detection** | `dalfox` / `kxss` parameter fuzzing | **Vulnerabilities** |
| **SQL Injection** | `sqlmap` (threaded over sync.WaitGroup pool) | **Vulnerabilities** |
| **GF Patterns** | `gf` pattern clustering & structural mapping | **Vulnerabilities** |
| **DNS Takeover** | Orphaned record identification (`dnsreap`) | **Vulnerabilities** |
| **Cloudflare DNS** | `cf1016` edge-server routing evaluation | **Vulnerabilities** |
| **Github Scan** | `trufflehog` live repository scraping | **Vulnerabilities** / Log DB |

---

> *Maintained natively by AutoAR's structural parser backend (`inferModuleFromFileName`).*
