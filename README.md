# AutoAR — Automated Attack & Reconnaissance Platform

<div align="center">

**The ultimate bug bounty automation framework. Scan smarter, find more, ship faster.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Discord](https://img.shields.io/badge/Interface-Discord_Bot-5865F2?logo=discord)](https://discord.com)

</div>

---

AutoAR is a powerful, end-to-end automated security reconnaissance and vulnerability hunting platform built in Go. It is purpose-built for **bug bounty hunters** and **penetration testers** who want to automate the full recon-to-report pipeline at scale — from subdomain enumeration and DNS takeover detection to nuclei scanning, JavaScript secrets extraction, GitHub exposure, mobile app analysis, and more.

Results are automatically uploaded to **Cloudflare R2 storage** and linked directly in your output — no hunting through directories.

---

## ✨ Feature Highlights

| Category | What AutoAR Does |
|---|---|
| 🌐 **Subdomains** | Enumerate using 15+ sources: Subfinder, CertSpotter, SecurityTrails, Chaos, crt.sh, OTX, VirusTotal, and more |
| 🔍 **Live Hosts** | Detect alive hosts using httpx with follow-redirects and status detection |
| 🕳️ **DNS Takeovers** | Detect CNAME, NS, Azure/AWS cloud, DNSReaper, and dangling-IP takeover opportunities |
| 💥 **Nuclei Scanning** | Automated vulnerability scanning using Nuclei templates with rate limiting |
| 🧠 **Zero-Days** | Smart scan configured for detected tech stacks — finds active CVEs |
| ☁️ **S3 Buckets** | Enumerate and scan AWS S3 buckets for exposure and misconfig |
| 🔗 **JavaScript** | Extract secrets, API endpoints, auth tokens from JS files |
| 🐙 **GitHub Recon** | Org-level and repo-level scanning for secrets, dependency confusion |
| 📱 **Mobile Apps** | APK/IPA analysis with MobSF + MITM traffic interception |
| ⚙️ **Misconfigs** | 100+ service misconfiguration checks |
| 🏴‍☠️ **BB Scope** | Fetch scope from HackerOne, Bugcrowd, Intigriti, YesWeHack, Immunefi |
| 🔄 **Monitoring** | Subdomain + URL change monitoring daemon with Discord alerts & DB history |
| 🤖 **AI Agent** | Full AI hunt loop (CLI + Discord `/ai` & `/brain`) — powered by **Step-3.5 Flash via OpenRouter (free tier)** — zero cost required |
| 📤 **R2 Storage** | Auto-upload every non-empty result file to Cloudflare R2 and print the public URL |

---

## 🗂️ Complete Command Reference

### Workflows (Start Here)

```
autoar domain run      -d <domain>           Full end-to-end workflow: subdomains → live hosts → ports →
                       [--skip-ffuf]         tech → DNS → S3 → nuclei → JS → URLs → GF → backup → misconfig

autoar subdomain run   -s <subdomain>        Focused deep-dive on a single subdomain:
                                             live check → ports → JS → vuln scan → nuclei

autoar lite run        -d <domain>           Lighter workflow: livehosts → reflection → JS → CNAME → DNS → misconfig

autoar fastlook run    -d <domain>           Quick recon: subdomains → live hosts → URLs/JS collection
```

### Reconnaissance

```
autoar subdomains get  -d <domain>            Enumerate subdomains (15+ passive sources + Subfinder)
autoar livehosts get   -d <domain>            Detect live hosts via httpx
autoar cnames get      -d <domain>            Collect all CNAME records
autoar urls collect    -d <domain>            Collect URLs (Wayback, gau, katana)
                       [--subdomain]          Focus on specific subdomain URLs
autoar tech detect     -d <domain>            Detect web technologies (Wappalyzer, headers)
autoar ports scan      -d <domain>            Port scan with naabu
```

### Vulnerability Scanning

```
autoar nuclei run      -d <domain>            Run Nuclei templates on all live hosts
autoar zerodays scan   -d <domain>            Smart CVE scanning based on detected tech
                       -s <subdomain>         Scan a specific subdomain
                       -f <domains_file>      Scan domains from a file
                       [--cve <CVE-ID>]       Target a specific CVE
                       [--dos-test]           Include DoS checks (use on your own targets only)
                       [--silent]             Output only vulnerable hosts
autoar reflection scan -d <domain>            Scan for XSS/injection reflection points
autoar dalfox run      -d <domain>            Advanced XSS scanning with Dalfox
autoar sqlmap run      -d <domain>            SQL injection testing with SQLMap
autoar gf scan         -d <domain>            Grep for interesting patterns (SQLi, SSTI, LFI, etc.)
autoar jwt scan        --token <JWT_TOKEN>    Analyze JWT tokens for vulnerabilities
                       [--skip-crack]
                       [--test-attacks]
                       [-w <wordlist>]
```

### DNS Takeover Detection

```
autoar dns takeover    -d <domain>            Comprehensive DNS takeover scan (all methods)
autoar dns cname       -d <domain>            CNAME takeover detection
autoar dns ns          -d <domain>            Nameserver takeover detection
autoar dns azure-aws   -d <domain>            Azure/AWS cloud service takeover
autoar dns dnsreaper   -d <domain>            DNSReaper-based detection
autoar dns dangling-ip -d <domain>            Dangling IP detection
autoar dns all         -d <domain>            Run all DNS checks simultaneously
```

### JavaScript Scanning

```
autoar js scan         -d <domain>            Scan all JS files for secrets and endpoints
                       [-s <subdomain>]       Scope to a specific subdomain's JS
```

### Fuzzing (FFUF)

```
autoar ffuf fuzz       -u <url>               Fuzz a URL (must contain FUZZ placeholder)
                       -d <domain>            Fuzz all live hosts for a domain
                       [-w <wordlist>]        Custom wordlist (default: Wordlists/quick_fuzz.txt)
                       [-t <threads>]         Thread count
                       [--bypass-403]         Attempt 403 bypass techniques
                       [--recursion]          Recursive fuzzing
                       [-e <extensions>]      File extensions to fuzz
                       [--header <k:v>]       Custom headers
```

### Backup File Discovery

```
autoar backup scan     -d <domain>            Hunt for exposed backup files on a domain
                       -l <live_hosts_file>   Scan from a file of live hosts
                       -f <domains_file>      Scan from a file of domains
                       [-m <method>]          Methods: regular, withoutdots, withoutvowels,
                                              reverse, mixed, withoutdv, shuffle, all
                       [-ex .zip,.rar]        Specific extensions to hunt
                       [-t <threads>]         Thread count
```

### S3 Bucket Hunting and Cloud Storage

```
autoar s3 enum         -b <root_domain>       Generate and check S3 bucket name permutations
autoar s3 scan         -b <bucket_name>       Scan a specific bucket for access
                       [-r <region>]          AWS region
```

### GitHub Reconnaissance

```
autoar github scan     -r <owner/repo>        Scan a single repository for secrets
autoar github org      -o <org>               Full org-level scan (all repos)
                       [-m <max-repos>]       Limit number of repos scanned
autoar github depconfusion -r <owner/repo>    Check for dependency confusion
autoar github experimental -r <owner/repo>    Deep experimental analysis
autoar github-wordlist scan -o <github_org>   Build wordlist from org's codebase
```

### Misconfiguration Detection

```
autoar misconfig scan  <target>               Scan for common misconfigurations (100+ checks)
                       [--service <id>]       Test a specific service
                       [--delay <ms>]         Request delay
                       [--permutations]       Include path permutations
autoar misconfig service <target> <service>   Test a single service
autoar misconfig list                          List all available service checks
autoar misconfig update                        Update built-in templates
```

### API Key Validation

```
autoar keyhack list                           List all API key validation templates
autoar keyhack search  <query>               Search for a specific provider
autoar keyhack validate <provider> <api_key> Generate validation command for an API key
autoar keyhack add <name> <cmd> <desc>       Add a custom validation template
```

### Adobe Experience Manager (AEM)

```
autoar aem scan        -d <domain>            Detect AEM instances and test vulnerabilities
                       -l <live_hosts_file>   Scan from a file
                       [--ssrf-host <host>]   SSRF callback host
                       [--proxy <proxy>]      HTTP proxy
```

### Mobile Application Analysis (APKx)

```
autoar apkx scan       -i <apk_or_ipa_path>  Analyze an APK or IPA file
                       -p <package_id>        Download and scan by package ID
                       [--platform android|ios]
                       [--mitm]               Set up MITM proxy interception
autoar apkx mitm       -i <apk_path>          Patch APK for MITM traffic analysis
```

### Dependency Confusion

```
autoar depconfusion scan <file>               Scan a local dependency file
autoar depconfusion github repo <owner/repo>  Scan a GitHub repo's dependencies
autoar depconfusion github org <org>          Scan all repos in a GitHub org
autoar depconfusion web <url> [url2...]       Scan web targets
autoar depconfusion web-file <file>           Scan targets listed in a file
autoar wpDepConf scan  -d <domain>            WordPress plugin dependency confusion
                       -l <live_hosts_file>
```

### Bug Bounty Platform Scope Fetching

```
autoar scope -p h1  -u <username> -t <token>        HackerOne
autoar scope -p bc  -e <email> -P <password>         Bugcrowd
autoar scope -p it  -t <token>                        Intigriti
autoar scope -p ywh -e <email> -P <password>         YesWeHack
autoar scope -p immunefi                              Immunefi

Options:
  --bbp-only         Only programs offering monetary rewards
  --pvt-only         Only private programs
  --active-only      Only active programs
  --extract-roots    Extract root domains (default: true)
  -o <output>        Save output to a file
```

### Subdomain Monitoring

The monitoring daemon uses a dedicated `last_run_at` DB column (fixes the old timer bug), persists every detected change to `monitor_changes` for history, and sends Discord webhook alerts automatically.

```
autoar monitor subdomains -d <domain>         One-time check for subdomain changes
                          [--check-new]       Alert on newly discovered subdomains

autoar monitor subdomains manage add    -d <domain> -i <interval_sec>
autoar monitor subdomains manage list
autoar monitor subdomains manage start  --all | --id <id> | -d <domain>
autoar monitor subdomains manage stop   --all
```

### AI Agent Commands

Autonomous bug hunting directly from the terminal — no Discord required.

```
autoar agent "<request>" [--json]
    Run the full AI agent loop (up to 20 iterations) from the CLI.
    Example: autoar agent "find XSS vulnerabilities on example.com"
    Example: autoar agent "full recon on example.com" --json

autoar explain <result-file> [--json]
    Feed any scan result file to the AI for triage and follow-up suggestions.
    Example: autoar explain new-results/example.com/nuclei-output.txt
    Example: autoar explain new-results/example.com/js-secrets.txt --json

autoar status [--json]
    Show runtime metrics and DB scan progress.
    Useful for AI agents polling long-running scans:
    Example: autoar status --json
    Returns: { "active_scans": [ { "target": "...", "current_phase": 4, "total_phases": 12 } ] }
```


---

## 🤖 AI-Driven Security Framework — Free for Everyone

As of the latest release, AutoAR's AI engine runs on **[`stepfun/step-3.5-flash:free`](https://openrouter.ai/stepfun/step-3.5-flash:free)** via [OpenRouter](https://openrouter.ai). This is a **completely free model** — no credits, no billing required.

> **Every AutoAR user can now access a full AI-driven bug bounty framework at zero cost** — just sign up for a free OpenRouter account and paste your key into `.env`.

### What the AI powers

| Discord Command | What it does |
|---|---|
| `/ai message:<request>` | Chat with AutoAR AI in natural language. Describe your target and it will queue the right scans automatically. |
| `/ai message:<request> agent_mode:True` | Autonomous agent loop — the AI plans, runs tools, validates findings, and reports confirmed bugs. |
| `/ai message:<request> dry_run:True` | Preview what scans would run without executing anything. |
| `/brain` | AI analysis of your latest scan results — suggests next-step attacks and highlights interesting findings. |
| `autoar agent "<request>"` | Same autonomous agent loop from the terminal (no Discord needed). |
| `autoar explain <result-file>` | Feed any result file to the AI for triage and follow-up suggestions. |

### Getting your free OpenRouter key

1. Go to [openrouter.ai](https://openrouter.ai) and create a **free account** (no credit card required for free models)
2. Navigate to **Keys** → **Create Key**
3. Copy your key and add it to `.env`:

```env
OPENROUTER_API_KEY=sk-or-v1-...
```

That's it. AutoAR will automatically use `stepfun/step-3.5-flash:free` for all `/ai` and `/brain` commands.

> **Tip:** If `OPENROUTER_API_KEY` is set, it is used first. `GEMINI_API_KEY` is a fallback for direct Gemini access. You only need one of the two.


### Database & Results

```
autoar db domains list                         List all scanned domains
autoar db domains delete    -d <domain>        Remove a domain from the database
autoar db subdomains list   -d <domain>        List all stored subdomains for a domain
autoar db subdomains export -d <domain>        Export subdomains to a file
                            [-o <output.txt>]
autoar db js list           -d <domain>        List stored JS endpoints for a domain
autoar db backup                               Create a database backup
             [--upload-r2]                     Also upload the backup to Cloudflare R2
```

### Utilities

```
autoar check-tools          Verify all required tools are installed
autoar setup               Install all AutoAR dependencies
autoar cleanup             Delete all contents of the results directory
autoar help                Show help
```

### Special Modes

```
autoar bot                 Start Discord bot only
autoar api                 Start REST API server only
autoar both                Start Discord bot + API server simultaneously
```

---

## 🛠️ Installation

### Prerequisites

- **Go 1.21+** — [Download](https://golang.org/dl/)
- **Git**
- System tools: `curl`, `bash`
- *(Optional)* PostgreSQL for persistent storage, or use SQLite for zero-config

### Option 1 — Clone & Build (Recommended)

```bash
git clone https://github.com/h0tak88r/AutoAR.git
cd AutoAR

# Install Go dependencies
go mod tidy

# Build the binary
go build -tags netgo -o autoar ./cmd/autoar/

# Verify it works
./autoar help
```

### Option 2 — Go Install

```bash
go install github.com/h0tak88r/AutoAR/cmd/autoar@latest
```

> Make sure `$GOPATH/bin` (typically `~/go/bin`) is in your `$PATH`:
> ```bash
> echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc && source ~/.bashrc
> ```

### Option 3 — Docker

```bash
# Discord bot
docker-compose up autoar-discord

# REST API
docker-compose --profile api up autoar-api

# Both
docker-compose --profile full up autoar-full
```

---

## ⚙️ Configuration

Copy `env.example` to `.env` and fill in your values:

```bash
cp env.example .env
```

### Core Config

```env
# Mode: discord | api | both
AUTOAR_MODE=discord

# Results storage directory
AUTOAR_RESULTS_DIR=./new-results

# Database: postgresql or sqlite
DB_TYPE=sqlite
DB_HOST=./bughunt.db
```

### Discord Bot

```env
DISCORD_BOT_TOKEN=your_discord_bot_token
DISCORD_ALLOWED_GUILD_ID=your_guild_id   # Optional: restrict to one server
```

Getting a Discord Bot Token:
1. Go to [discord.com/developers/applications](https://discord.com/developers/applications)
2. New Application → Bot → Copy Token
3. Enable **Message Content Intent** under Privileged Gateway Intents
4. Invite bot to your server with `applications.commands` scope

### Cloudflare R2 Storage (Highly Recommended)

AutoAR automatically uploads every non-empty result file to R2 and prints a public URL in the scan output. AI assistants and Discord bots can see and share these links directly.

```env
USE_R2_STORAGE=true
R2_BUCKET_NAME=autoar
R2_ACCOUNT_ID=your_cloudflare_account_id
R2_ACCESS_KEY_ID=your_r2_access_key_id
R2_SECRET_KEY=your_r2_secret_key
R2_PUBLIC_URL=https://pub-xxxx.r2.dev   # Your bucket's public URL
```

Creating R2 Credentials:
1. Cloudflare dashboard → R2 → Create Bucket
2. Account Settings → API Tokens → Create R2 Token (read+write)
3. Enable public access: Bucket Settings → Public Access → Allow

### API Keys for Maximum Subdomain Coverage

All keys are optional but recommended. AutoAR uses whichever are provided:

```env
# Subdomain enumeration sources
GITHUB_TOKEN=...
SECURITYTRAILS_API_KEY=...
SHODAN_API_KEY=...
VIRUSTOTAL_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
CERTSPOTTER_API_KEY=...
CHAOS_API_KEY=...
FOFA_EMAIL=...
FOFA_KEY=...
BINARYEDGE_API_KEY=...
URLSCAN_API_KEY=...
BEVIGIL_API_KEY=...
WHOISXMLAPI_API_KEY=...
ZOOMEYE_USERNAME=...
ZOOMEYE_PASSWORD=...

# Bug bounty platforms
H1_API_KEY=...           # HackerOne
INTEGRITI_API_KEY=...    # Intigriti

# AI analysis — only ONE key is needed
# ✅ Recommended: OpenRouter free tier (no credit card required)
#    Sign up at https://openrouter.ai · Uses stepfun/step-3.5-flash:free automatically
OPENROUTER_API_KEY=...   # Powers /ai, /brain, and `autoar agent` — completely free

# Optional fallback: direct Gemini API (only if you don't use OpenRouter)
GEMINI_API_KEY=...
```

### Scan Tuning

```env
# Nuclei
NUCLEI_RATE_LIMIT=150       # Requests per second
NUCLEI_CONCURRENCY=25       # Parallel templates

# Fuzzing
FFUF_THREADS=50
FFUF_WORDLIST_PATH=./Wordlists/quick_fuzz.txt

# Subfinder
SUBFINDER_THREADS=10

# Timeouts (seconds, 0 = no timeout)
DOMAIN_RUN_TIMEOUT=18000    # 5 hours for full domain runs
AUTOAR_TIMEOUT_MISCONFIG=1800
AUTOAR_TIMEOUT_NUCLEI=0
```

---

## 🚀 Quick Start

```bash
# 1. Clone and build
git clone https://github.com/h0tak88r/AutoAR.git && cd AutoAR
go build -tags netgo -o autoar ./cmd/autoar/

# 2. Configure
cp env.example .env
# Edit .env with your credentials

# 3. Install required tools
./autoar setup

# 4. Run your first full scan
./autoar domain run -d example.com

# 5. Or run a specific workflow
./autoar subdomain run -s api.example.com
./autoar lite run -d example.com
./autoar fastlook run -d example.com
```

---

## 📂 Results Directory Structure

All scan results are saved to `./new-results/` and automatically uploaded to R2 if configured:

```
new-results/
├── <domain>/
│   ├── subs/
│   │   ├── subdomains.txt          All discovered subdomains
│   │   └── live-subs.txt           Alive hosts
│   ├── ports/
│   │   └── port-scan.txt           Open ports per host
│   ├── nuclei/
│   │   └── nuclei-results.txt      Vulnerability findings
│   ├── js/
│   │   └── js-endpoints.txt        Extracted JS endpoints & secrets
│   ├── urls/
│   │   └── all-urls.txt            Collected URLs
│   ├── misconfig/
│   │   └── misconfig-scan-results.txt
│   ├── backup/
│   │   └── backup-files.txt        Discovered backup files
│   └── wp-confusion/               WordPress confusion results
├── s3/<domain>/                    S3 bucket scan results
└── github/<owner>/                 GitHub scan results
```

When **R2 is enabled**, each file is uploaded immediately after writing and the URL is printed:

```
🔗 R2 Result: new-results/example.com/subs/subdomains.txt
   URL: https://pub-xxxx.r2.dev/new-results/example.com/subs/subdomains.txt
```

---

## 🤖 CoPaw AI Integration

AutoAR is designed to work seamlessly with **CoPaw** AI assistant, enabling natural language control of your entire recon pipeline:

> *"Scan all subdomains of example.com and check for DNS takeovers"*
> *"Run a full domain scan on target.com and share me the results"*
> *"Check if api.example.com has any JavaScript secrets"*

The AI automatically calls the right AutoAR commands, waits for results, and shares R2 links directly in your chat.

See the [CoPaw AutoAR Skill documentation](/blob/main/docs/copaw-skill.md) for full setup instructions.

---

## 🐳 Docker Usage

### Docker Compose Profiles

```bash
# Discord bot (default)
docker-compose up autoar-discord

# REST API only
docker-compose --profile api up autoar-api

# Both Discord + API
docker-compose --profile full up autoar-full
```

### Environment for Docker

```env
AUTOAR_RESULTS_DIR=/app/new-results
NUCLEI_TEMPLATES_PATH=/app/nuclei_templates
FFUF_WORDLIST_PATH=/app/Wordlists/quick_fuzz.txt
DB_TYPE=postgresql
DB_HOST=postgresql://user:pass@db:5432/autoar
```

---

## 🗄️ Database

AutoAR supports two databases:

### PostgreSQL (Production)

```env
DB_TYPE=postgresql
DB_HOST=postgresql://username:password@host:5432/autoar
```

#### Using Supabase (Free Cloud Postgres)

1. Create a project at [supabase.com](https://supabase.com)
2. Get connection URI from Settings → Database
3. Use the pooled connection string:
   ```env
   DB_HOST=postgresql://postgres.xxx:password@aws-eu.pooler.supabase.com:6543/postgres?sslmode=require
   ```

### SQLite (Zero-config Local)

```env
DB_TYPE=sqlite
DB_HOST=./bughunt.db
```

---

## 🔧 Troubleshooting

### No Terminal Logs?

AutoAR logs to a file by default (`autoar-bot.log`). To see live output:

```bash
tail -f autoar-bot.log
# or set LOG_LEVEL=debug in your .env
```

### Missing Tools?

Run the built-in check:

```bash
./autoar check-tools
./autoar setup    # Auto-install missing dependencies
```

### BuildError: `pcap.h: No such file or directory`

Install `libpcap-dev`:

```bash
sudo apt-get install -y libpcap-dev   # Debian/Ubuntu
sudo yum install -y libpcap-devel     # RHEL/CentOS
brew install libpcap                  # macOS
```

### R2 Uploads Not Working?

1. Verify `USE_R2_STORAGE=true` in `.env`
2. Check `R2_BUCKET_NAME`, `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_KEY` are all set
3. Ensure your bucket has **public access enabled** in Cloudflare R2 settings
4. Check the bucket allows the access key's permissions (object read/write)

### Database Connection Refused

For PostgreSQL, ensure:
- The DB_HOST URL is correct and the server is running
- Network allows connections (firewall rules, VPN)
- For Supabase: use the **pooler** (port 6543) not the direct port (5432)

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push and open a Pull Request

---

## ⚠️ Legal Disclaimer

AutoAR is intended for **authorized security testing only**. Only use it on targets where you have explicit written permission, or on bug bounty programs where the target is in-scope. Unauthorized scanning of systems you do not own is illegal.

The authors of AutoAR assume no liability for misuse of this tool.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ for the bug bounty community · [GitHub](https://github.com/h0tak88r/AutoAR)

</div>
