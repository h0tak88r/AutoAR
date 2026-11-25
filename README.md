# AutoAR — Automated Attack & Reconnaissance Platform



**The ultimate bug bounty automation framework. Scan smarter, find more, ship faster.**

[Go](https://golang.org/)
[License](LICENSE)



---

AutoAR is a powerful, end-to-end automated security reconnaissance and vulnerability hunting platform built in Go. It is purpose-built for **bug bounty hunters** and **penetration testers** who want to automate the full recon-to-report pipeline at scale — from subdomain enumeration and DNS takeover detection to nuclei scanning, JavaScript secrets extraction, GitHub exposure, mobile app analysis, and more.

Results are automatically uploaded to **Cloudflare R2 storage** and linked directly in your output — no hunting through directories.

**Public VPS / dashboard:** uses native Go JWT authentication with local PostgreSQL — no Supabase required. See [docs/DASHBOARD_AUTH.md](docs/DASHBOARD_AUTH.md).

![Dashboard](image.png)
---

##  Feature Highlights


| Category               | What AutoAR Does                                                                                                                       |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
|  **Subdomains**      | Enumerate using 15+ sources: Subfinder, CertSpotter, SecurityTrails, Chaos, crt.sh, OTX, VirusTotal, and more                          |
|  **Live Hosts**      | Detect alive hosts using httpx with follow-redirects and status detection                                                              |
|  **DNS Takeovers**  | Detect CNAME, NS, Azure/AWS cloud, DNSReaper, dangling-IP, and **CF-1016 Cloudflare dangling record** vulnerabilities                  |
|  **Nuclei Scanning** | Automated vulnerability scanning using Nuclei templates with rate limiting. Scans are **cancellable** from the UI, and past scans support **rescan** (incl. raw-template runs) |
|  **Zero-Days**       | Smart scan configured for detected tech stacks — finds active CVEs                                                                                                                                             |
|  **Firebase**        | Read-only Firebase misconfiguration scanner — fingerprints Firebase on live hosts and tests Realtime DB / Firestore / Storage for unauthenticated exposure (opt-in aggressive write tests)                        |
|  **S3 Buckets**      | Enumerate and scan AWS S3 buckets for exposure and misconfig                                                                                                                                                    |
|  **JavaScript**      | Extract secrets, API endpoints, auth tokens from JS files — plus **client-side bug candidates** (DOM XSS sources/sinks, postMessage, open-redirect sinks, prototype pollution) via 25 RE2 patterns               |
|  **GitHub Recon**    | Org-level and repo-level scanning for secrets, dependency confusion                                                                    |
|  **APK Auditor**     | Browser-based Android analysis: DEX decompiler, manifest + cert parsing, tracker detection, MASVS mapping, and regex-driven findings with APX secret patterns. (Based on [apkauditor](https://github.com/thecybersandeep/apkauditor) by @thecybersandeep) |
|  **IPA Auditor**     | Browser-based iOS IPA analysis: plist + Mach-O inspection, binary strings extraction, and findings tab powered by 200+ regex signatures plus MASVS-style rules. (Based on [ipaauditor](https://github.com/thecybersandeep/ipaauditor) by @thecybersandeep) |
|  **ADB Auditor**    | Browser-based ADB security tool: USB device inspection, app enumeration, logcat tailing, file pull, activity launching. (Based on [adbauditor](https://github.com/thecybersandeep/adbauditor) by @thecybersandeep) |
|  **Misconfigs**      | 100+ service misconfiguration checks                                                                                                   |
|  **BB Scope**     | Fetch scope from HackerOne, Bugcrowd, Intigriti, YesWeHack (token), Immunefi — CLI & **dashboard Targets page**                       |
|  **Monitoring**      | Subdomain + URL change monitoring daemon with webhook alerts (Discord-compatible) & DB history                                          |
|  **AI Assist**       | AI finding validation & bug-bounty reports from the dashboard — defaults to the **official DeepSeek API**; OpenCode, OpenRouter, Z.ai and Gemini selectable in Settings |
|  **R2 Storage**      | Auto-upload every non-empty result file to Cloudflare R2 and print the public URL                                                      |
|  **Smart Alerts**    | Rich webhook notifications for zero-findings scans — no more empty files or spam                                                       |
|  **Web dashboard**  | **v4.3+** — Stats, scans, domains, monitors, R2 browser, Targets, APK/IPA/ADB Auditors, CF-1016 findings. Unified findings table with per-module columns, inline expandable detail panels, severity/chip/multi-field filters            |
|  **DB-backed Settings** | Configure a running instance from the dashboard — platform accounts (multi-account, editable), provider/subfinder keys (multi-key), webhook, Cloudflare R2, AI keys, scan timeouts. Stored in the database, survives redeploys; env vars become optional seeds |


---

##  Complete Command Reference

### Workflows (Start Here)

```
autoar domain run      -d <domain>           Full end-to-end workflow: subdomains → live hosts → ports →
                       [--skip-ffuf]         tech → DNS → S3 → nuclei → JS → URLs → GF → backup → misconfig

autoar subdomain run   -s <subdomain>        Focused deep-dive on a single subdomain:
                                             live check → ports → JS → vuln scan → nuclei

autoar lite run        -d <domain>           Lighter workflow: livehosts → reflection → JS → CNAME → DNS → misconfig
                       [--skip-js]           Skip JavaScript scanning
                       [--phase-timeout]     Set default phase timeout in seconds
                       [--timeout-<phase>]   Specific overrides (e.g. --timeout-livehosts)

autoar recon run       -d <domain>           Unified recon: subdomains → live hosts → tech → CNAMEs → URLs/JS

autoar asr             -d <domain>           High-depth reconnaissance (ASR Modes)
                       [-mode 1-5]           Recon mode (default: 5)
                       [-t <threads>]        Number of threads
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
autoar firebase scan   -d <domain>            Fingerprint Firebase on live hosts and test Realtime DB /
                                              Firestore / Storage for unauthenticated exposure
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
                       [-s <subdomain>]       Target a single subdomain directly (skips enumeration)
autoar dns cname       -d <domain>            CNAME takeover detection
autoar dns ns          -d <domain>            Nameserver takeover detection
autoar dns azure-aws   -d <domain>            Azure/AWS cloud service takeover
autoar dns dnsreaper   -d <domain>            DNSReaper-based detection
autoar dns dangling-ip -d <domain>            Dangling IP detection
autoar dns cf1016      -d <domain>            Cloudflare 1016 Dangling DNS — auto-enumerates subdomains,
                                               then scans all for CF-1016 dangling records.
                                               Saves structured JSON findings + writes live status to DB.
                       -s <subdomain>         Scan a single subdomain directly
                       -l <file>              Scan subdomains from a file
autoar dns all         -d <domain>            Run all DNS checks simultaneously
```

### Client-side Scanning (formerly "JavaScript scan")

Collects a target's JavaScript and runs the JS-secrets and client-side source/sink patterns over it
(DOM XSS sources/sinks/flows, open-redirect sinks, postMessage listeners, prototype pollution, eval,
credentials in storage). A root domain covers every subdomain; a host covers only that app.

```
POST /scan/clientside  {"domain": "example.com"}       every subdomain's JS   (old name: /scan/js)
POST /scan/clientside  {"domain": "app.example.com"}   that host's JS only
MCP  run_scan {type: "clientside", target: ...}  →  clientside_results {scan_id}
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

### Mobile Application Analysis (APK Auditor)

The **APK Auditor** is a fully browser-based static analysis tool available at `/ui/apkauditor/`.

**Drag & Drop Analysis (no server required):**
- Drop any APK to instantly decompile DEX and run regex-based findings in the browser
- Parsed binary AndroidManifest (exported components, permissions, SDK, backup flags, deep links)
- Certificate analysis (debug keys, expired certs, weak algorithms)
- 38+ tracker & SDK detection from DEX strings
- Full in-browser file explorer (XML, JSON, images, .so files with hex view)
- Regex presets and bulk pattern scans for secrets/tokens across code and resources
- OWASP MASVS aligned reporting — one-click export

> **Want to MITM an app's HTTPS traffic?** The auditor is static-analysis only — kept deliberately lightweight (all in-browser, no heavy server-side Java toolchain). To prepare an APK for interception, patch it locally with [apk-mitm](https://github.com/niklashigi/apk-mitm) (`npx apk-mitm app.apk`), install the patched build on your test device, then drop it back into the auditor if you want to analyze it.

> **The APK Auditor never creates records in the main Scans dashboard** — it runs in its own context.

### Mobile Application Analysis (IPA Auditor)

The **IPA Auditor** is a browser-based iOS static analysis tool available at `/ui/ipaauditor/`.

**What it covers:**
- IPA parsing in-browser (no upload required for local analysis)
- Info.plist extraction, URL schemes, entitlement/permission indicators
- Mach-O binary string extraction with security pattern matching
- Findings tab generated from:
  - native iOS security rules (ATS, storage, crypto, webview/runtime checks)
  - regex preset secret scans
  - imported APX regex signatures from APK Auditor (200 patterns)
- Combined findings coverage is now 200+ regex signatures plus core iOS rules
- Explorer mode for source/resources with line-level finding navigation

> **Important:** Auditor findings are signatures for triage and manual validation, not guaranteed exploitability.

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

**CLI:**

```
autoar scope -p h1  -u <username> -t <token>        HackerOne
autoar scope -p bc  -t <token>                       Bugcrowd
autoar scope -p it  -t <token>                       Intigriti
autoar scope -p ywh -t <token>                       YesWeHack (JWT token — no email/password needed)
autoar scope -p immunefi                             Immunefi (no auth required)

Options:
  --bbp-only         Only programs offering monetary rewards
  --pvt-only         Only private programs
  --active-only      Only active programs
  --extract-roots    Extract root domains (default: true)
  -o <output>        Save output to a file
```

**Dashboard —  Targets page:**

The web dashboard includes a dedicated **Targets** page (sidebar → Targets) that:
- Shows color-coded cards for each platform with credential status
- Lets you paste credentials or relies on env vars (`H1_TOKEN`, `BUGCROWD_TOKEN`, `YWH_TOKEN`, `INTIGRITI_TOKEN`)
- Fetches all in-scope root domains with one click
- Provides per-domain **+ Add** (saves to Domains DB) and **> Scan** (opens new scan)
- **+ Add All** saves all domains in one bulk request
- **Copy List** copies to clipboard (works on both HTTP and HTTPS)

### Subdomain Monitoring

The monitoring daemon uses a dedicated `last_run_at` DB column (fixes the old timer bug), persists every detected change to `monitor_changes` for history, and sends webhook alerts automatically. Set `MONITOR_WEBHOOK_URL` in your `.env` to any webhook endpoint (Discord webhook URLs work out of the box).

```
autoar monitor subdomains -d <domain>         One-time check for subdomain changes
                          [--check-new]       Alert on newly discovered subdomains

autoar monitor subdomains manage add    -d <domain> -i <interval_sec>
autoar monitor subdomains manage list
autoar monitor subdomains manage start  --all | --id <id> | -d <domain>
autoar monitor subdomains manage stop   --all | --id <id> | -d <domain>

autoar monitor updates manage add       -u <url> [--strategy hash|content|regex] [--pattern <regex>]
autoar monitor updates manage remove    -u <url>
autoar monitor updates manage start     [--id <id>] [--all]
autoar monitor updates manage list
```


---

##  AI-Driven Security Framework

AutoAR's AI layer defaults to the **official [DeepSeek API](https://platform.deepseek.com)** (`deepseek-chat`). Exactly one provider is active at a time; OpenCode Zen, OpenRouter, Z.ai (GLM) and Google Gemini are optional alternatives you can switch to from the dashboard. There is no silent fallback chain — requests go to the provider you picked, and a missing key or upstream error is reported as such.

### What the AI powers

| Feature | Where |
| ------- | ----- |
| AI vulnerability reports for selected findings (one or many) | Scan detail → select rows → **AI report** |
| **Automatic triage of every finished scan** → reportable findings to Discord with a draft report | **AI Triage** page (`/triage`) |
| Finding validation / report endpoints | `POST /api/findings/validate`, `/api/findings/report`, `/api/findings/report-batch` |
| Ranking of release/changelog pages to monitor | Monitor → **Suggest from domain** |

Scan evidence sent to the model is treated as untrusted (it comes from the target), and the prompts tell the model never to follow instructions inside it.

### AI triage & Discord reporting

When a scan finishes, AutoAR queues it for **AI triage** (race-pass scans jump the queue):

1. Its nuclei hits at or above the minimum severity (default *medium*) are read from the scan's result files, most severe first; CVE templates go first.
2. Each hit is sent to the active provider with its template, request, response, extracted values and catalog scope. The model returns a JSON verdict (`true_positive` / `likely` / `false_positive` / `needs_manual_review`), a confidence, a reason and — when reportable — a draft report.
3. Optionally AutoAR first does **one safe re-check**: a single GET to the matched URL, only for hits that were themselves GET requests, through the SSRF-guarded client. The model only ever *reads* evidence; it never chooses requests or commands.
4. A finding is **reportable** only if the model says true/likely positive *and* confidence ≥ the threshold (default 75%) *and* severity ≥ the minimum *and* the host is not out of scope or in a paused program (optionally: must match an in-scope program).
5. Reportable findings are posted once to the **Findings** Discord webhook (`WEBHOOK_FINDINGS`, falling back to the monitor webhook) with the draft report attached as a `.md` file. Mentions are disabled and all target/model text is escaped.

Cost controls: a daily AI-call limit (default 200), a per-scan cap (default 40), and per-template sampling — after 3 confident false positives from one template in a scan, its remaining hits are skipped. Each finding is triaged once; re-runs reuse the stored verdict.

Review everything on the **AI Triage** page (`/triage`): verdicts, reasons, the evidence the model saw, draft reports (copy), *Send/Resend* to Discord, and *Mark TP / FP* overrides — an FP override is never reported. Tune the policy in **Settings → AI Providers → AI Triage & Discord reporting**. API: `GET /api/triage`, `GET /api/triage/status`, `POST /api/triage/scans/:id`, `POST /api/triage/item/:id/notify`, `POST /api/triage/item/:id/verdict`.

### Setting it up (dashboard — recommended)

1. Create a key at [platform.deepseek.com/api_keys](https://platform.deepseek.com/api_keys).
2. Open **Settings → AI Providers**, paste it into **DeepSeek (official)** and click **Save key**. The key is stored in the database (it survives redeploys) and is never sent back to the browser.
3. Click **Test connection** — it sends a one-word prompt and shows the model, latency and reply.
4. Optional: change the model (**Load models** lists what your key can use, e.g. `deepseek-reasoner`), or pick a different **Active provider**.

### Setting it up (env seed)

```env
AI_PROVIDER=deepseek        # deepseek | opencode | openrouter | zai | gemini
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_MODEL=             # optional; defaults to deepseek-chat
```

Env values are copied into the settings DB on first boot; after that the DB (i.e. the dashboard) is the source of truth.

| Provider (`AI_PROVIDER`) | Key | Model override | Default model |
| ------------------------ | --- | -------------- | ------------- |
| `deepseek` (default) | `DEEPSEEK_API_KEY` | `DEEPSEEK_MODEL` | `deepseek-chat` |
| `opencode` | `OPENCODE_API_KEY` | `OPENCODE_MODEL` | `deepseek-v4-flash-free` |
| `openrouter` | `OPENROUTER_API_KEY` | `OPENROUTER_MODEL` | `z-ai/glm-4.5-air:free` |
| `zai` | `ZHIPU_API_KEY` | `ZAI_MODEL` | `glm-4.5-air` |
| `gemini` | `GEMINI_API_KEY` | `GEMINI_MODEL` | `gemini-2.5-flash` |

### Database & Results

```
autoar db backup                               Create a database backup
             [--upload-r2]                     Also upload the backup to Cloudflare R2
```

> Schedule this (cron / Dokploy schedule) on any deployment you care about — see
> [Backups & growth](#backups--growth-production). Domain/subdomain listing and
> deletion is available from the dashboard (Domains page, subdomain search) and
> the REST API rather than the CLI.

### Utilities

```
autoar check-tools          Verify all required tools are installed
autoar setup               Install all AutoAR dependencies
autoar cleanup             Delete all contents of the results directory
autoar help                Show help
```

### Server Mode

```
autoar api                 Start the REST API server + web dashboard
```

---

##  Installation

### Option 1 — Docker (Primary & Recommended)

The easiest way to run AutoAR with all dependencies (Go, Nuclei, FFUF, APK Auditor tools, etc.) pre-installed. Requires [Docker](https://docs.docker.com/get-docker/) and [Docker Compose V2](https://docs.docker.com/compose/).

1. **Clone & Configure:**
   ```bash
   git clone https://github.com/h0tak88r/AutoAR.git && cd AutoAR
   cp .env.example .env
   # Edit .env to set your API keys and configuration
   ```

2. **Database Choice:**
   - **PostgreSQL (Standard):** Ensure `DB_TYPE=postgresql` and `DB_HOST` points to the `postgres` service:
     ```env
     DB_TYPE=postgresql
     DB_HOST=postgresql://autoar:autoar@postgres:5432/bughunt?sslmode=disable
     ```
   - **SQLite (Quick Test):** `DB_TYPE=sqlite` and `DB_HOST=/app/bughunt.db`.

3. **Launch:**
   ```bash
   # Build and start the API + Dashboard (add --profile localdb to also start PostgreSQL)
   docker compose --profile localdb up -d
   ```

### Option 1b — Dokploy (VPS deployment with Traefik)

AutoAR runs well on a single VPS managed by [Dokploy](https://dokploy.com): Dokploy builds the
`Dockerfile` from your Git repo (use a **private** repo remote for this), and Traefik — Dokploy's
bundled reverse proxy — terminates TLS for your domain and routes to the `autoar-api` service.
PostgreSQL runs as a second Dokploy service with its own volume; no ports need to be published for
it (the app talks to it over the internal Docker network).

Setup outline:

1. Create a Dokploy **project** → application pointing at your repo's `master` and the `Dockerfile`.
2. Create a **PostgreSQL service** in the same project; set `DB_TYPE=postgresql` and
   `DB_HOST=postgresql://<user>:<pass>@<postgres-service>:5432/bughunt?sslmode=disable` in the
   application env. Schema init happens automatically on boot.
3. Attach your domain (e.g. `autoar.example.com`) — Traefik gets a Let's Encrypt cert and adds an
   HTTP→HTTPS redirect.
4. Set `DASHBOARD_USER` / `DASHBOARD_PASSWORD` / `AUTOAR_JWT_SECRET` in the app env — the server
   refuses to start with a public bind and no auth.

Production checklist (things to get right on a public VPS):

- **Don't publish the API port.** If the service publishes `8000` on the host, the dashboard is
  reachable over plain HTTP on the raw VPS IP, bypassing Traefik's TLS. Let Traefik reach the
  service over the internal network instead.
- **Persist results.** Mount a volume at `/app/new-results` (or a host bind) if you want scan
  output files and rescan template files to survive redeploys. Without a volume, container
  rebuilds wipe local files — R2 uploads and DB rows survive either way.
- **Back up the database.** Dokploy's volume backups are opt-in. Either enable them for the
  Postgres volume or schedule `autoar db backup --upload-r2` (uploads a DB dump to your R2 bucket).
  Do one of these — Postgres holds all scans, subdomains, settings and monitor history.
- **Set `POSTGRES_PASSWORD`** (don't rely on defaults) and keep the Postgres port unpublished.
- **Add resource limits** (`deploy.resources.limits`) — nuclei/ffuf bursts can otherwise starve
  other stacks on the box.



### Option 2 — Manual Build

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

### Option 3 — Go Install

```bash
go install github.com/h0tak88r/AutoAR/cmd/autoar@latest
```

> Make sure `$GOPATH/bin` (typically `~/go/bin`) is in your `$PATH`:
>
> ```bash
> echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc && source ~/.bashrc
> ```


---

##  Configuration

> **Dashboard-first (recommended).** Most settings below can be set from the web dashboard
> **Settings** page instead of `.env` — platform accounts, subfinder/recon provider keys, the
> monitor webhook, Cloudflare R2 storage, AI keys/models, and scan timeouts. Anything set there is
> **stored in the database and survives redeploys**, so the matching environment variables become
> optional. On boot AutoAR seeds any env-only value into the DB once (so you can then drop it from
> your deployment) and the DB value wins thereafter. Truly required in `.env`: the database
> connection (`DB_TYPE`/`DB_HOST`), server bind (`API_HOST`/`API_PORT`), dashboard login
> (`DASHBOARD_USER`/`DASHBOARD_PASSWORD`, `AUTOAR_JWT_SECRET`), and runtime paths — these bootstrap
> the app before the DB exists. See [Dashboard Settings](#dashboard-settings) below.

Copy `.env.example` to `.env` and fill in your values (or configure via the dashboard):

```bash
cp .env.example .env
```

### Core Config

```env
# Server mode (the API server also serves the web dashboard)
AUTOAR_MODE=api

# Results storage directory
AUTOAR_RESULTS_DIR=./new-results

# Database: postgresql or sqlite
DB_TYPE=sqlite
DB_HOST=./bughunt.db
```

### Monitor Webhook (Optional)

The monitoring daemon posts change alerts to a webhook of your choice. Leave it unset to disable notifications.

```env
# Any webhook endpoint — Discord webhook URLs work out of the box (payload is {"content": "..."})
MONITOR_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

> Or set it in **Settings → Notifications** — it's stored in the DB and survives redeploys, so the env var isn't required.

### Cloudflare R2 Storage (Highly Recommended)

AutoAR automatically uploads every non-empty result file to R2 and prints a public URL in the scan output. AI assistants can see and share these links directly.

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

> Or configure all of the above in **Settings → System → Cloudflare R2** — the fields are DB-backed
> (survive redeploys) and applied live on save, so you can switch buckets or rotate keys without a
> redeploy and without setting any `R2_*` env vars.

### API Keys for Maximum Subdomain Coverage

All keys are optional but recommended. AutoAR uses whichever are provided.

> Prefer the dashboard: **Settings → Platforms & Keys** manages the recon/subfinder provider keys
> (multiple keys per provider, add without replacing via the `+` action) and the bug-bounty platform
> accounts (multiple accounts per platform, each with **Test / Edit / enable / delete**). Everything
> is DB-backed and survives redeploys — a stored value overrides the env of the same name. The env
> vars below are just an alternative / initial seed.

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

# Bug bounty platforms (Programs page + Targets page + `autoar scope`)
H1_USERNAME=...          # HackerOne
H1_TOKEN=...             # HackerOne API token
BUGCROWD_TOKEN=...       # Bugcrowd _crowdcontrol_session_key cookie
INTIGRITI_TOKEN=...      # Intigriti researcher API token (INTIGRITI_API_KEY also accepted)
YWH_TOKEN=...            # YesWeHack JWT

# AI analysis — only ONE key is needed
#  Recommended (free): OpenCode Zen (no credit card required)
#    Sign up at https://opencode.ai/zen · uses deepseek-v4-flash-free automatically
DEEPSEEK_API_KEY=sk-...   # Default AI provider (official DeepSeek API); or set it in Settings ▸ AI Providers
# OPENCODE_MODEL=         # Optional override; see https://opencode.ai/zen/v1/models

# Optional: OpenRouter for premium / alternative models
OPENROUTER_API_KEY=...
# OPENROUTER_MODEL=        # Optional override; defaults to z-ai/glm-4.5-air:free

# Optional fallback: direct Gemini API
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

> Per-phase scan timeouts are also editable in **Settings → Scan Timeouts** (DB-backed as
> `timeout_<phase>`; the DB value wins over `AUTOAR_TIMEOUT_<PHASE>`).

<a id="dashboard-settings"></a>
### Dashboard Settings

The web dashboard **Settings** page is the primary way to configure a running instance. Every value
here is written to the database (so it survives container/Dokploy redeploys that reset `.env`); the
matching env var becomes an optional seed. Tabs:

| Tab | What you manage |
| --- | --- |
| **Platforms & Keys** | Bug-bounty accounts — multiple per platform (HackerOne, Bugcrowd, Intigriti, YesWeHack), each with **Test / Edit / enable / delete** (editing keeps a stored secret when the field is left blank). External aggregator keys (Shodan, Chaos) and the **Subfinder provider keys** (multi-key, `+` to append without replacing). |
| **AI Providers** | OpenRouter / OpenCode / Gemini keys and the two model overrides — masked, blank keeps the saved value. |
| **Scan Timeouts** | Per-phase timeouts (nuclei, misconfig, katana, xss, …). |
| **Notifications** | Monitor webhook URL (Discord-compatible). |
| **System** | **Cloudflare R2 storage** (account ID, keys, bucket, public URL, enable toggle — applied live on save), plus system status and API endpoints. |

Secrets are never returned by the API — inputs render masked and show a "set / not set" badge; submit
a blank field to keep the stored value or a new value to overwrite.

---

##  Quick Start (Docker)

```bash
# 1. Setup
git clone https://github.com/h0tak88r/AutoAR.git && cd AutoAR
cp .env.example .env  # Edit .env with your keys

# 2. Start the stack (API + Dashboard + Postgres)
docker compose --profile localdb up -d

# 3. Run a scan via Docker
docker compose run --rm autoar-api domain run -d example.com

# 4. Access the Dashboard
# Open http://localhost:8000/ui/ in your browser
```

---

##  Results Directory Structure

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
 R2 Result: new-results/example.com/subs/subdomains.txt
   URL: https://pub-xxxx.r2.dev/new-results/example.com/subs/subdomains.txt
```

---

##  CoPaw AI Integration

AutoAR is designed to work seamlessly with **CoPaw** AI assistant, enabling natural language control of your entire recon pipeline:

> *"Scan all subdomains of example.com and check for DNS takeovers"*
> *"Run a full domain scan on target.com and share me the results"*
> *"Check if api.example.com has any JavaScript secrets"*

The AI automatically calls the right AutoAR commands, waits for results, and shares R2 links directly in your chat.

See the [CoPaw AutoAR Skill documentation](/blob/main/docs/copaw-skill.md) for full setup instructions.

---

##  Docker & Compose Deep Dive

###  Architecture & Internal Structure (v4.1+)

AutoAR follows a strictly decoupled, package-based architecture designed for enterprise scaling and clean dependency management:

- **`cmd/autoar/`**: The main entry point. All binaries and commands start here.
- **`internal/api/`**: The core backend source of truth. Manages all scan states (`ActiveScans`), database operations, REST endpoints, and orchestration. The web dashboard UI is served from here.
- **`internal/cmd/`**: The Cobra command layer — every `autoar` CLI subcommand is registered here.
- **`internal/utils/`**: Centralized, shared logic (binary paths, helper functions, logging, env loading). This acts as the foundational layer to strictly prevent circular imports between packages.

---

The repository includes a multi-stage **Dockerfile** and a **docker-compose.yml** that manages the API server (which also serves the Dashboard UI) and an optional PostgreSQL container.

### Environment Variables in Docker

Docker services automatically load variables from the `.env` file in the root directory.

| Variable | Recommended for Docker |
| -------- | ---------------------- |
| `AUTOAR_RESULTS_DIR` | `/app/new-results` (mounted as volume) |
| `NUCLEI_TEMPLATES_PATH` | `/app/nuclei_templates` |
| `DB_TYPE` | `postgresql` |
| `DB_HOST` | `postgresql://autoar:autoar@postgres:5432/bughunt?sslmode=disable` |

### PostgreSQL Integration

AutoAR's Docker stack includes a dedicated PostgreSQL container. This is the **recommended** way to run AutoAR for persistence and performance.

1. **Persistence:** Data is stored in the `postgres_data` Docker volume.
2. **Access:** You can access the DB via `docker exec -it autoar-postgres psql -U autoar -d bughunt`.
3. **Migration:** No manual migration needed; AutoAR handles schema initialization on startup.

### Service Profiles

| Service / Profile | Services Started | Use Case |
| ----------------- | ---------------- | -------- |
| `autoar-api` (no profile) | `autoar-api` | API server + dashboard (uses an external/remote DB) |
| `localdb` | `postgres` | Start the bundled PostgreSQL container |

**Example:**
```bash
# Run the API + dashboard together with a local PostgreSQL container
docker compose --profile localdb up -d
```

### Path Mapping & Volumes

AutoAR maps the following host directories into the container:
- `./new-results` → `/app/new-results` (Scan outputs)
- `./nuclei_templates` → `/app/nuclei_templates` (Nuclei rules)
- `./Wordlists` → `/app/Wordlists` (Fuzzing lists)

### Typical `.env` for Docker Full Stack

```env
AUTOAR_MODE=api
AUTOAR_RESULTS_DIR=/app/new-results
DB_TYPE=postgresql
DB_HOST=postgresql://autoar:autoar@postgres:5432/bughunt?sslmode=disable
USE_R2_STORAGE=true
DEEPSEEK_API_KEY=sk-...   # or pick another provider in Settings ▸ AI Providers
```

---

##  Database

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

### Backups & growth (production)

- **Backups:** `autoar db backup --upload-r2` creates a DB dump and (optionally) uploads it to your
  R2 bucket. Schedule it (cron / Dokploy schedule) on any deployment you care about — scan history,
  subdomains, settings and monitor state all live in the DB.
- **Growth:** `subdomains`, `scan_artifacts` and `monitor_changes` grow without bound by design.
  On long-running instances, prune old rows periodically (e.g. delete scans older than N months and
  run `VACUUM`/`pg_repack` on Postgres) — 800k+ subdomain rows are normal for active targets.

---

##  Troubleshooting

### No Terminal Logs?

The API server logs to `api.log` by default. To see live output:

```bash
tail -f api.log
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

### Program/Scope Fetches Fail with 401

The Programs page refresh logs `[PROGRAMS] Intigriti fetch failed: ... (401)` (or similar for other
platforms) when a stored platform token expired or was rotated. Fix it in **Settings → Platforms &
Keys** — edit the account, paste the fresh token, and use **Test** to verify. Stale-token failures
don't clear existing cached programs (last-known-good scope is preserved).

### Scan Results Missing After a Redeploy

Scan output files live under `/app/new-results` inside the container. If no volume is mounted
there, a container rebuild wipes them (DB records and R2 uploads survive). Mount a volume at
`/app/new-results` to keep files across redeploys — see the Dokploy checklist above.

---

##  GitHub release (tag → CI)

Versions are defined once in `[internal/version/version.go](internal/version/version.go)` (`Version`, no `v` prefix). To publish **v4.2.0**:

1. Set `const Version = "4.2.0"` and commit.
2. From the repo root:
  ```bash
   chmod +x scripts/tag-release.sh
   ./scripts/tag-release.sh v4.2.0
  ```
   This pushes your current branch and the annotated tag. `**[.github/workflows/release.yml](.github/workflows/release.yml)**` then builds Linux binaries, attaches `tar.gz` / `zip`, generates release notes, and pushes the private image `**ghcr.io/<owner>/autoar-private**` for that tag.

   To re-publish the image for an existing tag (for example after a failed docker job), run the **Release** workflow manually from the Actions tab with the tag as input. It builds only the image; the tag and GitHub release are left alone.

You need a Git remote with push access (HTTPS + token or SSH). No manual “Create release” step in the UI is required.

---

##  Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push and open a Pull Request

---

##  Legal Disclaimer

AutoAR is intended for **authorized security testing only**. Only use it on targets where you have explicit written permission, or on bug bounty programs where the target is in-scope. Unauthorized scanning of systems you do not own is illegal.

The authors of AutoAR assume no liability for misuse of this tool.

---

##  License

MIT License — see [LICENSE](LICENSE) for details.

---



Built with  for the bug bounty community · [GitHub](https://github.com/h0tak88r/AutoAR)

