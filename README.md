# AutoAR - Automated Attack & Reconnaissance Platform

AutoAR is a powerful, highly scalable automated security reconnaissance tool and Discord bot specifically designed for bug bounty hunters and penetration testers. It automates gathering subdomains, scanning ports, detecting technologies, mapping GitHub repositories, fuzzing, testing vulnerabilities, and executing AI analysis.

## 🚀 Key Features

- **Centralized Discord Command Hub**: Run, monitor, and manage full reconnaissance workflows directly from a Discord interface using slash commands.
- **Granular & Automated Workflows**:
  - `/domain_run`: A comprehensive, fully-automated recon and vulnerability assessment pipeline for an entire root domain.
  - `/subdomain_run`: A focused, deep-dive workflow targeting a single specific subdomain (including port scanning, exposure checks, and nuclei profiling).
  - `/lite_scan` & `/fast_look`: Scalable scanning options designed to quickly summarize targets while skipping heavy fuzzing execution.
- **Comprehensive Infrastructure Mapping**: Integrates seamlessly with Subfinder, Amass, crt.sh, Wayback Machine, and Chaos to enumerate subdomains and live hosts.
- **AI Brain & Natural Language Processing**:
  - Send direct natural language instructions via `/ai` (e.g., *"Do a quick scan on example.com for zero-days"*).
  - Use `/brain` to feed scan records to an AI model (Gemini/OpenRouter), allowing it to intelligently analyze the output and suggest follow-up attacks or generate exploit `curl` commands.
- **Continuous Vulnerability Assessment**:
  - `/nuclei`: Continuous targeted exposure monitoring using customized templates.
  - `/zerodays`: Specialized rapid verification scanners for the newest active Zero-Day vulnerabilities.
- **Advanced Target Deep Dives**:
  - Intelligent JavaScript endpoint and secrets extraction.
  - Mobile application security scanning (`/apkx_scan`, `/apkx_ios`).
  - Active Misconfiguration testing, S3 Bucket detection, and GitHub source code exposure scanning.

---

## 📋 Available Commands 

AutoAR provides an extensive toolkit of over 30 Discord commands to orchestrate your workflow:

- **Automated Orchestration**: `/domain_run`, `/subdomain_run`, `/lite_scan`, `/fast_look`
- **Reconnaissance & Asset Discovery**: `/subdomains`, `/livehosts`, `/urls`, `/ports`
- **Vulnerability Checks**: `/zerodays`, `/nuclei`, `/sqlmap`, `/dalfox`, `/dns`
- **Specific Scanners**: `/apkx_scan`, `/apkx_ios`, `/s3_scan`, `/github`, `/jwt_scan`
- **AI Intelligence**: `/ai`, `/brain`
- **Utilities & State**: `/help`, `/cancel_scan`, `/scans`, `/db`

*(Type `/help` in your Discord server for a completely categorized view of all features.)*

---

## ⚙️ Prerequisites

Ensure you have the following installed on your host or Docker environment:
- **Go** (1.21+ recommended)

*(AutoAR gracefully handles security tools and utilities internally via Go modules and system libraries.)*

---

## 🛠️ Installation & Setup

There are two primary ways to install and run AutoAR:

### Option 1: Quick Install using `go install`
Because the main executable is located in the `cmd/autoar` directory, you cannot simply run `go install github.com/h0tak88r/AutoAR@latest`. Instead, point directly to the binary package:

```bash
go install github.com/h0tak88r/AutoAR/cmd/autoar@latest
```
*Note: This will install the `autoar` binary to your `$GOPATH/bin` directory (typically `~/go/bin`). Make sure this directory is in your system `$PATH`.*

### Option 2: Clone and Build manually (Recommended)
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/h0tak88r/AutoAR.git
   cd AutoAR
   ```

2. **Download Dependencies and Build:**
   ```bash
   go mod tidy
   go build -o autoar ./cmd/autoar
   ```

3. **Database Initialization:**
   AutoAR uses PostgreSQL or SQLite (depending on your `.env`).
   ```bash
   # Create new-results directory to store findings
   mkdir -p new-results
   ```

4. **Configure the Environment (`.env` file):**
   Copy the provided `.env.example` or tailor your `.env` in the root directory. AutoAR relies strictly on these environment variables:

   - **DISCORD_BOT_TOKEN**: Your Discord Bot Token (Bot must have `applications.commands` and standard message intents).
   - **DISCORD_ALLOWED_GUILD_ID**: Restricts the bot exclusively to your own Guild (Server) ID.
   - **DB_TYPE**: `postgresql` or `sqlite3`
   - **DB_HOST**: Your connection URI or sqlite path.
   - **OPENROUTER_API_KEY** / **GEMINI_API_KEY**: API key for your AI Analysis features.
   - **AUTOAR_RESULTS_DIR**: Set to `./new-results` or `/app/new-results` if running via Docker.
   - **Optional Integrations**: Shodan, Censys, VirusTotal, R2 Storage IDs as needed.

5. **Run the Bot or API:**
   Run the bot natively, ensuring `.env` is loaded automatically:
   ```bash
   # Start the Discord Bot
   ./autoar bot
   
   # Or start the REST API
   ./autoar api
   
   # Or start both simultaneously
   ./autoar both
   ```

---

## 🐛 Troubleshooting 

**No Logs Displaying in the Terminal?**

If you run the bot and notice there is zero output in the terminal console, it is likely due to the logging configuration formatting.
In `internal/modules/utils/logger.go`, `logrus` is instructed to **only write to a log file** (by default: `autoar-bot.log`) when JSON format is enabled. 
It writes to `os.Stdout` (Terminal) only if JSON formatting is disabled. 

To see logs in the terminal, check your settings to ensure `JSONFormat: false`, or tail the log file directly in another window:
```bash
tail -f autoar-bot.log
```
