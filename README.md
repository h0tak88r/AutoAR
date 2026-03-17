# AutoAR - Automated Reconnaissance Platform

AutoAR is an automated security reconnaissance tool and Discord bot for bug bounty hunters and penetration testers. It automates gathering subdomains, scanning ports, detecting technologies, mapping GitHub repositories, fuzzing, testing vulnerabilities, and AI analysis.

## Features

- **Discord Bot Interface**: Run and manage full reconnaissance workflows from Discord commands (`/domain_run`, `/subdomain_run`, `/brain`, etc.).
- **Subdomain Enumeration**: Subfinder, amass, crt.sh, wayback machine and chaos integration.
- **Port Scanning**: Naabu integration for continuous port scanning.
- **Vulnerability Scanning**: Nuclei templates for continuous exposure monitoring.
- **AI Brain**: AI-driven analysis of discovery logs, automated follow-up commands (`curl`, `nmap` scanning) via Gemini and OpenRouter using the `/brain` command.
- **Web App Analysis**: JavaScript file analysis, secret scanning (jwt-hack, dalfox), misconfiguration and S3 bucket testing.
- **Mobile Scanning**: APK and iOS package fetching and testing.
- **Zero Days & Exposures**: Specialized scanning components for recent CVEs and quick verifications.

---

## Prerequisites

Ensure you have the following installed on your host or Docker environment:
- **Go** (1.21+ recommended)

*(AutoAR handles security tools and utilities internally via Go modules and libraries.)*

## Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/h0tak88r/AutoAR.git
   cd AutoAR
   ```

2. **Database Initialization:**
   AutoAR uses PostgreSQL or SQLite (depending on your `.env`).
   ```bash
   # Create new-results directory to store findings
   mkdir -p new-results
   ```

3. **Configure the Environment (`.env` file):**
   Copy the provided `.env.example` or tailor your `.env` in the root directory. AutoAR relies strictly on these environment variables:

   - **DISCORD_BOT_TOKEN**: Your Discord Bot Token (Bot must have `applications.commands` and standard message intents).
   - **DISCORD_ALLOWED_GUILD_ID**: Restricts the bot exclusively to your own Guild (Server) ID.
   - **DB_TYPE**: `postgresql` or `sqlite3`
   - **DB_HOST**: Your connection URI or sqlite path.
   - **OPENROUTER_API_KEY** / **GEMINI_API_KEY**: API key for your AI Analysis features.
   - **AUTOAR_RESULTS_DIR**: Set to `./new-results` or `/app/new-results` if running via Docker.
   - **Additional Integrations**: Shodan, Censys, VirusTotal, R2 Storage IDs as needed in `.env`.

4. **Build the Bot:**
   ```bash
   # Download go modules
   go mod tidy
   
   # Build the main AutoAR executable
   go build -o autoar ./cmd/autoar
   ```

5. **Run the Bot:**
   Run the bot natively, ensuring `.env` is loaded automatically:
   ```bash
   ./autoar bot
   ```

## Troubleshooting 

**No Logs Displaying in the Terminal?**

If you run the bot and notice there is zero output in the terminal console, it is likely due to the logging configuration formatting.
In `internal/modules/utils/logger.go`, `logrus` is instructed to **only write to a log file** (by default: `autoar-bot.log`) when JSON format is enabled. 
It writes to `os.Stdout` (Terminal) only if JSON formatting is disabled. 

To see logs in the terminal, check your settings to ensure `JSONFormat: false`, or tail the log file directly in another window:
```bash
tail -f autoar-bot.log
```
