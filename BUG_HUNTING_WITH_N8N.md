### Using n8n To Orchestrate Bug Hunting With AutoAR, Notion, and AI

Modern bug hunting benefits from automation and orchestration. This write‑up describes how I use n8n as a control plane to run scans via AutoAR’s API, track state in Notion, notify via Discord, and generate AI‑assisted reports.

### Architecture Overview
- n8n: event bus, scheduler, and workflow engine
- AutoAR: scan engine exposed as a REST API
- Notion: single source of truth for targets and statuses
- Discord: real‑time notifications (capacity, completion, errors)
- AI reporting: OpenRouter model drafting structured markdown reports

### Workflow In Practice
1) Intake in Notion
- New items are added to a Notion database with fields like Target and Scan Type.
- n8n watches Notion and triggers when a new/updated record needs a scan.

2) Capacity Guard
- n8n queries AutoAR `/capacity`. If at capacity, a Discord warning is posted and the item is deferred.

3) Launch Scan
- n8n POSTs to AutoAR `/scan` with the chosen scan type. AutoAR runs asynchronously and stores results under `new-results/`.

4) Persistence and Status
- Once completed, n8n sets the Notion item to “Completed”. Discord receives a concise completion message and, when useful, file artifacts (lists, findings, wordlists).

5) AI‑Assisted Reporting
- A dedicated n8n flow sends structured findings to an LLM via OpenRouter and writes a clean, templated markdown report back into Notion for review.

### Scan Types (What I Run and Why)

#### Domain
- Full domain reconnaissance across subdomains, live host filtering, URL harvesting, technology detection, DNS checks, nuclei templates, reflection, JS exposure scans, port scanning, and vulnerability patterns.
- Best for comprehensive coverage on a root program domain.

#### Subdomain
- Targets a single subdomain with the same core modules (URLs, JS, reflection, tech detection, nuclei, ports, etc.).
- Useful for deep‑dive validation or triaging high‑value assets quickly.

#### liteScan
- Fast but broad: subdomain enumeration, CNAME checks, live hosts, technology detection, dangling DNS, reflection, URLs + JS exposure, nuclei scans, and optional backup exposure discovery.
- My default when I want actionable results quickly without the full weight of a domain‑wide run.

#### fastLook
- Minimal reconnaissance: subenum → live hosts → URLs → tech detect → CNAME check → reflection.
- Great for “is this worth a deeper look?”

#### GitHub (Repo, Org, Wordlist)
- github_single_repo: Scans a single repository for secrets with modern TruffleHog, producing JSON/HTML artifacts.
- github_org_scan: Scans an organization’s public surface for secret leaks across repos.
- github_wordlist: Generates a deduplicated wordlist from an organization’s ignore files (e.g., `.gitignore`, `.npmignore`, `.dockerignore`).
  - Filters comments/empties/HTML, normalizes slashes, enforces safe charset/length, and sends to Discord.
  - Uses GitHub CLI when available; otherwise falls back to REST + raw.

#### Android (APKX pipeline)
- Orchestrated via n8n to a dedicated mobile automation backend.
- Supports queueing, capacity checks, app download, optional MITM patching, HTML artifact generation, and Discord notifications.
- Tracked and closed out in Notion when processing ends.

#### iOS (APKX iOS pipeline)
- Similar to Android flow with an iOS‑oriented backend, including capacity checks, job submission, and Discord reporting.
- Managed as first‑class entries in the same Notion board.

### Why This Automation Works
- Consistency: Every run is defined, logged, and repeatable.
- Scale: Capacity checks prevent overload and degraded results.
- Speed: One click in Notion triggers end‑to‑end workflows.
- Signal over noise: Discord carries just the right events; detailed data lives in results and Notion.
- Extensibility: New tools are new nodes; new scans are new API routes.
- Quality: AI drafts structured reports so I spend time validating and expanding impact.

### Operational Tips
- Keep tokens and webhooks in configuration, never in code.
- Let n8n gate execution on `/capacity` for stable throughput.
- Store canonical statuses in Notion; treat Discord as a broadcast channel.
- Restart the API when adding new scan types or capabilities.

### Outcome
This setup turns recon and analysis into a controlled system: n8n orchestrates, AutoAR executes, Notion tracks, Discord informs, and AI accelerates reporting. It’s professional, maintainable, and easy to extend as programs evolve.


