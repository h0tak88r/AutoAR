package gobot

import (
	"log"

	"github.com/bwmarrin/discordgo"
)

// registerAllCommands registers all Discord commands
func registerAllCommands(s *discordgo.Session) {
	commands := []*discordgo.ApplicationCommand{
		// AI Natural Language command
		{
			Name:        "ai",
			Description: "🤖 Talk to AutoAR in natural language — the AI will decide what scans to run",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "message", Description: "Your natural language request (e.g. 'scan example.com for open ports')", Required: true},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "agent_mode",
					Description: "Enable full autonomous agent mode (runs commands, validates results, reports to Discord)",
					Required:    false,
				},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "dry_run", Description: "Explain what you would do without running scans", Required: false},
			},
		},
		// ASR commands
		{
			Name:        "asr",
			Description: "High-depth reconnaissance (ASR Modes)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Domain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "mode", Description: "Recon mode (1-5, default: 5)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 50)", Required: false},
			},
		},
		// Zerodays commands
		{
			Name:        "zerodays",
			Description: "Zerodays scan (CVE-2025-55182 React2Shell, CVE-2025-14847 MongoDB) - domain hosts or single URL",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Domain to scan (for host scanning)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "Single URL to test (for single URL testing)", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File containing domains (one per line) - will do live hosts + smart scan for each", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "host_list", Description: "File containing specific hosts/URLs to scan (skips enumeration)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (for domain scan, default: 100)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "enable_source_exposure", Description: "Enable source code exposure check (for domain scan)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "dos_test", Description: "Enable DoS test (for domain scan)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output (for URL test)", Required: false},
			},
		},
		// Scan commands
		{
			Name:        "scan_domain",
			Description: "Perform a full domain scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "keep_results", Description: "Keep scan results after completion", Required: false},
			},
		},
		{
			Name:        "scan_subdomain",
			Description: "Scan a single subdomain",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "subdomain", Description: "The subdomain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
			},
		},
		{
			Name:        "lite_scan",
			Description: "Full scan: livehosts → reflection → JS → CNAME → backup → DNS → misconfig",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "skip_js", Description: "Skip JavaScript scanning step", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "phase_timeout", Description: "Default per-phase timeout in seconds (default: 3600)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "timeout_livehosts", Description: "Override timeout for livehosts phase (seconds)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "timeout_reflection", Description: "Override timeout for reflection phase (seconds)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "timeout_js", Description: "Override timeout for JS phase (seconds)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "timeout_nuclei", Description: "Override timeout for nuclei phase (seconds)", Required: false},
			},
		},
		{
			Name:        "fast_look",
			Description: "Quick reconnaissance: subdomain enumeration → live host filtering → URL/JS collection",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
			},
		},
		{
			Name:        "domain_run",
			Description: "Run full domain workflow",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "skip_ffuf", Description: "Skip FFuf fuzzing phase (faster)", Required: false},
			},
		},
		{
			Name:        "subdomain_run",
			Description: "Run full workflow on a single subdomain (checks if live, then runs all scans)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "subdomain", Description: "The subdomain to scan (e.g., subdomain.example.com)", Required: true},
			},
		},
		{
			Name:        "brain",
			Description: "🧠 AI Analysis: Suggest or execute follow-up attacks based on scan results",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "scan_id", Description: "The ID of the scan to analyze", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "attachment", Description: "File containing results to analyze", Required: false},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "mode",
					Description: "Analysis mode: Suggest or Execute (default: Execute)",
					Required:    false,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "Suggest", Value: "suggest"},
						{Name: "Execute", Value: "execute"},
					},
				},
			},
		},
		{
			Name:        "scans",
			Description: "📜 List recent scans to find Scan IDs",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "limit", Description: "Number of scans to list (default: 10)", Required: false},
			},
		},
		// Reconnaissance commands
		{
			Name:        "subdomains",
			Description: "Enumerate subdomains",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to enumerate", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "cnames",
			Description: "Collect CNAME records for domain subdomains",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "livehosts",
			Description: "Filter live hosts from subdomains",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "urls",
			Description: "Collect URLs and JS URLs",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain or subdomain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "subdomain", Description: "Treat input as a single subdomain (skip subdomain enumeration)", Required: false},
			},
		},
		{
			Name:        "reflection",
			Description: "Run reflection scan (kxss)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
			},
		},
		{
			Name:        "tech",
			Description: "Detect technologies on live hosts",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "ports",
			Description: "Scan ports for a domain",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
			},
		},
		// Vulnerability scanning
		{
			Name:        "nuclei",
			Description: "Run nuclei templates on domain/URL",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan (use either domain, url, or file)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "Single URL to scan (use either domain, url, or file)", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains/URLs (one per line)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "mode", Description: "Scan mode: full, cves, panels, default-logins, or vulnerabilities (default: full)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "enum", Description: "Enable enumeration (only valid with domain)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "js_scan",
			Description: "Scan for JavaScript files and endpoints",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "subdomain", Description: "Specific subdomain to scan (optional)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
			},
		},
		{
			Name:        "gf_scan",
			Description: "Run GF pattern scans",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
			},
		},
		{
			Name:        "sqlmap",
			Description: "Run SQLMap on GF SQLi results",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
			},
		},
		{
			Name:        "dalfox",
			Description: "Run Dalfox XSS scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File with domains (one per line)", Required: false},
			},
		},
		// DNS commands
		{
			Name:        "dns",
			Description: "Run DNS takeover scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Root domain (enumerates subdomains first)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "subdomain", Description: "Single subdomain to scan directly (skips enumeration, ideal for cf1016)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "type", Description: "Scan type: takeover (all), cname, ns, azure-aws, dnsreaper, dangling-ip, cf1016", Required: false, Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "Takeover (All)", Value: "takeover"},
					{Name: "CNAME", Value: "cname"},
					{Name: "NS", Value: "ns"},
					{Name: "Azure/AWS", Value: "azure-aws"},
					{Name: "DNSReaper", Value: "dnsreaper"},
					{Name: "Dangling IP", Value: "dangling-ip"},
					{Name: "Cloudflare 1016 Dangling", Value: "cf1016"},
				}},
			},
		},
		// S3 commands
		{
			Name:        "s3_scan",
			Description: "Scan for S3 buckets",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "bucket", Description: "S3 bucket name to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "region", Description: "AWS region (optional)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
			},
		},
		{
			Name:        "s3_enum",
			Description: "Enumerate potential S3 buckets",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "root", Description: "Root domain name, e.g., vulnweb", Required: true},
			},
		},
		// GitHub commands
		{
			Name:        "github",
			Description: "GitHub scanning and analysis",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "mode", Description: "Scan mode: scan (repo), org, experimental, wordlist, depconf", Required: true, Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "Repo Scan", Value: "scan"},
					{Name: "Org Scan", Value: "org"},
					{Name: "Experimental", Value: "experimental"},
					{Name: "Wordlist", Value: "wordlist"},
					{Name: "Dependency Confusion", Value: "depconf"},
				}},
				{Type: discordgo.ApplicationCommandOptionString, Name: "repo", Description: "GitHub repository (owner/repo) - for scan, experimental, depconf", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "org", Description: "GitHub organization name - for org, wordlist, depconf", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "max_repos", Description: "Maximum number of repositories to scan (for org mode)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "token", Description: "GitHub token (for wordlist mode)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output (for scan, org, experimental)", Required: false},
			},
		},
		{
			Name:        "webdepconf",
			Description: "Web dependency confusion scan (use --full for subdomain enum + live hosts)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "Target URL(s)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Domain for full scan (with --full flag)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "full", Description: "Enable full scan (subdomain enum + live hosts)", Required: false},
			},
		},
		// Database commands
		{
			Name:        "db",
			Description: "Database operations",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "action", Description: "Action: list-domains, list-subdomains, delete-domain", Required: true, Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "List Domains", Value: "list-domains"},
					{Name: "List Subdomains", Value: "list-subdomains"},
					{Name: "Delete Domain", Value: "delete-domain"},
				}},
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Domain (required for list-subdomains and delete-domain)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "force", Description: "Skip confirmation (for delete-domain)", Required: false},
			},
		},
		// KeyHack commands
		{
			Name:        "keyhack",
			Description: "API key validation templates",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "action", Description: "Action: list all templates or search", Required: true, Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "List All", Value: "list"},
					{Name: "Search", Value: "search"},
				}},
				{Type: discordgo.ApplicationCommandOptionString, Name: "query", Description: "Search query (required for search action)", Required: false},
			},
		},
		// Monitoring commands
		{
			Name:        "monitor_subdomains_manage",
			Description: "Manage automatic subdomain monitoring targets (add/remove/list/start/stop)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "action", Description: "Action: add, remove, list, start, or stop", Required: true, Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "list", Value: "list"},
					{Name: "add", Value: "add"},
					{Name: "remove", Value: "remove"},
					{Name: "start", Value: "start"},
					{Name: "stop", Value: "stop"},
				}},
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Domain (for add/remove/start/stop)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "id", Description: "Target ID (for remove/start/stop)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "interval", Description: "Check interval in seconds (for add, default: 3600)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Threads for httpx (for add, default: 100)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "check_new", Description: "Check for new subdomains (for add, default: true)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "all", Description: "Apply to all targets (for start/stop)", Required: false},
			},
		},
		{
			Name:        "monitor_updates_manage",
			Description: "Monitor Updates: manage targets (add/remove/start/stop)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "action", Description: "Action: add, remove, start, or stop", Required: true, Choices: []*discordgo.ApplicationCommandOptionChoice{
					{Name: "add", Value: "add"},
					{Name: "remove", Value: "remove"},
					{Name: "start", Value: "start"},
					{Name: "stop", Value: "stop"},
				}},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "id", Description: "Target ID (for remove/start/stop)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "URL (for add/start/stop by URL)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "strategy", Description: "Strategy: hash|size|headers|regex (for add, default: hash)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "pattern", Description: "Regex pattern if strategy=regex (default: date format)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "interval", Description: "Interval in seconds (for start, default: 86400)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "all", Description: "Apply to all targets (for start/stop)", Required: false},
			},
		},
		// JWT commands
		{
			Name:        "jwt_scan",
			Description: "Scan JWT token for vulnerabilities using jwt-hack",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "token", Description: "JWT token to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "skip_crack", Description: "Skip secret cracking for faster results", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "skip_payloads", Description: "Skip payload generation", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "test_attacks", Description: "Generate test tokens for attacks (alg:none, null sig, alg confusion, weak secrets)", Required: false},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "wordlist",
					Description: "Wordlist for dictionary attack (fast or heavy)",
					Required:    false,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "Fast (jwt-common.txt)", Value: "fast"},
						{Name: "Heavy (scraped-JWT-secrets.txt)", Value: "heavy"},
					},
				},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "max_crack_attempts", Description: "Limit secret testing attempts", Required: false},
			},
		},
		// Other commands
		{
			Name:        "aem_scan",
			Description: "Scan for AEM webapps and test for vulnerabilities",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "Domain to scan", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "live_hosts_file", Description: "Path to live hosts file (alternative to domain)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 50)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "ssrf_host", Description: "Hostname/IP for SSRF detection (VPS required)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "ssrf_port", Description: "Port for SSRF detection", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "debug", Description: "Enable debug output", Required: false},
			},
		},
		{
			Name:        "backup_scan",
			Description: "Discover backup files using Fuzzuli",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain (or use file option for multiple domains)", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "File containing domains (one per line)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "method", Description: "Fuzzuli method: regular, withoutdots, reverse, mixed, shuffle, all (default: regular)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "extensions", Description: "File extensions (comma-separated, e.g., .rar,.zip) - default: all", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "delay", Description: "Delay between requests (default: 0)", Required: false},
			},
		},
		{
			Name:        "check_tools",
			Description: "Check if all required tools are installed",
		},
		{
			Name:        "scope",
			Description: "Fetch scope from bug bounty platforms and extract root domains",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "platform",
					Description: "Platform: h1, bc, it, ywh, immunefi",
					Required:    true,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "HackerOne", Value: "h1"},
						{Name: "Bugcrowd", Value: "bc"},
						{Name: "Intigriti", Value: "it"},
						{Name: "YesWeHack", Value: "ywh"},
						{Name: "Immunefi", Value: "immunefi"},
					},
				},
				{Type: discordgo.ApplicationCommandOptionString, Name: "username", Description: "Username (for HackerOne)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "token", Description: "API token (required for most platforms)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "email", Description: "Email (for Bugcrowd/YesWeHack login)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "password", Description: "Password (for Bugcrowd/YesWeHack login)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "categories", Description: "Categories filter (default: all)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "bbp_only", Description: "Only fetch programs offering monetary rewards", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "pvt_only", Description: "Only fetch private programs", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "include_oos", Description: "Include out-of-scope items", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "public_only", Description: "Only fetch public programs (HackerOne)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "active_only", Description: "Only fetch active programs (HackerOne)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "extract_roots", Description: "Extract root domains (default: true). Set false for raw targets", Required: false},
			},
		},
		{
			Name:        "misconfig",
			Description: "Scan for misconfigurations",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "target", Description: "Target to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "service", Description: "Specific service to scan (optional)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "delay", Description: "Delay between requests in ms (default: 50)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "permutations", Description: "Enable permutations for thorough scanning (slower but more comprehensive)", Required: false},
			},
		},
		{
			Name:        "scan_status",
			Description: "List all active and recent completed scans",
		},
		{
			Name:        "git_scan",
			Description: "Dump exposed .git repository and scan for secrets",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "Target URL (exposing .git)", Required: true},
			},
		},
		{
			Name:        "cancel_scan",
			Description: "Cancel a running scan (domain_run, subdomain_run, etc.)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "scan_id", Description: "Scan ID to cancel (get from /scan_status)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "target", Description: "Target (domain/subdomain) to cancel scans for", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "scan_type", Description: "Scan type (domain_run, subdomain_run, etc.) - required if target is provided", Required: false},
			},
		},
		// SSRF / Open Redirect bypass wordlist generator
		{
			Name:        "ssrf_bypass",
			Description: "Generate SSRF/Open Redirect bypass wordlist for Burp Suite Intruder",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "attacker", Description: "Your attacker/collaborator domain (e.g. attacker.com)", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "victim", Description: "Victim/target domain to bypass validation for (e.g. victim.com)", Required: true},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "scheme",
					Description: "URL scheme to prepend to raw payloads (default: https)",
					Required:    false,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "https", Value: "https"},
						{Name: "http", Value: "http"},
						{Name: "none (raw payloads)", Value: "none"},
					},
				},
			},
		},
		// Fuzzing command
		{
			Name:        "fuzz",
			Description: "🔍 Directory & path fuzzing with ffuf — single host or multi-host file",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "host", Description: "Single target host or URL to fuzz (e.g. example.com or https://api.example.com)", Required: false},
				{Type: discordgo.ApplicationCommandOptionAttachment, Name: "file", Description: "Text file with multiple hosts (one per line) to fuzz in bulk", Required: false},
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "wordlist",
					Description: "Wordlist preset (default: quick)",
					Required:    false,
					Choices: []*discordgo.ApplicationCommandOptionChoice{
						{Name: "Quick (quick_fuzz.txt)", Value: "quick"},
						{Name: "Small (dirsearch small)", Value: "small"},
						{Name: "Medium (dirsearch medium)", Value: "medium"},
						{Name: "Large (dirsearch big)", Value: "large"},
						{Name: "API Endpoints", Value: "api"},
					},
				},
				{Type: discordgo.ApplicationCommandOptionString, Name: "extensions", Description: "File extensions to append (e.g. .php,.html,.json)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of concurrent threads (default: 50)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "rate_limit", Description: "Max requests per second (0 = unlimited)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "match_codes", Description: "HTTP status codes to match (default: 200,204,301,302,307,401,403,405,500)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "filter_size", Description: "Filter out responses by size in bytes (e.g. 1234)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "recursive", Description: "Enable recursive fuzzing", Required: false},
			},
		},
		// AI Chat Mode
		{
			Name:        "ai",
			Description: "🤖 Chat with AutoAR AI — describe what you want to scan in plain language",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "message",
					Description: "Your request in plain language (e.g. 'do a domain scan on example.com')",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "dry_run",
					Description: "Only explain what would be done — don't actually run any scans",
					Required:    false,
				},
			},
		},
		{
			Name:        "help",
			Description: "📚 Display all available AutoAR commands and workflows",
		},
	}

	// List of commands to remove (old/obsolete commands)
	commandsToRemove := []string{
		"keyhack_add",
		"keyhack_validate",
		"monitor_updates_add",
		"monitor_updates_remove",
		"monitor_updates_start",
		"monitor_updates_stop",
		"monitor_updates_list",
		"help_autoar",
		"cleanup",
		"jwt_query",
		"live_depconfusion_scan",
		"wp_depconf",
	}

	// Fetch all existing commands from Discord
	existingCommands, err := s.ApplicationCommands(s.State.User.ID, "")
	if err != nil {
		log.Printf("Failed to fetch existing commands: %v", err)
	} else {
		// Delete old commands that are not in our new list
		for _, existingCmd := range existingCommands {
			shouldRemove := false
			for _, removeName := range commandsToRemove {
				if existingCmd.Name == removeName {
					shouldRemove = true
					break
				}
			}

			// Also check if command exists in our new commands list
			if !shouldRemove {
				found := false
				for _, newCmd := range commands {
					if existingCmd.Name == newCmd.Name {
						found = true
						break
					}
				}
				if !found {
					// Command exists in Discord but not in our new list - remove it
					shouldRemove = true
				}
			}

			if shouldRemove {
				err := s.ApplicationCommandDelete(s.State.User.ID, "", existingCmd.ID)
				if err != nil {
					log.Printf("Failed to delete command %s: %v", existingCmd.Name, err)
				} else {
					log.Printf("Deleted old command: %s", existingCmd.Name)
				}
			}
		}
	}

	// Create a map of command names for quick lookup
	commandMap := make(map[string]*discordgo.ApplicationCommand)
	for _, cmd := range commands {
		commandMap[cmd.Name] = cmd
	}

	// Update or create commands
	for _, cmd := range commands {
		// Check if command already exists
		var existingCmd *discordgo.ApplicationCommand
		for _, ec := range existingCommands {
			if ec.Name == cmd.Name {
				existingCmd = ec
				break
			}
		}

		if existingCmd != nil {
			// Update existing command
			_, err := s.ApplicationCommandEdit(s.State.User.ID, "", existingCmd.ID, cmd)
			if err != nil {
				log.Printf("Cannot update command %v: %v", cmd.Name, err)
			} else {
				log.Printf("Updated command: %s", cmd.Name)
			}
		} else {
			// Create new command
			_, err := s.ApplicationCommandCreate(s.State.User.ID, "", cmd)
			if err != nil {
				log.Printf("Cannot create command %v: %v", cmd.Name, err)
			} else {
				log.Printf("Registered command: %s", cmd.Name)
			}
		}
	}
	log.Printf("Total commands registered: %d", len(commands))
}
