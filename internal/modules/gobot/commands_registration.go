package gobot

import (
	"log"

	"github.com/bwmarrin/discordgo"
)

// registerAllCommands registers all 54 Discord commands
func registerAllCommands(s *discordgo.Session) {
	commands := []*discordgo.ApplicationCommand{
		// React2Shell commands
		{
			Name:        "react2shell_scan",
			Description: "Scan domain hosts for React Server Components RCE using next88 smart scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "enable_source_exposure", Description: "Enable source code exposure check (default: false)", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "dos_test", Description: "Enable DoS test (default: false)", Required: false},
			},
		},
		{
			Name:        "react2shell",
			Description: "Test single URL for React Server Components RCE using next88 smart scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "Target URL to test", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
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
			Description: "Perform a lite domain scan",
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
			Description: "Perform a fast domain lookup",
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
			},
		},
		// Reconnaissance commands
		{
			Name:        "subdomains",
			Description: "Enumerate subdomains",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to enumerate", Required: true},
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
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "urls",
			Description: "Collect URLs and JS URLs",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "reflection",
			Description: "Run reflection scan (kxss)",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "tech",
			Description: "Detect technologies on live hosts",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
			},
		},
		{
			Name:        "ports",
			Description: "Scan ports for a domain",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		// Vulnerability scanning
		{
			Name:        "nuclei",
			Description: "Run nuclei templates on domain/URL",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to scan (use either domain or url)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "url", Description: "Single URL to scan (use either domain or url)", Required: false},
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
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "sqlmap",
			Description: "Run SQLMap on GF SQLi results",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "dalfox",
			Description: "Run Dalfox XSS scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "apkx_scan",
			Description: "Analyze an APK or IPA file with apkX",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionAttachment,
					Name:        "file",
					Description: "APK or IPA file to analyze",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "mitm",
					Description: "Enable MITM patching (apkX -mitm)",
					Required:    false,
				},
			},
		},
		// DNS commands
		{
			Name:        "dns_takeover",
			Description: "Run comprehensive DNS takeover scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "dns_cname",
			Description: "Run CNAME takeover scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "dns_ns",
			Description: "Run NS takeover scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "dns_azure_aws",
			Description: "Run Azure & AWS takeover scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
			},
		},
		{
			Name:        "dns_dnsreaper",
			Description: "Run DNSReaper takeover scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
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
			Name:        "github_scan",
			Description: "Scan GitHub repository for secrets",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "repo", Description: "GitHub repository (owner/repo)", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
			},
		},
		{
			Name:        "github_org_scan",
			Description: "Scan GitHub organization for secrets",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "org", Description: "GitHub organization name", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "max_repos", Description: "Maximum number of repositories to scan", Required: false},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "verbose", Description: "Enable verbose output", Required: false},
			},
		},
		{
			Name:        "github_experimental_scan",
			Description: "Run experimental GitHub scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "repo", Description: "GitHub repository (owner/repo)", Required: true},
			},
		},
		{
			Name:        "github_wordlist",
			Description: "Generate wordlist from GitHub organization",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "org", Description: "GitHub organization name", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "token", Description: "GitHub token (optional)", Required: false},
			},
		},
		{
			Name:        "githubdepconf",
			Description: "GitHub dependency confusion scan",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "repo", Description: "GitHub repository (owner/repo)", Required: false},
				{Type: discordgo.ApplicationCommandOptionString, Name: "org", Description: "GitHub organization name", Required: false},
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
			Name:        "db_domains",
			Description: "List distinct domains stored in PostgreSQL database",
		},
		{
			Name:        "db_subdomains",
			Description: "List subdomains for a domain from PostgreSQL database",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to list subdomains for", Required: true},
			},
		},
		{
			Name:        "db_delete_domain",
			Description: "Delete domain and all related data from database",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain to delete", Required: true},
				{Type: discordgo.ApplicationCommandOptionBoolean, Name: "force", Description: "Skip confirmation prompt", Required: false},
			},
		},
		// KeyHack commands
		{
			Name:        "keyhack_list",
			Description: "List all API key validation templates",
		},
		{
			Name:        "keyhack_search",
			Description: "Search for API key validation templates",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "query", Description: "Search query (provider name or partial match)", Required: true},
			},
		},
		// Monitoring commands
		{
			Name:        "monitor_updates",
			Description: "Monitor Updates: list all targets with running status",
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
				{Type: discordgo.ApplicationCommandOptionString, Name: "pattern", Description: "Regex pattern if strategy=regex (for add)", Required: false},
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
				{Type: discordgo.ApplicationCommandOptionString, Name: "wordlist", Description: "Custom wordlist for weak secret detection", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "max_crack_attempts", Description: "Limit secret testing attempts", Required: false},
			},
		},
		// Other commands
		{
			Name:        "backup_scan",
			Description: "Discover backup files using Fuzzuli",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "domain", Description: "The domain", Required: true},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "threads", Description: "Number of threads (default: 100)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "delay", Description: "Delay between requests (default: 0)", Required: false},
			},
		},
		{
			Name:        "check_tools",
			Description: "Check if all required tools are installed",
		},
		{
			Name:        "misconfig",
			Description: "Scan for misconfigurations",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "target", Description: "Target to scan", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "service", Description: "Specific service to scan (optional)", Required: false},
				{Type: discordgo.ApplicationCommandOptionInteger, Name: "delay", Description: "Delay between requests (default: 0)", Required: false},
			},
		},
		{
			Name:        "scan_status",
			Description: "List all active and recent completed scans",
		},
		{
			Name:        "scan_from_file",
			Description: "Scan targets from a file. Attach file or use message_id",
			Options: []*discordgo.ApplicationCommandOption{
				{Type: discordgo.ApplicationCommandOptionString, Name: "scan_type", Description: "Type of scan (subdomains, livehosts, nuclei, etc.)", Required: true},
				{Type: discordgo.ApplicationCommandOptionString, Name: "message_id", Description: "Message ID with file (optional)", Required: false},
			},
		},
		// Message context command - right-click on message with file
		{
			Name: "Scan File",
			Type: discordgo.MessageApplicationCommand,
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
		if existingCommands != nil {
			for _, ec := range existingCommands {
				if ec.Name == cmd.Name {
					existingCmd = ec
					break
				}
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
