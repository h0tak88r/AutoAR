package gobot

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
	next88 "github.com/h0tak88r/AutoAR/v3/internal/tools/next88"
)

// handleReact2Shell handles both /react2shell_scan (domain) and /react2shell (URL) commands
func handleReact2Shell(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	url := ""
	threads := 100
	enableSourceExposure := false
	dosTest := false
	verbose := false
	var attachment *discordgo.MessageAttachment

	// Check for file attachment
	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "url":
			url = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		case "enable_source_exposure":
			enableSourceExposure = opt.BoolValue()
		case "dos_test":
			dosTest = opt.BoolValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	// Handle file attachment (list of domains)
	if attachment != nil {
		// Respond immediately
		err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "📥 Downloading file and processing domains...",
			},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to respond to interaction: %v", err)
		return
	}

		// Download and process file
		targets, err := downloadAndProcessFile(attachment)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error processing file: %v", err),
			})
			return
		}

		if len(targets) == 0 {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: "❌ No valid domains found in file",
			})
			return
		}

		// Update initial response
		content := fmt.Sprintf("📋 Found %d domains in file. Starting react2shell scan (live hosts + smart scan) for each...", len(targets))
		_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Content: &content,
		})
		if err != nil {
			log.Printf("[WARN] Failed to update interaction: %v", err)
		}

		// Process each domain: get live hosts, then run smart scan
		for idx, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			log.Printf("[INFO] Processing domain %d/%d: %s", idx+1, len(targets), target)

			embed := &discordgo.MessageEmbed{
				Title:       "React2Shell Host Scan",
				Description: fmt.Sprintf("**Domain:** `%s`\n**Threads:** %d\n**Source Exposure Check:** %s\n**DoS Test:** %s\n**Scan Method:** Smart Scan (next88 - sequential testing)", target, threads, boolToStatus(enableSourceExposure), boolToStatus(dosTest)),
				Color:       0x3498db,
				Fields: []*discordgo.MessageEmbedField{
					{Name: "Status", Value: "🟡 Running", Inline: false},
				},
			}

			_, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Embeds: []*discordgo.MessageEmbed{embed},
			})
			if err != nil {
				log.Printf("[ERROR] Failed to create followup message: %v", err)
				continue
			}

			// Create a new interaction create for this target
			targetInteraction := &discordgo.InteractionCreate{
				Interaction: &discordgo.Interaction{
					ID:        i.Interaction.ID + fmt.Sprintf("_%d", idx),
					ChannelID: i.ChannelID,
				},
			}

			go runReact2ShellScan(s, targetInteraction, target, threads, enableSourceExposure, dosTest)

			// Small delay between scans
			time.Sleep(1 * time.Second)
		}

		// Send summary
		summary := fmt.Sprintf("✅ **File Scan Initiated**\n\n**Scan Type:** react2shell (live hosts + smart scan)\n**Total Domains:** %d", len(targets))
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: summary,
		})
		return
	}

	// Validate: exactly one of domain or url must be provided
	if domain == "" && url == "" {
		respond(s, i, "❌ Either domain, URL, or file attachment is required", false)
		return
	}
	if domain != "" && url != "" {
		respond(s, i, "❌ Please provide either domain OR url, not both", false)
		return
	}
	if (domain != "" || url != "") && attachment != nil {
		respond(s, i, "❌ Cannot specify both domain/url and file. Use either domain/url or file attachment.", false)
		return
	}

	// Handle domain scan
	if domain != "" {
	// Send initial response
	embed := &discordgo.MessageEmbed{
		Title:       "React2Shell Host Scan",
		Description: fmt.Sprintf("**Domain:** `%s`\n**Threads:** %d\n**Source Exposure Check:** %s\n**DoS Test:** %s\n**Scan Method:** Smart Scan (next88 - sequential testing)", domain, threads, boolToStatus(enableSourceExposure), boolToStatus(dosTest)),
		Color:       0x3498db, // Blue
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "🟡 Running", Inline: false},
		},
	}

	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction: %v", err)
		return
	}

	// Run scan in background
	go runReact2ShellScan(s, i, domain, threads, enableSourceExposure, dosTest)
		return
	}

	// Handle single URL test
	// Normalize URL
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	// Send initial response
	embed := &discordgo.MessageEmbed{
		Title:       "🔍 React2Shell RCE Test",
		Description: fmt.Sprintf("**Target:** `%s`\n**Method:** next88 Smart Scan (sequential: normal → WAF bypass → Vercel WAF → paths)", url),
		Color:       0x3498db, // Blue
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "🟡 Running", Inline: false},
		},
	}

	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction: %v", err)
		return
	}

	// Run scan in background
	go runReact2ShellSingle(s, i, url, verbose)
}

// runReact2ShellScan runs the actual scan
func runReact2ShellScan(s *discordgo.Session, i *discordgo.InteractionCreate, domain string, threads int, enableSourceExposure, dosTest bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] Panic in runReact2ShellScan: %v", r)
			updateEmbed(s, i, fmt.Sprintf("❌ Scan failed with error: %v", r), 0xff0000)
		}
	}()

	log.Printf("[DEBUG] Starting domain scan for: %s", domain)

	// Step 1: Get live hosts
	log.Printf("[DEBUG] Step 1: Getting live hosts for %s", domain)
	liveHostsFile, err := getLiveHosts(domain, threads)
	if err != nil {
		log.Printf("[ERROR] Failed to get live hosts: %v", err)
		updateEmbed(s, i, fmt.Sprintf("❌ Failed to get live hosts: %v", err), 0xff0000)
		return
	}
	log.Printf("[DEBUG] Live hosts file: %s", liveHostsFile)

	// Step 2: Normalize hosts
	log.Printf("[DEBUG] Step 2: Normalizing hosts")
	hosts, err := normalizeHosts(liveHostsFile)
	if err != nil {
		log.Printf("[ERROR] Failed to normalize hosts: %v", err)
		updateEmbed(s, i, fmt.Sprintf("❌ Failed to normalize hosts: %v", err), 0xff0000)
		return
	}

	log.Printf("[DEBUG] Normalized %d hosts from %s", len(hosts), liveHostsFile)
	if len(hosts) == 0 {
		log.Printf("[WARN] No hosts found to scan")
		sendReact2ShellResults(s, i, domain, 0, 0, 0, 0, []string{})
		return
	}

	if len(hosts) > 0 {
		log.Printf("[DEBUG] First 5 hosts: %v", hosts[:min(5, len(hosts))])
	}

	// Step 3: Run smart scan
	log.Printf("[DEBUG] Step 3: Running smart scan on %d hosts", len(hosts))
	smartScanResults, err := runNext88ScanLib(hosts, []string{"-smart-scan"}, getDiscordWebhook())
	if err != nil {
		log.Printf("[ERROR] Smart scan failed: %v", err)
		smartScanResults = []string{}
	} else {
		log.Printf("[DEBUG] Smart scan completed, found %d vulnerable hosts", len(smartScanResults))
	}

	// Step 4: DoS test (if enabled)
	dosResults := []string{}
	if dosTest {
		log.Printf("[DEBUG] Step 4: Running DoS test")
		dosResults, err = runNext88ScanLib(hosts, []string{"-dos-test", "-dos-requests", "100"}, getDiscordWebhook())
		if err != nil {
			log.Printf("[ERROR] DoS test failed: %v", err)
		} else {
			log.Printf("[DEBUG] DoS test completed, found %d vulnerable hosts", len(dosResults))
		}
	}

	// Step 5: Source exposure check (if enabled)
	sourceExposureResults := []string{}
	if enableSourceExposure {
		log.Printf("[DEBUG] Step 5: Running source exposure check")
		sourceExposureResults, err = runSourceExposureCheck(domain, hosts, getDiscordWebhook())
		if err != nil {
			log.Printf("[ERROR] Source exposure check failed: %v", err)
		} else {
			log.Printf("[DEBUG] Source exposure check completed, found %d vulnerable hosts", len(sourceExposureResults))
		}
	}

	// Collect all vulnerable hosts
	log.Printf("[DEBUG] Collecting all vulnerable hosts")
	allVulnerable := make(map[string]bool)
	for _, h := range smartScanResults {
		allVulnerable[h] = true
	}
	for _, h := range dosResults {
		allVulnerable[h] = true
	}
	for _, h := range sourceExposureResults {
		allVulnerable[h] = true
	}

	vulnerableList := make([]string, 0, len(allVulnerable))
	for h := range allVulnerable {
		vulnerableList = append(vulnerableList, h)
	}

	log.Printf("[DEBUG] Total unique vulnerable hosts: %d", len(vulnerableList))
	log.Printf("[DEBUG] Sending results to Discord for domain: %s", domain)

	// Send results - with retry logic
	maxRetries := 3
	for retry := 0; retry < maxRetries; retry++ {
		err := sendReact2ShellResults(s, i, domain, len(hosts), len(smartScanResults), len(dosResults), len(sourceExposureResults), vulnerableList)
		if err == nil {
			log.Printf("[DEBUG] Successfully sent results to Discord")
			break
		}
		log.Printf("[WARN] Failed to send results (attempt %d/%d): %v", retry+1, maxRetries, err)
		if retry < maxRetries-1 {
			time.Sleep(2 * time.Second)
		}
	}

	log.Printf("[DEBUG] Domain scan completed for: %s", domain)
	
	// Cleanup domain directory after scan
	if err := cleanupDomainDirectory(domain); err != nil {
		log.Printf("[WARN] Failed to cleanup domain directory: %v", err)
	}
}

// runNext88Scan runs the next88 library with given flags and returns vulnerable hosts.
func runNext88Scan(hosts []string, extraFlags []string, webhookURL string) ([]string, error) {
	return runNext88ScanLib(hosts, extraFlags, webhookURL)
}

// runNext88ScanLib is the library-based implementation that uses internal/tools/next88.
func runNext88ScanLib(hosts []string, extraFlags []string, webhookURL string) ([]string, error) {
	if len(hosts) == 0 {
		return []string{}, nil
	}

	opts := next88.ScanOptions{
		Timeout:         10 * time.Second,
		VerifySSL:       false,
		FollowRedirects: true,
		SafeCheck:       false,
		Windows:         false,
		WAFBypass:       false,
		WAFBypassSizeKB: 128,
		VercelWAFBypass: false,
		Paths:           nil,
		DoubleEncode:    false,
		SemicolonBypass: false,
		CheckSourceExp:  false,
		CustomHeaders:   make(map[string]string),
		Threads:         10,
		Quiet:           true,
		Verbose:         false,
		NoColor:         true,
		AllResults:      true,
		DiscordWebhook:  "",
		DOSTest:         false,
		DOSRequests:     100,
		SmartScan:       false,
	}

	if len(hosts) < opts.Threads {
		opts.Threads = len(hosts)
		if opts.Threads == 0 {
			opts.Threads = 1
		}
	}

	for i := 0; i < len(extraFlags); i++ {
		flag := extraFlags[i]
		switch flag {
		case "-smart-scan":
			opts.SmartScan = true
		case "-dos-test":
			opts.DOSTest = true
		case "-dos-requests":
			if i+1 < len(extraFlags) {
				if v, err := strconv.Atoi(extraFlags[i+1]); err == nil && v > 0 {
					opts.DOSRequests = v
				}
				i++
			}
		case "-check-source-exposure":
			opts.CheckSourceExp = true
		}
	}

	log.Printf("[DEBUG] Running next88 library scan for %d hosts (smart=%v dos=%v checkSource=%v)", len(hosts), opts.SmartScan, opts.DOSTest, opts.CheckSourceExp)

	results, err := next88.Run(hosts, opts)
	if err != nil {
		return nil, err
	}

	vulnerableHosts := make(map[string]bool)
	for _, res := range results {
		if res.Vulnerable != nil && *res.Vulnerable {
			host := res.Host
			if host == "" {
				host = res.TestedURL
			}
			if host == "" {
				continue
			}
			hostname := extractHostname(host)
			if hostname != "" {
				vulnerableHosts[hostname] = true
			}
		}
	}

	out := make([]string, 0, len(vulnerableHosts))
	for h := range vulnerableHosts {
		out = append(out, h)
	}

	log.Printf("[DEBUG] Total vulnerable hosts found via next88 library: %d", len(out))
	return out, nil
}

// parseNext88Results parses next88 JSON output
func parseNext88Results(resultsFile string) ([]string, error) {
	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return []string{}, nil
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		// Try as array
		var arrayData []interface{}
		if err2 := json.Unmarshal(data, &arrayData); err2 != nil {
			return nil, fmt.Errorf("failed to parse JSON: %v", err)
		}
		jsonData = map[string]interface{}{"results": arrayData}
	}

	results, ok := jsonData["results"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	log.Printf("[DEBUG] Processing %d results from next88", len(results))

	vulnerableHosts := make(map[string]bool)
	for idx, result := range results {
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			continue
		}

		if idx < 3 {
			keys := make([]string, 0, len(resultMap))
			for k := range resultMap {
				keys = append(keys, k)
			}
			sample, _ := json.MarshalIndent(resultMap, "", "  ")
			if len(sample) > 300 {
				sample = sample[:300]
			}
			log.Printf("[DEBUG] Result %d keys: %v", idx, keys)
			log.Printf("[DEBUG] Result %d sample: %s", idx, string(sample))
		}

		// Check if vulnerable
		isVulnerable := false
		if v, ok := resultMap["vulnerable"].(bool); ok && v {
			isVulnerable = true
		} else if v, ok := resultMap["vulnerable"].(string); ok && strings.ToLower(v) == "true" {
			isVulnerable = true
		}

		host := ""
		if h, ok := resultMap["host"].(string); ok {
			host = h
		} else if h, ok := resultMap["url"].(string); ok {
			host = h
		} else if h, ok := resultMap["target"].(string); ok {
			host = h
		}

		if idx < 5 {
			log.Printf("[DEBUG] Result %d - Host: %s, Vulnerable: %v", idx, host, isVulnerable)
		}

		if isVulnerable && host != "" {
			// Extract hostname
			hostname := extractHostname(host)
			if hostname != "" {
				vulnerableHosts[hostname] = true
				log.Printf("[DEBUG] Found vulnerable host: %s (from: %s)", hostname, host)
			}
		}
	}

	result := make([]string, 0, len(vulnerableHosts))
	for h := range vulnerableHosts {
		result = append(result, h)
	}

	return result, nil
}

// Helper functions
// findNext88 removed - we now use the library directly via runNext88ScanLib

// writeLinesToFile writes lines to a file
func writeLinesToFile(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			return err
		}
	}
	return nil
}

func getLiveHosts(domain string, threads int) (string, error) {
	resultsDir := getResultsDir()

	subsDir := filepath.Join(resultsDir, domain, "subs")

	// Check if subdomains exist in database first
	shouldCollect := true
	if os.Getenv("DB_HOST") != "" || os.Getenv("SAVE_TO_DB") == "true" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			count, err := db.CountSubdomains(domain)
			if err == nil && count > 0 {
				log.Printf("[INFO] Found %d subdomains in database for %s, skipping collection", count, domain)
				shouldCollect = false
				// Load subdomains from DB and write to file for compatibility
				subs, err := db.ListSubdomains(domain)
				if err == nil && len(subs) > 0 {
					allSubsFile := filepath.Join(subsDir, "all-subs.txt")
					os.MkdirAll(subsDir, 0755)
					if err := writeLinesToFile(allSubsFile, subs); err != nil {
						log.Printf("[WARN] Failed to write subdomains from DB to file: %v", err)
					}
				}
			}
		}
	}

	// Only collect subdomains if not in database
	if shouldCollect {
	// Ensure subdomains exist first (this will enumerate if needed) using Go-backed CLI
	subCmd := exec.Command(autoarScript, "subdomains", "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "-s")
	if err := subCmd.Run(); err != nil {
		log.Printf("[WARN] Subdomain enumeration via autoar failed: %v, continuing anyway", err)
		}
	}

	// Now run livehosts via Go-backed CLI to filter live hosts
	cmd := exec.Command(autoarScript, "livehosts", "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "--silent")

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] livehosts command failed: %v, output: %s", err, string(output))
		return "", fmt.Errorf("livehosts failed: %v", err)
	}

	log.Printf("[DEBUG] livehosts output: %s", string(output))

	// Check for live hosts file first
	liveHostsFile := filepath.Join(subsDir, "live-subs.txt")
	if fileInfo, err := os.Stat(liveHostsFile); err == nil {
		// Verify file is not empty
		if fileInfo.Size() > 0 {
			// Count lines to verify we got results
			data, err := os.ReadFile(liveHostsFile)
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				nonEmptyLines := 0
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						nonEmptyLines++
					}
				}
				log.Printf("[DEBUG] Found %d live hosts in %s", nonEmptyLines, liveHostsFile)
				if nonEmptyLines > 0 {
					return liveHostsFile, nil
				}
			}
		}
	}

	// Fallback to all-subs.txt only if live-subs.txt doesn't exist or is empty
	allSubsFile := filepath.Join(subsDir, "all-subs.txt")
	if fileInfo, err := os.Stat(allSubsFile); err == nil {
		if fileInfo.Size() > 0 {
			// Count lines to verify we got results
			data, err := os.ReadFile(allSubsFile)
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				nonEmptyLines := 0
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						nonEmptyLines++
					}
				}
				log.Printf("[DEBUG] Found %d total subdomains in %s (using as fallback)", nonEmptyLines, allSubsFile)
				if nonEmptyLines > 0 {
					return allSubsFile, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no live hosts file found or all files are empty")
}

func normalizeHosts(hostsFile string) ([]string, error) {
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	normalized := make([]string, 0, len(lines))

	for _, line := range lines {
		host := strings.TrimSpace(line)
		if host == "" {
			continue
		}
		host = strings.TrimSuffix(host, "/")
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "https://" + host
		}
		normalized = append(normalized, host)
	}

	return normalized, nil
}

func extractHostname(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	parts := strings.Split(url, "/")
	host := parts[0]
	parts = strings.Split(host, ":")
	return parts[0]
}

func getDiscordWebhook() string {
	return os.Getenv("DISCORD_WEBHOOK")
}

func runSourceExposureCheck(domain string, hosts []string, webhookURL string) ([]string, error) {
	// Don't pass webhook - we handle Discord messages directly
	return runNext88ScanLib(hosts, []string{"-check-source-exposure"}, "")
}

func sendReact2ShellResults(s *discordgo.Session, i *discordgo.InteractionCreate, domain string, totalHosts, smartScanCount, dosCount, sourceExposureCount int, allVulnerable []string) error {
	embed := &discordgo.MessageEmbed{
		Title:       "🔍 React2Shell RCE Test Results",
		Description: fmt.Sprintf("**Target:** `%s`", domain),
	}

	if len(allVulnerable) > 0 {
		embed.Color = 0xff0000 // Red
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "🔴 **Vulnerable**", Inline: false},
			{Name: "Vulnerable Hosts Found", Value: fmt.Sprintf("**%d** unique host(s)", len(allVulnerable)), Inline: false},
		}

		hostsText := ""
		for i, host := range allVulnerable {
			if i >= 15 {
				hostsText += fmt.Sprintf("\n... and %d more", len(allVulnerable)-15)
				break
			}
			hostsText += fmt.Sprintf("`%s`\n", host)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Vulnerable Hosts",
			Value:  hostsText,
			Inline: false,
		})

		breakdown := []string{}
		if smartScanCount > 0 {
			breakdown = append(breakdown, fmt.Sprintf("Smart Scan: %d", smartScanCount))
		}
		if dosCount > 0 {
			breakdown = append(breakdown, fmt.Sprintf("DoS Test: %d", dosCount))
		}
		if sourceExposureCount > 0 {
			breakdown = append(breakdown, fmt.Sprintf("Source Exposure: %d", sourceExposureCount))
		}
		if len(breakdown) > 0 {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   "Breakdown",
				Value:  strings.Join(breakdown, " • "),
				Inline: false,
			})
		}
	} else {
		embed.Color = 0x00ff00 // Green
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "✅ **Not Vulnerable**", Inline: false},
		}

		statsText := fmt.Sprintf("**Live hosts:** `%d`\n", totalHosts)
		statsText += fmt.Sprintf("**Smart Scan findings:** `%d`\n", smartScanCount)
		if dosCount > 0 {
			statsText += fmt.Sprintf("**DoS Test findings:** `%d`\n", dosCount)
		}
		if sourceExposureCount > 0 {
			statsText += fmt.Sprintf("**Source Exposure findings:** `%d`\n", sourceExposureCount)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Statistics",
			Value:  statsText,
			Inline: false,
		})
	}

	_, err := s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to update Discord message: %v", err)
		// Try to send as followup message as fallback
		_, err2 := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err2 != nil {
			log.Printf("[ERROR] Failed to send followup message: %v", err2)
			return fmt.Errorf("both edit and followup failed: edit=%v, followup=%v", err, err2)
		}
		log.Printf("[DEBUG] Sent results as followup message (edit failed)")
		return nil
	}
	log.Printf("[DEBUG] Successfully updated Discord message for domain scan: %s", domain)
	return nil
}


func runReact2ShellSingle(s *discordgo.Session, i *discordgo.InteractionCreate, target string, verbose bool) {
	// Use the library-based implementation instead of binary
	log.Printf("[DEBUG] Running next88 library scan for single URL: %s", target)

	// Run smart scan using the library
	results, err := runNext88ScanLib([]string{target}, []string{"-smart-scan"}, "")
	if err != nil {
		embed := &discordgo.MessageEmbed{
			Title:       "❌ React2Shell Test Failed",
			Description: fmt.Sprintf("**Target:** `%s`\n**Error:** %v", target, err),
			Color:       0xff0000,
		}
		s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Embeds: &[]*discordgo.MessageEmbed{embed},
		})
		return
	}

	// Check if vulnerable (if any results returned, it's vulnerable)
	isVulnerable := len(results) > 0

	// Get detailed results from the library
	var vulnerabilityDetails map[string]interface{}
	var pocData map[string]interface{}

	if isVulnerable {
		// Run the scan again with detailed options to get full results
		opts := next88.ScanOptions{
			Timeout:         10 * time.Second,
			VerifySSL:       false,
			FollowRedirects: true,
			SafeCheck:       false,
			Windows:         false,
			WAFBypass:       false,
			WAFBypassSizeKB: 128,
			VercelWAFBypass: false,
			Paths:           nil,
			DoubleEncode:    false,
			SemicolonBypass: false,
			CheckSourceExp:  false,
			CustomHeaders:   make(map[string]string),
			Threads:         1,
			Quiet:           true,
			Verbose:         verbose,
			NoColor:         true,
			AllResults:      true,
			DiscordWebhook:  "",
			DOSTest:         false,
			DOSRequests:     100,
			SmartScan:       true,
		}

		scanResults, err := next88.Run([]string{target}, opts)
		if err == nil && len(scanResults) > 0 {
			for _, res := range scanResults {
				if res.Vulnerable != nil && *res.Vulnerable {
					statusCode := ""
					if res.StatusCode != nil {
						statusCode = fmt.Sprintf("%d", *res.StatusCode)
					}
					vulnerabilityDetails = map[string]interface{}{
						"method":      "Smart Scan",
						"phase":       "Smart Scan (sequential)",
						"path":        res.TestedURL,
						"status_code": statusCode,
					}

					pocData = map[string]interface{}{
						"request":      res.Request,
						"response":     res.Response,
						"request_body": res.RequestBody,
						"response_body": res.ResponseBody,
						"final_url":    res.FinalURL,
					}
					break
				}
			}
		}
	}

	// Create result embed
	color := 0xff0000 // Red
	if !isVulnerable {
		color = 0x00ff00 // Green
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🔍 React2Shell RCE Test Results",
		Description: fmt.Sprintf("**Target:** `%s`", target),
		Color:       color,
	}

	statusText := "🔴 **Vulnerable**"
	if !isVulnerable {
		statusText = "✅ **Not Vulnerable**"
	}
	embed.Fields = []*discordgo.MessageEmbedField{
		{Name: "Status", Value: statusText, Inline: false},
	}

	// Add detection phase/method details if available
	if isVulnerable && vulnerabilityDetails != nil {
		phase := getStringFromMap(vulnerabilityDetails, "phase", "Unknown")
		method := getStringFromMap(vulnerabilityDetails, "method", "Unknown")

		// Map phase to readable format
		phaseMap := map[string]string{
			"normal":     "Normal RCE Test",
			"waf_bypass": "WAF Bypass",
			"vercel_waf": "Vercel WAF Bypass",
			"paths":      "Common Paths",
		}
		phaseDisplay := phaseMap[strings.ToLower(phase)]
		if phaseDisplay == "" {
			phaseDisplay = strings.Title(phase)
		}

		detectionInfo := fmt.Sprintf("**Detection Phase:** %s", phaseDisplay)
		if method != "" && method != "Unknown" {
			detectionInfo += fmt.Sprintf("\n**Method:** %s", method)
		}
		if path := getStringFromMap(vulnerabilityDetails, "path", ""); path != "" {
			detectionInfo += fmt.Sprintf("\n**Path:** `%s`", path)
		}
		if statusCode := getStringFromMap(vulnerabilityDetails, "status_code", ""); statusCode != "" {
			detectionInfo += fmt.Sprintf("\n**Status Code:** `%s`", statusCode)
		}

		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Detection Details",
			Value: detectionInfo,
		})
	} else {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Method",
			Value: "next88 Smart Scan (sequential: normal → WAF bypass → Vercel WAF → paths)",
		})
	}

	// Create PoC JSON file if vulnerable
	var pocFile *os.File
	if isVulnerable && pocData != nil {
		pocJSON := map[string]interface{}{
			"target":                target,
			"vulnerable":            true,
			"vulnerability_details": vulnerabilityDetails,
			"poc":                   pocData,
			"timestamp":             time.Now().Format(time.RFC3339),
		}

		pocDataJSON, err := json.MarshalIndent(pocJSON, "", "  ")
		if err == nil {
			pocFile, err = os.CreateTemp("", "poc-*.json")
			if err == nil {
				pocFile.Write(pocDataJSON)
				pocFile.Close()
			}
		}
	}

	// Update embed
	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("[ERROR] Error updating embed: %v", err)
		// Try followup as fallback
		_, err2 := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err2 != nil {
			log.Printf("[ERROR] Failed to send followup message: %v", err2)
		}
	}

	// Send PoC file if available (as followup message)
	if pocFile != nil && pocFile.Name() != "" {
		file, err := os.Open(pocFile.Name())
		if err == nil {
			defer file.Close()
			defer os.Remove(pocFile.Name())

			fileName := fmt.Sprintf("poc-%s.json", time.Now().Format("20060102-150405"))

			// Read file content
			fileData, err := os.ReadFile(pocFile.Name())
			if err == nil {
				// Send as followup message with file attachment
				_, err = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
					Files: []*discordgo.File{
						{
							Name:        fileName,
							ContentType: "application/json",
							Reader:      strings.NewReader(string(fileData)),
						},
					},
				})
				if err != nil {
					log.Printf("Error sending PoC file: %v", err)
				}
			}
		}
	}
}

// Helper function to get string value from map with multiple possible keys
func getStringValue(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if val, ok := m[key]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}
	return ""
}

// Helper function to get string from map
func getStringFromMap(m map[string]interface{}, key, defaultValue string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultValue
}

func handleLivehosts(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	threads := 100
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	if domain == "" && attachment == nil {
		respond(s, i, "❌ Either domain or file attachment is required", false)
		return
	}
	if domain != "" && attachment != nil {
		respond(s, i, "❌ Cannot specify both domain and file. Use either domain or file attachment.", false)
		return
	}

	// Handle file attachment
	if attachment != nil {
		// Respond immediately
		err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Content: "📥 Downloading file and processing targets...",
			},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to respond to interaction: %v", err)
			return
		}

		// Download and process file
		targets, err := downloadAndProcessFile(attachment)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error processing file: %v", err),
			})
			return
		}

		if len(targets) == 0 {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: "❌ No valid targets found in file",
			})
			return
		}

		// Update initial response
		content := fmt.Sprintf("📋 Found %d targets in file. Starting livehosts scan...", len(targets))
		_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Content: &content,
		})
		if err != nil {
			log.Printf("[WARN] Failed to update interaction: %v", err)
		}

		// Process each target
		for idx, target := range targets {
			target = strings.TrimSpace(target)
			if target == "" {
				continue
			}

			log.Printf("[INFO] Processing target %d/%d: %s", idx+1, len(targets), target)

			embed := &discordgo.MessageEmbed{
				Title:       "🔍 Livehosts Scan",
				Description: fmt.Sprintf("**Target:** `%s`\n**Threads:** %d", target, threads),
				Color:       0x3498db,
				Fields: []*discordgo.MessageEmbedField{
					{Name: "Status", Value: "🟡 Running", Inline: false},
				},
			}

			_, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Embeds: []*discordgo.MessageEmbed{embed},
			})
			if err != nil {
				log.Printf("[ERROR] Failed to create followup message: %v", err)
				continue
			}

			// Create a new interaction create for this target
			targetInteraction := &discordgo.InteractionCreate{
				Interaction: &discordgo.Interaction{
					ID:        i.Interaction.ID + fmt.Sprintf("_%d", idx),
					ChannelID: i.ChannelID,
				},
			}

			go runLivehostsScan(s, targetInteraction, target, threads)

			// Small delay between scans
			time.Sleep(1 * time.Second)
		}

		// Send summary
		summary := fmt.Sprintf("✅ **File Scan Initiated**\n\n**Scan Type:** livehosts\n**Total Targets:** %d", len(targets))
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: summary,
		})
		return
	}

	// Send initial response
	embed := &discordgo.MessageEmbed{
		Title:       "🔍 Livehosts Scan",
		Description: fmt.Sprintf("**Target:** `%s`\n**Threads:** %d", domain, threads),
		Color:       0x3498db,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "🟡 Running", Inline: false},
		},
	}

	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
	if err != nil {
		log.Printf("Error responding to interaction: %v", err)
		return
	}

	// Run scan in background
	go runLivehostsScan(s, i, domain, threads)
}

func runLivehostsScan(s *discordgo.Session, i *discordgo.InteractionCreate, domain string, threads int) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[ERROR] Panic in runLivehostsScan: %v", r)
			updateEmbed(s, i, fmt.Sprintf("❌ Scan failed with error: %v", r), 0xff0000)
		}
	}()

	log.Printf("[DEBUG] Starting livehosts scan for: %s", domain)

	// Run livehosts via Go-backed CLI (it handles DB operations internally)
	cmd := exec.Command(autoarScript, "livehosts", "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "--silent")

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	if err != nil {
		log.Printf("[ERROR] livehosts command failed: %v, output: %s", err, outputStr)
		embed := &discordgo.MessageEmbed{
			Title:       "❌ Livehosts Scan Failed",
			Description: fmt.Sprintf("**Target:** `%s`\n**Error:** %v", domain, err),
			Color:       0xff0000,
			Fields: []*discordgo.MessageEmbedField{
				{Name: "Output", Value: fmt.Sprintf("```%s```", outputStr[:1000]), Inline: false},
			},
		}
		s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Embeds: &[]*discordgo.MessageEmbed{embed},
		})
		return
	}

	// Get results file
	resultsDir := getResultsDir()
	liveHostsFile := filepath.Join(resultsDir, domain, "subs", "live-subs.txt")

	var totalHosts, liveHosts int
	var liveHostsList []string

	// Read live hosts file
	if fileInfo, err := os.Stat(liveHostsFile); err == nil && fileInfo.Size() > 0 {
		data, err := os.ReadFile(liveHostsFile)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					liveHostsList = append(liveHostsList, line)
				}
			}
			liveHosts = len(liveHostsList)
		}
	}

	// Get total subdomains count
	allSubsFile := filepath.Join(resultsDir, domain, "subs", "all-subs.txt")
	if fileInfo, err := os.Stat(allSubsFile); err == nil && fileInfo.Size() > 0 {
		data, err := os.ReadFile(allSubsFile)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					totalHosts++
				}
			}
		}
	}

	// Create result embed
	color := 0x00ff00 // Green
	if liveHosts == 0 {
		color = 0xffaa00 // Orange
	}

	embed := &discordgo.MessageEmbed{
		Title:       "✅ Livehosts Scan Complete",
		Description: fmt.Sprintf("**Target:** `%s`", domain),
		Color:       color,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "✅ Completed", Inline: false},
			{Name: "Results", Value: fmt.Sprintf("**Live:** `%d`\n**Total:** `%d`", liveHosts, totalHosts), Inline: false},
		},
	}

	// Add live hosts list if available
	if liveHosts > 0 {
		hostsText := ""
		for i, host := range liveHostsList {
			if i >= 20 {
				hostsText += fmt.Sprintf("\n... and %d more", liveHosts-20)
				break
			}
			hostsText += fmt.Sprintf("`%s`\n", host)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  fmt.Sprintf("Live Hosts (%d)", liveHosts),
			Value: hostsText,
		})

		// Attach live hosts file
		if fileInfo, err := os.Stat(liveHostsFile); err == nil && fileInfo.Size() > 0 {
			file, err := os.Open(liveHostsFile)
			if err == nil {
				defer file.Close()
				fileData, err := os.ReadFile(liveHostsFile)
				if err == nil {
					fileName := fmt.Sprintf("live-subs-%s.txt", time.Now().Format("20060102-150405"))
					_, err = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
						Files: []*discordgo.File{
							{
								Name:        fileName,
								ContentType: "text/plain",
								Reader:      strings.NewReader(string(fileData)),
							},
						},
					})
					if err != nil {
						log.Printf("[WARN] Failed to send live hosts file: %v", err)
					}
				}
			}
		}
	}

	// Update embed
	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to update embed: %v", err)
	}

	log.Printf("[DEBUG] Livehosts scan completed for: %s (live: %d, total: %d)", domain, liveHosts, totalHosts)
}

func respond(s *discordgo.Session, i *discordgo.InteractionCreate, message string, ephemeral bool) {
	flags := discordgo.MessageFlagsEphemeral
	if !ephemeral {
		flags = 0
	}

	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: message,
			Flags:   flags,
		},
	})
	if err != nil {
		log.Printf("Error responding: %v", err)
	}
}

func updateEmbed(s *discordgo.Session, i *discordgo.InteractionCreate, message string, color int) {
	embed := &discordgo.MessageEmbed{
		Title:       "React2Shell Host Scan",
		Description: message,
		Color:       color,
	}

	_, err := s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("Error updating embed: %v", err)
	}
}

func boolToStatus(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
