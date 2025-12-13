package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// handleReact2ShellScan handles the /react2shell_scan command
func handleReact2ShellScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	threads := 100
	enableSourceExposure := false
	dosTest := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		case "enable_source_exposure":
			enableSourceExposure = opt.BoolValue()
		case "dos_test":
			dosTest = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

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
	smartScanResults, err := runNext88Scan(hosts, []string{"-smart-scan"}, getDiscordWebhook())
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
		dosResults, err = runNext88Scan(hosts, []string{"-dos-test", "-dos-requests", "100"}, getDiscordWebhook())
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
}

// runNext88Scan runs next88 with given flags and returns vulnerable hosts
func runNext88Scan(hosts []string, extraFlags []string, webhookURL string) ([]string, error) {
	// Find next88 binary
	next88Bin := findNext88()
	if next88Bin == "" {
		return nil, fmt.Errorf("next88 binary not found")
	}

	// Create temp file for hosts
	tmpFile, err := os.CreateTemp("", "next88-hosts-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpFile.Name())

	for _, host := range hosts {
		tmpFile.WriteString(host + "\n")
	}
	tmpFile.Close()

	log.Printf("[DEBUG] Writing %d hosts to temp file: %s", len(hosts), tmpFile.Name())
	if len(hosts) > 0 {
		log.Printf("[DEBUG] First 5 hosts in file: %v", hosts[:min(5, len(hosts))])
		tictactoeInList := false
		for _, h := range hosts {
			if strings.Contains(strings.ToLower(h), "tictactoe") {
				tictactoeInList = true
				log.Printf("[DEBUG] tictactoe.digitalofthings.dev in hosts list: true")
				log.Printf("[DEBUG] tictactoe host format: %s", h)
				break
			}
		}
		if !tictactoeInList {
			log.Printf("[DEBUG] tictactoe.digitalofthings.dev in hosts list: false")
		}
	}

	// Create temp file for results
	resultsFile, err := os.CreateTemp("", "next88-results-*.json")
	if err != nil {
		return nil, err
	}
	defer os.Remove(resultsFile.Name())
	resultsFile.Close()

	// Build command with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	
	args := []string{"-l", tmpFile.Name(), "-k", "-q", "-o", resultsFile.Name(), "-all-results"}
	args = append(args, extraFlags...)
	// Don't pass webhook URL - we handle Discord messages directly via bot
	// if webhookURL != "" {
	// 	args = append(args, "--discord-webhook", webhookURL)
	// }

	log.Printf("[DEBUG] next88 command: %s %s", next88Bin, strings.Join(args, " "))

	// Run command with timeout
	cmd := exec.CommandContext(ctx, next88Bin, args...)
	
	log.Printf("[DEBUG] Executing next88 command (timeout: 10min)")
	output, err := cmd.CombinedOutput()
	
	if ctx.Err() == context.DeadlineExceeded {
		log.Printf("[ERROR] next88 command timed out after 10 minutes")
		return []string{}, fmt.Errorf("command timed out")
	}
	
	if err != nil {
		log.Printf("[WARN] next88 command failed: %v, output: %s", err, string(output))
		// Continue anyway - might have found vulnerabilities before error
	} else {
		log.Printf("[DEBUG] next88 command completed successfully")
	}

	// Check if results file exists and has content
	if fileInfo, err := os.Stat(resultsFile.Name()); err != nil || fileInfo.Size() == 0 {
		log.Printf("[WARN] Results file is empty or missing: %v", err)
		// Fallback: check stdout for vulnerable hosts
		if strings.Contains(strings.ToLower(string(output)), "vulnerable") {
			log.Printf("[DEBUG] Found 'vulnerable' keyword in stdout, attempting to extract hosts")
			// Try to extract hosts from stdout
			lines := strings.Split(string(output), "\n")
			hosts := []string{}
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), "vulnerable") {
					// Try to extract URL/host from line
					if strings.Contains(line, "http") {
						parts := strings.Fields(line)
						for _, part := range parts {
							if strings.HasPrefix(part, "http") {
								hostname := extractHostname(part)
								if hostname != "" {
									hosts = append(hosts, hostname)
								}
							}
						}
					}
				}
			}
			if len(hosts) > 0 {
				log.Printf("[DEBUG] Extracted %d vulnerable hosts from stdout", len(hosts))
				return hosts, nil
			}
		}
		return []string{}, nil
	}

	// Parse results
	log.Printf("[DEBUG] Parsing next88 JSON results from: %s", resultsFile.Name())
	vulnerableHosts, err := parseNext88Results(resultsFile.Name())
	if err != nil {
		log.Printf("[ERROR] Failed to parse next88 results: %v", err)
		return []string{}, nil
	}

	log.Printf("[DEBUG] Total vulnerable hosts found: %d", len(vulnerableHosts))
	return vulnerableHosts, nil
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
func findNext88() string {
	paths := []string{"next88", "react2shell"}
	for _, path := range paths {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
	}
	return ""
}

func getLiveHosts(domain string, threads int) (string, error) {
	script := "/app/modules/livehosts.sh"
	cmd := exec.Command(script, "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "--silent")
	if err := cmd.Run(); err != nil {
		return "", err
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "/app/new-results"
	}

	liveHostsFile := filepath.Join(resultsDir, domain, "subs", "live-subs.txt")
	if _, err := os.Stat(liveHostsFile); err == nil {
		return liveHostsFile, nil
	}

	allSubsFile := filepath.Join(resultsDir, domain, "subs", "all-subs.txt")
	if _, err := os.Stat(allSubsFile); err == nil {
		return allSubsFile, nil
	}

	return "", fmt.Errorf("no live hosts file found")
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
	return runNext88Scan(hosts, []string{"-check-source-exposure"}, "")
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

func handleReact2Shell(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	url := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "url":
			url = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if url == "" {
		respond(s, i, "❌ URL is required", false)
		return
	}

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

func runReact2ShellSingle(s *discordgo.Session, i *discordgo.InteractionCreate, target string, verbose bool) {
	// Find next88 binary
	next88Bin := findNext88()
	if next88Bin == "" {
		embed := &discordgo.MessageEmbed{
			Title:       "❌ React2Shell Test Failed",
			Description: fmt.Sprintf("**Target:** `%s`\n**Error:** next88 binary not found. Please install: go install github.com/h0tak88r/next88@latest", target),
			Color:       0xff0000,
		}
		s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Embeds: &[]*discordgo.MessageEmbed{embed},
		})
		return
	}

	// Create temp file for JSON output
	resultsFile, err := os.CreateTemp("", "next88-single-*.json")
	if err != nil {
		embed := &discordgo.MessageEmbed{
			Title:       "❌ React2Shell Test Failed",
			Description: fmt.Sprintf("**Target:** `%s`\n**Error:** Failed to create temp file: %v", target, err),
			Color:       0xff0000,
		}
		s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Embeds: &[]*discordgo.MessageEmbed{embed},
		})
		return
	}
	resultsFile.Close()
	defer os.Remove(resultsFile.Name())

	// Build next88 command
	command := []string{
		next88Bin,
		"-u", target,
		"-k", // Insecure (skip SSL verification)
		"-o", resultsFile.Name(),
		"-all-results", // Get all results in JSON
	}

	// Don't pass webhook URL - we handle Discord messages directly via bot
	// webhookURL := getDiscordWebhook()
	// if webhookURL != "" {
	// 	command = append(command, "--discord-webhook", webhookURL)
	// }

	log.Printf("[DEBUG] next88 single URL command: %s", strings.Join(command, " "))

	// Run next88
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()

	stdoutStr := string(output)
	stderrStr := ""
	if err != nil {
		stderrStr = err.Error()
	}

	// Parse JSON results
	isVulnerable := false
	var vulnerabilityDetails map[string]interface{}
	var pocData map[string]interface{}

	if fileInfo, err := os.Stat(resultsFile.Name()); err == nil && fileInfo.Size() > 0 {
		data, err := os.ReadFile(resultsFile.Name())
		if err == nil {
			var jsonData map[string]interface{}
			if err := json.Unmarshal(data, &jsonData); err == nil {
				results, ok := jsonData["results"].([]interface{})
				if ok {
					for _, result := range results {
						resultMap, ok := result.(map[string]interface{})
						if !ok {
							continue
						}

						// Check if vulnerable
						if v, ok := resultMap["vulnerable"].(bool); ok && v {
							isVulnerable = true

							// Extract vulnerability details
							vulnerabilityDetails = map[string]interface{}{
								"method":      getStringValue(resultMap, "method", "test_method", "Unknown"),
								"phase":       getStringValue(resultMap, "phase", "waf_bypass", "bypass_type", "normal"),
								"path":        getStringValue(resultMap, "path", "url", ""),
								"status_code": getStringValue(resultMap, "status_code", "status", ""),
							}

							// Extract PoC data
							pocData = map[string]interface{}{
								"request":  getStringValue(resultMap, "request", "request_body", "payload", "request_data", ""),
								"response": getStringValue(resultMap, "response", "response_body", "response_data", ""),
								"headers":  resultMap["headers"],
							}
							break
						}
					}
				}
			}
		}
	}

	// Fallback to stdout check if JSON parsing failed
	if !isVulnerable {
		isVulnerable = strings.Contains(strings.ToLower(stdoutStr), "vulnerable") ||
			strings.Contains(strings.ToLower(stderrStr), "vulnerable")
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
			"target":              target,
			"vulnerable":          true,
			"vulnerability_details": vulnerabilityDetails,
			"poc":                 pocData,
			"timestamp":           time.Now().Format(time.RFC3339),
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
	options := i.ApplicationCommandData().Options
	domain := ""
	threads := 100

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
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

	// Run livehosts.sh script (it handles DB operations internally)
	script := "/app/modules/livehosts.sh"
	cmd := exec.Command(script, "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "--silent")
	
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
	resultsDir := getEnv("AUTOAR_RESULTS_DIR", "/app/new-results")
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
