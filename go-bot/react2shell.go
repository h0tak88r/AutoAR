package main

import (
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
	// Step 1: Get live hosts
	liveHostsFile, err := getLiveHosts(domain, threads)
	if err != nil {
		updateEmbed(s, i, fmt.Sprintf("❌ Failed to get live hosts: %v", err), 0xff0000)
		return
	}

	// Step 2: Normalize hosts
	hosts, err := normalizeHosts(liveHostsFile)
	if err != nil {
		updateEmbed(s, i, fmt.Sprintf("❌ Failed to normalize hosts: %v", err), 0xff0000)
		return
	}

	log.Printf("[DEBUG] Normalized %d hosts from %s", len(hosts), liveHostsFile)
	if len(hosts) > 0 {
		log.Printf("[DEBUG] First 5 hosts: %v", hosts[:min(5, len(hosts))])
		tictactoeFound := false
		for _, h := range hosts {
			if strings.Contains(strings.ToLower(h), "tictactoe") {
				tictactoeFound = true
				log.Printf("[DEBUG] tictactoe.digitalofthings.dev in list: true")
				log.Printf("[DEBUG] tictactoe host format: %s", h)
				break
			}
		}
		if !tictactoeFound {
			log.Printf("[DEBUG] tictactoe.digitalofthings.dev in list: false")
		}
	}

	// Step 3: Run smart scan
	smartScanResults, err := runNext88Scan(hosts, []string{"-smart-scan"}, getDiscordWebhook())
	if err != nil {
		log.Printf("[ERROR] Smart scan failed: %v", err)
		smartScanResults = []string{}
	}

	// Step 4: DoS test (if enabled)
	dosResults := []string{}
	if dosTest {
		dosResults, err = runNext88Scan(hosts, []string{"-dos-test", "-dos-requests", "100"}, getDiscordWebhook())
		if err != nil {
			log.Printf("[ERROR] DoS test failed: %v", err)
		}
	}

	// Step 5: Source exposure check (if enabled)
	sourceExposureResults := []string{}
	if enableSourceExposure {
		sourceExposureResults, err = runSourceExposureCheck(domain, hosts, getDiscordWebhook())
		if err != nil {
			log.Printf("[ERROR] Source exposure check failed: %v", err)
		}
	}

	// Collect all vulnerable hosts
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

	// Send results
	sendReact2ShellResults(s, i, domain, len(hosts), len(smartScanResults), len(dosResults), len(sourceExposureResults), vulnerableList)
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

	// Build command
	cmd := exec.Command(next88Bin, "-l", tmpFile.Name(), "-k", "-q", "-o", resultsFile.Name(), "-all-results")
	cmd.Args = append(cmd.Args, extraFlags...)
	if webhookURL != "" {
		cmd.Args = append(cmd.Args, "--discord-webhook", webhookURL)
	}

	log.Printf("[DEBUG] next88 command: %s", strings.Join(cmd.Args, " "))

	// Run command
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[WARN] next88 command failed: %v, output: %s", err, string(output))
		// Continue anyway - might have found vulnerabilities before error
	}

	// Parse results
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
	return runNext88Scan(hosts, []string{"-check-source-exposure"}, webhookURL)
}

func sendReact2ShellResults(s *discordgo.Session, i *discordgo.InteractionCreate, domain string, totalHosts, smartScanCount, dosCount, sourceExposureCount int, allVulnerable []string) {
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
		log.Printf("Error updating interaction: %v", err)
	}
}

func handleReact2Shell(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// TODO: Implement single URL test
	respond(s, i, "Single URL test - Coming soon in Go implementation", false)
}

func handleLivehosts(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// TODO: Implement livehosts command
	respond(s, i, "Livehosts command - Coming soon in Go implementation", false)
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
