package gobot

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bwmarrin/discordgo"
)

var (
	autoarScript = getAutoarScriptPath()
	activeScans  = make(map[string]*ScanInfo)
	scansMutex   sync.RWMutex
)

// getAutoarScriptPath returns the path to the autoar binary
// Tries: AUTOAR_SCRIPT_PATH env var -> executable path -> /usr/local/bin/autoar
func getAutoarScriptPath() string {
	if path := os.Getenv("AUTOAR_SCRIPT_PATH"); path != "" {
		return path
	}
	// Try to find the executable
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	// Fallback to default
	return "autoar" // Will use PATH lookup
}

type ScanInfo struct {
	ScanID      string
	Type        string
	ScanType    string // For API compatibility
	Target      string
	Status      string
	StartTime   time.Time
	StartedAt   time.Time // For API compatibility
	CompletedAt *time.Time
	Command     string
}

// Note: ScanInfo is shared between commands.go and api.go

// Helper function to run scan in background
// Store channel ID for file notifications
func storeChannelID(scanID, channelID string) {
	channelsMutex.Lock()
	activeChannels[scanID] = channelID
	channelsMutex.Unlock()
}

// Get channel ID for file notifications
func getChannelID(scanID string) string {
	channelsMutex.RLock()
	defer channelsMutex.RUnlock()
	return activeChannels[scanID]
}

// downloadAndProcessFile downloads a file attachment and returns targets as a slice
func downloadAndProcessFile(attachment *discordgo.MessageAttachment) ([]string, error) {
	log.Printf("[INFO] Downloading file from: %s", attachment.URL)
	resp, err := http.Get(attachment.URL)
	if err != nil {
		return nil, fmt.Errorf("error downloading file: %v", err)
	}
	defer resp.Body.Close()

	// Create temp file
	tmpFile, err := os.CreateTemp("", "autoar-upload-*.txt")
	if err != nil {
		return nil, fmt.Errorf("error creating temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Copy file content
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error saving file: %v", err)
	}
	tmpFile.Close()

	// Read targets from file
	return readTargetsFromFile(tmpFile.Name())
}

// getAttachmentFromOptions extracts file attachment from command options
func getAttachmentFromOptions(data *discordgo.ApplicationCommandInteractionData) *discordgo.MessageAttachment {
	if data.Resolved != nil && data.Resolved.Attachments != nil {
		for _, opt := range data.Options {
			if opt.Type == discordgo.ApplicationCommandOptionAttachment {
				if attID, ok := opt.Value.(string); ok {
					if att, ok := data.Resolved.Attachments[attID]; ok && att != nil {
						return att
					}
				}
			}
		}
	}
	return nil
}

// readTargetsFromFile reads targets from a file (one per line)
func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

// handleFileBasedScan processes a file attachment and runs scan for each target
func handleFileBasedScan(s *discordgo.Session, i *discordgo.InteractionCreate, scanType string, attachment *discordgo.MessageAttachment, buildCommand func(string) []string, threads int) {
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
	content := fmt.Sprintf("📋 Found %d targets in file. Starting %s scan...", len(targets), scanType)
	if err := UpdateInteractionContent(s, i, content); err != nil {
		log.Printf("[WARN] Failed to update interaction: %v", err)
	}

	// Process each target
	var successCount int64 // Use atomic for thread-safe counting
	var wg sync.WaitGroup

	for idx, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		log.Printf("[INFO] Processing target %d/%d: %s", idx+1, len(targets), target)

		command := buildCommand(target)
		scanID := fmt.Sprintf("%s_%s_%d_%d", scanType, strings.ReplaceAll(target, ".", "_"), time.Now().Unix(), idx)

		embed := createScanEmbed(scanType, target, "running")
		_, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to create followup message: %v", err)
			continue
		}

		// Pass channel ID directly instead of creating fake interaction
		// Store channel ID for this scan
		storeChannelID(scanID, i.ChannelID)

		wg.Add(1)
		go func(target, scanID string, cmd []string) {
			defer wg.Done()
			// Create a minimal interaction-like struct just for channel ID
			// We'll pass channel ID directly to runScanBackground
			runScanBackground(scanID, scanType, target, cmd, s, i)
			atomic.AddInt64(&successCount, 1)
		}(target, scanID, command)

		// Small delay between scans
		time.Sleep(1 * time.Second)
	}

	// Wait for all scans to start (they run in background)
	// Note: We wait a bit to ensure all goroutines have started
	time.Sleep(2 * time.Second)

	// Send summary with actual started count
	startedCount := int(atomic.LoadInt64(&successCount))
	summary := fmt.Sprintf("✅ **File Scan Initiated**\n\n**Scan Type:** %s\n**Total Targets:** %d\n**Scans Started:** %d",
		scanType, len(targets), startedCount)
	s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Content: summary,
	})
}

func runScanBackground(scanID, scanType, target string, command []string, s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Store channel ID for file notifications from modules
	// If i is nil or doesn't have ChannelID, try to get it from stored channel IDs
	if i != nil && i.ChannelID != "" {
	storeChannelID(scanID, i.ChannelID)
	} else {
		// Fallback: try to get from stored channel IDs
		if chID := getChannelID(scanID); chID == "" {
			log.Printf("[WARN] No channel ID available for scan %s", scanID)
		}
	}

	scansMutex.Lock()
	now := time.Now()
	activeScans[scanID] = &ScanInfo{
		ScanID:    scanID,
		Type:      scanType,
		ScanType:  scanType,
		Target:    target,
		Status:    "running",
		StartTime: now,
		StartedAt: now,
		Command:   strings.Join(command, " "),
	}
	scansMutex.Unlock()

	// Create context with timeout for long-running scans (30 minutes max)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Get channel ID (from interaction or stored)
	channelID := ""
	if i != nil && i.ChannelID != "" {
		channelID = i.ChannelID
	} else {
		channelID = getChannelID(scanID)
	}

	// Execute command with environment variables for modules
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("AUTOAR_CURRENT_SCAN_ID=%s", scanID),
		fmt.Sprintf("AUTOAR_CURRENT_CHANNEL_ID=%s", channelID),
	)
	output, err := cmd.CombinedOutput()

	// Update status and get it for the embed
	scansMutex.Lock()
	var status string
	if scan, ok := activeScans[scanID]; ok {
		if err != nil {
			scan.Status = "failed"
			status = "failed"
		} else {
			scan.Status = "completed"
			status = "completed"
		}
	} else {
		// Fallback if scan not found
		if err != nil {
			status = "failed"
		} else {
			status = "completed"
		}
	}
	scansMutex.Unlock()

	// Update Discord message
	embed := createScanEmbed(scanType, target, status)
	if err != nil {
		embed.Color = 0xff0000 // Red
		outputStr := string(output)
		// Truncate very long error messages
		if len(outputStr) > 1500 {
			outputStr = outputStr[:1500] + "\n... (truncated)"
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Error",
			Value: fmt.Sprintf("```%s```", outputStr),
		})
	} else {
		embed.Color = 0x00ff00 // Green
		if len(output) > 0 {
			outputStr := string(output)
			if len(outputStr) > 1000 {
				outputStr = outputStr[:1000] + "..."
			}
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:  "Output",
				Value: fmt.Sprintf("```%s```", outputStr),
			})
		}
	}

	// Update Discord message using safe helper that handles token expiration
	if i != nil {
		if err := UpdateInteractionMessage(s, i, embed); err != nil {
			log.Printf("[ERROR] Failed to update Discord message for scan %s: %v", scanID, err)
		}
	}

	// Send result files directly from bot (like livehosts does)
	// IMPORTANT: Send files BEFORE cleanup, otherwise files will be deleted
	// Skip sending files for modules that handle their own messaging: dns, aem, misconfig, ffuf
	if err == nil && scanType != "dns" && scanType != "dns_takeover" && scanType != "dns_cname" && 
		scanType != "dns_ns" && scanType != "dns_azure_aws" && scanType != "dns_dnsreaper" && 
		scanType != "dns_dangling_ip" && scanType != "aem_scan" && scanType != "misconfig" && scanType != "ffuf" {
		// Wait for files to be written to disk with retry logic
		// Some commands (like subdomains) may take longer to write files
		maxRetries := 5
		retryDelay := 500 * time.Millisecond
		for retry := 0; retry < maxRetries; retry++ {
			time.Sleep(retryDelay)
			// Check if at least one expected file exists before sending
			if scanType == "subdomains" {
				resultsDir := getResultsDir()
				expectedFile := filepath.Join(resultsDir, target, "subs", "all-subs.txt")
				if fileInfo, err := os.Stat(expectedFile); err == nil && fileInfo.Size() > 0 {
					log.Printf("[DEBUG] Subdomains file ready after %d retries: %s (size: %d)", retry+1, expectedFile, fileInfo.Size())
					break
				} else if retry == maxRetries-1 {
					log.Printf("[WARN] Subdomains file not found after %d retries: %s", maxRetries, expectedFile)
				}
			} else {
				break // For other scan types, proceed immediately
			}
		}
		sendResultFiles(s, i, scanType, target)
		
		// Small delay to ensure files are sent before cleanup
		time.Sleep(1 * time.Second)
	}

	// Cleanup results directory after scan completes AND files are sent
	if err == nil {
		resultsDir := getResultsDir()
		var cleanupPath, cleanupPrefix string
		
		// Determine cleanup path based on scan type
		if scanType == "github_scan" || scanType == "github_org" || scanType == "github_exp" {
			// GitHub scans: {resultsDir}/github/repos/{target} or {resultsDir}/github/orgs/{target}
			cleanupPath = filepath.Join(resultsDir, "github", "repos", target)
			if _, err := os.Stat(cleanupPath); os.IsNotExist(err) {
				cleanupPath = filepath.Join(resultsDir, "github", "orgs", target)
			}
			if _, err := os.Stat(cleanupPath); os.IsNotExist(err) {
				cleanupPath = filepath.Join(resultsDir, "github", "experimental", target)
			}
			cleanupPrefix = "github/repos/" + target
			if strings.HasPrefix(cleanupPath, filepath.Join(resultsDir, "github", "orgs")) {
				cleanupPrefix = "github/orgs/" + target
			} else if strings.HasPrefix(cleanupPath, filepath.Join(resultsDir, "github", "experimental")) {
				cleanupPrefix = "github/experimental/" + target
			}
		} else {
			// Domain-based scans (subdomains, urls, etc.)
			cleanupPath = filepath.Join(resultsDir, target)
			cleanupPrefix = target
		}
		
		if cleanupPath != "" {
			if err := cleanupResultsDirectory(cleanupPrefix, cleanupPath); err != nil {
				log.Printf("[WARN] Failed to cleanup results directory for %s: %v", target, err)
			}
		}
	}
}

// sendResultFiles sends result files directly from the bot using FollowupMessageCreate
// This works like livehosts and doesn't require an HTTP API
func sendResultFiles(s *discordgo.Session, i *discordgo.InteractionCreate, scanType, target string) {
	resultsDir := getResultsDir()

	// Map scan types to their expected result file paths
	var resultFiles []string

	switch scanType {
	case "cnames":
		resultFiles = []string{filepath.Join(resultsDir, target, "subs", "cname-records.txt")}
	case "urls":
		resultFiles = []string{
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, target, "urls", "js-urls.txt"),
		}
	case "js":
		// JS scan results: vulnerabilities/js plus URL/JS lists
		jsDir := filepath.Join(resultsDir, target, "vulnerabilities", "js")
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			resultFiles = append(resultFiles, matches...)
		}
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, target, "urls", "js-urls.txt"),
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
		)
	case "reflection":
		resultFiles = []string{filepath.Join(resultsDir, target, "vulnerabilities", "kxss-results.txt")}
	case "tech":
		resultFiles = []string{filepath.Join(resultsDir, target, "subs", "tech-detect.txt")}
	case "ports":
		resultFiles = []string{filepath.Join(resultsDir, target, "ports", "ports.txt")}
	case "sqlmap":
		resultFiles = []string{filepath.Join(resultsDir, target, "vulnerabilities", "sqli", "sqlmap-results.txt")}
	case "dalfox":
		resultFiles = []string{filepath.Join(resultsDir, target, "dalfox-results.txt")}
	case "backup_scan":
		// Fuzzuli backup scan results
		// Sanitize domain for filesystem (remove protocol, replace : with -)
		// This matches the sanitization used in the backup module
		sanitizedTarget := target
		if strings.HasPrefix(target, "http://") {
			sanitizedTarget = strings.TrimPrefix(target, "http://")
		} else if strings.HasPrefix(target, "https://") {
			sanitizedTarget = strings.TrimPrefix(target, "https://")
		}
		sanitizedTarget = strings.ReplaceAll(sanitizedTarget, ":", "-")
		sanitizedTarget = strings.TrimRight(sanitizedTarget, "/")
		resultFiles = []string{
			filepath.Join(resultsDir, sanitizedTarget, "backup", "fuzzuli-results.txt"),
			filepath.Join(resultsDir, sanitizedTarget, "backup", "fuzzuli-output.log"),
		}
	case "subdomains":
		resultFiles = []string{filepath.Join(resultsDir, target, "subs", "all-subs.txt")}
	case "jwt":
		// JWT scan results - find the most recent file with retry logic
		jwtDir := filepath.Join(resultsDir, "jwt-scan", "vulnerabilities", "jwt")
		log.Printf("[DEBUG] Looking for JWT result files in: %s", jwtDir)

		// Retry up to 5 times with delays (file might still be writing, JSON encoding can take time)
		var latestFile string
		for attempt := 0; attempt < 5; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Duration(attempt) * 1 * time.Second)
			}
			// Look for jwt_scan_*.json files (the actual pattern used by the JWT module)
			if matches, err := filepath.Glob(filepath.Join(jwtDir, "jwt_scan_*.json")); err == nil && len(matches) > 0 {
				log.Printf("[DEBUG] Found %d JWT result file(s) on attempt %d", len(matches), attempt+1)
				// Get the most recent file
				var latestTime time.Time
				for _, match := range matches {
					if info, err := os.Stat(match); err == nil {
						if info.ModTime().After(latestTime) {
							latestTime = info.ModTime()
							latestFile = match
						}
					}
				}
				if latestFile != "" {
					// Verify file has content
					if info, err := os.Stat(latestFile); err == nil && info.Size() > 0 {
						log.Printf("[DEBUG] Selected most recent JWT file: %s (size: %d bytes)", latestFile, info.Size())
						resultFiles = []string{latestFile}
						// Parse and send JWT results with attack tokens summary
						sendJWTResultsSummary(s, i, latestFile)
						break
					}
				}
			}
		}
		if latestFile == "" {
			log.Printf("[WARN] No JWT result files found in %s after retries", jwtDir)
		}
	case "fast":
		// Fast look sends multiple files from different modules
		resultFiles = []string{
			filepath.Join(resultsDir, target, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, target, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, target, "urls", "js-urls.txt"),
		}
	case "lite":
		// Lite scan sends multiple result files from all phases
		// Subdomains
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, target, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, target, "subs", "live-subs.txt"),
		)
		// CNAME records
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, target, "subs", "cname-records.txt"),
		)
		// URLs
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, target, "urls", "js-urls.txt"),
		)
		// JS vulnerabilities
		jsDir := filepath.Join(resultsDir, target, "vulnerabilities", "js")
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			resultFiles = append(resultFiles, matches...)
		}
		// Reflection/KXSS
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, target, "vulnerabilities", "kxss-results.txt"),
		)
		// Backup scan results
		// Sanitize domain for filesystem (remove protocol, replace : with -)
		sanitizedTarget := target
		if strings.HasPrefix(target, "http://") {
			sanitizedTarget = strings.TrimPrefix(target, "http://")
		} else if strings.HasPrefix(target, "https://") {
			sanitizedTarget = strings.TrimPrefix(target, "https://")
		}
		sanitizedTarget = strings.ReplaceAll(sanitizedTarget, ":", "-")
		sanitizedTarget = strings.TrimRight(sanitizedTarget, "/")
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, sanitizedTarget, "backup", "fuzzuli-results.txt"),
		)
		// DNS takeover results
		dnsDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = append(resultFiles,
			filepath.Join(dnsDir, "dns-takeover-summary.txt"),
		)
		// Misconfiguration scan results
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, "misconfig", target, "scan-results.txt"),
		)
		// Nuclei results (if any)
		// Nuclei writes files directly to vulnerabilities/ directory (not vulnerabilities/nuclei/)
		// Files are named: nuclei-custom-others.txt, nuclei-public-http.txt, nuclei-custom-cves.txt, etc.
		vulnDir := filepath.Join(resultsDir, target, "vulnerabilities")
		if matches, err := filepath.Glob(filepath.Join(vulnDir, "nuclei-*.txt")); err == nil {
			resultFiles = append(resultFiles, matches...)
		}
	case "dns_takeover":
		domainDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = []string{
			filepath.Join(domainDir, "dns-takeover-summary.txt"),
			filepath.Join(domainDir, "nuclei-takeover-public.txt"),
			filepath.Join(domainDir, "nuclei-takeover-custom.txt"),
			filepath.Join(domainDir, "dnsreaper-results.txt"),
			filepath.Join(domainDir, "azure-takeover.txt"),
			filepath.Join(domainDir, "aws-takeover.txt"),
			filepath.Join(domainDir, "azure-aws-takeover.txt"),
			filepath.Join(domainDir, "ns-takeover-raw.txt"),
			filepath.Join(domainDir, "ns-takeover-vuln.txt"),
			filepath.Join(domainDir, "ns-servers.txt"),
			filepath.Join(domainDir, "ns-servers-vuln.txt"),
			filepath.Join(domainDir, "dangling-ip.txt"),
			filepath.Join(domainDir, "dangling-ip-summary.txt"),
		}
	case "dns_cname":
		domainDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = []string{
			filepath.Join(domainDir, "nuclei-takeover-public.txt"),
			filepath.Join(domainDir, "nuclei-takeover-custom.txt"),
			filepath.Join(domainDir, "dnsreaper-results.txt"),
			filepath.Join(domainDir, "azure-takeover.txt"),
			filepath.Join(domainDir, "aws-takeover.txt"),
			filepath.Join(domainDir, "azure-aws-takeover.txt"),
		}
	case "dns_ns":
		domainDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = []string{
			filepath.Join(domainDir, "ns-servers.txt"),
			filepath.Join(domainDir, "ns-takeover-raw.txt"),
			filepath.Join(domainDir, "ns-servers-vuln.txt"),
			filepath.Join(domainDir, "ns-takeover-vuln.txt"),
		}
	case "dns_azure_aws":
		domainDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = []string{
			filepath.Join(domainDir, "azure-takeover.txt"),
			filepath.Join(domainDir, "aws-takeover.txt"),
			filepath.Join(domainDir, "azure-aws-takeover.txt"),
		}
	case "dns_dnsreaper":
		domainDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = []string{
			filepath.Join(domainDir, "dnsreaper-results.txt"),
		}
	case "dns_dangling_ip":
		domainDir := filepath.Join(resultsDir, target, "vulnerabilities", "dns-takeover")
		resultFiles = []string{
			filepath.Join(domainDir, "dangling-ip.txt"),
			filepath.Join(domainDir, "dangling-ip-summary.txt"),
		}
	case "github":
		base := filepath.Join(resultsDir, "github", "repos", target)
		resultFiles = []string{
			filepath.Join(base, "secrets.json"),
			filepath.Join(base, "secrets_table.txt"),
			filepath.Join(base, "trufflehog.log"),
		}
	case "github_org":
		base := filepath.Join(resultsDir, "github", "orgs", target)
		resultFiles = []string{
			filepath.Join(base, "secrets.json"),
			filepath.Join(base, "secrets_table.txt"),
			filepath.Join(base, "trufflehog.log"),
		}
	case "github_experimental":
		base := filepath.Join(resultsDir, "github", "experimental", target)
		resultFiles = []string{
			filepath.Join(base, "secrets.json"),
			filepath.Join(base, "secrets_table.txt"),
			filepath.Join(base, "trufflehog.log"),
		}
	case "db_domains":
		resultFiles = []string{
			filepath.Join(resultsDir, "db", "domains.txt"),
		}
	case "db_subdomains":
		resultFiles = []string{
			filepath.Join(resultsDir, "db", "subdomains", fmt.Sprintf("%s.txt", target)),
		}
	case "github_wordlist":
		base := filepath.Join(resultsDir, fmt.Sprintf("github-%s", target), "wordlists")
		resultFiles = []string{
			filepath.Join(base, "github-patterns.txt"),
			filepath.Join(base, "github-wordlist.txt"),
		}
	case "s3_enum":
		// S3 enumeration results
		resultFiles = []string{
			filepath.Join(resultsDir, "s3", target, "buckets.txt"),
			filepath.Join(resultsDir, "s3", target, "enum.log"),
		}
	case "s3":
		// S3 scan results
		resultFiles = []string{
			filepath.Join(resultsDir, "s3", target, "scan-results.txt"),
			filepath.Join(resultsDir, "s3", target, "scan.log"),
		}
		// Add more scan types as needed
	}

	// Send each result file that exists
	for _, filePath := range resultFiles {
		// Handle glob patterns (e.g., *.txt)
		if strings.Contains(filePath, "*") {
			matches, err := filepath.Glob(filePath)
			if err == nil {
				for _, match := range matches {
					sendSingleFile(s, i, match)
				}
			}
		} else {
			sendSingleFile(s, i, filePath)
		}
	}
}

// sendJWTResultsSummary parses JWT scan results and sends a summary embed with attack tokens
func sendJWTResultsSummary(s *discordgo.Session, i *discordgo.InteractionCreate, jsonPath string) {
	fileData, err := os.ReadFile(jsonPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read JWT results file: %v", err)
		return
	}

	var result struct {
		TokenType     string `json:"token_type"`
		Algorithm     string `json:"algorithm"`
		Issues        []struct {
			Type        string `json:"type"`
			Description string `json:"description"`
		} `json:"issues"`
		CrackedSecret string `json:"cracked_secret,omitempty"`
		AttackTokens []struct {
			AttackType  string `json:"attack_type"`
			Description string `json:"description"`
			Token       string `json:"token"`
			Vulnerable  bool   `json:"vulnerable,omitempty"`
		} `json:"attack_tokens,omitempty"`
	}

	if err := json.Unmarshal(fileData, &result); err != nil {
		log.Printf("[ERROR] Failed to parse JWT results JSON: %v", err)
		return
	}

	// Build summary embed
	embed := &discordgo.MessageEmbed{
		Title:       "🔐 JWT Scan Results",
		Description: fmt.Sprintf("**Algorithm:** `%s`\n**Token Type:** %s", result.Algorithm, result.TokenType),
		Color:       0x3498db,
		Fields:      []*discordgo.MessageEmbedField{},
	}

	// Add issues summary
	if len(result.Issues) > 0 {
		issuesText := ""
		for _, issue := range result.Issues {
			emoji := "⚠️"
			if issue.Type == "weak_secret" || issue.Type == "alg_none" {
				emoji = "🔴"
			}
			issuesText += fmt.Sprintf("%s **%s**: %s\n", emoji, issue.Type, issue.Description)
		}
		if len(issuesText) > 1024 {
			issuesText = issuesText[:1020] + "..."
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🔍 Issues Found",
			Value:  issuesText,
			Inline: false,
		})
	}

	// Add cracked secret if found
	if result.CrackedSecret != "" {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🔑 Cracked Secret",
			Value:  fmt.Sprintf("```%s```", result.CrackedSecret),
			Inline: false,
		})
		embed.Color = 0xff0000 // Red for vulnerable
	} else {
		// Check if cracking was attempted but secret not found
		for _, issue := range result.Issues {
			if issue.Type == "crack_attempted" {
				embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
					Name:   "🔍 Cracking Status",
					Value:  issue.Description,
					Inline: false,
				})
				break
			}
		}
	}

	// Add attack tokens if available
	if len(result.AttackTokens) > 0 {
		attackText := ""
		for _, attack := range result.AttackTokens {
			vulnMark := ""
			if attack.Vulnerable {
				vulnMark = " 🔴 **VULNERABLE**"
				embed.Color = 0xff0000 // Red for confirmed vulnerability
			}
			attackText += fmt.Sprintf("**%s**%s\n", attack.AttackType, vulnMark)
			attackText += fmt.Sprintf("`%s`\n", attack.Token)
			if len(attack.Description) > 0 {
				attackText += fmt.Sprintf("_%s_\n\n", attack.Description)
			}
		}
		if len(attackText) > 1024 {
			attackText = attackText[:1020] + "..."
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "🎯 Attack Tokens",
			Value:  attackText,
			Inline: false,
		})
	}

	// Send embed
	_, err = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("[WARN] Failed to send JWT results summary: %v", err)
	}
}

// sendSingleFile sends a single file via FollowupMessageCreate
func sendSingleFile(s *discordgo.Session, i *discordgo.InteractionCreate, filePath string) {
	log.Printf("[DEBUG] Attempting to send file: %s", filePath)
	
	// Retry logic for file reading (in case file is still being written)
	maxRetries := 3
	var fileData []byte
	var err error
	for retry := 0; retry < maxRetries; retry++ {
		if fileInfo, statErr := os.Stat(filePath); statErr == nil {
		if fileInfo.Size() == 0 {
				if retry < maxRetries-1 {
					log.Printf("[DEBUG] File %s is empty, retrying in 200ms (attempt %d/%d)", filePath, retry+1, maxRetries)
					time.Sleep(200 * time.Millisecond)
					continue
				}
			log.Printf("[WARN] File %s exists but is empty (size: 0)", filePath)
			return
		}
		log.Printf("[DEBUG] File found: %s (size: %d bytes)", filePath, fileInfo.Size())
			fileData, err = os.ReadFile(filePath)
			if err == nil {
				break
			}
			if retry < maxRetries-1 {
				log.Printf("[DEBUG] Failed to read file %s, retrying in 200ms (attempt %d/%d): %v", filePath, retry+1, maxRetries, err)
				time.Sleep(200 * time.Millisecond)
				continue
			}
		} else {
			if retry < maxRetries-1 {
				log.Printf("[DEBUG] File %s not found, retrying in 200ms (attempt %d/%d): %v", filePath, retry+1, maxRetries, statErr)
				time.Sleep(200 * time.Millisecond)
				continue
			}
			log.Printf("[WARN] File not found or cannot access: %s (err: %v)", filePath, statErr)
			return
		}
	}
	
		if err != nil {
		log.Printf("[ERROR] Failed to read file %s after %d retries: %v", filePath, maxRetries, err)
			return
		}
	
		fileName := filepath.Base(filePath)
	contentType := "text/plain"
	if strings.HasSuffix(strings.ToLower(fileName), ".json") {
		contentType = "application/json"
	}
	
		_, err = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Files: []*discordgo.File{
				{
					Name:        fileName,
				ContentType: contentType,
					Reader:      strings.NewReader(string(fileData)),
				},
			},
		})
		if err != nil {
		log.Printf("[ERROR] Failed to send result file %s: %v", fileName, err)
		} else {
		log.Printf("[INFO] Successfully sent result file via bot: %s (size: %d bytes)", fileName, len(fileData))
	}
}

func createScanEmbed(scanType, target, status string) *discordgo.MessageEmbed {
	statusEmoji := "🟡"
	if status == "completed" {
		statusEmoji = "✅"
	} else if status == "failed" {
		statusEmoji = "❌"
	} else if status == "running in background" {
		statusEmoji = "⏳"
	}

	return &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("🔍 %s Scan", scanType),
		Description: fmt.Sprintf("**Target:** `%s`\n**Status:** %s %s", target, statusEmoji, status),
		Color:       0x3498db,
		Fields:      []*discordgo.MessageEmbedField{},
	}
}

// Scan Domain
func handleScanDomain(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	verbose := false
	keepResults := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		case "keep_results":
			keepResults = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("domain_%d", time.Now().Unix())
	command := []string{autoarScript, "domain", "run", "-d", domain}
	if verbose {
		command = append(command, "-v")
	}
	if keepResults {
		command = append(command, "--keep-results")
	}

	embed := createScanEmbed("Domain", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "domain", domain, command, s, i)
}

// Scan Subdomain
func handleScanSubdomain(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	subdomain := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "subdomain":
			subdomain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if subdomain == "" {
		respond(s, i, "❌ Subdomain is required", false)
		return
	}

	scanID := fmt.Sprintf("subdomain_%d", time.Now().Unix())
	command := []string{autoarScript, "subdomains", "get", "-d", subdomain}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("Subdomain", subdomain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "subdomain", subdomain, command, s, i)
}

// Lite Scan
func handleLiteScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	verbose := false
	skipJS := false
	phaseTimeout := 3600
	var timeoutLivehosts, timeoutReflection, timeoutJS, timeoutNuclei *int

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		case "skip_js":
			skipJS = opt.BoolValue()
		case "phase_timeout":
			phaseTimeout = int(opt.IntValue())
		case "timeout_livehosts":
			val := int(opt.IntValue())
			timeoutLivehosts = &val
		case "timeout_reflection":
			val := int(opt.IntValue())
			timeoutReflection = &val
		case "timeout_js":
			val := int(opt.IntValue())
			timeoutJS = &val
		case "timeout_nuclei":
			val := int(opt.IntValue())
			timeoutNuclei = &val
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("lite_%d", time.Now().Unix())
	command := []string{autoarScript, "lite", "run", "-d", domain}
	if verbose {
		command = append(command, "-v")
	}
	if skipJS {
		command = append(command, "--skip-js")
	}
	if phaseTimeout > 0 {
		command = append(command, "--phase-timeout", strconv.Itoa(phaseTimeout))
	}
	if timeoutLivehosts != nil && *timeoutLivehosts >= 0 {
		command = append(command, "--timeout-livehosts", strconv.Itoa(*timeoutLivehosts))
	}
	if timeoutReflection != nil && *timeoutReflection >= 0 {
		command = append(command, "--timeout-reflection", strconv.Itoa(*timeoutReflection))
	}
	if timeoutJS != nil && *timeoutJS >= 0 {
		command = append(command, "--timeout-js", strconv.Itoa(*timeoutJS))
	}
	if timeoutNuclei != nil && *timeoutNuclei >= 0 {
		command = append(command, "--timeout-nuclei", strconv.Itoa(*timeoutNuclei))
	}

	desc := fmt.Sprintf("**Target:** `%s`\n**Default per-phase timeout:** %ds", domain, phaseTimeout)
	if skipJS {
		desc += "\n**JS Phase:** skipped"
	}
	embed := &discordgo.MessageEmbed{
		Title:       "🔍 AutoAR Lite Scan",
		Description: desc,
		Color:       0x3498db,
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "lite", domain, command, s, i)
}

// Fast Look
func handleFastLook(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("fast_%d", time.Now().Unix())
	command := []string{autoarScript, "fastlook", "run", "-d", domain}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("Fast Look", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "fast", domain, command, s, i)
}

// Domain Run
func handleDomainRun(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("domain_run_%d", time.Now().Unix())
	command := []string{autoarScript, "domain", "run", "-d", domain}

	// For domain_run, immediately show "running in background" since it takes a long time
	embed := createScanEmbed("Domain Workflow", domain, "running in background")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "domain_run", domain, command, s, i)
}

// Subdomain Run
func handleSubdomainRun(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	subdomain := ""

	for _, opt := range options {
		if opt.Name == "subdomain" {
			subdomain = opt.StringValue()
		}
	}

	if subdomain == "" {
		respond(s, i, "❌ Subdomain is required", false)
		return
	}

	scanID := fmt.Sprintf("subdomain_run_%d", time.Now().Unix())
	command := []string{autoarScript, "subdomain", "run", "-s", subdomain}

	// For subdomain_run, immediately show "running in background" since it takes a long time
	embed := createScanEmbed("Subdomain Workflow", subdomain, "running in background")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "subdomain_run", subdomain, command, s, i)
}

// Subdomains
func handleSubdomains(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	threads := 100
	var attachment *discordgo.MessageAttachment

	// Check for file attachment
	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	// Validate: exactly one of domain or file must be provided
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
		handleFileBasedScan(s, i, "subdomains", attachment, func(target string) []string {
			return []string{autoarScript, "subdomains", "get", "-d", target, "-t", strconv.Itoa(threads)}
		}, threads)
		return
	}

	// Handle single domain
	scanID := fmt.Sprintf("subdomains_%d", time.Now().Unix())
	command := []string{autoarScript, "subdomains", "get", "-d", domain, "-t", strconv.Itoa(threads)}

	embed := createScanEmbed("Subdomains", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "subdomains", domain, command, s, i)
}

// CNAMEs
func handleCnames(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("cnames_%d", time.Now().Unix())
	command := []string{autoarScript, "cnames", "get", "-d", domain}

	embed := createScanEmbed("CNAMEs", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "cnames", domain, command, s, i)
}

// URLs
func handleURLs(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	threads := 100
	skipSubdomainEnum := false
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		case "subdomain":
			skipSubdomainEnum = opt.BoolValue()
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

	if attachment != nil {
		handleFileBasedScan(s, i, "urls", attachment, func(target string) []string {
			cmd := []string{autoarScript, "urls", "collect", "-d", target, "-t", strconv.Itoa(threads)}
			if skipSubdomainEnum {
				cmd = append(cmd, "--subdomain")
			}
			return cmd
		}, threads)
		return
	}

	scanID := fmt.Sprintf("urls_%d", time.Now().Unix())
	command := []string{autoarScript, "urls", "collect", "-d", domain, "-t", strconv.Itoa(threads)}
	if skipSubdomainEnum {
		command = append(command, "--subdomain")
	}

	embed := createScanEmbed("URLs", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "urls", domain, command, s, i)
}

// Reflection
func handleReflection(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
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

	if attachment != nil {
		handleFileBasedScan(s, i, "reflection", attachment, func(target string) []string {
			return []string{autoarScript, "reflection", "scan", "-d", target}
		}, 0)
		return
	}

	scanID := fmt.Sprintf("reflection_%d", time.Now().Unix())
	command := []string{autoarScript, "reflection", "scan", "-d", domain}

	embed := createScanEmbed("Reflection", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "reflection", domain, command, s, i)
}

// Tech Detection
func handleTech(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	if attachment != nil {
		handleFileBasedScan(s, i, "tech", attachment, func(target string) []string {
			return []string{autoarScript, "tech", "detect", "-d", target, "-t", strconv.Itoa(threads)}
		}, threads)
		return
	}

	scanID := fmt.Sprintf("tech_%d", time.Now().Unix())
	command := []string{autoarScript, "tech", "detect", "-d", domain, "-t", strconv.Itoa(threads)}

	embed := createScanEmbed("Tech Detection", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "tech", domain, command, s, i)
}

// Ports
func handlePorts(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
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

	if attachment != nil {
		handleFileBasedScan(s, i, "ports", attachment, func(target string) []string {
			return []string{autoarScript, "ports", "scan", "-d", target}
		}, 0)
		return
	}

	scanID := fmt.Sprintf("ports_%d", time.Now().Unix())
	command := []string{autoarScript, "ports", "scan", "-d", domain}

	embed := createScanEmbed("Ports", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "ports", domain, command, s, i)
}

// Nuclei
func handleNuclei(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	var domain, url, mode *string
	enum := false
	threads := 100
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			val := opt.StringValue()
			domain = &val
		case "url":
			val := opt.StringValue()
			url = &val
		case "mode":
			val := opt.StringValue()
			mode = &val
		case "enum":
			enum = opt.BoolValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	// Validate: exactly one of domain, url, or file must be provided
	if domain == nil && url == nil && attachment == nil {
		respond(s, i, "❌ Either domain, url, or file attachment must be provided", true)
		return
	}

	// Count how many are provided
	count := 0
	if domain != nil {
		count++
	}
	if url != nil {
		count++
	}
	if attachment != nil {
		count++
	}
	if count > 1 {
		respond(s, i, "❌ Cannot use domain, url, and file together. Use only one.", true)
		return
	}

	// Handle file attachment
	if attachment != nil {
		modeVal := "full"
		if mode != nil {
			modeVal = *mode
		}
		handleFileBasedScan(s, i, "nuclei", attachment, func(target string) []string {
			cmd := []string{autoarScript, "nuclei", "run", "-d", target, "-m", modeVal, "-t", strconv.Itoa(threads)}
			if enum {
				cmd = append(cmd, "-e")
			}
			return cmd
		}, threads)
		return
	}

	scanID := fmt.Sprintf("nuclei_%d", time.Now().Unix())
	command := []string{autoarScript, "nuclei", "run"}

	var target string
	if domain != nil {
		command = append(command, "-d", *domain)
		target = *domain
	} else {
		command = append(command, "-u", *url)
		target = *url
	}

	modeVal := "full"
	if mode != nil {
		modeVal = *mode
	}
	command = append(command, "-m", modeVal)

	if enum && domain != nil {
		command = append(command, "-e")
	}

	command = append(command, "-t", strconv.Itoa(threads))

	modeDesc := map[string]string{
		"full":            "Full (All Templates)",
		"cves":            "CVEs Only",
		"panels":          "Panels Discovery",
		"default-logins":  "Default Logins Only",
		"vulnerabilities": "Generic Vulnerabilities",
	}[modeVal]

	enumText := ""
	if enum && domain != nil {
		enumText = " with enum"
	}

	embed := createScanEmbed(fmt.Sprintf("Nuclei %s%s", modeDesc, enumText), target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, fmt.Sprintf("nuclei-%s", modeVal), target, command, s, i)
}

// JS Scan
func handleJSScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	var subdomain *string

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "subdomain":
			val := opt.StringValue()
			subdomain = &val
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("js_%d", time.Now().Unix())
	command := []string{autoarScript, "js", "scan", "-d", domain}
	if subdomain != nil && *subdomain != "" {
		command = append(command, "-s", *subdomain)
	}

	embed := createScanEmbed("JS Scan", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "js", domain, command, s, i)
}

// GF Scan
func handleGFScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
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

	if attachment != nil {
		handleFileBasedScan(s, i, "gf", attachment, func(target string) []string {
			return []string{autoarScript, "gf", "scan", "-d", target}
		}, 0)
		return
	}

	scanID := fmt.Sprintf("gf_%d", time.Now().Unix())
	command := []string{autoarScript, "gf", "scan", "-d", domain}

	embed := createScanEmbed("GF Scan", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "gf", domain, command, s, i)
}

// SQLMap
func handleSQLMap(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
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

	if attachment != nil {
		handleFileBasedScan(s, i, "sqlmap", attachment, func(target string) []string {
			return []string{autoarScript, "sqlmap", "run", "-d", target}
		}, 0)
		return
	}

	scanID := fmt.Sprintf("sqlmap_%d", time.Now().Unix())
	command := []string{autoarScript, "sqlmap", "run", "-d", domain}

	embed := createScanEmbed("SQLMap", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "sqlmap", domain, command, s, i)
}

// Dalfox
func handleDalfox(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()
	options := data.Options
	domain := ""
	var attachment *discordgo.MessageAttachment

	attachment = getAttachmentFromOptions(&data)

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
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

	if attachment != nil {
		handleFileBasedScan(s, i, "dalfox", attachment, func(target string) []string {
			return []string{autoarScript, "dalfox", "run", "-d", target}
		}, 0)
		return
	}

	scanID := fmt.Sprintf("dalfox_%d", time.Now().Unix())
	command := []string{autoarScript, "dalfox", "run", "-d", domain}

	embed := createScanEmbed("Dalfox", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dalfox", domain, command, s, i)
}
