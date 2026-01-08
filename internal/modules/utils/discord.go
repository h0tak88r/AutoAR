package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/gobot"
)

// SendPhaseFiles sends result files for a specific phase to Discord via webhook/bot
// This is used by modules like lite scan to send files in real-time after each phase
// Only sends minimal webhook messages: phase name and file results
func SendPhaseFiles(phaseName, domain string, filePaths []string) error {
	// Get channel ID and scan ID from environment (set by bot)
	channelID := os.Getenv("AUTOAR_CURRENT_CHANNEL_ID")
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	
	// Debug logs only (not sent to webhook)
	log.Printf("[DEBUG] [DISCORD] Attempting to send phase files for phase: %s, domain: %s", phaseName, domain)
	log.Printf("[DEBUG] [DISCORD] Channel ID: %s, Scan ID: %s, File paths: %d", channelID, scanID, len(filePaths))
	
	// Even if there's no channel ID (CLI usage), we can still send via webhook
	// The sendSingleFileToDiscord function will handle webhook fallback

	// Get API host/port
	apiHost := os.Getenv("API_HOST")
	if apiHost == "" {
		apiHost = "localhost"
	}
	apiPort := os.Getenv("API_PORT")
	if apiPort == "" {
		apiPort = "8000"
	}

	// Retry logic: try to find files with multiple attempts
	maxRetries := 5
	retryDelay := 500 * time.Millisecond
	var existingFiles []string
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		existingFiles = []string{}
		for _, filePath := range filePaths {
			if info, err := os.Stat(filePath); err == nil {
				// For zerodays phase, accept files even if empty (they're always created to indicate scan completion)
				// For other phases, only send non-empty files
				if phaseName == "zerodays" || phaseName == "0days" || info.Size() > 0 {
					existingFiles = append(existingFiles, filePath)
					log.Printf("[DEBUG] [DISCORD] File found: %s (size: %d bytes)", filePath, info.Size())
				} else {
					log.Printf("[DEBUG] [DISCORD] File check (attempt %d/%d): %s - empty file (skipping)", attempt, maxRetries, filePath)
				}
			} else {
				log.Printf("[DEBUG] [DISCORD] File check (attempt %d/%d): %s - %v", attempt, maxRetries, filePath, err)
			}
		}

		if len(existingFiles) > 0 {
			log.Printf("[DEBUG] [DISCORD] Found %d valid file(s) after %d attempt(s)", len(existingFiles), attempt)
			break
		}

		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	if len(existingFiles) == 0 {
		log.Printf("[DEBUG] [DISCORD] No valid files to send for phase %s", phaseName)
		// Send webhook message indicating 0 findings
		SendWebhookLogAsync(fmt.Sprintf("[-] %s completed with 0 findings", phaseName))
		return nil
	}

	// Send each file (no webhook log messages - only terminal logs)
	successCount := 0
	failCount := 0
	for i, filePath := range existingFiles {
		fileName := filepath.Base(filePath)
		log.Printf("[DEBUG] [DISCORD] Sending file %d/%d: %s", i+1, len(existingFiles), fileName)
		
		// For GF files, extract pattern name from path for better description
		description := fileName
		if phaseName == "gf" && strings.Contains(filePath, "vulnerabilities") {
			// Extract pattern name from path like: .../vulnerabilities/img-traversal/gf-results.txt
			parts := strings.Split(filePath, string(filepath.Separator))
			for j, part := range parts {
				if part == "vulnerabilities" && j+1 < len(parts) {
					pattern := parts[j+1]
					description = fmt.Sprintf("gf-%s-results.txt", pattern)
					break
				}
			}
		}
		
		// Send file (will use bot if available, otherwise webhook, even if no channel ID)
		// sendSingleFileToDiscord handles webhook fallback when channelID is empty
		if err := sendSingleFileToDiscordWithDescription(apiHost, apiPort, channelID, scanID, phaseName, filePath, description); err != nil {
			log.Printf("[DEBUG] [DISCORD] Failed to send file %s: %v", fileName, err)
			failCount++
		} else {
			log.Printf("[DEBUG] [DISCORD] Successfully sent file: %s", fileName)
			successCount++
		}
		// Small delay between files to avoid rate limits
		if i < len(existingFiles)-1 {
			time.Sleep(300 * time.Millisecond)
		}
	}
	
	log.Printf("[DEBUG] [DISCORD] Phase %s: %d success, %d failed", phaseName, successCount, failCount)

	return nil
}

func sendSingleFileToDiscord(apiHost, apiPort, channelID, scanID, phaseName, filePath string) error {
	return sendSingleFileToDiscordWithDescription(apiHost, apiPort, channelID, scanID, phaseName, filePath, filepath.Base(filePath))
}

func sendSingleFileToDiscordWithDescription(apiHost, apiPort, channelID, scanID, phaseName, filePath, description string) error {
	
	// If channel ID is provided, try bot first (for Discord bot context)
	// If no channel ID (CLI usage), skip bot and go straight to webhook
	if channelID != "" {
		// Check if Discord bot session is available (only in main process, not subprocess)
		// When commands run via exec.Command, they're in a separate process where bot session is nil
		if err := trySendFileDirectly(channelID, filePath, description); err == nil {
			// Bot session is available and file was sent successfully
			log.Printf("[DEBUG] [DISCORD] Sent file via bot: %s", filepath.Base(filePath))
			return nil
		} else {
			// Debug logs only
			if strings.Contains(err.Error(), "not available") || strings.Contains(err.Error(), "nil") {
				log.Printf("[DEBUG] [DISCORD] Bot session not available (subprocess) - using webhook")
			} else {
				log.Printf("[DEBUG] [DISCORD] Bot send failed: %v - trying webhook", err)
			}
		}
	} else {
		log.Printf("[DEBUG] [DISCORD] No channel ID (CLI usage) - using webhook")
	}
	
	// Webhook is the primary method when no channel ID or bot unavailable
	webhookErr := SendWebhookFile(filePath, description)
	if webhookErr == nil {
		log.Printf("[DEBUG] [DISCORD] Sent file via webhook: %s", filepath.Base(filePath))
		return nil
	}
	log.Printf("[DEBUG] [DISCORD] Webhook send failed: %v", webhookErr)
	
	// Fallback: Try HTTP API as last resort (only if webhook also failed)
	log.Printf("[DEBUG] [DISCORD] Trying HTTP API fallback...")
	reqBody := map[string]string{
		"file_path":  filePath,
		"channel_id": channelID,
		"description": description,
	}
	if scanID != "" {
		reqBody["scan_id"] = scanID
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Send HTTP request
	url := fmt.Sprintf("http://%s:%s/internal/send-file", apiHost, apiPort)
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DEBUG] [DISCORD] All methods failed: webhook=%v, http=%v", webhookErr, err)
		return fmt.Errorf("all file send methods failed: webhook=%v, http=%v", webhookErr, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	log.Printf("[DEBUG] [DISCORD] HTTP API response: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	log.Printf("[DEBUG] [DISCORD] Sent file via HTTP API: %s", filepath.Base(filePath))
	return nil
}

// trySendFileDirectly attempts to send file directly through Discord bot session
func trySendFileDirectly(channelID, filePath, description string) error {
	return gobot.SendFileToChannel(channelID, filePath, description)
}

// GetPhaseFiles returns the result files for a specific lite scan phase
// Note: This returns ALL expected file paths, not just existing ones
// The caller should use retry logic to wait for files to be created
func GetPhaseFiles(phaseName, domain string) []string {
	resultsDir := GetResultsDir()
	var files []string

	switch phaseName {
	case "subdomains":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
		}
	case "livehosts":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, domain, "subs", "live-subs.txt"),
		}
	case "reflection":
		files = []string{
			filepath.Join(resultsDir, domain, "vulnerabilities", "kxss-results.txt"),
		}
	case "js", "jsscan":
		// JS scan results: only send vulnerability findings, not the URL files (already sent in urls phase)
		jsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "js")
		// Only include files that are actual scan results (not js-urls.txt which is just a copy)
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			for _, match := range matches {
				// Exclude js-urls.txt as it's just a copy of the URL file
				if !strings.HasSuffix(match, "js-urls.txt") {
					files = append(files, match)
				}
			}
		}
		// If no specific result files, don't send anything (will send "no results" message)
	case "cnames":
		// CNAME module extracts root domain from subdomain and saves to root domain directory
		// Check both subdomain directory and root domain directory for compatibility
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			// Extract last two parts (e.g., account.gomotive.com -> gomotive.com)
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		files = []string{
			filepath.Join(resultsDir, rootDomain, "subs", "cname-records.txt"), // CNAME saves to root domain
			filepath.Join(resultsDir, domain, "subs", "cname-records.txt"),     // Also check subdomain directory for compatibility
		}
	case "tech":
		// Tech detection saves to tech-detect.txt in subs directory
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "tech-detect.txt"),
		}
	case "urls":
		files = []string{
			filepath.Join(resultsDir, domain, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "js-urls.txt"),
		}
	case "ports":
		files = []string{
			filepath.Join(resultsDir, domain, "ports", "ports.txt"),
		}
	case "backup":
		files = []string{
			filepath.Join(resultsDir, domain, "backup", "fuzzuli-results.txt"),
		}
	case "dns":
		// DNS scan uses root domain for directory structure (DNS works on domain level)
		// Extract root domain from subdomain if needed
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			// Extract last two parts (e.g., www.example.com -> example.com)
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		dnsDir := filepath.Join(resultsDir, rootDomain, "vulnerabilities", "dns-takeover")
		files = []string{
			filepath.Join(dnsDir, "dns-takeover-summary.txt"),
		}
	case "misconfig":
		// Misconfig saves to subdomain directory with renamed file
		files = []string{
			filepath.Join(resultsDir, domain, "misconfig", "misconfig-scan-results.txt"),
			// Also check old locations for compatibility
			filepath.Join(resultsDir, domain, "misconfig", "scan-results.txt"),
			filepath.Join(resultsDir, "misconfig", domain, "scan-results.txt"),
		}
	case "nuclei":
		// Nuclei writes files directly to vulnerabilities/ directory (not vulnerabilities/nuclei/)
		// Files are named: nuclei-custom-others.txt, nuclei-public-http.txt, nuclei-custom-cves.txt, etc.
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		if matches, err := filepath.Glob(filepath.Join(vulnDir, "nuclei-*.txt")); err == nil {
			files = append(files, matches...)
		}
	case "gf":
		// GF results are in vulnerabilities/<pattern>/gf-results.txt
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		patterns := []string{"debug_logic", "idor", "iext", "img-traversal", "iparams", "isubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"}
		for _, pattern := range patterns {
			gfFile := filepath.Join(vulnDir, pattern, "gf-results.txt")
			files = append(files, gfFile)
		}
	case "ffuf":
		files = []string{
			filepath.Join(resultsDir, domain, "ffuf", "ffuf-results.txt"),
		}
	case "wp_confusion":
		files = []string{
			filepath.Join(resultsDir, domain, "wp-confusion", "wp-confusion-results.txt"),
		}
	case "depconfusion":
		// Depconfusion saves to subdomain directory when Subdomain is provided
		// Only check subdomain-specific directory, not global directories (to avoid sending other domains' results)
		depconfusionSubdomainDir := filepath.Join(resultsDir, domain, "depconfusion", "web-file")
		files = []string{
			filepath.Join(depconfusionSubdomainDir, "depconfusion-results.txt"), // Human-readable text file
			filepath.Join(depconfusionSubdomainDir, "confused2-web-results.json"),
		}
	case "s3":
		// S3 saves to subdomain directory when Subdomain is provided
		// Check both subdomain directory and root domain directory for compatibility
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			// Extract last two parts (e.g., www.example.com -> example.com)
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		files = []string{
			filepath.Join(resultsDir, domain, "s3", "buckets.txt"), // New location (subdomain directory)
			filepath.Join(resultsDir, "s3", rootDomain, "buckets.txt"), // Old location (for compatibility)
		}
	case "githubscan":
		// GitHub scan results location - check both orgs and repos directories
		// Try orgs first (most common for domain scans)
		githubOrgDir := filepath.Join(resultsDir, "github", "orgs", domain)
		githubRepoDir := filepath.Join(resultsDir, "github", "repos", domain)
		files = []string{
			filepath.Join(githubOrgDir, "secrets.json"),
			filepath.Join(githubOrgDir, "secrets_table.txt"),
			filepath.Join(githubRepoDir, "secrets.json"),
			filepath.Join(githubRepoDir, "secrets_table.txt"),
		}
	case "aem", "aem_scan":
		// AEM saves consolidated results to aem-scan.txt
		files = []string{
			filepath.Join(resultsDir, domain, "aem", "aem-scan.txt"),
		}
	case "zerodays", "0days":
		// Zerodays saves results to {domain}/zerodays/ directory
		zerodaysDir := filepath.Join(resultsDir, domain, "zerodays")
		files = []string{
			filepath.Join(zerodaysDir, "react2shell-cve-2025-55182.txt"),
			filepath.Join(zerodaysDir, "mongodb-cve-2025-14847.txt"),
			filepath.Join(zerodaysDir, "zerodays-results.json"),
		}
		// Also include any leaked data files
		if matches, err := filepath.Glob(filepath.Join(zerodaysDir, "mongodb-leaked-*.bin")); err == nil {
			files = append(files, matches...)
		}
	}

	// Return all expected files (don't filter here - let SendPhaseFiles handle retries)
	return files
}

