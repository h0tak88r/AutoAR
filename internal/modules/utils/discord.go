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
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/gobot"
)

// SendPhaseFiles sends result files for a specific phase to Discord via HTTP API
// This is used by modules like lite scan to send files in real-time after each phase
func SendPhaseFiles(phaseName, domain string, filePaths []string) error {
	// Get channel ID and scan ID from environment (set by bot)
	channelID := os.Getenv("AUTOAR_CURRENT_CHANNEL_ID")
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	
	log.Printf("[DISCORD] Attempting to send phase files for phase: %s, domain: %s", phaseName, domain)
	log.Printf("[DISCORD] Channel ID from env: %s, Scan ID from env: %s", channelID, scanID)
	log.Printf("[DISCORD] Total file paths provided: %d", len(filePaths))
	
	if channelID == "" {
		// No Discord context, skip sending
		log.Printf("[DISCORD] No channel ID found in environment, skipping file send (this is normal for CLI usage)")
		return nil
	}

	// Get API host/port
	apiHost := os.Getenv("API_HOST")
	if apiHost == "" {
		apiHost = "localhost"
	}
	apiPort := os.Getenv("API_PORT")
	if apiPort == "" {
		apiPort = "8000"
	}

	// Wait a bit for files to be written (some modules write files asynchronously)
	log.Printf("[DISCORD] Waiting 2 seconds for files to be written...")
	time.Sleep(2 * time.Second)

	// Retry logic: try to find files with multiple attempts
	maxRetries := 5
	retryDelay := 1 * time.Second
	var existingFiles []string
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		existingFiles = []string{}
		for _, filePath := range filePaths {
			if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
				existingFiles = append(existingFiles, filePath)
				log.Printf("[DISCORD] File found and ready: %s (size: %d bytes)", filePath, info.Size())
			} else if err != nil {
				if attempt < maxRetries {
					log.Printf("[DISCORD] File not found (attempt %d/%d): %s (will retry)", attempt, maxRetries, filePath)
				} else {
					log.Printf("[DISCORD] File not found after %d attempts: %s (error: %v)", maxRetries, filePath, err)
				}
			} else {
				if attempt < maxRetries {
					log.Printf("[DISCORD] File exists but is empty (attempt %d/%d): %s (will retry)", attempt, maxRetries, filePath)
				} else {
					log.Printf("[DISCORD] File exists but is empty after %d attempts: %s (size: 0)", maxRetries, filePath)
				}
			}
		}

		if len(existingFiles) > 0 {
			log.Printf("[DISCORD] Found %d valid file(s) after %d attempt(s)", len(existingFiles), attempt)
			break
		}

		if attempt < maxRetries {
			log.Printf("[DISCORD] No files found yet, retrying in %v (attempt %d/%d)...", retryDelay, attempt, maxRetries)
			time.Sleep(retryDelay)
		}
	}

	if len(existingFiles) == 0 {
		// No files to send
		log.Printf("[DISCORD] No valid files to send for phase %s after %d attempts (checked %d paths)", phaseName, maxRetries, len(filePaths))
		return nil
	}

	log.Printf("[DISCORD] Sending %d file(s) for phase %s via API at %s:%s", len(existingFiles), phaseName, apiHost, apiPort)
	SendWebhookLogAsync(fmt.Sprintf("📤 **Sending %d File(s) for Phase: %s**\n**Files:** %d file(s) ready to send", len(existingFiles), phaseName, len(existingFiles)))

	// Send each file (Discord API has limits, so send one at a time)
	successCount := 0
	failCount := 0
	for i, filePath := range existingFiles {
		fileName := filepath.Base(filePath)
		log.Printf("[DISCORD] Sending file %d/%d: %s", i+1, len(existingFiles), filePath)
		SendWebhookLogAsync(fmt.Sprintf("📤 **Sending File %d/%d**\n**Phase:** %s\n**File:** %s", i+1, len(existingFiles), phaseName, fileName))
		
		if err := sendSingleFileToDiscord(apiHost, apiPort, channelID, scanID, phaseName, filePath); err != nil {
			// Log but don't fail - continue with other files
			log.Printf("[DISCORD] [ERROR] Failed to send file %s for phase %s: %v", filePath, phaseName, err)
			SendWebhookLogAsync(fmt.Sprintf("❌ **File Send Failed**\n**Phase:** %s\n**File:** %s\n**Error:** %v", phaseName, fileName, err))
			failCount++
		} else {
			log.Printf("[DISCORD] [SUCCESS] Successfully sent file: %s", filePath)
			SendWebhookLogAsync(fmt.Sprintf("✅ **File Sent Successfully**\n**Phase:** %s\n**File:** %s", phaseName, fileName))
			successCount++
		}
		// Small delay between files to avoid rate limits
		time.Sleep(500 * time.Millisecond)
	}
	
	log.Printf("[DISCORD] Completed sending files for phase %s: %d success, %d failed", phaseName, successCount, failCount)
	if successCount > 0 {
		SendWebhookLogAsync(fmt.Sprintf("✅ **Files Sent for Phase: %s**\n**Success:** %d file(s)\n**Failed:** %d file(s)", phaseName, successCount, failCount))
	} else if failCount > 0 {
		SendWebhookLogAsync(fmt.Sprintf("❌ **All Files Failed for Phase: %s**\n**Failed:** %d file(s)", phaseName, failCount))
	}

	return nil
}

func sendSingleFileToDiscord(apiHost, apiPort, channelID, scanID, phaseName, filePath string) error {
	// Try to send directly through Discord bot session first (if available)
	// This avoids needing the HTTP API server to be running
	description := fmt.Sprintf("📁 Phase: %s - %s", phaseName, filepath.Base(filePath))
	
	// Import gobot package to use SendFileToChannel
	// Note: We need to import it, but to avoid circular dependency, we'll try direct method first
	// If that fails, fall back to HTTP API
	
	// Try direct Discord session method (preferred)
	if err := trySendFileDirectly(channelID, filePath, description); err == nil {
		log.Printf("[DISCORD] Successfully sent file directly through Discord session")
		return nil
	} else {
		log.Printf("[DISCORD] Direct send failed: %v, trying HTTP API fallback", err)
	}

	// Fallback to HTTP API if direct method fails
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
	log.Printf("[DISCORD] Sending HTTP POST to: %s", url)
	log.Printf("[DISCORD] Request body: %s", string(jsonData))
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[DISCORD] [ERROR] HTTP request failed: %v", err)
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	log.Printf("[DISCORD] API response status: %d", resp.StatusCode)
	log.Printf("[DISCORD] API response body: %s", string(bodyBytes))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

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
	case "livehosts":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, domain, "subs", "live-subs.txt"),
		}
	case "reflection":
		files = []string{
			filepath.Join(resultsDir, domain, "vulnerabilities", "kxss-results.txt"),
		}
	case "js":
		jsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "js")
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			files = append(files, matches...)
		}
		files = append(files,
			filepath.Join(resultsDir, domain, "urls", "js-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "all-urls.txt"),
		)
	case "cnames":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "cname-records.txt"),
		}
	case "backup":
		files = []string{
			filepath.Join(resultsDir, domain, "backup", "fuzzuli-results.txt"),
		}
	case "dns":
		dnsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "dns-takeover")
		files = []string{
			filepath.Join(dnsDir, "dns-takeover-summary.txt"),
		}
	case "misconfig":
		files = []string{
			filepath.Join(resultsDir, "misconfig", domain, "scan-results.txt"),
		}
	case "nuclei":
		// Nuclei writes files directly to vulnerabilities/ directory (not vulnerabilities/nuclei/)
		// Files are named: nuclei-custom-others.txt, nuclei-public-http.txt, nuclei-custom-cves.txt, etc.
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		if matches, err := filepath.Glob(filepath.Join(vulnDir, "nuclei-*.txt")); err == nil {
			files = append(files, matches...)
		}
	}

	// Return all expected files (don't filter here - let SendPhaseFiles handle retries)
	return files
}

