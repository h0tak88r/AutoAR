// Package utils — Discord bot integration helpers.
//
// File sending is done exclusively via the internal bot HTTP API
// (POST /internal/send-file) when AUTOAR_CURRENT_SCAN_ID / AUTOAR_CURRENT_CHANNEL_ID
// are set (i.e. when running under the Discord bot).
//
// Discord webhook delivery has been removed; the bot handles all notifications
// when in bot mode.  CLI-only runs produce no Discord output.
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
)

// SendFileFunc is populated by the gobot module to allow direct in-process
// file delivery when the bot session is running in the same process.
var SendFileFunc func(string, string, string) error

// SendPhaseFiles sends result files for a specific phase to the Discord bot
// via the internal HTTP API (POST /internal/send-file).
//
// Only active when running under a bot session (AUTOAR_CURRENT_CHANNEL_ID must
// be set). API-triggered scans set AUTOAR_CURRENT_SCAN_ID but NOT CHANNEL_ID —
// those runs are silent no-ops here; the dashboard serves their results instead.
func SendPhaseFiles(phaseName, domain string, filePaths []string) error {
	channelID := os.Getenv("AUTOAR_CURRENT_CHANNEL_ID")

	// Require a Discord channel target. Without it we are in API/CLI mode —
	// the dashboard handles result display; no file delivery needed.
	if channelID == "" {
		return nil
	}

	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")

	apiHost := os.Getenv("API_HOST")
	if apiHost == "" {
		apiHost = "localhost"
	}
	apiPort := os.Getenv("API_PORT")
	if apiPort == "" {
		apiPort = "8000"
	}

	// Retry up to 5 times waiting for files to appear.
	maxRetries := 5
	retryDelay := 500 * time.Millisecond
	var existingFiles []string

	for attempt := 1; attempt <= maxRetries; attempt++ {
		existingFiles = nil
		for _, fp := range filePaths {
			if !IsFileEmpty(fp) {
				existingFiles = append(existingFiles, fp)
			} else {
				log.Printf("[DISCORD] File missing/empty (attempt %d/%d): %s", attempt, maxRetries, fp)
			}
		}
		if len(existingFiles) > 0 {
			break
		}
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	if len(existingFiles) == 0 {
		log.Printf("[DISCORD] No valid files for phase %s — sending status message", phaseName)
		msg := phaseNoResultsMessage(phaseName, domain)
		if err := sendMessageToDiscordAPI(apiHost, apiPort, channelID, scanID, msg); err != nil {
			log.Printf("[DISCORD] Failed to send status message: %v", err)
		}
		return nil
	}

	successCount, failCount := 0, 0
	for i, fp := range existingFiles {
		description := buildFileDescription(phaseName, fp)
		if err := sendSingleFileToBot(apiHost, apiPort, channelID, scanID, fp, description); err != nil {
			log.Printf("[DISCORD] Failed to send %s: %v", filepath.Base(fp), err)
			failCount++
		} else {
			successCount++
		}
		if i < len(existingFiles)-1 {
			time.Sleep(300 * time.Millisecond)
		}
	}

	log.Printf("[DISCORD] Phase %s: %d sent, %d failed", phaseName, successCount, failCount)
	return nil
}

// sendSingleFileToBot delivers a file via the in-process bot session (if available)
// or the internal HTTP API.  No webhook fallback.
func sendSingleFileToBot(apiHost, apiPort, channelID, scanID, filePath, description string) error {
	// 1. Try in-process bot session (same-process bot only).
	if channelID != "" && SendFileFunc != nil {
		if err := SendFileFunc(channelID, filePath, description); err == nil {
			log.Printf("[DISCORD] Sent via bot session: %s", filepath.Base(filePath))
			return nil
		}
	}

	// 2. Try internal HTTP API (subprocess / out-of-process cases).
	reqBody := map[string]string{
		"file_path":   filePath,
		"channel_id":  channelID,
		"description": description,
	}
	if scanID != "" {
		reqBody["scan_id"] = scanID
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("http://%s:%s/internal/send-file", apiHost, apiPort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		log.Printf("[DISCORD] Sent via internal API: %s", filepath.Base(filePath))
		return nil
	}
	return fmt.Errorf("internal API status %d: %s", resp.StatusCode, string(body))
}

// sendMessageToDiscordAPI sends a plain text message via the internal bot API.
func sendMessageToDiscordAPI(apiHost, apiPort, channelID, scanID, message string) error {
	if scanID == "" && channelID == "" {
		return fmt.Errorf("no bot context")
	}
	reqBody := map[string]string{
		"message":    message,
		"channel_id": channelID,
	}
	if scanID != "" {
		reqBody["scan_id"] = scanID
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("http://%s:%s/internal/send-message", apiHost, apiPort)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

// buildFileDescription returns the description string used when sending a file.
func buildFileDescription(phaseName, filePath string) string {
	base := filepath.Base(filePath)
	if phaseName == "gf" && strings.Contains(filePath, "vulnerabilities") {
		if strings.HasPrefix(base, "gf-") && strings.HasSuffix(base, "-results.txt") {
			return base
		}
		parts := strings.Split(filePath, string(filepath.Separator))
		for i, part := range parts {
			if part == "vulnerabilities" && i+1 < len(parts) {
				return fmt.Sprintf("gf-%s-results.txt", parts[i+1])
			}
		}
	}
	return base
}

// GetPhaseFiles returns the expected result file paths for a scan phase.
// The caller should use retry logic since files may not yet exist.
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
		jsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "js")
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			for _, m := range matches {
				if !strings.HasSuffix(m, "js-urls.txt") {
					files = append(files, m)
				}
			}
		}
	case "cnames":
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		files = []string{
			filepath.Join(resultsDir, rootDomain, "subs", "cname-records.txt"),
		}
	case "tech":
		files = []string{
			filepath.Join(resultsDir, domain, "subs", "tech-detect.txt"),
		}
	case "urls":
		files = []string{
			filepath.Join(resultsDir, domain, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "js-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "interesting-urls.txt"),
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
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		dnsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "dns-takeover")
		if matches, err := filepath.Glob(filepath.Join(dnsDir, "*.txt")); err == nil && len(matches) > 0 {
			files = append(files, matches...)
		}
		if domain != rootDomain {
			dnsRootDir := filepath.Join(resultsDir, rootDomain, "vulnerabilities", "dns-takeover")
			if matches, err := filepath.Glob(filepath.Join(dnsRootDir, "*.txt")); err == nil && len(matches) > 0 {
				files = append(files, matches...)
			}
		}
	case "cf1016":
		dnsDir := filepath.Join(resultsDir, domain, "vulnerabilities", "dns-takeover")
		files = []string{filepath.Join(dnsDir, "cf1016-dangling.txt")}
	case "exposure":
		files = []string{
			filepath.Join(resultsDir, domain, "vulnerabilities", "exposure", "exposure-findings.txt"),
		}
	case "misconfig":
		files = []string{
			filepath.Join(resultsDir, domain, "misconfig", "misconfig-scan-results.txt"),
			filepath.Join(resultsDir, domain, "misconfig", "scan-results.txt"),
			filepath.Join(resultsDir, "misconfig", domain, "scan-results.txt"),
		}
	case "nuclei":
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		if matches, err := filepath.Glob(filepath.Join(vulnDir, "nuclei-*.txt")); err == nil {
			for _, m := range matches {
				if !strings.HasSuffix(m, "nuclei-summary.txt") {
					files = append(files, m)
				}
			}
		}
	case "gf":
		vulnDir := filepath.Join(resultsDir, domain, "vulnerabilities")
		patterns := []string{"debug_logic", "idor", "iext", "img-traversal", "iparams", "isubs", "jsvar", "lfi", "rce", "redirect", "sqli", "ssrf", "ssti", "xss"}
		for _, pattern := range patterns {
			newPath := filepath.Join(vulnDir, pattern, fmt.Sprintf("gf-%s-results.txt", pattern))
			oldPath := filepath.Join(vulnDir, pattern, "gf-results.txt")
			if !IsFileEmpty(newPath) {
				files = append(files, newPath)
			} else if !IsFileEmpty(oldPath) {
				files = append(files, oldPath)
			} else {
				files = append(files, newPath)
			}
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
		depDir := filepath.Join(resultsDir, domain, "depconfusion", "web-file")
		files = []string{
			filepath.Join(depDir, "depconfusion-results.txt"),
			filepath.Join(depDir, "confused2-web-results.json"),
		}
	case "s3":
		rootDomain := domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			rootDomain = strings.Join(parts[len(parts)-2:], ".")
		}
		files = []string{
			filepath.Join(resultsDir, domain, "s3", "buckets.txt"),
			filepath.Join(resultsDir, "s3", rootDomain, "buckets.txt"),
		}
		s3Dir := filepath.Join(resultsDir, domain, "s3")
		if matches, err := filepath.Glob(filepath.Join(s3Dir, "*", "scan-results.txt")); err == nil {
			files = append(files, matches...)
		}
	case "githubscan":
		files = []string{
			filepath.Join(resultsDir, "github", "orgs", domain, "secrets.json"),
			filepath.Join(resultsDir, "github", "orgs", domain, "secrets_table.txt"),
			filepath.Join(resultsDir, "github", "repos", domain, "secrets.json"),
			filepath.Join(resultsDir, "github", "repos", domain, "secrets_table.txt"),
		}
	case "aem", "aem_scan":
		files = []string{
			filepath.Join(resultsDir, domain, "aem", "aem-scan.txt"),
		}
	case "zerodays", "0days":
		zerodaysDir := filepath.Join(resultsDir, domain, "zerodays")
		files = []string{
			filepath.Join(zerodaysDir, "react2shell-cve-2025-55182.txt"),
			filepath.Join(zerodaysDir, "mongodb-cve-2025-14847.txt"),
			filepath.Join(zerodaysDir, "zerodays-results.json"),
		}
		if matches, err := filepath.Glob(filepath.Join(zerodaysDir, "mongodb-leaked-*.bin")); err == nil {
			files = append(files, matches...)
		}
	}
	return files
}

// phaseNoResultsMessage returns a styled Discord message for a phase with zero results.
func phaseNoResultsMessage(phaseName, domain string) string {
	target := domain
	if target == "" {
		target = "targets"
	} else {
		target = "`" + target + "`"
	}
	switch phaseName {
	case "ports":
		return fmt.Sprintf("[ ⚪ ] **Port Scan** — No open ports found for %s", target)
	case "aem", "aem_scan":
		return fmt.Sprintf("[ ⚪ ] **AEM Scan** — No AEM instances discovered for %s", target)
	case "tech":
		return fmt.Sprintf("[ ⚪ ] **Tech Detection** — No live hosts found for %s", target)
	case "backup":
		return fmt.Sprintf("[ ⚪ ] **Backup Scan** — No backup files found for %s", target)
	case "misconfig":
		return fmt.Sprintf("[ ⚪ ] **Misconfig Scan** — No misconfigurations found for %s", target)
	case "subdomains":
		return fmt.Sprintf("[ ⚪ ] **Subdomains** — No subdomains found for %s", target)
	case "livehosts":
		return fmt.Sprintf("[ ⚪ ] **Live Hosts** — No live hosts found for %s", target)
	case "urls":
		return fmt.Sprintf("[ ⚪ ] **URLs** — No interesting URLs found for %s", target)
	case "jsscan", "js":
		return fmt.Sprintf("[ ⚪ ] **JS Scan** — No JavaScript vulnerabilities found for %s", target)
	case "reflection":
		return fmt.Sprintf("[ ⚪ ] **Reflection** — 0 findings for %s", target)
	case "nuclei":
		return fmt.Sprintf("[ ⚪ ] **Nuclei** — No vulnerabilities found for %s", target)
	case "gf":
		return fmt.Sprintf("[ ⚪ ] **GF Patterns** — No vulnerable parameters found for %s", target)
	case "s3":
		return fmt.Sprintf("[ ⚪ ] **S3 Scan** — No exposed buckets found for %s", target)
	case "githubscan":
		return fmt.Sprintf("[ ⚪ ] **GitHub Scan** — No secrets found for %s", target)
	case "zerodays", "0days":
		return fmt.Sprintf("[ ⚪ ] **0-Days** — No zero-day vulnerabilities found for %s", target)
	case "ffuf":
		return fmt.Sprintf("[ ⚪ ] **Fuzzing** — No hidden directories found for %s", target)
	case "dns":
		return fmt.Sprintf("[ ⚪ ] DNS takeover — No vulnerable records or dangling IPs found for %s", target)
	case "cf1016":
		return fmt.Sprintf("[ ⚪ ] **CF1016 Dangling DNS** — No missing Cloudflare origins found for %s", target)
	default:
		name := phaseName
		if len(phaseName) > 0 {
			name = strings.ToUpper(string(phaseName[0])) + phaseName[1:]
		}
		return fmt.Sprintf("[ ⚪ ] **%s** — 0 findings for %s", name, target)
	}
}

// SendMonitorWebhook sends an alert to the MONITOR_WEBHOOK_URL if configured.
func SendMonitorWebhook(msg string) {
	webhookURL := strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL"))
	if webhookURL == "" {
		return
	}

	payload := map[string]interface{}{"content": msg}

	// Basic generic JSON payload
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[MONITOR] Failed to marshal webhook payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[MONITOR] Failed to create webhook POST request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MONITOR] Failed to send webhook alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("[MONITOR] Webhook returned status %d: %s", resp.StatusCode, string(b))
	} else {
		log.Printf("[MONITOR] Successfully sent monitor webhook alert.")
	}
}
