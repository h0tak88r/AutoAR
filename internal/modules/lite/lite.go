package lite

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/backup"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/jsscan"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/misconfig"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/reflection"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
)

// Options holds lite scan options
type Options struct {
	Domain              string
	SkipJS              bool
	PhaseTimeoutDefault int // seconds
	Timeouts            map[string]int
}

// Result holds lite scan results
type Result struct {
	Domain string
	Steps  int
}

// RunLite runs the lite scan workflow
func RunLite(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if opts.PhaseTimeoutDefault == 0 {
		opts.PhaseTimeoutDefault = 3600 // 1 hour default
	}

	if opts.Timeouts == nil {
		opts.Timeouts = make(map[string]int)
	}

	// Set defaults for unset timeouts
	phases := []string{"livehosts", "reflection", "js", "cnames", "backup", "dns", "misconfig", "nuclei"}
	for _, phase := range phases {
		if opts.Timeouts[phase] == 0 {
			opts.Timeouts[phase] = opts.PhaseTimeoutDefault
		}
	}

	// Calculate total steps: livehosts, reflection, js (if not skipped), cnames, backup, dns, misconfig, nuclei
	totalSteps := 6 // livehosts, reflection, cnames, backup, dns, misconfig, nuclei
	if !opts.SkipJS {
		totalSteps = 7 // + js
	}

	log.Printf("[INFO] Starting Lite Scan for %s (%d steps)", opts.Domain, totalSteps)
	utils.SendWebhookLogAsync(fmt.Sprintf("🚀 **Lite Scan Started**\n**Domain:** %s\n**Total Steps:** %d", opts.Domain, totalSteps))

	step := 1

	// Step 1: Live host filtering (with increased concurrency)
	if err := runPhase("livehosts", step, totalSteps, "Live host filtering", opts.Domain, opts.Timeouts["livehosts"], func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: Live Host Filtering**\n**Domain:** %s\n**Status:** Starting...\n**Threads:** 200", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting live host filtering for %s (threads: 200)", step, totalSteps, opts.Domain)
		startTime := time.Now()
		
		result, err := livehosts.FilterLiveHosts(opts.Domain, 200, true) // Increased from 100 to 200
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: Live Host Filtering FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: Live Host Filtering COMPLETED**\n**Domain:** %s\n**Duration:** %s\n**Live Hosts Found:** Processing...", step, totalSteps, opts.Domain, duration))
		log.Printf("[LITE] [Step %d/%d] Live host filtering completed in %s", step, totalSteps, duration)
		_ = result // Use result if needed
		return nil
	}); err != nil {
		log.Printf("[WARN] Live host filtering failed: %v", err)
	}
	step++

	// Step 2: Reflection scanning (with timeout and increased concurrency)
	reflectionTimeout := opts.Timeouts["reflection"]
	if reflectionTimeout == 0 {
		reflectionTimeout = 900 // 15 minutes default
	}
	if err := runPhase("reflection", step, totalSteps, "Reflection scanning", opts.Domain, reflectionTimeout, func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: Reflection Scanning**\n**Domain:** %s\n**Status:** Starting...\n**Threads:** 50 (kxss), 200 (URL collection)", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting reflection scanning for %s (threads: 50, timeout: %ds)", step, totalSteps, opts.Domain, reflectionTimeout)
		startTime := time.Now()
		
		// Use options with increased concurrency and timeout
		result, err := reflection.ScanReflectionWithOptions(reflection.Options{
			Domain:     opts.Domain,
			Threads:    50,  // Concurrency for kxss scanning
			Timeout:    time.Duration(reflectionTimeout) * time.Second,
			URLThreads: 200, // Higher concurrency for URL collection
		})
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: Reflection Scanning FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: Reflection Scanning COMPLETED**\n**Domain:** %s\n**Duration:** %s\n**Reflections Found:** %d", step, totalSteps, opts.Domain, duration, result.Reflections))
		log.Printf("[LITE] [Step %d/%d] Reflection scanning completed in %s, found %d reflections", step, totalSteps, duration, result.Reflections)
		return nil
	}); err != nil {
		log.Printf("[WARN] Reflection scanning failed: %v", err)
	}
	step++

	// Step 3: JavaScript scanning (skippable)
	if !opts.SkipJS {
		if err := runPhase("js", step, totalSteps, "JavaScript scanning", opts.Domain, opts.Timeouts["js"], func() error {
			utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: JavaScript Scanning**\n**Domain:** %s\n**Status:** Starting...", step, totalSteps, opts.Domain))
			log.Printf("[LITE] [Step %d/%d] Starting JavaScript scanning for %s", step, totalSteps, opts.Domain)
			startTime := time.Now()
			
			// Use jsscan module directly instead of exec (increased concurrency)
			result, err := jsscan.Run(jsscan.Options{Domain: opts.Domain, Threads: 200}) // Increased from 100 to 200
			duration := time.Since(startTime)
			
			if err != nil {
				utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: JavaScript Scanning FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
				return err
			}
			
			utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: JavaScript Scanning COMPLETED**\n**Domain:** %s\n**Duration:** %s\n**JS URLs Found:** %d", step, totalSteps, opts.Domain, duration, result.TotalJS))
			log.Printf("[LITE] [Step %d/%d] JavaScript scanning completed in %s, found %d JS URLs", step, totalSteps, duration, result.TotalJS)
			return nil
		}); err != nil {
			log.Printf("[WARN] JavaScript scanning failed: %v", err)
		}
		step++
	}

	// Step 4: CNAME records collection (with increased concurrency)
	cnamesTimeout := opts.Timeouts["cnames"]
	if cnamesTimeout == 0 {
		cnamesTimeout = 300 // 5 minutes default
	}
	if err := runPhase("cnames", step, totalSteps, "CNAME records collection", opts.Domain, cnamesTimeout, func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: CNAME Records Collection**\n**Domain:** %s\n**Status:** Starting...\n**Threads:** 100 concurrent", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting CNAME collection for %s (threads: 100, timeout: %ds)", step, totalSteps, opts.Domain, cnamesTimeout)
		startTime := time.Now()
		
		result, err := cnames.CollectCNAMEsWithOptions(cnames.Options{
			Domain:  opts.Domain,
			Threads: 100,                              // Increased concurrency
			Timeout: time.Duration(cnamesTimeout) * time.Second,
		})
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: CNAME Collection FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: CNAME Collection COMPLETED**\n**Domain:** %s\n**Duration:** %s\n**CNAME Records Found:** %d", step, totalSteps, opts.Domain, duration, result.Records))
		log.Printf("[LITE] [Step %d/%d] CNAME collection completed in %s, found %d records", step, totalSteps, duration, result.Records)
		return nil
	}); err != nil {
		log.Printf("[WARN] CNAME collection failed: %v", err)
	}
	step++

	// Step 5: Backup scan (using live hosts from Step 1)
	resultsDir := utils.GetResultsDir()
	liveHostsFile := filepath.Join(resultsDir, opts.Domain, "subs", "live-subs.txt")
	if err := runPhase("backup", step, totalSteps, "Backup file scan", opts.Domain, opts.Timeouts["backup"], func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: Backup File Scan**\n**Domain:** %s\n**Status:** Starting...\n**Note:** Using live hosts from Step 1", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting backup scan for %s (using live hosts from Step 1)", step, totalSteps, opts.Domain)
		startTime := time.Now()
		
		// Use live hosts file if it exists, otherwise fall back to domain scan
		var result *backup.Result
		var err error
		if _, err := os.Stat(liveHostsFile); err == nil {
			result, err = backup.Run(backup.Options{
				LiveHostsFile: liveHostsFile,
				Threads:       200, // Increased from 100 to 200
				Method:        "regular",
			})
		} else {
			// Fallback to domain scan if live hosts file doesn't exist
			result, err = backup.Run(backup.Options{
				Domain:  opts.Domain,
				Threads: 200,
				Method:  "regular",
			})
		}
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: Backup Scan FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: Backup Scan COMPLETED**\n**Domain:** %s\n**Duration:** %s\n**Backups Found:** %d", step, totalSteps, opts.Domain, duration, result.FoundCount))
		log.Printf("[LITE] [Step %d/%d] Backup scan completed in %s, found %d backups", step, totalSteps, duration, result.FoundCount)
		return nil
	}); err != nil {
		log.Printf("[WARN] Backup scan failed: %v", err)
	}
	step++

	// Step 6: DNS takeover scan
	if err := runPhase("dns", step, totalSteps, "DNS takeover scan", opts.Domain, opts.Timeouts["dns"], func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: DNS Takeover Scan**\n**Domain:** %s\n**Status:** Starting...", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting DNS takeover scan for %s", step, totalSteps, opts.Domain)
		startTime := time.Now()
		
		err := dns.Takeover(opts.Domain)
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: DNS Takeover Scan FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: DNS Takeover Scan COMPLETED**\n**Domain:** %s\n**Duration:** %s", step, totalSteps, opts.Domain, duration))
		log.Printf("[LITE] [Step %d/%d] DNS takeover scan completed in %s", step, totalSteps, duration)
		return nil
	}); err != nil {
		log.Printf("[WARN] DNS takeover scan failed: %v", err)
	}
	step++

	// Step 7: Misconfiguration scan (with increased concurrency)
	// Note: This uses the live hosts file from Step 1 (livehosts phase)
	misconfigTimeout := opts.Timeouts["misconfig"]
	if misconfigTimeout == 0 {
		misconfigTimeout = 1800 // 30 minutes default
	}
	if err := runPhase("misconfig", step, totalSteps, "Misconfiguration scan", opts.Domain, misconfigTimeout, func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: Misconfiguration Scan**\n**Domain:** %s\n**Status:** Starting...\n**Threads:** 200 concurrent\n**Note:** Using live hosts from Step 1", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting misconfiguration scan for %s (threads: 200, timeout: %ds) - using live hosts from Step 1", step, totalSteps, opts.Domain, misconfigTimeout)
		startTime := time.Now()
		
		err := misconfig.Run(misconfig.Options{
			Target:    opts.Domain,
			Action:    "scan",
			ServiceID: "",
			Delay:     0,
			Threads:   200, // Increased from 50 to 200
			Timeout:   misconfigTimeout,
		})
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: Misconfiguration Scan FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: Misconfiguration Scan COMPLETED**\n**Domain:** %s\n**Duration:** %s", step, totalSteps, opts.Domain, duration))
		log.Printf("[LITE] [Step %d/%d] Misconfiguration scan completed in %s", step, totalSteps, duration)
		return nil
	}); err != nil {
		log.Printf("[WARN] Misconfiguration scan failed: %v", err)
	}
	step++

	// Step 8: Nuclei vulnerability scan (with increased concurrency)
	// Note: Nuclei uses live hosts from Step 1 automatically (checks for live-subs.txt)
	// It scans both public templates (nuclei-templates/http) and custom templates (nuclei_templates/vulns, cves, panels, etc.)
	if err := runPhase("nuclei", step, totalSteps, "Nuclei vulnerability scan", opts.Domain, opts.Timeouts["nuclei"], func() error {
		utils.SendWebhookLogAsync(fmt.Sprintf("🔍 **Step %d/%d: Nuclei Vulnerability Scan**\n**Domain:** %s\n**Status:** Starting...\n**Threads:** 500 concurrent\n**Templates:** Public + Custom\n**Note:** Using live hosts from Step 1", step, totalSteps, opts.Domain))
		log.Printf("[LITE] [Step %d/%d] Starting Nuclei scan for %s (threads: 500, templates: public + custom, using live hosts from Step 1)", step, totalSteps, opts.Domain)
		startTime := time.Now()
		
		result, err := nuclei.RunNuclei(nuclei.Options{Domain: opts.Domain, Mode: nuclei.ModeFull, Threads: 500}) // Increased from 200 to 500
		duration := time.Since(startTime)
		
		if err != nil {
			utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: Nuclei Scan FAILED**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, totalSteps, opts.Domain, err, duration))
			return err
		}
		
		utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: Nuclei Scan COMPLETED**\n**Domain:** %s\n**Duration:** %s", step, totalSteps, opts.Domain, duration))
		log.Printf("[LITE] [Step %d/%d] Nuclei scan completed in %s", step, totalSteps, duration)
		_ = result // Use result if needed
		return nil
	}); err != nil {
		log.Printf("[WARN] Nuclei scan failed: %v", err)
	}

	log.Printf("[OK] Lite Scan completed for %s", opts.Domain)
	utils.SendWebhookLogAsync(fmt.Sprintf("🎉 **Lite Scan COMPLETED**\n**Domain:** %s\n**Total Steps:** %d\n**Status:** All phases finished", opts.Domain, totalSteps))
	return &Result{Domain: opts.Domain, Steps: totalSteps}, nil
}

func runPhase(phaseKey string, step, total int, description, domain string, timeoutSeconds int, fn func() error) error {
	log.Printf("[INFO] Step %d/%d: %s", step, total, description)
	utils.SendWebhookLogAsync(fmt.Sprintf("⏱️ **Step %d/%d: %s**\n**Timeout:** %s\n**Status:** Running...", step, total, description, formatTimeout(timeoutSeconds)))

	var err error
	phaseStartTime := time.Now()
	if timeoutSeconds > 0 {
		err = runWithTimeout(fn, time.Duration(timeoutSeconds)*time.Second)
	} else {
		err = fn()
	}
	phaseDuration := time.Since(phaseStartTime)

	if err != nil {
		if err == ErrTimeout {
			log.Printf("[WARN] %s timed out after %s", description, formatTimeout(timeoutSeconds))
			utils.SendWebhookLogAsync(fmt.Sprintf("⏰ **Step %d/%d: %s TIMED OUT**\n**Domain:** %s\n**Timeout:** %s\n**Duration:** %s", step, total, description, domain, formatTimeout(timeoutSeconds), phaseDuration))
			return nil // Continue with next phase
		}
		utils.SendWebhookLogAsync(fmt.Sprintf("❌ **Step %d/%d: %s ERROR**\n**Domain:** %s\n**Error:** %v\n**Duration:** %s", step, total, description, domain, err, phaseDuration))
		return err
	}

	log.Printf("[OK] %s completed in %s", description, phaseDuration)
	utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Step %d/%d: %s COMPLETED**\n**Domain:** %s\n**Duration:** %s", step, total, description, domain, phaseDuration))
	
	// Send phase files via webhook in real-time
	if phaseKey != "" {
		log.Printf("[LITE] Preparing to send files for phase: %s via webhook", phaseKey)
		utils.SendWebhookLogAsync(fmt.Sprintf("📁 **Step %d/%d: Preparing Files**\n**Phase:** %s\n**Domain:** %s", step, total, phaseKey, domain))
		
		// Get expected file paths for this phase
		phaseFiles := utils.GetPhaseFiles(phaseKey, domain)
		log.Printf("[LITE] Expected %d file(s) for phase %s", len(phaseFiles), phaseKey)
		utils.SendWebhookLogAsync(fmt.Sprintf("📁 **Step %d/%d: File Discovery**\n**Phase:** %s\n**Expected Files:** %d", step, total, phaseKey, len(phaseFiles)))
		
		if len(phaseFiles) > 0 {
			// Wait a bit for files to be written
			time.Sleep(2 * time.Second)
			
			// Retry logic to find files
			maxRetries := 5
			retryDelay := 1 * time.Second
			var existingFiles []string
			
			for attempt := 1; attempt <= maxRetries; attempt++ {
				existingFiles = []string{}
				for _, filePath := range phaseFiles {
					if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
						existingFiles = append(existingFiles, filePath)
					}
				}
				if len(existingFiles) > 0 {
					break
				}
				if attempt < maxRetries {
					time.Sleep(retryDelay)
				}
			}
			
			if len(existingFiles) > 0 {
				log.Printf("[LITE] Sending %d file(s) for phase %s via webhook", len(existingFiles), phaseKey)
				utils.SendWebhookLogAsync(fmt.Sprintf("📤 **Step %d/%d: Sending Files via Webhook**\n**Phase:** %s\n**Files:** %d file(s)", step, total, phaseKey, len(existingFiles)))
				
				successCount := 0
				for i, filePath := range existingFiles {
					fileName := filepath.Base(filePath)
					description := fmt.Sprintf("📁 **Phase: %s** - %s", phaseKey, fileName)
					
					if err := utils.SendWebhookFile(filePath, description); err != nil {
						log.Printf("[LITE] [ERROR] Failed to send file %s via webhook: %v", filePath, err)
						utils.SendWebhookLogAsync(fmt.Sprintf("❌ **File Send Failed**\n**Phase:** %s\n**File:** %s\n**Error:** %v", phaseKey, fileName, err))
					} else {
						log.Printf("[LITE] [SUCCESS] Sent file %d/%d via webhook: %s", i+1, len(existingFiles), fileName)
						successCount++
					}
					// Small delay between files
					time.Sleep(500 * time.Millisecond)
				}
				
				if successCount > 0 {
					utils.SendWebhookLogAsync(fmt.Sprintf("✅ **Files Sent via Webhook**\n**Phase:** %s\n**Success:** %d/%d file(s)", phaseKey, successCount, len(existingFiles)))
				}
			} else {
				log.Printf("[LITE] No files found for phase %s after retries", phaseKey)
				utils.SendWebhookLogAsync(fmt.Sprintf("ℹ️ **Step %d/%d: No Files Found**\n**Phase:** %s\n**Note:** Files not found (may be normal)", step, total, phaseKey))
			}
		} else {
			log.Printf("[LITE] No expected files for phase %s", phaseKey)
			utils.SendWebhookLogAsync(fmt.Sprintf("ℹ️ **Step %d/%d: No Files**\n**Phase:** %s\n**Note:** No result files expected", step, total, phaseKey))
		}
	}
	
	return nil
}

var ErrTimeout = fmt.Errorf("timeout")

func runWithTimeout(fn func() error, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrTimeout
	}
}

func formatTimeout(seconds int) string {
	if seconds <= 0 {
		return "no limit"
	}
	hrs := seconds / 3600
	mins := (seconds % 3600) / 60
	secs := seconds % 60
	var parts []string
	if hrs > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hrs))
	}
	if mins > 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	if hrs == 0 && mins == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	return strings.Join(parts, "")
}

// ParseTimeout parses timeout string like "30m", "2h", "3600" into seconds
func ParseTimeout(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "none" || s == "off" || s == "disable" || s == "disabled" || s == "0" {
		return 0, nil
	}

	// Try to parse as number with optional suffix
	if strings.HasSuffix(s, "s") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "s")); err == nil {
			return val, nil
		}
	}
	if strings.HasSuffix(s, "m") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "m")); err == nil {
			return val * 60, nil
		}
	}
	if strings.HasSuffix(s, "h") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "h")); err == nil {
			return val * 3600, nil
		}
	}
	if strings.HasSuffix(s, "d") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil {
			return val * 86400, nil
		}
	}

	// Try plain number
	if val, err := strconv.Atoi(s); err == nil {
		return val, nil
	}

	return 0, fmt.Errorf("invalid timeout format: %s", s)
}
