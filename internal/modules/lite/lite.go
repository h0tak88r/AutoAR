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

	step := 1

	// Step 1: Live host filtering (with increased concurrency)
	if err := runPhase("livehosts", step, totalSteps, "Live host filtering", opts.Domain, opts.Timeouts["livehosts"], func() error {
		log.Printf("[LITE] [Step %d/%d] Starting live host filtering for %s (threads: 200)", step, totalSteps, opts.Domain)
		result, err := livehosts.FilterLiveHosts(opts.Domain, 200, true) // Increased from 100 to 200
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] Live host filtering completed", step, totalSteps)
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
		log.Printf("[LITE] [Step %d/%d] Starting reflection scanning for %s (threads: 50, timeout: %ds)", step, totalSteps, opts.Domain, reflectionTimeout)
		result, err := reflection.ScanReflectionWithOptions(reflection.Options{
			Domain:     opts.Domain,
			Threads:    50,  // Concurrency for kxss scanning
			Timeout:    time.Duration(reflectionTimeout) * time.Second,
			URLThreads: 200, // Higher concurrency for URL collection
		})
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] Reflection scanning completed, found %d reflections", step, totalSteps, result.Reflections)
		return nil
	}); err != nil {
		log.Printf("[WARN] Reflection scanning failed: %v", err)
	}
	step++

	// Step 3: JavaScript scanning (skippable)
	if !opts.SkipJS {
		if err := runPhase("js", step, totalSteps, "JavaScript scanning", opts.Domain, opts.Timeouts["js"], func() error {
			log.Printf("[LITE] [Step %d/%d] Starting JavaScript scanning for %s", step, totalSteps, opts.Domain)
			result, err := jsscan.Run(jsscan.Options{Domain: opts.Domain, Threads: 200}) // Increased from 100 to 200
			if err != nil {
				return err
			}
			log.Printf("[LITE] [Step %d/%d] JavaScript scanning completed, found %d JS URLs", step, totalSteps, result.TotalJS)
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
		log.Printf("[LITE] [Step %d/%d] Starting CNAME collection for %s (threads: 100, timeout: %ds)", step, totalSteps, opts.Domain, cnamesTimeout)
		result, err := cnames.CollectCNAMEsWithOptions(cnames.Options{
			Domain:  opts.Domain,
			Threads: 100,                              // Increased concurrency
			Timeout: time.Duration(cnamesTimeout) * time.Second,
		})
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] CNAME collection completed, found %d records", step, totalSteps, result.Records)
		return nil
	}); err != nil {
		log.Printf("[WARN] CNAME collection failed: %v", err)
	}
	step++

	// Step 5: Backup scan (using live hosts from Step 1)
	resultsDir := utils.GetResultsDir()
	liveHostsFile := filepath.Join(resultsDir, opts.Domain, "subs", "live-subs.txt")
	if err := runPhase("backup", step, totalSteps, "Backup file scan", opts.Domain, opts.Timeouts["backup"], func() error {
		log.Printf("[LITE] [Step %d/%d] Starting backup scan for %s (using live hosts from Step 1)", step, totalSteps, opts.Domain)
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
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] Backup scan completed, found %d backups", step, totalSteps, result.FoundCount)
		return nil
	}); err != nil {
		log.Printf("[WARN] Backup scan failed: %v", err)
	}
	step++

	// Step 6: DNS takeover scan
	if err := runPhase("dns", step, totalSteps, "DNS takeover scan", opts.Domain, opts.Timeouts["dns"], func() error {
		log.Printf("[LITE] [Step %d/%d] Starting DNS takeover scan for %s", step, totalSteps, opts.Domain)
		err := dns.Takeover(opts.Domain)
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] DNS takeover scan completed", step, totalSteps)
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
		log.Printf("[LITE] [Step %d/%d] Starting misconfiguration scan for %s (threads: 200, timeout: %ds)", step, totalSteps, opts.Domain, misconfigTimeout)
		err := misconfig.Run(misconfig.Options{
			Target:    opts.Domain,
			Action:    "scan",
			ServiceID: "",
			Delay:     0,
			Threads:   200, // Increased from 50 to 200
			Timeout:   misconfigTimeout,
		})
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] Misconfiguration scan completed", step, totalSteps)
		return nil
	}); err != nil {
		log.Printf("[WARN] Misconfiguration scan failed: %v", err)
	}
	step++

	// Step 8: Nuclei vulnerability scan (with increased concurrency)
	// Note: Nuclei uses live hosts from Step 1 automatically (checks for live-subs.txt)
	// It scans both public templates (nuclei-templates/http) and custom templates (nuclei_templates/vulns, cves, panels, etc.)
	if err := runPhase("nuclei", step, totalSteps, "Nuclei vulnerability scan", opts.Domain, opts.Timeouts["nuclei"], func() error {
		log.Printf("[LITE] [Step %d/%d] Starting Nuclei scan for %s (threads: 500)", step, totalSteps, opts.Domain)
		result, err := nuclei.RunNuclei(nuclei.Options{Domain: opts.Domain, Mode: nuclei.ModeFull, Threads: 500}) // Increased from 200 to 500
		if err != nil {
			return err
		}
		log.Printf("[LITE] [Step %d/%d] Nuclei scan completed", step, totalSteps)
		_ = result // Use result if needed
		return nil
	}); err != nil {
		log.Printf("[WARN] Nuclei scan failed: %v", err)
	}

	log.Printf("[OK] Lite Scan completed for %s", opts.Domain)
	return &Result{Domain: opts.Domain, Steps: totalSteps}, nil
}

func runPhase(phaseKey string, step, total int, description, domain string, timeoutSeconds int, fn func() error) error {
	log.Printf("[INFO] Step %d/%d: %s", step, total, description)

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
			return nil // Continue with next phase
		}
		log.Printf("[ERROR] Step %d/%d: %s failed: %v (duration: %s)", step, total, description, err, phaseDuration)
		return err
	}

	log.Printf("[OK] %s completed in %s", description, phaseDuration)
	
	// Send phase files in real-time (minimal webhook messages - only phase name and files)
	if phaseKey != "" {
		log.Printf("[DEBUG] [LITE] Preparing to send files for phase: %s", phaseKey)
		
		// Get expected file paths for this phase
		phaseFiles := utils.GetPhaseFiles(phaseKey, domain)
		log.Printf("[DEBUG] [LITE] Expected %d file(s) for phase %s", len(phaseFiles), phaseKey)
		
		if len(phaseFiles) > 0 {
			// Retry logic to find files
			maxRetries := 5
			retryDelay := 500 * time.Millisecond
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
				log.Printf("[DEBUG] [LITE] Sending %d file(s) for phase %s", len(existingFiles), phaseKey)
				
				// SendPhaseFiles will send minimal webhook message (phase name) and files
				if err := utils.SendPhaseFiles(phaseKey, domain, existingFiles); err != nil {
					log.Printf("[DEBUG] [LITE] Failed to send files for phase %s: %v", phaseKey, err)
				} else {
					log.Printf("[DEBUG] [LITE] Successfully sent %d file(s) for phase %s", len(existingFiles), phaseKey)
				}
			} else {
				log.Printf("[DEBUG] [LITE] No files found for phase %s after retries", phaseKey)
			}
		} else {
			log.Printf("[DEBUG] [LITE] No expected files for phase %s", phaseKey)
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
