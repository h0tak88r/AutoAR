package domain

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	aemmod "github.com/h0tak88r/AutoAR/v3/internal/modules/aem"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/backup"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/depconfusion"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/envloader"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/ffuf"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/jsscan"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/misconfig"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/reflection"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/s3"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
	wpconfusion "github.com/h0tak88r/AutoAR/v3/internal/modules/wp-confusion"
)

// Result holds domain scan results
type Result struct {
	Domain string
}

// RunDomain runs the full domain scan workflow with ALL features
// Note: GF scan runs, but modules that depend on GF (dalfox, sqlmap) are excluded
// Sends real-time webhook updates and files after each phase
func RunDomain(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Load .env file to ensure webhook URL is available
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	}

	log.Printf("[INFO] Starting full domain scan (all features) for %s", domain)

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	liveHostsFile := filepath.Join(domainDir, "subs", "live-subs.txt")

	totalSteps := 20 // Updated: Removed githubscan (not web-related), added zerodays
	step := 1

	// Phase 1: Reconnaissance
	if err := runDomainPhase("subdomains", step, totalSteps, "Subdomain enumeration", domain, 0, func() error {
		_, err := subdomains.EnumerateSubdomains(domain, 200)
		return err
	}); err != nil {
		log.Printf("[WARN] Subdomain enumeration failed: %v", err)
	}
	step++

	if err := runDomainPhase("cnames", step, totalSteps, "CNAME collection", domain, 0, func() error {
		_, err := cnames.CollectCNAMEsWithOptions(cnames.Options{
			Domain:  domain,
			Threads: 200,
			Timeout: 5 * time.Minute,
		})
		return err
	}); err != nil {
		log.Printf("[WARN] CNAME collection failed: %v", err)
	}
	step++

	if err := runDomainPhase("livehosts", step, totalSteps, "Live host filtering", domain, 0, func() error {
		_, err := livehosts.FilterLiveHosts(domain, 200, true)
		return err
	}); err != nil {
		log.Printf("[WARN] Live host filtering failed: %v", err)
	}
	step++

	if err := runDomainPhase("tech", step, totalSteps, "Technology detection", domain, 0, func() error {
		_, err := tech.DetectTech(domain, 200)
		return err
	}); err != nil {
		log.Printf("[WARN] Technology detection failed: %v", err)
	}
	step++

	if err := runDomainPhase("urls", step, totalSteps, "URL collection", domain, 0, func() error {
		_, err := urls.CollectURLs(domain, 200, false)
		return err
	}); err != nil {
		log.Printf("[WARN] URL collection failed: %v", err)
	}
	step++

	if err := runDomainPhase("jsscan", step, totalSteps, "JavaScript scan", domain, 0, func() error {
		_, err := jsscan.Run(jsscan.Options{Domain: domain, Threads: 200})
		return err
	}); err != nil {
		log.Printf("[WARN] JavaScript scan failed: %v", err)
	}
	step++

	// Phase 2: Vulnerability Scanning
	if err := runDomainPhase("reflection", step, totalSteps, "Reflection scan", domain, 0, func() error {
		_, err := reflection.ScanReflection(domain)
		return err
	}); err != nil {
		log.Printf("[WARN] Reflection scan failed: %v", err)
	}
	step++

	if err := runDomainPhase("ports", step, totalSteps, "Port scanning", domain, 0, func() error {
		_, err := ports.ScanPorts(domain, 200)
		return err
	}); err != nil {
		log.Printf("[WARN] Port scanning failed: %v", err)
	}
	step++

	if err := runDomainPhase("gf", step, totalSteps, "GF pattern matching", domain, 0, func() error {
		// Run GF scan (it's OK to run it)
		_, err := gf.ScanGF(domain)
		return err
	}); err != nil {
		log.Printf("[WARN] GF scan failed: %v", err)
	}
	step++

	// Phase 3: Additional Scanners (excluding dalfox and sqlmap as they depend on GF)
	if err := runDomainPhase("backup", step, totalSteps, "Backup file discovery", domain, 0, func() error {
		// Use live hosts file if available
		if _, err := os.Stat(liveHostsFile); err == nil {
			_, err := backup.Run(backup.Options{
				LiveHostsFile: liveHostsFile,
				Threads:       200,
				Method:        "all",
			})
			return err
		}
		// Fallback to domain scan
		_, err := backup.Run(backup.Options{
			Domain:  domain,
			Threads: 200,
			Method:  "all",
		})
		return err
	}); err != nil {
		log.Printf("[WARN] Backup file discovery failed: %v", err)
	}
	step++

	if err := runDomainPhase("misconfig", step, totalSteps, "Cloud misconfiguration scan", domain, 1800, func() error {
		// Use existing live hosts file if available to avoid re-scanning
		liveHostsFileToUse := ""
		if _, err := os.Stat(liveHostsFile); err == nil {
			liveHostsFileToUse = liveHostsFile
		}
		err := misconfig.Run(misconfig.Options{
			Target:        domain,
			Action:        "scan",
			Threads:       200, // Use same thread count as other phases
			Timeout:       1800,
			LiveHostsFile: liveHostsFileToUse, // Pass live hosts file to avoid enumeration
		})
		// Don't fail if no live subdomains found - this is expected for some domains
		if err != nil && strings.Contains(err.Error(), "no live subdomains found") {
			log.Printf("[INFO] Misconfiguration scan skipped: %v", err)
			return nil // Continue workflow
		}
		return err
	}); err != nil {
		log.Printf("[WARN] Misconfiguration scan failed: %v", err)
	}
	step++

	if err := runDomainPhase("aem", step, totalSteps, "AEM webapp discovery and scan", domain, 0, func() error {
		// Use live hosts file if available
		liveHostsFileToUse := ""
		if _, err := os.Stat(liveHostsFile); err == nil {
			liveHostsFileToUse = liveHostsFile
		}
		_, err := aemmod.Run(aemmod.Options{
			Domain:        domain,
			LiveHostsFile: liveHostsFileToUse,
			Threads:       50,
		})
		return err
	}); err != nil {
		log.Printf("[WARN] AEM scan failed: %v", err)
	}
	step++

	if err := runDomainPhase("dns", step, totalSteps, "DNS takeover scan", domain, 0, func() error {
		return dns.Takeover(domain)
	}); err != nil {
		log.Printf("[WARN] DNS takeover scan failed: %v", err)
	}
	step++

	if err := runDomainPhase("ffuf", step, totalSteps, "FFuf fuzzing", domain, 0, func() error {
		// FFuf on all live hosts with 403 bypass enabled (domain workflow only)
		if _, err := os.Stat(liveHostsFile); err == nil {
			// Read live hosts from file
			file, err := os.Open(liveHostsFile)
			if err != nil {
				return fmt.Errorf("failed to open live hosts file: %w", err)
			}
			defer file.Close()
			
			scanner := bufio.NewScanner(file)
			var targets []string
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					// Ensure URL has protocol
					if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
						line = "https://" + line
					}
					targets = append(targets, line)
				}
			}
			
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("failed to read live hosts file: %w", err)
			}
			
			if len(targets) == 0 {
				log.Printf("[WARN] No live hosts found for FFuf fuzzing")
				return nil
			}
			
			// Run FFuf on each target with 403 bypass
			for _, target := range targets {
				_, err := ffuf.RunFFuf(ffuf.Options{
					Target:     target,
					Threads:    40,
					Bypass403:   true, // Enable 403 bypass
				})
				if err != nil {
					log.Printf("[WARN] FFuf fuzzing failed for %s: %v", target, err)
					// Continue with other targets
				}
			}
			return nil
		}
		// Fallback: use domain if no live hosts file
		_, err := ffuf.RunFFuf(ffuf.Options{
			Target:    fmt.Sprintf("https://%s", domain),
			Threads:   40,
			Bypass403: true,
		})
		return err
	}); err != nil {
		log.Printf("[WARN] FFuf fuzzing failed: %v", err)
	}
	step++

	if err := runDomainPhase("wp_confusion", step, totalSteps, "WordPress confusion scan", domain, 0, func() error {
		// WordPress confusion scan
		url := fmt.Sprintf("https://%s", domain)
		return wpconfusion.ScanWPConfusion(wpconfusion.ScanOptions{
			URL:     url,
			Plugins: true,
			Theme:   true,
		})
	}); err != nil {
		log.Printf("[WARN] WordPress confusion scan failed: %v", err)
	}
	step++

	if err := runDomainPhase("depconfusion", step, totalSteps, "Dependency confusion scan", domain, 0, func() error {
		// Dependency confusion scan in web mode
		// Use TargetFile instead of Targets to ensure proper URL handling
		if _, err := os.Stat(liveHostsFile); err == nil {
			// Use live hosts file directly
			return depconfusion.Run(depconfusion.Options{
				Mode:      "web",
				TargetFile: liveHostsFile,
				Workers:   10,
				Verbose:   false,
			})
		}
		// Fallback: create a temp file with domain URL
		tempFile := filepath.Join(filepath.Dir(liveHostsFile), "temp-depconfusion-targets.txt")
		if err := os.WriteFile(tempFile, []byte(fmt.Sprintf("https://%s\n", domain)), 0644); err != nil {
			return fmt.Errorf("failed to create temp file: %v", err)
		}
		defer os.Remove(tempFile)
		return depconfusion.Run(depconfusion.Options{
			Mode:      "web",
			TargetFile: tempFile,
			Workers:   10,
			Verbose:   false,
		})
	}); err != nil {
		log.Printf("[WARN] Dependency confusion scan failed: %v", err)
	}
	step++

	if err := runDomainPhase("s3", step, totalSteps, "S3 bucket enumeration", domain, 0, func() error {
		// S3 enumeration
		return s3.Run(s3.Options{
			Action: "enum",
			Root:   domain,
		})
	}); err != nil {
		log.Printf("[WARN] S3 enumeration failed: %v", err)
	}
	step++


	// Phase: Zerodays scan (sends webhooks in real-time, no file sending needed)
	if err := runDomainPhase("", step, totalSteps, "Zerodays scan", domain, 0, func() error {
		// Run zerodays via CLI command - it sends webhooks in real-time
		cmd := exec.Command(os.Args[0], "zerodays", "scan", "-d", domain, "-t", "100", "--silent")
		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] Zerodays scan failed: %v", err)
			return nil // Don't fail workflow if zerodays fails
		}
		return nil
	}); err != nil {
		log.Printf("[WARN] Zerodays scan failed: %v", err)
	}
	step++

	// Final Phase: Nuclei full scan (runs last to catch all vulnerabilities after all other scans)
	if err := runDomainPhase("nuclei", step, totalSteps, "Nuclei vulnerability scan (final)", domain, 0, func() error {
		_, err := nuclei.RunNuclei(nuclei.Options{Domain: domain, Mode: nuclei.ModeFull, Threads: 500})
		return err
	}); err != nil {
		log.Printf("[WARN] Nuclei scan failed: %v", err)
	}

	log.Printf("[OK] Full domain scan completed for %s", domain)
	return &Result{Domain: domain}, nil
}

// runDomainPhase runs a single phase with webhook updates and file sending
func runDomainPhase(phaseKey string, step, total int, description, domain string, timeoutSeconds int, fn func() error) error {
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
		log.Printf("[ERROR] Step %d/%d: %s failed: %v (duration: %s)", step, total, description, err, phaseDuration)
		// Send error message to webhook
		utils.SendWebhookLogAsync(fmt.Sprintf("[ERROR] %s failed: %v", description, err))
		// Still try to send any files that might have been created before the error
		if phaseKey != "" {
			phaseFiles := utils.GetPhaseFiles(phaseKey, domain)
			if len(phaseFiles) > 0 {
				var existingFiles []string
				for _, filePath := range phaseFiles {
					if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
						existingFiles = append(existingFiles, filePath)
					}
				}
				if len(existingFiles) > 0 {
					utils.SendPhaseFiles(phaseKey, domain, existingFiles)
				}
			}
		}
		return err
	}

	log.Printf("[OK] %s completed in %s", description, phaseDuration)
	
	// Send phase files in real-time (skip for modules that handle their own messaging)
	// Modules that handle their own messaging: dns, aem, misconfig, ffuf
	if phaseKey != "" && phaseKey != "dns" && phaseKey != "aem" && phaseKey != "misconfig" && phaseKey != "ffuf" {
		log.Printf("[DEBUG] [DOMAIN] Preparing to send files for phase: %s", phaseKey)
		
		// Get expected file paths for this phase
		phaseFiles := utils.GetPhaseFiles(phaseKey, domain)
		log.Printf("[DEBUG] [DOMAIN] Expected %d file(s) for phase %s", len(phaseFiles), phaseKey)
		
		if len(phaseFiles) > 0 {
			// Retry logic to find files (reduced delays for real-time sending)
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
				log.Printf("[DEBUG] [DOMAIN] Sending %d file(s) for phase %s", len(existingFiles), phaseKey)
				
				// SendPhaseFiles will send minimal webhook message (phase name) and files
				if err := utils.SendPhaseFiles(phaseKey, domain, existingFiles); err != nil {
					log.Printf("[WARN] [DOMAIN] Failed to send files for phase %s: %v", phaseKey, err)
				} else {
					log.Printf("[DEBUG] [DOMAIN] Successfully sent %d file(s) for phase %s", len(existingFiles), phaseKey)
				}
			} else {
				log.Printf("[DEBUG] [DOMAIN] No files found for phase %s after retries", phaseKey)
				// SendPhaseFiles will handle sending the "0 findings" message
				utils.SendPhaseFiles(phaseKey, domain, []string{})
			}
		} else {
			log.Printf("[DEBUG] [DOMAIN] No expected files for phase %s", phaseKey)
			// SendPhaseFiles will handle sending the "0 findings" message
			utils.SendPhaseFiles(phaseKey, domain, []string{})
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
