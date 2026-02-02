package domain

import (

	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aemmod "github.com/h0tak88r/AutoAR/internal/modules/aem"
	"github.com/h0tak88r/AutoAR/internal/modules/backup"
	"github.com/h0tak88r/AutoAR/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/internal/modules/depconfusion"
	"github.com/h0tak88r/AutoAR/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/internal/modules/envloader"
	"github.com/h0tak88r/AutoAR/internal/modules/ffuf"
	"github.com/h0tak88r/AutoAR/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/internal/modules/jsscan"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/misconfig"
	"github.com/h0tak88r/AutoAR/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/internal/modules/reflection"
	"github.com/h0tak88r/AutoAR/internal/modules/s3"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	wpconfusion "github.com/h0tak88r/AutoAR/internal/modules/wp-confusion"
)

// Result holds domain scan results
type Result struct {
	Domain string
}

// UploadedFileInfo holds information about an uploaded file
type UploadedFileInfo struct {
	Phase     string `json:"phase"`
	FileName  string `json:"file_name"`
	FilePath  string `json:"file_path"`
	Size      int64  `json:"size"`
	SizeHuman string `json:"size_human"`
	URL       string `json:"url"`
}

// DomainScanUploads holds all uploaded files information
type DomainScanUploads struct {
	Domain string             `json:"domain"`
	Files  []UploadedFileInfo `json:"files"`
}

// ScanOptions holds options for domain scan
type ScanOptions struct {
	Domain   string
	SkipFFuf bool
}

// RunDomain runs the full domain scan workflow with ALL features
// Note: GF scan runs, but modules that depend on GF (dalfox, sqlmap) are excluded
// Sends real-time webhook updates and files after each phase
func RunDomain(opts ScanOptions) (*Result, error) {
	domain := opts.Domain
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	// Load .env file to ensure webhook URL is available
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	}

	// Initialize logger if not already initialized
	if utils.Log == nil {
		logConfig := utils.DefaultLogConfig()
		logConfig.Level = os.Getenv("LOG_LEVEL")
		if logConfig.Level == "" {
			logConfig.Level = "info"
		}
		if err := utils.InitLogger(logConfig); err != nil {
			log.Printf("[WARN] Failed to initialize logger: %v", err)
		} else {
			utils.Log.WithField("domain", domain).Info("Logger initialized for domain workflow")
		}
	}

	// Initialize metrics
	metrics := utils.InitMetrics()
	metrics.IncrementActiveScans()
	defer metrics.DecrementActiveScans()

	// Check if shutting down
	shutdownMgr := utils.GetShutdownManager()
	if shutdownMgr.IsShuttingDown() {
		utils.Log.Warn("Shutdown in progress, domain scan cancelled")
		return nil, fmt.Errorf("shutdown in progress")
	}
	shutdownMgr.IncrementActiveScans()
	defer shutdownMgr.DecrementActiveScans()

	utils.Log.WithField("domain", domain).Info("Starting full domain scan (all features)")

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	
	// Ensure domain directory exists
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		log.Printf("[WARN] Failed to create domain directory %s: %v", domainDir, err)
	}
	
	liveHostsFile := filepath.Join(domainDir, "subs", "live-subs.txt")

	// Initialize uploaded files tracking
	uploadedFiles := &DomainScanUploads{
		Domain: domain,
		Files:  []UploadedFileInfo{},
	}

	totalSteps := 19 
	var currentStep int32
	
	// Helper to get next step safely
	getNextStep := func() int {
		return int(atomic.AddInt32(&currentStep, 1))
	}

	// Phase 1: Reconnaissance (Sequential - Foundation for everything else)
	// Subdomains runs first to generate the list for everyone else
	if err := runDomainPhase("subdomains", getNextStep(), totalSteps, "Subdomain enumeration", domain, 0, uploadedFiles, func() error {
		subs, err := subdomains.EnumerateSubdomains(domain, 200)
		if err != nil {
			return err
		}
		// Write subdomains to file (modules expect this file to exist)
		subsDir := filepath.Join(domainDir, "subs")
		if err := os.MkdirAll(subsDir, 0755); err != nil {
			return fmt.Errorf("failed to create subs dir: %w", err)
		}
		allSubsFile := filepath.Join(subsDir, "all-subs.txt")
		if err := utils.WriteLines(allSubsFile, subs); err != nil {
			return fmt.Errorf("failed to write subdomains file: %w", err)
		}
		log.Printf("[OK] Wrote %d subdomains to %s", len(subs), allSubsFile)
		return nil
	}); err != nil {
		log.Printf("[WARN] Subdomain enumeration failed: %v", err)
	}

	// Phase 2: Host Discovery (Parallel)
	// LiveHosts and CNAMEs use the subdomain list but are independent of each other
	// We wait for LiveHosts to finish because Phase 3 modules depend on live-subs.txt
	var wgPhase2 sync.WaitGroup

	wgPhase2.Add(1)
	go func() {
		defer wgPhase2.Done()
		if err := runDomainPhase("cnames", getNextStep(), totalSteps, "CNAME collection", domain, 0, uploadedFiles, func() error {
			_, err := cnames.CollectCNAMEsWithOptions(cnames.Options{
				Domain:  domain,
				Threads: 200,
				Timeout: 5 * time.Minute,
			})
			return err
		}); err != nil {
			log.Printf("[WARN] CNAME collection failed: %v", err)
		}
	}()

	wgPhase2.Add(1)
	go func() {
		defer wgPhase2.Done()
		if err := runDomainPhase("livehosts", getNextStep(), totalSteps, "Live host filtering", domain, 0, uploadedFiles, func() error {
			_, err := livehosts.FilterLiveHosts(domain, 200, true)
			return err
		}); err != nil {
			log.Printf("[WARN] Live host filtering failed: %v", err)
		}
	}()

	wgPhase2.Wait()

	// Phase 3: Vulnerability Discovery & Scanners (Parallel)
	// These modules mostly read live-subs.txt (which is now ready) or are completely independent.
	// URLs is collected here for Phase 4.
	var wgPhase3 sync.WaitGroup

	// Group 3a: Standard Scanners
	phases3 := []struct {
		key, desc string
		fn        func() error
		timeout   int
	}{
		{"tech", "Technology detection", func() error { _, err := tech.DetectTech(domain, 200); return err }, 0},
		{"ports", "Port scanning", func() error { _, err := ports.ScanPorts(domain, 200); return err }, 0},
		{"urls", "URL collection", func() error { _, err := urls.CollectURLs(domain, 200, false); return err }, 0},
		{"jsscan", "JavaScript scan", func() error { _, err := jsscan.Run(jsscan.Options{Domain: domain, Threads: 200}); return err }, 0},
		{"dns", "DNS takeover scan", func() error { return dns.Takeover(domain) }, 0},
		{"aem", "AEM webapp discovery and scan", func() error {
			liveHostsFileToUse := ""
			if _, err := os.Stat(liveHostsFile); err == nil {
				liveHostsFileToUse = liveHostsFile
			}
			_, err := aemmod.Run(aemmod.Options{Domain: domain, LiveHostsFile: liveHostsFileToUse, Threads: 50}); return err
		}, 0},
		{"wp_confusion", "WordPress confusion scan", func() error {
			url := fmt.Sprintf("https://%s", domain)
			return wpconfusion.ScanWPConfusion(wpconfusion.ScanOptions{URL: url, Plugins: true, Theme: true, Output: filepath.Join(domainDir, "wp-confusion", "wp-confusion-results.txt")})
		}, 0},
		{"depconfusion", "Dependency confusion scan", func() error {
			if _, err := os.Stat(liveHostsFile); err == nil {
				return depconfusion.Run(depconfusion.Options{Mode: "web", Domain: domain, TargetFile: liveHostsFile, Workers: 10, Verbose: false})
			}
			tempFile := filepath.Join(filepath.Dir(liveHostsFile), "temp-depconfusion-targets.txt")
			if err := os.WriteFile(tempFile, []byte(fmt.Sprintf("https://%s\n", domain)), 0644); err != nil { return err }
			defer os.Remove(tempFile)
			return depconfusion.Run(depconfusion.Options{Mode: "web", Domain: domain, TargetFile: tempFile, Workers: 10, Verbose: false})
		}, 0},
		{"s3", "S3 bucket enumeration and scanning", func() error {
			if err := s3.Run(s3.Options{Action: "enum", Root: domain}); err != nil { return err }
			bucketsFile := filepath.Join(domainDir, "s3", "buckets.txt")
			if info, err := os.Stat(bucketsFile); err == nil && info.Size() > 0 {
				data, _ := os.ReadFile(bucketsFile)
				bucketNames := strings.Split(strings.TrimSpace(string(data)), "\n")
				for _, bn := range bucketNames {
					if bn = strings.TrimSpace(bn); bn != "" { s3.Run(s3.Options{Action: "scan", Bucket: bn}) }
				}
			}
			return nil
		}, 0},
		{"zerodays", "Zerodays scan", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()
			runner := utils.NewCommandRunner(0) // Timeout handled by context
			return runner.RunSilent(ctx, os.Args[0], "zerodays", "scan", "-d", domain, "-t", "100", "--silent")
		}, 0},
		{"backup", "Backup file discovery", func() error {
			if _, err := os.Stat(liveHostsFile); err == nil {
				_, err := backup.Run(backup.Options{Domain: domain, LiveHostsFile: liveHostsFile, Threads: 200, Method: "all"})
				return err
			}
			_, err := backup.Run(backup.Options{Domain: domain, Threads: 200, Method: "all"})
			return err
		}, 0},
	}
	
	// Misconfig timeout handling
	misconfigTimeout := 1800
	if val := os.Getenv("AUTOAR_TIMEOUT_MISCONFIG"); val != "" {
		if t, err := strconv.Atoi(val); err == nil { misconfigTimeout = t }
	}
	phases3 = append(phases3, struct{key, desc string; fn func() error; timeout int}{
		"misconfig", "Cloud misconfiguration scan", func() error {
			liveHostsFileToUse := ""
			if _, err := os.Stat(liveHostsFile); err == nil { liveHostsFileToUse = liveHostsFile }
			err := misconfig.Run(misconfig.Options{Target: domain, Action: "scan", Threads: 200, Timeout: 1800, LiveHostsFile: liveHostsFileToUse})
			if err != nil && strings.Contains(err.Error(), "no live subdomains found") { return nil }
			return err
		}, misconfigTimeout,
	})

	for _, p := range phases3 {
		wgPhase3.Add(1)
		go func(phase struct{key, desc string; fn func() error; timeout int}) {
			defer wgPhase3.Done()
			stepNum := getNextStep()
			if err := runDomainPhase(phase.key, stepNum, totalSteps, phase.desc, domain, phase.timeout, uploadedFiles, phase.fn); err != nil {
				log.Printf("[WARN] %s failed: %v", phase.desc, err)
			}
		}(p)
	}

	wgPhase3.Wait()

	// Phase 4: URL-Dependent & Heavy Scanners (Parallel)
	// GF and Reflection depend on URLs collected in Phase 3.
	// Nuclei and FFUF are heavy, so running them alone or parallel is a trade-off. 
	// We run them parallel here as they are the final stage.
	var wgPhase4 sync.WaitGroup

	wgPhase4.Add(1)
	go func() {
		defer wgPhase4.Done()
		if err := runDomainPhase("reflection", getNextStep(), totalSteps, "[Stage 3] Reflection scan", domain, 0, uploadedFiles, func() error {
			_, err := reflection.ScanReflection(domain)
			return err
		}); err != nil {
			log.Printf("[WARN] Reflection scan failed: %v", err)
		}
	}()

	wgPhase4.Add(1)
	go func() {
		defer wgPhase4.Done()
		if err := runDomainPhase("gf", getNextStep(), totalSteps, "[Stage 3] GF pattern matching", domain, 0, uploadedFiles, func() error {
			// Output of URLs is expected from Phase 3
			_, err := gf.ScanGFWithOptions(gf.Options{Domain: domain, SkipCheck: true})
			return err
		}); err != nil {
			log.Printf("[WARN] GF scan failed: %v", err)
		}
	}()

	if !opts.SkipFFuf {
		wgPhase4.Add(1)
		go func() {
			defer wgPhase4.Done()
			if err := runDomainPhase("ffuf", getNextStep(), totalSteps, "[Stage 3] FFuf fuzzing", domain, 0, uploadedFiles, func() error {
				_, err := ffuf.RunFFuf(ffuf.Options{Domain: domain, Threads: 40, Bypass403: true})
				return err
			}); err != nil {
				log.Printf("[WARN] FFuf fuzzing failed: %v", err)
			}
		}()
	} else {
		log.Printf("[INFO] Skipping FFuf fuzzing (requested)")
	}

	wgPhase4.Add(1)
	go func() {
		defer wgPhase4.Done()
		if err := runDomainPhase("nuclei", getNextStep(), totalSteps, "[Stage 3] Nuclei vulnerability scan (final)", domain, 0, uploadedFiles, func() error {
			_, err := nuclei.RunNuclei(nuclei.Options{Domain: domain, Mode: nuclei.ModeFull, Threads: 500})
			return err
		}); err != nil {
			log.Printf("[WARN] Nuclei scan failed: %v", err)
		}
	}()

	wgPhase4.Wait()

	log.Printf("[OK] Full domain scan completed for %s", domain)
	
	// Convert to absolute path to avoid issues
	if absPath, err := filepath.Abs(domainDir); err == nil {
		domainDir = absPath
	}
	
	// Ensure domain directory exists (in case it was never created or was deleted)
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		log.Printf("[WARN] Failed to ensure domain directory exists: %s: %v", domainDir, err)
	}
	
	// Verify directory exists before attempting zip
	if dirInfo, err := os.Stat(domainDir); err != nil {
		log.Printf("[WARN] Domain directory does not exist: %s (resultsDir: %s)", domainDir, resultsDir)
		// List what's in resultsDir for debugging
		if entries, err := os.ReadDir(resultsDir); err == nil {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			log.Printf("[DEBUG] Contents of resultsDir: %v", names)
		}
	} else {
		log.Printf("[INFO] Domain directory exists: %s (isDir: %v)", domainDir, dirInfo.IsDir())
		// Count files in directory for debugging
		fileCount := 0
		var fileList []string
		filepath.Walk(domainDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileCount++
				relPath, _ := filepath.Rel(domainDir, path)
				fileList = append(fileList, relPath)
			}
			return nil
		})
		log.Printf("[DEBUG] Domain directory contains %d files", fileCount)
		if fileCount > 0 {
			maxFiles := 10
			if len(fileList) < maxFiles {
				maxFiles = len(fileList)
			}
			log.Printf("[DEBUG] Sample files in domain directory (showing %d of %d): %v", maxFiles, len(fileList), fileList[:maxFiles])
		} else {
			log.Printf("[WARN] Domain directory is EMPTY! Listing subdirectories...")
			if entries, err := os.ReadDir(domainDir); err == nil {
				for _, e := range entries {
					log.Printf("[DEBUG] Found entry: %s (isDir: %v)", e.Name(), e.IsDir())
					// If it's a directory, list its contents
					if e.IsDir() {
						subDir := filepath.Join(domainDir, e.Name())
						if subEntries, err := os.ReadDir(subDir); err == nil {
							log.Printf("[DEBUG]   Contents of %s/: %d entries", e.Name(), len(subEntries))
							for i, subE := range subEntries {
								if i < 5 { // Show first 5 entries
									log.Printf("[DEBUG]     - %s (isDir: %v)", subE.Name(), subE.IsDir())
								}
							}
						}
					}
				}
			}
		}
	}
	
	// Wait a moment to ensure all file writes are flushed to disk
	// This is important because some modules might still be writing files asynchronously
	log.Printf("[DEBUG] Ensuring file writes complete...")
	// WaitGroup usage guarantees completion, small buffer for OS flush
	time.Sleep(100 * time.Millisecond)
	
	// Re-check file count after waiting
	if dirInfo, err := os.Stat(domainDir); err == nil && dirInfo.IsDir() {
		fileCount := 0
		filepath.Walk(domainDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileCount++
			}
			return nil
		})
		log.Printf("[DEBUG] After wait: Domain directory now contains %d files", fileCount)
	}
	
	// R2 upload removed - files are sent directly to Discord threads in real-time
	
	// Cleanup: Remove domain directory after workflow completion (except apkx and db backup)
	// Skip cleanup if R2 is enabled - files are already uploaded, no need to keep local copies
	// Only cleanup if explicitly requested AND R2 is not enabled
	shouldCleanup := (os.Getenv("AUTOAR_ENV") == "docker" || os.Getenv("AUTOAR_CLEANUP_RESULTS") == "true") && !r2storage.IsEnabled()
	if shouldCleanup {
		// Check if directory exists
		if info, err := os.Stat(domainDir); err == nil && info.IsDir() {
			// Preserve apkx directory
			apkxDir := filepath.Join(domainDir, "apkx")
			
			// Remove all subdirectories except apkx
			err := filepath.Walk(domainDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				
				// Skip the domain directory itself
				if path == domainDir {
					return nil
				}
				
				// Preserve apkx directory
				if strings.HasPrefix(path, apkxDir) {
					return filepath.SkipDir
				}
				
				// Remove everything else
				if info.IsDir() {
					return os.RemoveAll(path)
				}
				return os.Remove(path)
			})
			
			if err != nil {
				log.Printf("[WARN] Failed to cleanup domain directory %s: %v", domainDir, err)
			} else {
				log.Printf("[OK] Cleaned up domain directory: %s (preserved apkx)", domainDir)
			}
		}
	}
	
	utils.Log.WithField("domain", domain).Info("Full domain scan completed successfully")
	
	// Track successful completion
	metrics.IncrementCompletedScans()
	
	// Cleanup: Remove local files after all phases complete and files are sent
	utils.Log.WithField("domain", domain).Info("Cleaning up domain directory")
	// Wait a moment to ensure all file operations complete
	time.Sleep(100 * time.Millisecond)
	
	// Remove domain directory contents (preserving apkx directory if exists)
	if err := filepath.Walk(domainDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip root directory
		if path == domainDir {
			return nil
		}
		// Preserve apkx directory and its contents
		if strings.Contains(path, "/apkx/") || strings.HasSuffix(path, "/apkx") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		// Remove everything else
		if info.IsDir() {
			return os.RemoveAll(path)
		}
		return os.Remove(path)
	}); err != nil {
		log.Printf("[WARN] Failed to cleanup domain directory %s: %v", domainDir, err)
	} else {
		log.Printf("[OK] Cleaned up domain directory: %s", domainDir)
	}
	
	return &Result{Domain: domain}, nil
}


// runDomainPhase runs a single phase with webhook updates and file sending
func runDomainPhase(phaseKey string, step, total int, description, domain string, timeoutSeconds int, uploadedFiles *DomainScanUploads, fn func() error) error {
	log.Printf("[INFO] Step %d/%d: %s", step, total, description)

	// Update database with current phase progress
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	if scanID != "" {
		phaseStartTime := time.Now()
		progress := &db.ScanProgress{
			CurrentPhase:   step,
			TotalPhases:    total,
			PhaseName:      description,
			PhaseStartTime: phaseStartTime,
		}
		if err := db.UpdateScanProgress(scanID, progress); err != nil {
			log.Printf("[WARN] Failed to update scan progress in database: %v", err)
		} else {
			log.Printf("[DEBUG] Updated scan progress: Phase %d/%d - %s", step, total, description)
		}
	}

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
		// Send error message to webhook (but avoid sending files in bot context)
		utils.SendWebhookLogAsync(fmt.Sprintf("[ERROR] %s failed: %v", description, err))
		if phaseKey != "" && os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
			// Only send phase files when not running under Discord bot
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
	
	// Upload phase files to R2 if enabled (always, regardless of bot context)
	// This ensures files are uploaded to R2 for tracking and bot response
	if phaseKey != "" {
		log.Printf("[DEBUG] [DOMAIN] Preparing to upload files for phase: %s", phaseKey)
		
		// Get expected file paths for this phase
		phaseFiles := utils.GetPhaseFiles(phaseKey, domain)
		log.Printf("[DEBUG] [DOMAIN] Expected %d file(s) for phase %s", len(phaseFiles), phaseKey)
		
		if len(phaseFiles) > 0 {
			// Retry logic to find files
			maxRetries := 5
			retryDelay := 500 * time.Millisecond
			var existingFiles []string
			
			for attempt := 1; attempt <= maxRetries; attempt++ {
				existingFiles = []string{}
				for _, filePath := range phaseFiles {
					if _, err := os.Stat(filePath); err == nil {
						// Send ALL files, even if empty (size = 0)
						// This ensures users can see that a phase ran, even if it found nothing
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
				log.Printf("[DEBUG] [DOMAIN] Found %d file(s) for phase %s", len(existingFiles), phaseKey)
				
				// Send files to Discord in real-time
				// When running under bot, utils.SendPhaseFiles will send to thread via HTTP API
				// When running standalone (CLI), it sends via webhook
				log.Printf("[DEBUG] [DOMAIN] Sending %d file(s) for phase %s", len(existingFiles), phaseKey)
				if err := utils.SendPhaseFiles(phaseKey, domain, existingFiles); err != nil {
					log.Printf("[WARN] [DOMAIN] Failed to send files for phase %s: %v", phaseKey, err)
				} else {
					log.Printf("[DEBUG] [DOMAIN] Successfully sent %d file(s) for phase %s", len(existingFiles), phaseKey)
				}
			} else {
				log.Printf("[DEBUG] [DOMAIN] No files found for phase %s after retries", phaseKey)
				// Send "0 findings" message to webhook only when not under bot
				if os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
					utils.SendPhaseFiles(phaseKey, domain, []string{})
				}
			}
		} else {
			log.Printf("[DEBUG] [DOMAIN] No expected files for phase %s", phaseKey)
			// Send "0 findings" message to webhook only when not under bot
			if os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
				utils.SendPhaseFiles(phaseKey, domain, []string{})
			}
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

// mapFilePathsToNames maps file paths to friendly names for Discord display
func mapFilePathsToNames(urls map[string]string) map[string]string {
	linkMap := make(map[string]string)
	
	// Define priority order for files (most important first)
	// Format: path pattern -> friendly name
	priorityFiles := []struct {
		pattern string
		name    string
	}{
		{"subs/all-subs.txt", "all subs"},
		{"subs/live-subs.txt", "live subs"},
		{"ports/ports.txt", "ports"},
		{"urls/all-urls.txt", "all urls"},
		{"aem/aem-scan.txt", "aem"},
		{"misconfig/misconfig-scan-results.txt", "misconfig"},
		{"ffuf/ffuf-results.txt", "ffuf"},
		{"backup/fuzzuli-results.txt", "backup"},
		{"s3/buckets.txt", "s3 buckets"},
		{"zerodays/zerodays-results.json", "zerodays"},
		{"vulnerabilities/nuclei-custom-cves.txt", "nuclei cves"},
		{"vulnerabilities/dns-takeover/dns-takeover-summary.txt", "dns takeover"},
		{"vulnerabilities/dns-takeover/dangling-ip-summary.txt", "dangling ips"},
		{"subs/tech-detect.txt", "tech stack"},
		{"depconfusion/web-file/depconfusion-results.txt", "dep confusion"},
	}
	
	// First pass: match priority files
	matched := make(map[string]bool)
	for _, priority := range priorityFiles {
		for path, url := range urls {
			if strings.Contains(path, priority.pattern) && !matched[path] {
				linkMap[priority.name] = url
				matched[path] = true
				break
			}
		}
	}
	
	// Second pass: add other important files by directory
	dirNames := map[string]string{
		"vulnerabilities/xss/":           "xss",
		"vulnerabilities/sqli/":           "sqli",
		"vulnerabilities/ssrf/":           "ssrf",
		"vulnerabilities/lfi/":            "lfi",
		"vulnerabilities/rce/":            "rce",
		"vulnerabilities/ssti/":           "ssti",
		"vulnerabilities/idor/":          "idor",
		"vulnerabilities/redirect/":      "redirect",
		"vulnerabilities/kxss-results.txt": "kxss",
	}
	
	for dirPattern, name := range dirNames {
		if _, exists := linkMap[name]; !exists {
			for path, url := range urls {
				if strings.Contains(path, dirPattern) && !matched[path] {
					// Get the first file from this directory
					linkMap[name] = url
					matched[path] = true
					break
				}
			}
		}
	}
	
	return linkMap
}

// uploadDomainPhaseFileToR2 uploads a phase file to R2 and records the information
func uploadDomainPhaseFileToR2(phaseKey, domain, filePath string, uploadedFiles *DomainScanUploads) error {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	
	if fileInfo.Size() == 0 {
		return nil // Skip empty files
	}
	
	// Create R2 object key: domain/{domain}/{phase}/{filename}
	fileName := filepath.Base(filePath)
	objectKey := fmt.Sprintf("domain/%s/%s/%s", domain, phaseKey, fileName)
	
	// Upload to R2
	publicURL, err := r2storage.UploadFile(filePath, objectKey, false)
	if err != nil {
		return fmt.Errorf("failed to upload to R2: %w", err)
	}
	
	// Format file size
	sizeHuman := formatDomainFileSize(fileInfo.Size())
	
	// Record uploaded file information
	uploadedFiles.Files = append(uploadedFiles.Files, UploadedFileInfo{
		Phase:     phaseKey,
		FileName:  fileName,
		FilePath:  filePath,
		Size:      fileInfo.Size(),
		SizeHuman: sizeHuman,
		URL:       publicURL,
	})
	
	log.Printf("[R2] [DOMAIN] Uploaded phase file: %s (%s) -> %s", fileName, sizeHuman, publicURL)
	return nil
}

// formatDomainFileSize formats file size in human-readable format
func formatDomainFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// saveDomainUploadedFilesInfo saves uploaded files information to a JSON file
func saveDomainUploadedFilesInfo(domain string, uploadedFiles *DomainScanUploads) error {
	resultsDir := utils.GetResultsDir()
	
	// Get scan ID from environment if available
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	if scanID == "" {
		// Generate a simple ID based on timestamp
		scanID = fmt.Sprintf("domain_%d", time.Now().Unix())
	}
	
	// Save to file: .domain-uploads-{scanID}.json
	uploadInfoFile := filepath.Join(resultsDir, fmt.Sprintf(".domain-uploads-%s.json", scanID))
	
	// Marshal to JSON
	jsonData, err := json.MarshalIndent(uploadedFiles, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(uploadInfoFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	log.Printf("[DOMAIN] Saved uploaded files info to: %s (%d files)", uploadInfoFile, len(uploadedFiles.Files))
	
	// Also print to stdout for bot to parse (backup method)
	fmt.Fprintf(os.Stdout, "[DOMAIN-UPLOADS] %s\n", string(jsonData))
	os.Stdout.Sync()
	
	return nil
}
