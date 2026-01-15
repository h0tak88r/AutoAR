package subdomain

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

	aemmod "github.com/h0tak88r/AutoAR/v3/internal/modules/aem"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/backup"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/depconfusion"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/envloader"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/ffuf"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/jsscan"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/misconfig"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/reflection"
	s3mod "github.com/h0tak88r/AutoAR/v3/internal/modules/s3"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
	wpconfusion "github.com/h0tak88r/AutoAR/v3/internal/modules/wp-confusion"
	"github.com/projectdiscovery/httpx/runner"
)

// Result holds subdomain scan results
type Result struct {
	Subdomain string
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

// SubdomainScanUploads holds all uploaded files information
type SubdomainScanUploads struct {
	Subdomain string             `json:"subdomain"`
	Files     []UploadedFileInfo `json:"files"`
}

// RunSubdomain runs the full subdomain scan workflow with ALL features on a single subdomain
// First checks if the subdomain is live, then runs all follow-up phases
func RunSubdomain(subdomain string) (*Result, error) {
	if subdomain == "" {
		return nil, fmt.Errorf("subdomain is required")
	}

	// Load .env file
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
			utils.Log.WithField("subdomain", subdomain).Info("Logger initialized for subdomain workflow")
		}
	}

	// Initialize metrics
	metrics := utils.InitMetrics()
	metrics.IncrementActiveScans()
	defer metrics.DecrementActiveScans()

	// Check if shutting down
	shutdownMgr := utils.GetShutdownManager()
	if shutdownMgr.IsShuttingDown() {
		utils.Log.Warn("Shutdown in progress, subdomain scan cancelled")
		return nil, fmt.Errorf("shutdown in progress")
	}
	shutdownMgr.IncrementActiveScans()
	defer shutdownMgr.DecrementActiveScans()

	utils.Log.WithField("subdomain", subdomain).Info("Starting full subdomain scan")

	// Use subdomain itself for directory structure (not root domain)
	// Remove protocol if present
	subdomainClean := strings.TrimPrefix(strings.TrimPrefix(subdomain, "http://"), "https://")
	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, subdomainClean)
	subsDir := filepath.Join(domainDir, "subs")
	if err := os.MkdirAll(subsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create subs directory: %v", err)
	}

	liveHostsFile := filepath.Join(subsDir, "live-subs.txt")
	
	// Extract root domain for modules that need it (e.g., DNS, S3)
	rootDomain := extractDomain(subdomainClean)

	// Initialize uploaded files tracking
	uploadedFiles := &SubdomainScanUploads{
		Subdomain: subdomainClean,
		Files:     []UploadedFileInfo{},
	}

	totalSteps := 19 
	var currentStep int32
	
	// Helper to get next step safely
	getNextStep := func() int {
		return int(atomic.AddInt32(&currentStep, 1))
	}

	// Phase 1: Live Check (Sequential - Critical Path)
	if err := runSubdomainPhase("livehosts", getNextStep(), totalSteps, "Live host check", subdomain, 0, uploadedFiles, func() error {
		return checkAndSaveLiveSubdomain(subdomain, liveHostsFile)
	}); err != nil {
		log.Printf("[ERROR] Live host check failed: %v", err)
		return nil, fmt.Errorf("subdomain %s is not live or check failed: %v", subdomain, err)
	}

	// Phase 2: Discovery Group (Parallel, requires LiveHosts)
	// These modules are mostly independent or read the live-subs.txt file just created.
	var wgPhase2 sync.WaitGroup

	// Helper for parallel phase execution
	runParallelPhase := func(wg *sync.WaitGroup, key, desc string, timeout int, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := runSubdomainPhase(key, getNextStep(), totalSteps, desc, subdomain, timeout, uploadedFiles, fn); err != nil {
				log.Printf("[WARN] %s failed: %v", desc, err)
			}
		}()
	}

	phases2 := []struct {
		key, desc string
		fn        func() error
		timeout   int
	}{
		{"cnames", "[Stage 2] CNAME collection", func() error {
			// Remove protocol if present for CNAME check
			subdomainClean := strings.TrimPrefix(strings.TrimPrefix(subdomain, "http://"), "https://")
			_, err := cnames.CollectCNAMEsWithOptions(cnames.Options{Subdomain: subdomainClean, Threads: 200, Timeout: 5 * time.Minute})
			return err
		}, 0},
		{"tech", "[Stage 2] Technology detection", func() error { _, err := tech.DetectTech(subdomainClean, 200); return err }, 0},
		{"ports", "[Stage 2] Port scan", func() error { _, err := ports.ScanPorts(subdomainClean, 200); return err }, 0},
		{"urls", "[Stage 2] URL collection", func() error { _, err := urls.CollectURLs(subdomainClean, 200, true); return err }, 0},
		{"jsscan", "[Stage 2] JS scan", func() error { _, err := jsscan.Run(jsscan.Options{Domain: subdomainClean, Subdomain: subdomainClean, Threads: 200}); return err }, 0},
		{"aem", "[Stage 2] AEM scan", func() error { _, err := aemmod.Run(aemmod.Options{Domain: subdomainClean, LiveHostsFile: liveHostsFile, Threads: 50}); return err }, 0},
		{"dns", "[Stage 2] DNS scan", func() error { return dns.TakeoverWithOptions(dns.TakeoverOptions{Domain: rootDomain, Subdomain: subdomainClean}) }, 0},
		{"s3", "[Stage 2] S3 bucket enumeration and scanning", func() error {
			// S3 enumeration on the root domain (S3 works on domain level) but save results under subdomain directory
			if err := s3mod.Run(s3mod.Options{Action: "enum", Root: rootDomain, Subdomain: subdomainClean, Threads: 100}); err != nil { return err }
			// After enumeration, scan found buckets for permissions
			bucketsFile := filepath.Join(domainDir, "s3", "buckets.txt")
			if info, err := os.Stat(bucketsFile); err == nil && info.Size() > 0 {
				data, _ := os.ReadFile(bucketsFile)
				bucketNames := strings.Split(strings.TrimSpace(string(data)), "\n")
				for _, bn := range bucketNames {
					if bn = strings.TrimSpace(bn); bn != "" { s3mod.Run(s3mod.Options{Action: "scan", Bucket: bn, Subdomain: subdomainClean}) }
				}
			}
			return nil
		}, 0},
		{"backup", "[Stage 2] Backup scan", func() error { _, err := backup.Run(backup.Options{Domain: subdomainClean, LiveHostsFile: liveHostsFile, Method: "all", Threads: 200}); return err }, 0},
		{"zerodays", "[Stage 2] Zerodays scan", func() error {
			runner := utils.NewCommandRunner(0)
			return runner.RunSilent(context.Background(), os.Args[0], "zerodays", "scan", "-s", subdomainClean, "-t", "100", "--silent")
		}, 0},
		{"wp_confusion", "[Stage 2] WordPress confusion", func() error {
			// Check if live hosts file exists with retry logic is not needed if we trust Phase 1 succeeded, 
			// but keeping robust check for safety inside the anonymous func
			data, err := os.ReadFile(liveHostsFile)
			if err != nil || len(data) == 0 { return fmt.Errorf("live hosts file empty or check failed") }
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) > 0 && lines[0] != "" {
				return wpconfusion.ScanWPConfusion(wpconfusion.ScanOptions{URL: strings.TrimSpace(lines[0]), Plugins: true, Theme: false})
			}
			return nil
		}, 0},
		{"depconfusion", "[Stage 2] Dependency confusion", func() error {
			if _, err := os.Stat(liveHostsFile); err != nil { return fmt.Errorf("live hosts file not found") }
			return depconfusion.Run(depconfusion.Options{Mode: "web", TargetFile: liveHostsFile, Workers: 10, Subdomain: subdomainClean})
		}, 0},
	}

	// Misconfig timeout
	misconfigTimeout := 1800
	if val := os.Getenv("AUTOAR_TIMEOUT_MISCONFIG"); val != "" {
		if t, err := strconv.Atoi(val); err == nil { misconfigTimeout = t }
	}
	phases2 = append(phases2, struct{key, desc string; fn func() error; timeout int}{
		"misconfig", "[Stage 2] Misconfig scan", func() error {
			err := misconfig.Run(misconfig.Options{Target: subdomainClean, Action: "scan", Threads: 200, LiveHostsFile: liveHostsFile})
			if err != nil && strings.Contains(err.Error(), "no live subdomains found") { return nil }
			return err
		}, misconfigTimeout,
	})

	for _, p := range phases2 {
		runParallelPhase(&wgPhase2, p.key, p.desc, p.timeout, p.fn)
	}

	wgPhase2.Wait()

	// Phase 3: Deep Scan Group (Parallel, requires Stage 2 - specifically URLs)
	var wgPhase3 sync.WaitGroup

	runParallelPhase(&wgPhase3, "gf", "[Stage 3] GF scan", 0, func() error {
		urlsFile := filepath.Join(domainDir, "urls", "all-urls.txt")
		_, err := gf.ScanGFWithOptions(gf.Options{Domain: subdomainClean, URLsFile: urlsFile, SkipCheck: true})
		return err
	})

	runParallelPhase(&wgPhase3, "reflection", "[Stage 3] Reflection scan", 0, func() error {
		_, err := reflection.ScanReflectionWithOptions(reflection.Options{Domain: subdomainClean, Subdomain: subdomainClean, Threads: 50, Timeout: 15 * time.Minute, URLThreads: 200})
		return err
	})

	runParallelPhase(&wgPhase3, "ffuf", "[Stage 3] FFuf fuzzing", 0, func() error {
		data, err := os.ReadFile(liveHostsFile)
		if err != nil { return err }
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			url := strings.TrimSpace(lines[0])
			if !strings.Contains(url, "FUZZ") {
				if !strings.HasSuffix(url, "/") { url += "/" }
				url += "FUZZ"
			}
			_, err := ffuf.RunFFuf(ffuf.Options{Target: url, Wordlist: "", Threads: 40, FollowRedirects: true})
			return err
		}
		return fmt.Errorf("no live URL found")
	})

	runParallelPhase(&wgPhase3, "nuclei", "[Stage 3] Nuclei scan (final)", 0, func() error {
		data, err := os.ReadFile(liveHostsFile)
		if err != nil { return err }
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			_, err := nuclei.RunNuclei(nuclei.Options{URL: strings.TrimSpace(lines[0]), Threads: 200, Mode: nuclei.ModeFull})
			return err
		}
		return fmt.Errorf("no live URL found")
	})

	wgPhase3.Wait()

	log.Printf("[OK] Full subdomain scan completed for %s", subdomain)
	
	// Get subdomain directory path (resultsDir already declared earlier)
	subdomainDir := filepath.Join(resultsDir, subdomainClean)
	
	// Convert to absolute path to avoid issues
	if absPath, err := filepath.Abs(subdomainDir); err == nil {
		subdomainDir = absPath
	}
	
	// Ensure subdomain directory exists (in case it was never created or was deleted)
	if err := os.MkdirAll(subdomainDir, 0755); err != nil {
		log.Printf("[WARN] Failed to ensure subdomain directory exists: %s: %v", subdomainDir, err)
	}
	
	// Verify directory exists before attempting zip
	if dirInfo, err := os.Stat(subdomainDir); err != nil {
		log.Printf("[WARN] Subdomain directory does not exist: %s (resultsDir: %s)", subdomainDir, resultsDir)
		// List what's in resultsDir for debugging
		if entries, err := os.ReadDir(resultsDir); err == nil {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			log.Printf("[DEBUG] Contents of resultsDir: %v", names)
		}
	} else {
		log.Printf("[INFO] Subdomain directory exists: %s (isDir: %v)", subdomainDir, dirInfo.IsDir())
		// Count files in directory for debugging
		fileCount := 0
		filepath.Walk(subdomainDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileCount++
			}
			return nil
		})
		log.Printf("[DEBUG] Subdomain directory contains %d files", fileCount)
	}
	
	// R2 upload removed - files are sent directly to Discord threads in real-time
	
	// Cleanup: Remove subdomain directory after workflow completion (except apkx and db backup)
	// Skip cleanup if R2 is enabled - files are already uploaded, no need to keep local copies
	// Only cleanup if explicitly requested AND R2 is not enabled
	shouldCleanup := (os.Getenv("AUTOAR_ENV") == "docker" || os.Getenv("AUTOAR_CLEANUP_RESULTS") == "true") && !r2storage.IsEnabled()
	if shouldCleanup {
		// Check if directory exists
		if info, err := os.Stat(subdomainDir); err == nil && info.IsDir() {
			// Preserve apkx directory if it exists
			apkxDir := filepath.Join(subdomainDir, "apkx")
			
			// Remove all subdirectories except apkx
			err := filepath.Walk(subdomainDir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				
				// Skip the subdomain directory itself
				if path == subdomainDir {
					return nil
				}
				
				// Preserve apkx directory
				if strings.HasPrefix(path, apkxDir) {
					return filepath.SkipDir
				}
				
				return os.Remove(path)
			})
			
			if err != nil {
				log.Printf("[WARN] Failed to cleanup subdomain directory %s: %v", subdomainDir, err)
			} else {
				log.Printf("[OK] Cleaned up subdomain directory: %s", subdomainDir)
			}
		}
	}
	
	utils.Log.WithField("subdomain", subdomain).Info("Full subdomain scan completed successfully")
	
	// Track successful completion
	metrics.IncrementCompletedScans()
	
	// Cleanup: Remove local files after all phases complete and files are sent
	utils.Log.WithField("subdomain", subdomain).Info("Cleaning up subdomain directory")
	// Wait a moment to ensure all file operations complete
	time.Sleep(2 * time.Second)
	
	// Remove subdomain directory contents (preserving apkx directory if exists)
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
		log.Printf("[WARN] Failed to cleanup subdomain directory %s: %v", domainDir, err)
	} else {
		log.Printf("[OK] Cleaned up subdomain directory: %s", domainDir)
	}
	
	return &Result{Subdomain: subdomain}, nil
}

// checkAndSaveLiveSubdomain checks if a single subdomain is live and saves it to file
func checkAndSaveLiveSubdomain(subdomain, liveHostsFile string) error {
	// Normalize subdomain (ensure it has protocol)
	targets := []string{subdomain}
	if !strings.HasPrefix(subdomain, "http://") && !strings.HasPrefix(subdomain, "https://") {
		targets = []string{"https://" + subdomain, "http://" + subdomain}
	}

	log.Printf("[INFO] Checking if subdomain is live: %s", subdomain)

	var liveHosts []string
	var mu sync.Mutex

	// Configure httpx options
	options := runner.Options{
		InputTargetHost: targets,
		Threads:        200,
		Methods:        "GET",
		FollowRedirects: true,
		HTTPProxy:      os.Getenv("HTTP_PROXY"),
	}

	// Use a map to track unique URLs and avoid duplicates
	liveHostsMap := make(map[string]bool)
	
	// Callback to collect live hosts
	options.OnResult = func(result runner.Result) {
		if result.StatusCode > 0 {
			mu.Lock()
			// Only add if not already present (deduplicate)
			if !liveHostsMap[result.URL] {
				liveHostsMap[result.URL] = true
				liveHosts = append(liveHosts, result.URL)
			}
			mu.Unlock()
			log.Printf("%s [%d]", result.URL, result.StatusCode)
		}
	}

	// Run httpx
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return fmt.Errorf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	httpxRunner.RunEnumeration()

	if len(liveHosts) == 0 {
		return fmt.Errorf("subdomain %s is not live", subdomain)
	}

	// Ensure directory exists before writing
	if err := os.MkdirAll(filepath.Dir(liveHostsFile), 0755); err != nil {
		return fmt.Errorf("failed to create directory for live hosts file: %v", err)
	}
	
	// Write live hosts to file (already deduplicated)
	if err := utils.WriteLines(liveHostsFile, liveHosts); err != nil {
		return fmt.Errorf("failed to write live hosts file: %v", err)
	}
	
	// Verify file was created
	if info, err := os.Stat(liveHostsFile); err != nil {
		return fmt.Errorf("live hosts file was not created: %s: %v", liveHostsFile, err)
	} else {
		log.Printf("[DEBUG] Live hosts file created: %s (size: %d bytes)", liveHostsFile, info.Size())
	}

	log.Printf("[OK] Found %d live URL(s) for %s", len(liveHosts), subdomain)
	return nil
}

// extractDomain extracts the root domain from a subdomain
func extractDomain(subdomain string) string {
	// Remove protocol if present
	subdomain = strings.TrimPrefix(subdomain, "http://")
	subdomain = strings.TrimPrefix(subdomain, "https://")
	
	parts := strings.Split(subdomain, ".")
	if len(parts) >= 2 {
		// Return last two parts (e.g., example.com)
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return subdomain
}

// runSubdomainPhase runs a single phase with webhook updates and file sending
func runSubdomainPhase(phaseKey string, step, total int, description, subdomain string, timeoutSeconds int, uploadedFiles *SubdomainScanUploads, fn func() error) error {
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

	// Use subdomain for directory structure (not root domain)
	subdomainClean := strings.TrimPrefix(strings.TrimPrefix(subdomain, "http://"), "https://")
	
	if err != nil {
		log.Printf("[ERROR] Step %d/%d: %s failed: %v (duration: %s)", step, total, description, err, phaseDuration)
		// Send error message to webhook (but avoid sending files in bot context)
		utils.SendWebhookLogAsync(fmt.Sprintf("[ERROR] %s failed: %v", description, err))
		if phaseKey != "" && os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
			// Only send phase files when not running under Discord bot
			phaseFiles := utils.GetPhaseFiles(phaseKey, subdomainClean)
			if len(phaseFiles) > 0 {
				var existingFiles []string
				for _, filePath := range phaseFiles {
					if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
						existingFiles = append(existingFiles, filePath)
					}
				}
				if len(existingFiles) > 0 {
					utils.SendPhaseFiles(phaseKey, subdomainClean, existingFiles)
				}
			}
		}
		return err
	}

	log.Printf("[OK] %s completed in %s", description, phaseDuration)
	
	// Upload phase files to R2 if enabled (always, regardless of bot context)
	// This ensures files are uploaded to R2 for tracking and bot response
	if phaseKey != "" {
		log.Printf("[DEBUG] [SUBDOMAIN] Preparing to upload files for phase: %s", phaseKey)
		
		// Get expected file paths for this phase
		phaseFiles := utils.GetPhaseFiles(phaseKey, subdomainClean)
		log.Printf("[DEBUG] [SUBDOMAIN] Expected %d file(s) for phase %s", len(phaseFiles), phaseKey)
		
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
			log.Printf("[DEBUG] [SUBDOMAIN] Found %d file(s) for phase %s", len(existingFiles), phaseKey)
			
			// Send files to Discord in real-time
			// When running under bot, utils.SendPhaseFiles will send to thread via HTTP API
			// When running standalone (CLI), it sends via webhook
			log.Printf("[DEBUG] [SUBDOMAIN] Sending %d file(s) for phase %s", len(existingFiles), phaseKey)
			if err := utils.SendPhaseFiles(phaseKey, subdomainClean, existingFiles); err != nil {
				log.Printf("[DEBUG] [SUBDOMAIN] Failed to send files for phase %s: %v", phaseKey, err)
			}
		} else {
			log.Printf("[DEBUG] [SUBDOMAIN] No files found for phase %s after retries", phaseKey)
			// Send "0 findings" message to webhook only when not under bot
			if os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
				utils.SendPhaseFiles(phaseKey, subdomainClean, []string{})
			}
		}	
		} else {
			log.Printf("[DEBUG] [SUBDOMAIN] No expected files for phase %s", phaseKey)
			// Send "0 findings" message to webhook only when not under bot
			if os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
				utils.SendPhaseFiles(phaseKey, subdomainClean, []string{})
			}
		}
	}

	return nil
}

// Helper functions

func runWithTimeout(fn func() error, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("operation timed out after %v", timeout)
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

// uploadSubdomainPhaseFileToR2 uploads a phase file to R2 and records the information
func uploadSubdomainPhaseFileToR2(phaseKey, subdomain, filePath string, uploadedFiles *SubdomainScanUploads) error {
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	
	if fileInfo.Size() == 0 {
		return nil // Skip empty files
	}
	
	// Create R2 object key: subdomain/{subdomain}/{phase}/{filename}
	fileName := filepath.Base(filePath)
	objectKey := fmt.Sprintf("subdomain/%s/%s/%s", subdomain, phaseKey, fileName)
	
	// Upload to R2
	publicURL, err := r2storage.UploadFile(filePath, objectKey, false)
	if err != nil {
		return fmt.Errorf("failed to upload to R2: %w", err)
	}
	
	// Format file size
	sizeHuman := formatSubdomainFileSize(fileInfo.Size())
	
	// Record uploaded file information
	uploadedFiles.Files = append(uploadedFiles.Files, UploadedFileInfo{
		Phase:     phaseKey,
		FileName:  fileName,
		FilePath:  filePath,
		Size:      fileInfo.Size(),
		SizeHuman: sizeHuman,
		URL:       publicURL,
	})
	
	log.Printf("[R2] [SUBDOMAIN] Uploaded phase file: %s (%s) -> %s", fileName, sizeHuman, publicURL)
	return nil
}

// formatSubdomainFileSize formats file size in human-readable format
func formatSubdomainFileSize(size int64) string {
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

// saveSubdomainUploadedFilesInfo saves uploaded files information to a JSON file
func saveSubdomainUploadedFilesInfo(subdomain string, uploadedFiles *SubdomainScanUploads) error {
	resultsDir := utils.GetResultsDir()
	
	// Get scan ID from environment if available
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	if scanID == "" {
		// Generate a simple ID based on timestamp
		scanID = fmt.Sprintf("subdomain_%d", time.Now().Unix())
	}
	
	// Save to file: .subdomain-uploads-{scanID}.json
	uploadInfoFile := filepath.Join(resultsDir, fmt.Sprintf(".subdomain-uploads-%s.json", scanID))
	
	// Marshal to JSON
	jsonData, err := json.MarshalIndent(uploadedFiles, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(uploadInfoFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	log.Printf("[SUBDOMAIN] Saved uploaded files info to: %s (%d files)", uploadInfoFile, len(uploadedFiles.Files))
	
	// Also print to stdout for bot to parse (backup method)
	fmt.Fprintf(os.Stdout, "[SUBDOMAIN-UPLOADS] %s\n", string(jsonData))
	os.Stdout.Sync()
	
	return nil
}

