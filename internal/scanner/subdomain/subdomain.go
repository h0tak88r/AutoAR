package subdomain

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aemmod "github.com/h0tak88r/AutoAR/internal/scanner/aem"
	"github.com/h0tak88r/AutoAR/internal/scanner/backup"
	"github.com/h0tak88r/AutoAR/internal/scanner/cnames"
	"github.com/h0tak88r/AutoAR/internal/scanner/depconfusion"
	"github.com/h0tak88r/AutoAR/internal/scanner/dns"
	"github.com/h0tak88r/AutoAR/internal/envloader"
	"github.com/h0tak88r/AutoAR/internal/scanner/ffuf"
	"github.com/h0tak88r/AutoAR/internal/scanner/gf"
	"github.com/h0tak88r/AutoAR/internal/scanner/jsscan"
	"github.com/h0tak88r/AutoAR/internal/scanner/misconfig"
	"github.com/h0tak88r/AutoAR/internal/scanner/nuclei"
	"github.com/h0tak88r/AutoAR/internal/scanner/ports"
	"github.com/h0tak88r/AutoAR/internal/scanner/reflection"
	s3mod "github.com/h0tak88r/AutoAR/internal/scanner/s3"
	"github.com/h0tak88r/AutoAR/internal/scanner/tech"
	"github.com/h0tak88r/AutoAR/internal/scanner/urls"
	"github.com/h0tak88r/AutoAR/internal/utils"
	wpconfusion "github.com/h0tak88r/AutoAR/internal/scanner/wp-confusion"
	zerodaysmod "github.com/h0tak88r/AutoAR/internal/scanner/zerodays"
	"github.com/projectdiscovery/httpx/runner"
)

// Result holds subdomain scan results
type Result struct {
	Subdomain string
}

type RunOptions struct {
	SkipFFuf bool
}

// RunSubdomain runs the full subdomain scan workflow with ALL features on a single subdomain
// First checks if the subdomain is live, then runs all follow-up phases
func RunSubdomain(subdomain string) (*Result, error) {
	return RunSubdomainWithOptions(subdomain, RunOptions{})
}

// RunSubdomainWithOptions runs the full subdomain workflow with optional toggles.
func RunSubdomainWithOptions(subdomain string, opts RunOptions) (*Result, error) {
	if subdomain == "" {
		return nil, fmt.Errorf("subdomain is required")
	}

	// Load .env file
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	}

	// Initialize logger if not already initialized
	if utils.Log == nil {
		logConfig := utils.LogConfigFromEnv("autoar-bot.log")
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

	totalSteps := 18
	var currentStep int32

	// Helper to get next step safely
	getNextStep := func() int {
		return int(atomic.AddInt32(&currentStep, 1))
	}

	// Phase 1: Live Check (Sequential - Critical Path)
	if err := utils.RunWorkflowPhase("livehosts", getNextStep(), totalSteps, "Live host check", subdomain, 0, func() error {
		return checkAndSaveLiveSubdomain(subdomain, liveHostsFile)
	}); err != nil {
		log.Printf("[ERROR] Live host check failed: %v", err)
		return nil, fmt.Errorf("subdomain %s is not live or check failed: %v", subdomain, err)
	}

	// Phase 2: Discovery Group (Parallel, requires LiveHosts)
	// These modules are mostly independent or read the live-subs.txt file just created.
	var wgPhase2 sync.WaitGroup

	// Capture the scan ID from the parent goroutine *before* spawning children.
	// Each child goroutine registers its own entry in the goroutine-local registry
	// so that RunWorkflowPhase can call db.AppendScanPhase / db.UpdateScanProgress
	// with the correct scan ID. Without this, child goroutines see an empty ID
	// and phase tracking is silently skipped.
	parentScanID := utils.GetCurrentScanID()

	// Helper for parallel phase execution with optional timeout (seconds, 0=none)
	runParallelPhase := func(wg *sync.WaitGroup, key, desc string, timeout int, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Propagate scan ID to this child goroutine.
			if parentScanID != "" {
				utils.SetGoroutineScanID(parentScanID)
				defer utils.ClearGoroutineScanID()
			}
			var wrappedFn func() error
			if timeout > 0 {
				wrappedFn = func() error {
					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
					defer cancel()
					done := make(chan error, 1)
					go func() { done <- fn() }()
					select {
					case err := <-done:
						return err
					case <-ctx.Done():
						log.Printf("[WARN] phase %s timed out after %ds", key, timeout)
						return fmt.Errorf("phase %s timed out", key)
					}
				}
			} else {
				wrappedFn = fn
			}
			if err := utils.RunWorkflowPhase(key, getNextStep(), totalSteps, desc, subdomain, timeout, wrappedFn); err != nil {
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
			_, err := cnames.CollectCNAMEsWithOptions(cnames.Options{Subdomain: subdomainClean, Threads: 150, Timeout: 5 * time.Minute})
			return err
		}, 0},
		{"tech", "[Stage 2] Technology detection", func() error { _, err := tech.DetectTech(subdomainClean, 150); return err }, 0},
		{"ports", "[Stage 2] Port scan", func() error { _, err := ports.ScanPorts(subdomainClean, 150); return err }, 0},
		{"urls", "[Stage 2] URL collection", func() error { _, err := urls.CollectURLs(subdomainClean, 150, true); return err }, 0},
		{"jsscan", "[Stage 2] JS scan", func() error {
			_, err := jsscan.Run(jsscan.Options{Domain: subdomainClean, Subdomain: subdomainClean, Threads: 150})
			return err
		}, 0},
		{"aem", "[Stage 2] AEM scan", func() error {
			_, err := aemmod.Run(aemmod.Options{Domain: subdomainClean, LiveHostsFile: liveHostsFile, Threads: 50})
			return err
		}, 0},
		{"dns", "[Stage 2] DNS scan", func() error {
			return dns.TakeoverWithOptions(dns.TakeoverOptions{Domain: rootDomain, Subdomain: subdomainClean})
		}, 0},
		{"s3", "[Stage 2] S3 bucket enumeration and scanning", func() error {
			// S3 enumeration on the root domain (S3 works on domain level) but save results under subdomain directory
			if err := s3mod.Run(s3mod.Options{Action: "enum", Root: rootDomain, Subdomain: subdomainClean, Threads: 100}); err != nil {
				return err
			}
			// After enumeration, scan found buckets for permissions
			bucketsFile := filepath.Join(domainDir, "s3", "buckets.txt")
			if info, err := os.Stat(bucketsFile); err == nil && info.Size() > 0 {
				data, _ := os.ReadFile(bucketsFile)
				bucketNames := strings.Split(strings.TrimSpace(string(data)), "\n")
				for _, bn := range bucketNames {
					if bn = strings.TrimSpace(bn); bn != "" {
						s3mod.Run(s3mod.Options{Action: "scan", Bucket: bn, Subdomain: subdomainClean})
					}
				}
			}
			return nil
		}, 0},
		{"backup", "[Stage 2] Backup scan", func() error {
			_, err := backup.Run(backup.Options{Domain: subdomainClean, LiveHostsFile: liveHostsFile, Method: "all", Threads: 150})
			return err
		}, backupTimeout()},
		{"zerodays", "[Stage 2] Zerodays scan", func() error {
			// Direct in-process call — no subprocess fork, no separate scan DB record.
			_, err := zerodaysmod.Run(zerodaysmod.Options{
				Subdomain: subdomainClean,
				Threads:   100,
				Silent:    true,
			})
			return err
		}, zerodaysTimeout()}, // configurable via AUTOAR_TIMEOUT_ZERODAYS (default 600s, 0=unlimited)
		{"wp_confusion", "[Stage 2] WordPress confusion", func() error {
			// Check if live hosts file exists with retry logic is not needed if we trust Phase 1 succeeded,
			// but keeping robust check for safety inside the anonymous func
			data, err := os.ReadFile(liveHostsFile)
			if err != nil || len(data) == 0 {
				return fmt.Errorf("live hosts file empty or check failed")
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) > 0 && lines[0] != "" {
				return wpconfusion.ScanWPConfusion(wpconfusion.ScanOptions{URL: strings.TrimSpace(lines[0]), Plugins: true, Theme: false})
			}
			return nil
		}, 0},
		{"depconfusion", "[Stage 2] Dependency confusion", func() error {
			if _, err := os.Stat(liveHostsFile); err != nil {
				return fmt.Errorf("live hosts file not found")
			}
			return depconfusion.Run(depconfusion.Options{Mode: "web", TargetFile: liveHostsFile, Workers: 10, Subdomain: subdomainClean})
		}, 0},
	}

	// Misconfig timeout — configurable from the dashboard Settings page.
	misconfigTimeout := utils.GetTimeout("misconfig", 1800)
	phases2 = append(phases2, struct {
		key, desc string
		fn        func() error
		timeout   int
	}{
		"misconfig", "[Stage 2] Misconfig scan", func() error {
			err := misconfig.Run(misconfig.Options{Target: subdomainClean, Action: "scan", Threads: 150, LiveHostsFile: liveHostsFile})
			if err != nil && strings.Contains(err.Error(), "no live subdomains found") {
				return nil
			}
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

	if !opts.SkipFFuf {
		runParallelPhase(&wgPhase3, "ffuf", "[Stage 3] FFuf fuzzing", 0, func() error {
			data, err := os.ReadFile(liveHostsFile)
			if err != nil {
				return err
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(lines) > 0 && lines[0] != "" {
				url := strings.TrimSpace(lines[0])
				if !strings.Contains(url, "FUZZ") {
					if !strings.HasSuffix(url, "/") {
						url += "/"
					}
					url += "FUZZ"
				}
				_, err := ffuf.RunFFuf(ffuf.Options{Target: url, Wordlist: "", Threads: 40, FollowRedirects: true})
				return err
			}
			return fmt.Errorf("no live URL found")
		})
	} else {
		log.Printf("[INFO] Skipping FFUF stage for subdomain scan: %s", subdomain)
	}

	runParallelPhase(&wgPhase3, "nuclei", "[Stage 3] Nuclei scan (final)", nucleiTimeout(), func() error {
		data, err := os.ReadFile(liveHostsFile)
		if err != nil {
			return err
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) > 0 && lines[0] != "" {
			_, err := nuclei.RunNuclei(nuclei.Options{URL: strings.TrimSpace(lines[0]), Threads: 120, Mode: nuclei.ModeFull})
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

	// Also cleanup shared module directories that write outside the subdomain directory
	// Modules like AEM, S3, misconfig write to new-results/aem/, new-results/s3/, etc.
	sharedDirs := []string{
		filepath.Join(resultsDir, "aem"),
		filepath.Join(resultsDir, "s3", rootDomain),
		filepath.Join(resultsDir, "s3", subdomainClean),
		filepath.Join(resultsDir, "misconfig", subdomainClean),
	}
	for _, sharedDir := range sharedDirs {
		if info, err := os.Stat(sharedDir); err == nil && info.IsDir() {
			if err := os.RemoveAll(sharedDir); err != nil {
				log.Printf("[WARN] Failed to cleanup shared directory %s: %v", sharedDir, err)
			} else {
				log.Printf("[OK] Cleaned up shared module directory: %s", sharedDir)
			}
		}
	}

	// Remove the subdomain directory itself if it's now empty (excluding apkx)
	if entries, err := os.ReadDir(domainDir); err == nil && len(entries) == 0 {
		os.Remove(domainDir)
		log.Printf("[OK] Removed empty subdomain directory: %s", domainDir)
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
		Threads:         150,
		Methods:         "GET",
		FollowRedirects: true,
		HTTPProxy:       os.Getenv("HTTP_PROXY"),
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
