package misconfig

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	mmapi "github.com/h0tak88r/AutoAR/v3/internal/tools/misconfigmapper"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/livehosts"
)

// Options for misconfig scan
type Options struct {
	Target        string
	ServiceID     string
	Delay         int
	Action        string // "scan", "list", "update", "service"
	Threads       int    // Concurrency for scanning subdomains
	Timeout       int    // Timeout in seconds
	LiveHostsFile string // Optional: path to live hosts file (avoids enumeration)
}

// Run executes misconfig command based on action
func Run(opts Options) error {
	if opts.Action == "" {
		return fmt.Errorf("action is required")
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	switch opts.Action {
	case "list":
		return handleList(resultsDir)
	case "update":
		return handleUpdate(resultsDir)
	case "scan":
		if opts.Target == "" {
			return fmt.Errorf("target is required for scan action")
		}
		return handleScan(opts, resultsDir)
	case "service":
		if opts.Target == "" || opts.ServiceID == "" {
			return fmt.Errorf("target and service-id are required for service action")
		}
		return handleService(opts, resultsDir)
	default:
		return fmt.Errorf("unknown action: %s", opts.Action)
	}
}

func templatesDir(root string) string {
	return filepath.Join(root, "templates")
}

func handleList(root string) error {
	tplDir := templatesDir(root)
	infos, err := mmapi.ListServices(tplDir)
	if err != nil {
		return fmt.Errorf("failed to list misconfig services: %w", err)
	}
	fmt.Println("ID\tService\tName")
	for _, s := range infos {
		fmt.Printf("%d\t%s\t%s\n", s.ID, s.Service, s.ServiceName)
	}
	return nil
}

func handleUpdate(root string) error {
	tplDir := templatesDir(root)
	if err := mmapi.UpdateTemplates(tplDir); err != nil {
		return fmt.Errorf("failed to update misconfig-mapper templates: %w", err)
	}
	fmt.Printf("[OK] Misconfig-mapper templates updated in %s\n", tplDir)
	return nil
}

func handleScan(opts Options, resultsDir string) error {
	// Save results under the target directory (which is the subdomain in subdomain mode)
	outputDir := filepath.Join(resultsDir, opts.Target, "misconfig")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	outputFile := filepath.Join(outputDir, "scan-results.txt")

	root := os.Getenv("AUTOAR_ROOT")
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		} else {
			root = "/app"
		}
	}
	tplDir := templatesDir(root)

	// Step 1: Get live subdomains file (checks provided file first, then existing file, then database)
	var liveHostsFile string
	var err error
	
	if opts.LiveHostsFile != "" {
		// Use provided live hosts file (e.g., from subdomain workflow)
		if _, err := os.Stat(opts.LiveHostsFile); err == nil {
			liveHostsFile = opts.LiveHostsFile
			if count, err := countLinesInFile(liveHostsFile); err == nil {
				log.Printf("[OK] Using %d live subdomains from provided file for %s", count, opts.Target)
			}
		} else {
			// In subdomain mode, if file doesn't exist, return error instead of enumerating
			return fmt.Errorf("provided live hosts file not found: %s", opts.LiveHostsFile)
		}
	}
	
	if liveHostsFile == "" {
		log.Printf("[INFO] Getting live subdomains for %s...", opts.Target)
		liveHostsFile, err = livehosts.GetLiveHostsFile(opts.Target)
		if err != nil {
			log.Printf("[WARN] Failed to get live hosts file for %s: %v, attempting to create it", opts.Target, err)
			// Fallback: try to create it by running livehosts
			liveResult, err2 := livehosts.FilterLiveHosts(opts.Target, opts.Threads, true)
			if err2 != nil {
				// Handle "no live subdomains found" as a soft error
				if strings.Contains(err2.Error(), "no live subdomains found") {
					log.Printf("[INFO] Misconfiguration scan skipped: %v", err2)
					return nil // Continue workflow
				}
				return fmt.Errorf("failed to get live subdomains: %w", err2)
			}
			if liveResult.LiveSubs == 0 {
				return fmt.Errorf("no live subdomains found for %s", opts.Target)
			}
			liveHostsFile = liveResult.LiveSubsFile
			log.Printf("[OK] Found %d live subdomains out of %d total for %s", liveResult.LiveSubs, liveResult.TotalSubs, opts.Target)
		} else {
			// Count live hosts from file for logging
			if count, err := countLinesInFile(liveHostsFile); err == nil {
				log.Printf("[OK] Using %d live subdomains from file/database for %s", count, opts.Target)
			}
		}
	}

	// Step 2: Read live subdomains from file
	var subdomainsList []string
	if liveHostsFile != "" {
		file, err := os.Open(liveHostsFile)
		if err != nil {
			return fmt.Errorf("failed to open live subdomains file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Extract hostname from URL (httpx outputs full URLs)
			host := line
			if strings.HasPrefix(host, "http://") {
				host = strings.TrimPrefix(host, "http://")
			} else if strings.HasPrefix(host, "https://") {
				host = strings.TrimPrefix(host, "https://")
			}
			// Remove path if present
			if idx := strings.Index(host, "/"); idx != -1 {
				host = host[:idx]
			}
			if host != "" {
				subdomainsList = append(subdomainsList, host)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read live subdomains file: %w", err)
		}
	}

	if len(subdomainsList) == 0 {
		return fmt.Errorf("no live subdomains to scan for %s", opts.Target)
	}

	// Step 3: Scan each live subdomain for misconfigurations with concurrency
	threads := opts.Threads
	if threads <= 0 {
		threads = 200 // Default 200 concurrent scans (increased from 50)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 300 // 5 minutes default timeout
	}

	log.Printf("[INFO] Scanning %d live subdomains for misconfigurations (threads: %d, timeout: %ds)...", len(subdomainsList), threads, timeout)
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	var allResults []mmapi.ScanResult
	var resultsMutex sync.Mutex
	totalScanned := int64(0)
	var scannedMutex sync.Mutex

	// Worker pool for concurrent scanning
	jobs := make(chan string, len(subdomainsList))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				// Check context cancellation
				select {
				case <-ctx.Done():
					return
				default:
				}

				subdomain = strings.TrimSpace(subdomain)
				if subdomain == "" {
					continue
				}

				// Scan this subdomain
				subResults, err := mmapi.Scan(mmapi.ScanOptions{
					Target:        subdomain,
					ServiceID:     opts.ServiceID,
					Delay:         opts.Delay,
					TemplatesPath: tplDir,
					AsDomain:      true, // Treat as domain to scan the subdomain directly
				})
				if err != nil {
					log.Printf("[WARN] Failed to scan %s: %v", subdomain, err)
					continue
				}

				// Thread-safe append
				if len(subResults) > 0 {
					resultsMutex.Lock()
					allResults = append(allResults, subResults...)
					resultsMutex.Unlock()
				}

				scannedMutex.Lock()
				totalScanned++
				scannedMutex.Unlock()
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, subdomain := range subdomainsList {
			select {
			case jobs <- subdomain:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for completion or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("[OK] Completed scanning %d subdomains", totalScanned)
	case <-ctx.Done():
		log.Printf("[WARN] Misconfig scan timed out after %ds (scanned %d/%d subdomains)", timeout, totalScanned, len(subdomainsList))
	}

	// Step 4: Write results to file
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	for _, r := range allResults {
		status := "EXISTS"
		if r.Vulnerable {
			status = "VULNERABLE"
		}
		line := fmt.Sprintf("[%s] %s (%s - %s)\n", status, r.URL, r.ServiceID, r.ServiceName)
		if _, err := f.WriteString(line); err != nil {
			return fmt.Errorf("failed to write result: %w", err)
		}
	}

	fmt.Printf("[OK] Misconfig scan completed for %s (%d findings across %d live subdomains)\n", opts.Target, len(allResults), totalScanned)
	fmt.Printf("[INFO] Results saved to: %s\n", outputFile)
	return nil
}

func handleService(opts Options, resultsDir string) error {
	// Service-specific scan is just a filtered scan with ServiceID set.
	return handleScan(opts, resultsDir)
}

// countLinesInFile counts the number of non-empty lines in a file
func countLinesInFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			count++
		}
	}
	return count, scanner.Err()
}
