package livehosts

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/projectdiscovery/httpx/runner"
)

// Result holds summary information for a livehosts run
type Result struct {
	Domain       string
	Threads      int
	TotalSubs    int
	LiveSubs     int
	SubsFile     string
	LiveSubsFile string
}

// FilterLiveHosts ensures subdomains exist for a domain and filters live hosts using httpx.
// It mirrors the behaviour of modules/livehosts.sh but implemented in Go.
func FilterLiveHosts(domain string, threads int, silent bool) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if threads <= 0 {
		threads = 100
	}

	// Initialize results directory structure
	domainDir, err := utils.DomainDirInit(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain dir: %v", err)
	}

	subsDir := filepath.Join(domainDir, "subs")
	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to ensure subs dir: %v", err)
	}

	subsFile := filepath.Join(subsDir, "all-subs.txt")
	liveFile := filepath.Join(subsDir, "live-subs.txt")

	// 1. Ensure subdomains exist (reuse Go subdomains module)
	totalSubs, err := ensureSubdomains(domain, threads, subsFile)
	if err != nil {
		return nil, err
	}

	// 2. Run httpx to filter live hosts
	liveCount, err := runHTTPX(domain, threads, subsFile, liveFile)
	if err != nil {
		return nil, err
	}

	log.Printf("[OK] Found %d live subdomains out of %d for %s", liveCount, totalSubs, domain)

	// 3. Update database with live host information (optional but desirable)
	if liveCount > 0 {
		if err := updateDatabase(domain, liveFile); err != nil {
			log.Printf("[WARN] Failed to update database with live hosts for %s: %v", domain, err)
		}
	}

	return &Result{
		Domain:       domain,
		Threads:      threads,
		TotalSubs:    totalSubs,
		LiveSubs:     liveCount,
		SubsFile:     subsFile,
		LiveSubsFile: liveFile,
	}, nil
}

// ensureSubdomains loads or re-generates subdomains for a domain.
// It returns the total number of subdomains.
// First checks database, then file, then collects if needed.
func ensureSubdomains(domain string, threads int, subsFile string) (int, error) {
	// Step 1: Check database first
	if os.Getenv("DB_HOST") != "" || os.Getenv("SAVE_TO_DB") == "true" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			count, err := db.CountSubdomains(domain)
			if err == nil && count > 0 {
				log.Printf("[INFO] Found %d subdomains in database for %s, using them", count, domain)
				// Load subdomains from database and write to file
				subs, err := db.ListSubdomains(domain)
				if err == nil && len(subs) > 0 {
					// Write to file for compatibility
					if err := writeLines(subsFile, subs); err != nil {
						log.Printf("[WARN] Failed to write subdomains from DB to file: %v", err)
					}
					return len(subs), nil
				}
			}
		}
	}

	// Step 2: If file exists and has enough subdomains, reuse it
	if info, err := os.Stat(subsFile); err == nil && info.Size() > 0 {
		count, err := countLines(subsFile)
		if err == nil {
			log.Printf("[INFO] Using existing subdomains from %s (%d subdomains)", subsFile, count)
			// If very few, treat as potentially stale and re-enumerate
			if count >= 5 {
				return count, nil
			}
			log.Printf("[WARN] Very few subdomains found (%d), re-enumerating...", count)
		}
	}

	// Step 3: Collect subdomains (not in database and no valid file)
	log.Printf("[INFO] Collecting subdomains for %s", domain)
	results, err := subdomains.EnumerateSubdomains(domain, threads)
	if err != nil {
		return 0, fmt.Errorf("failed to enumerate subdomains: %v", err)
	}

	// Write to file
	if err := writeLines(subsFile, results); err != nil {
		return 0, fmt.Errorf("failed to write subdomains file: %v", err)
	}

	total := len(results)
	log.Printf("[OK] Found %d unique subdomains for %s", total, domain)

	// Save to database if configured (EnumerateSubdomains already does this, but keep for compatibility)
	if os.Getenv("DB_HOST") != "" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			if err := db.BatchInsertSubdomains(domain, results, false); err != nil {
				log.Printf("[WARN] Failed to save subdomains to database: %v", err)
			}
		} else {
			log.Printf("[WARN] Database initialization failed, skipping subdomains save: %v", err)
		}
	}

	return total, nil
}

// runHTTPX executes httpx against the subdomains file and writes live hosts to liveFile.
// It returns the number of live hosts.
func runHTTPX(domain string, threads int, subsFile, liveFile string) (int, error) {
	if _, err := os.Stat(subsFile); err != nil {
		return 0, fmt.Errorf("subdomains file not found: %s", subsFile)
	}

	// Read subdomains from file
	file, err := os.Open(subsFile)
	if err != nil {
		return 0, fmt.Errorf("failed to open subdomains file: %v", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to read subdomains file: %v", err)
	}

	if len(targets) == 0 {
		log.Printf("[WARN] No subdomains found in file")
		if err := writeLines(liveFile, nil); err != nil {
			return 0, fmt.Errorf("failed to create empty live hosts file: %v", err)
		}
		return 0, nil
	}

	log.Printf("[INFO] Filtering live hosts via httpx with %d threads", threads)

	// Collect live hosts
	var liveHosts []string
	var mu sync.Mutex

	// Configure httpx options with callback
	options := runner.Options{
		InputTargetHost: targets,
		Threads:        threads,
		Silent:         true,
		NoColor:        true,
		FollowRedirects: true,
		FollowHostRedirects: true,
		HTTPProxy:      os.Getenv("HTTP_PROXY"),
		SocksProxy:     os.Getenv("SOCKS_PROXY"),
		OnResult: func(result runner.Result) {
			if result.URL != "" {
				mu.Lock()
				liveHosts = append(liveHosts, result.URL)
				mu.Unlock()
			}
		},
	}

	// Validate options
	if err := options.ValidateOptions(); err != nil {
		return 0, fmt.Errorf("failed to validate httpx options: %v", err)
	}

	// Create httpx runner
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return 0, fmt.Errorf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	// Run enumeration
	httpxRunner.RunEnumeration()

	// Write results to file
	outFile, err := os.Create(liveFile)
	if err != nil {
		return 0, fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	if len(liveHosts) > 0 {
		writer := bufio.NewWriter(outFile)
		for _, host := range liveHosts {
			writer.WriteString(host + "\n")
		}
		writer.Flush()
	}

	log.Printf("[OK] Found %d live hosts", len(liveHosts))
	return len(liveHosts), nil
}

// updateDatabase marks live hosts in the subdomains table using InsertSubdomain.
func updateDatabase(domain, liveFile string) error {
	if os.Getenv("DB_HOST") == "" {
		return nil
	}

	if err := db.Init(); err != nil {
		return err
	}

	if err := db.InitSchema(); err != nil {
		return err
	}

	file, err := os.Open(liveFile)
	if err != nil {
		return fmt.Errorf("failed to open live hosts file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// httpx output is usually full URL; extract host
		host := line
		if strings.HasPrefix(host, "http://") {
			host = strings.TrimPrefix(host, "http://")
		} else if strings.HasPrefix(host, "https://") {
			host = strings.TrimPrefix(host, "https://")
		}
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}

		httpURL := "http://" + host
		httpsURL := "https://" + host

		if err := db.InsertSubdomain(domain, host, true, httpURL, httpsURL, 200, 200); err != nil {
			log.Printf("[WARN] Failed to insert live subdomain %s: %v", host, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read live hosts file: %v", err)
	}

	return nil
}

// countLines counts the number of non-empty lines in a file.
func countLines(path string) (int, error) {
	file, err := os.Open(path)
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
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

// writeLines writes lines to a file (one per line).
func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}
