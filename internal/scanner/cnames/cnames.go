package cnames

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

	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Result holds summary information for a cnames run
type Result struct {
	Domain     string
	Records    int
	OutputFile string
}

// Options for CNAME collection
type Options struct {
	Domain    string   // Domain for full enumeration mode
	Subdomain string   // Single subdomain to check (alternative to Domain)
	Targets   []string // List of specific targets to check (alternative to Domain/Subdomain)
	Threads   int
	Timeout   time.Duration
}

// CollectCNAMEs mirrors the behaviour of modules/cnames.sh using Go.
// It ensures subdomains, then uses dnsx (if available) to resolve CNAME records.
func CollectCNAMEs(domain string) (*Result, error) {
	return CollectCNAMEsWithOptions(Options{
		Domain:  domain,
		Threads: 100,              // Default 100 concurrent DNS queries
		Timeout: 5 * time.Minute, // 5 minute timeout
	})
}

// CollectCNAMEsWithOptions collects CNAME records with custom options
func CollectCNAMEsWithOptions(opts Options) (*Result, error) {
	// Determine which mode we're in and set targets accordingly
	var targets []string
	var domain string
	
	if len(opts.Targets) > 0 {
		// Mode 1: Direct targets provided
		targets = opts.Targets
		// Extract domain from first target for output directory
		if len(targets) > 0 {
			parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(targets[0], "http://"), "https://"), ".")
			if len(parts) >= 2 {
				domain = strings.Join(parts[len(parts)-2:], ".")
			} else {
				domain = targets[0]
			}
		}
	} else if opts.Subdomain != "" {
		// Mode 2: Single subdomain provided
		// Remove protocol if present
		subdomain := strings.TrimPrefix(strings.TrimPrefix(opts.Subdomain, "http://"), "https://")
		targets = []string{subdomain}
		// Extract domain from subdomain
		parts := strings.Split(subdomain, ".")
		if len(parts) >= 2 {
			domain = strings.Join(parts[len(parts)-2:], ".")
		} else {
			domain = subdomain
		}
	} else if opts.Domain != "" {
		// Mode 3: Domain provided - enumerate subdomains (original behavior)
		domain = opts.Domain
		resultsDir := utils.GetResultsDir()
		domainDir := filepath.Join(resultsDir, domain)
		subsDir := filepath.Join(domainDir, "subs")
		if err := utils.EnsureDir(subsDir); err != nil {
			return nil, fmt.Errorf("failed to create subs dir: %w", err)
		}

		// Load subdomains via DB-backed temp file (DB first, then disk fallback)
		tmpPath, cleanupTmp, tmpErr := utils.WriteTempSubsFile(domain)
		if tmpErr != nil {
			log.Printf("[INFO] No subdomains in DB, enumerating for %s", domain)
			subs, enumErr := subdomains.EnumerateSubdomains(domain, 100)
			if enumErr != nil {
				return nil, fmt.Errorf("failed to enumerate subdomains: %w", enumErr)
			}
			// Write freshly enumerated subs as temp file
			var retryErr error
			tmpPath, cleanupTmp, retryErr = utils.WriteTempSubsFile(domain)
			if retryErr != nil {
				// Fallback: write inline to a manual temp file
				f, fErr := os.CreateTemp("", "autoar-cnames-subs-*.txt")
				if fErr != nil {
					return nil, fmt.Errorf("failed to create temp subs file: %w", fErr)
				}
				tmpPath = f.Name()
				cleanupTmp = func() { os.Remove(tmpPath) }
				for _, s := range subs {
					fmt.Fprintln(f, s)
				}
				f.Close()
			}
		}
		defer cleanupTmp()

		file, err := os.Open(tmpPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open subs file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read subdomains file: %w", err)
		}

	} else {
		return nil, fmt.Errorf("either Domain, Subdomain, or Targets must be provided")
	}

	if opts.Threads <= 0 {
		opts.Threads = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Minute
	}

	// Set up output directory
	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	subsDir := filepath.Join(domainDir, "subs")
	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to create subs dir: %w", err)
	}

	out := filepath.Join(subsDir, "cname-records.txt")

	if len(targets) == 0 {
		log.Printf("[WARN] No targets found; creating empty CNAME file for %s", domain)
		if err := writeLines(out, nil); err != nil {
			return nil, fmt.Errorf("failed to initialise %s: %w", out, err)
		}
		return &Result{
			Domain:     domain,
			Records:    0,
			OutputFile: out,
		}, nil
	}

	log.Printf("[INFO] Collecting CNAME records for %d target(s) via dnsx library (threads: %d)", len(targets), opts.Threads)

	// Initialize dnsx client
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create dnsx client: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	// Collect CNAME records with concurrency
	var cnameRecords []string
	var recordsMutex sync.Mutex

	// Worker pool
	jobs := make(chan string, len(targets))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				// Check context cancellation
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Query CNAME record
				results, err := dnsClient.QueryOne(target)
				if err != nil {
					continue
				}
				// Extract CNAME from response
				if results != nil && len(results.CNAME) > 0 {
					recordsMutex.Lock()
					for _, cname := range results.CNAME {
						cnameRecords = append(cnameRecords, fmt.Sprintf("%s CNAME %s", target, cname))
					}
					recordsMutex.Unlock()
					
					// Sync to core database Subdomains table
					go db.UpdateSubdomainCNAME(opts.Domain, target, strings.Join(results.CNAME, ","))
				}
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Completed
	case <-ctx.Done():
		log.Printf("[WARN] CNAME collection timed out after %v", opts.Timeout)
	}

	// Write results to file
	if err := writeLines(out, cnameRecords); err != nil {
		return nil, fmt.Errorf("failed to write CNAME records: %w", err)
	}

	count, _ := countLines(out)
	log.Printf("[OK] Found %d CNAME records for %s", count, domain)

	// Write JSON output to scan directory for dashboard
	if scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID"); scanID != "" {
		// Emit structured objects: {subdomain, cname, type}
		type cnameEntry struct {
			Subdomain string `json:"subdomain"`
			CNAME     string `json:"cname"`
			Type      string `json:"type"`
		}
		var entries []cnameEntry
		for _, rec := range cnameRecords {
			// format: "sub.example.com CNAME target.example.com"
			parts := strings.Fields(rec)
			if len(parts) >= 3 {
				entries = append(entries, cnameEntry{
					Subdomain: parts[0],
					CNAME:     parts[2],
					Type:      "CNAME",
				})
			}
		}
		if len(entries) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "cname-records.json", map[string]interface{}{
				"scan_id":   scanID,
				"target":    domain,
				"scan_type": "cnames",
				"generated": fmt.Sprintf("%v", count),
				"records":   entries,
				"count":     len(entries),
			}); err != nil {
				log.Printf("[WARN] Failed to write CNAME JSON: %v", err)
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "dns-takeover", "cname-records.json")
		}
	}

	// Send result files to Discord webhook (only when not running under bot)
	if os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			if info, err := os.Stat(out); err == nil && info.Size() > 0 {
				utils.SendWebhookFileAsync(out, fmt.Sprintf("CNAME Records: %d CNAME records found for %s", count, domain))
			} else if count == 0 {
				utils.SendWebhookLogAsync(fmt.Sprintf("CNAME collection completed for %s: 0 CNAME records found", domain))
			}
		}
	}

	return &Result{
		Domain:     domain,
		Records:    count,
		OutputFile: out,
	}, nil
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(lines) == 0 {
		return nil
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	n := 0
	for s.Scan() {
		n++
	}
	return n, s.Err()
}
