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

	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
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

		allSubs := filepath.Join(subsDir, "all-subs.txt")

		// Ensure we have subdomains – reuse Go subdomains module
		// Check if file exists AND has content
		needsEnum := false
		if info, err := os.Stat(allSubs); err != nil {
			needsEnum = true
		} else if info.Size() == 0 {
			needsEnum = true
		}
		
		if needsEnum {
			log.Printf("[INFO] all-subs.txt missing or empty, enumerating subdomains for %s", domain)
			subs, err := subdomains.EnumerateSubdomains(domain, 100)
			if err != nil {
				return nil, fmt.Errorf("failed to enumerate subdomains: %w", err)
			}
			if err := writeLines(allSubs, subs); err != nil {
				return nil, fmt.Errorf("failed to write %s: %w", allSubs, err)
			}
		}

		// Read subdomains from file
		file, err := os.Open(allSubs)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %w", allSubs, err)
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

	// Send result files to Discord webhook if configured (only when not running under bot)
	// When running under bot (AUTOAR_CURRENT_SCAN_ID is set), the bot handles R2 upload and zip link
	if os.Getenv("AUTOAR_CURRENT_SCAN_ID") == "" {
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			// Send CNAME output file if it exists and has content
			if info, err := os.Stat(out); err == nil && info.Size() > 0 {
				utils.SendWebhookFileAsync(out, fmt.Sprintf("CNAME Records: %d CNAME records found for %s", count, domain))
			} else if count == 0 {
				// Send "no findings" message if no CNAME records found
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
