package cnames

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/subdomains"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Result holds summary information for a cnames run
type Result struct {
	Domain     string
	Records    int
	OutputFile string
}

// CollectCNAMEs mirrors the behaviour of modules/cnames.sh using Go.
// It ensures subdomains, then uses dnsx (if available) to resolve CNAME records.
func CollectCNAMEs(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	subsDir := filepath.Join(domainDir, "subs")
	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to create subs dir: %w", err)
	}

	allSubs := filepath.Join(subsDir, "all-subs.txt")

	// Ensure we have subdomains – reuse Go subdomains module
	if _, err := os.Stat(allSubs); err != nil {
		log.Printf("[INFO] all-subs.txt missing, enumerating subdomains for %s", domain)
		subs, err := subdomains.EnumerateSubdomains(domain, 100)
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate subdomains: %w", err)
		}
		if err := writeLines(allSubs, subs); err != nil {
			return nil, fmt.Errorf("failed to write %s: %w", allSubs, err)
		}
	}

	out := filepath.Join(subsDir, "cname-records.txt")

	// Read subdomains from file
	file, err := os.Open(allSubs)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", allSubs, err)
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
		return nil, fmt.Errorf("failed to read subdomains file: %w", err)
	}

	if len(targets) == 0 {
		log.Printf("[WARN] No subdomains found; creating empty CNAME file for %s", domain)
		if err := writeLines(out, nil); err != nil {
			return nil, fmt.Errorf("failed to initialise %s: %w", out, err)
		}
		return &Result{
			Domain:     domain,
			Records:    0,
			OutputFile: out,
		}, nil
	}

	log.Printf("[INFO] Collecting CNAME records for %s via dnsx library", domain)

	// Initialize dnsx client
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create dnsx client: %w", err)
	}

	// Collect CNAME records
	var cnameRecords []string
	for _, target := range targets {
		// Query CNAME record
		results, err := dnsClient.QueryOne(target)
		if err != nil {
			continue
		}
		// Extract CNAME from response
		if results != nil && len(results.CNAME) > 0 {
			for _, cname := range results.CNAME {
				cnameRecords = append(cnameRecords, fmt.Sprintf("%s CNAME %s", target, cname))
			}
		}
	}

	// Write results to file
	if err := writeLines(out, cnameRecords); err != nil {
		return nil, fmt.Errorf("failed to write CNAME records: %w", err)
	}

	count, _ := countLines(out)
	log.Printf("[OK] Found %d CNAME records for %s", count, domain)

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
