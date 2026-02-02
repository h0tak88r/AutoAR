package backup

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	fuzzulitool "github.com/h0tak88r/AutoAR/internal/tools/fuzzuli"
)

// Options controls how the backup scan runs.
// This is a Go port of modules/backup_scan.sh (domain / live-hosts modes only).
type Options struct {
	Domain        string
	LiveHostsFile string
	OutputDir     string
	Threads       int
	DelayMS       int
	Method        string   // Fuzzuli method: regular, withoutdots, withoutvowels, reverse, mixed, withoutdv, shuffle, all
	Extensions    []string // Custom file extensions (e.g., [".rar", ".zip"])
}

type Result struct {
	OutputDir      string
	ResultsFile    string
	LogFile        string
	FoundCount     int
	Duration       time.Duration
	LiveHostsCount int
}

// Run executes the backup scan using the embedded fuzzuli engine.
func Run(opts Options) (*Result, error) {
	// Allow both Domain and LiveHostsFile - Domain is used for output directory, LiveHostsFile for input
	if opts.LiveHostsFile == "" && opts.Domain == "" {
		return nil, fmt.Errorf("either Domain or LiveHostsFile must be provided")
	}

	log.Printf("[DEBUG] Backup Run Options: Domain='%s', LiveHostsFile='%s', OutputDir='%s'", opts.Domain, opts.LiveHostsFile, opts.OutputDir)

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	// Normalize results directory path - if absolute path at root and not in Docker, convert to relative
	if filepath.IsAbs(resultsDir) && !strings.HasPrefix(resultsDir, "/app") {
		// Check if we're in Docker
		isDocker := false
		if _, err := os.Stat("/app"); err == nil {
			if err := os.MkdirAll("/app", 0755); err == nil {
				testPath := "/app/.test-write"
				if f, err := os.Create(testPath); err == nil {
					f.Close()
					os.Remove(testPath)
					isDocker = true
				}
			}
		}
		
		// If not in Docker and path is absolute (like /new-results), convert to relative
		if !isDocker {
			if cwd, err := os.Getwd(); err == nil {
				resultsDir = filepath.Join(cwd, "new-results")
			} else {
				resultsDir = "new-results"
			}
		}
	}

	// Determine output directory
	outDir := opts.OutputDir
	if outDir == "" {
		if opts.Domain != "" {
			// Sanitize domain for filesystem use (remove protocol, replace : with -)
			sanitizedDomain := sanitizeDomainForPath(opts.Domain)
			outDir = filepath.Join(resultsDir, sanitizedDomain, "backup")
		} else {
			outDir = filepath.Join(resultsDir, "backup")
		}
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", outDir, err)
	}

	resultsFile := filepath.Join(outDir, "fuzzuli-results.txt")
	logFile := filepath.Join(outDir, "fuzzuli-output.log")

	res := &Result{
		OutputDir:   outDir,
		ResultsFile: resultsFile,
		LogFile:     logFile,
	}

	resultsFH, err := os.Create(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create results file: %w", err)
	}
	defer resultsFH.Close()

	logFH, err := os.Create(logFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create log file: %w", err)
	}
	defer logFH.Close()

	threads := opts.Threads
	if threads <= 0 {
		threads = 100
	}

	fuzzOpts := fuzzulitool.DefaultOptions()
	fuzzOpts.Workers = threads
	
	// Set method if provided
	if opts.Method != "" {
		fuzzOpts.Method = fuzzulitool.Method(opts.Method)
	}
	
	// Set custom extensions if provided
	if len(opts.Extensions) > 0 {
		fuzzOpts.Extensions = opts.Extensions
	}

	start := time.Now()

	// Set default method to "all" if not specified
	if opts.Method == "" {
		opts.Method = "all"
		fuzzOpts.Method = fuzzulitool.MethodAll
	}

	var urls []string
	// Prioritize LiveHostsFile over Domain when both are provided
	switch {
	case opts.LiveHostsFile != "":
		log.Printf("[INFO] Backup scan: Reading live hosts from file: %s", opts.LiveHostsFile)
		// Count hosts in file for logging
		if lf, err := os.Open(opts.LiveHostsFile); err == nil {
			ls := bufio.NewScanner(lf)
			hostCount := 0
			for ls.Scan() {
				if strings.TrimSpace(ls.Text()) != "" {
					hostCount++
				}
			}
			lf.Close()
			log.Printf("[INFO] Backup scan: Found %d live host(s) in file", hostCount)
		}
		log.Printf("[INFO] Backup scan: Scanning live hosts with method %s, threads %d", opts.Method, threads)
		if len(opts.Extensions) > 0 {
			log.Printf("[INFO] Backup scan: Using custom extensions: %v", opts.Extensions)
		}
		u, err := fuzzulitool.ScanFromFile(opts.LiveHostsFile, fuzzOpts)
		if err != nil {
			return res, fmt.Errorf("fuzzuli scan failed: %w", err)
		}
		urls = u
		log.Printf("[INFO] Backup scan: Generated %d backup file URLs from live hosts", len(urls))
	case opts.Domain != "":
		log.Printf("[INFO] Backup scan: Scanning domain %s with method %s, threads %d", opts.Domain, opts.Method, threads)
		if len(opts.Extensions) > 0 {
			log.Printf("[INFO] Backup scan: Using custom extensions: %v", opts.Extensions)
		}
		u, err := fuzzulitool.ScanDomain(opts.Domain, fuzzOpts)
		if err != nil {
			return res, fmt.Errorf("fuzzuli scan failed: %w", err)
		}
		urls = u
		log.Printf("[INFO] Backup scan: Generated %d backup file URLs for domain %s", len(urls), opts.Domain)
		if len(urls) > 0 {
			log.Printf("[DEBUG] Backup scan: Sample URLs found: %v", urls[:min(5, len(urls))])
		}
	default:
		return nil, fmt.Errorf("invalid options")
	}

	foundCount := 0
	for _, u := range urls {
		if strings.TrimSpace(u) == "" {
			continue
		}
		if _, err := resultsFH.WriteString(u + "\n"); err == nil {
			foundCount++
		}
	}
	
	// Always write a message if no results found
	if foundCount == 0 {
		resultsFH.WriteString("No backup files found.\n")
	}
	
	log.Printf("[INFO] Backup scan: Wrote %d backup URLs to results file: %s", foundCount, resultsFile)

	res.Duration = time.Since(start)

	// Count lines containing "http" in results file, similar to the bash module.
	f, err := os.Open(resultsFile)
	if err != nil {
		return res, fmt.Errorf("failed to open results file for counting: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "http") {
			res.FoundCount++
		}
	}
	_ = scanner.Err()

	// If we scanned a live-hosts file, record host count as well.
	if opts.LiveHostsFile != "" {
		if lf, err := os.Open(opts.LiveHostsFile); err == nil {
			defer lf.Close()
			ls := bufio.NewScanner(lf)
			for ls.Scan() {
				if strings.TrimSpace(ls.Text()) != "" {
					res.LiveHostsCount++
				}
			}
		}
	}

	return res, nil
}

// sanitizeDomainForPath removes protocol and sanitizes domain for use in filesystem paths
func sanitizeDomainForPath(domain string) string {
	domain = strings.TrimSpace(domain)
	// Remove protocol if present
	if strings.HasPrefix(domain, "http://") {
		domain = strings.TrimPrefix(domain, "http://")
	} else if strings.HasPrefix(domain, "https://") {
		domain = strings.TrimPrefix(domain, "https://")
	}
	// Replace any remaining colons (e.g., from ports) with dashes
	domain = strings.ReplaceAll(domain, ":", "-")
	// Remove trailing slashes
	domain = strings.TrimRight(domain, "/")
	return domain
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
