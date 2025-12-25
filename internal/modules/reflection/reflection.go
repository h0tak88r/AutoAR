package reflection

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

	kxsstool "github.com/h0tak88r/AutoAR/v3/internal/tools/kxss"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
)

// Result holds reflection scan results
type Result struct {
	Domain      string
	Reflections int
	OutputFile  string
}

// Options holds reflection scan options
type Options struct {
	Domain      string
	Threads     int
	Timeout     time.Duration
	URLThreads  int // Concurrency for URL collection
}

// ScanReflection runs reflection scanning using kxss with timeout and concurrency support
func ScanReflection(domain string) (*Result, error) {
	return ScanReflectionWithOptions(Options{
		Domain:     domain,
		Threads:    50,  // Default concurrency for kxss scanning
		Timeout:    15 * time.Minute, // Default 15 minute timeout
		URLThreads: 200, // Higher concurrency for URL collection
	})
}

// ScanReflectionWithOptions runs reflection scanning with custom options
func ScanReflectionWithOptions(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Minute
	}
	if opts.URLThreads <= 0 {
		opts.URLThreads = 200
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, opts.Domain)
	urlsDir := filepath.Join(domainDir, "urls")
	urlsFile := filepath.Join(urlsDir, "all-urls.txt")
	outFile := filepath.Join(domainDir, "vulnerabilities", "kxss-results.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Ensure URLs exist via Go urls module (with higher concurrency)
	if _, err := os.Stat(urlsFile); err != nil {
		log.Printf("[INFO] URLs file missing, collecting URLs for %s (threads: %d)", opts.Domain, opts.URLThreads)
		urlCtx, urlCancel := context.WithTimeout(ctx, 10*time.Minute)
		defer urlCancel()
		
		// Run URL collection in goroutine with context
		urlErrChan := make(chan error, 1)
		go func() {
			_, err := urls.CollectURLs(opts.Domain, opts.URLThreads, false)
			urlErrChan <- err
		}()
		
		select {
		case err := <-urlErrChan:
			if err != nil {
				log.Printf("[WARN] Failed to collect URLs: %v", err)
				return nil, fmt.Errorf("failed to get URLs for %s: %w", opts.Domain, err)
			}
		case <-urlCtx.Done():
			log.Printf("[WARN] URL collection timed out after 10 minutes")
			return nil, fmt.Errorf("URL collection timed out for %s", opts.Domain)
		}
	}

	if _, err := os.Stat(urlsFile); err != nil {
		return nil, fmt.Errorf("URLs file not found: %s", urlsFile)
	}

	// Run embedded kxss engine with concurrency and timeout
	log.Printf("[INFO] Running embedded kxss reflection scan for %s (threads: %d, timeout: %v)", opts.Domain, opts.Threads, opts.Timeout)
	
	// Read URLs from file
	urlLines, err := readLines(urlsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read URLs file: %w", err)
	}

	// Scan URLs with concurrency and timeout
	kxssResults, err := scanURLsWithConcurrency(ctx, urlLines, opts.Threads)
	if err != nil {
		if err == context.DeadlineExceeded {
			log.Printf("[WARN] kxss scan timed out after %v", opts.Timeout)
		} else {
			log.Printf("[WARN] kxss scan failed: %v", err)
		}
		// Create empty file to keep downstream logic consistent
		if err := os.WriteFile(outFile, []byte(""), 0o644); err != nil {
			return nil, fmt.Errorf("failed to create empty output file: %w", err)
		}
	} else {
		// Write results in the same text format as original kxss
		var lines []string
		for _, r := range kxssResults {
			lines = append(lines, fmt.Sprintf("URL: %s Param: %s Unfiltered: %v ", r.URL, r.Param, r.Chars))
		}
		if err := os.WriteFile(outFile, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
			return nil, fmt.Errorf("failed to write kxss results: %w", err)
		}
		// Filter out empty results as before
		if err := filterEmptyLines(outFile); err != nil {
			log.Printf("[WARN] Failed to filter empty lines: %v", err)
		}
	}

	count, _ := countLines(outFile)
	if count > 0 {
		log.Printf("[OK] Found %d reflection points", count)
	} else {
		log.Printf("[INFO] No reflection points found")
	}

	return &Result{
		Domain:      opts.Domain,
		Reflections: count,
		OutputFile:  outFile,
	}, nil
}

// scanURLsWithConcurrency scans URLs with concurrency and context timeout
func scanURLsWithConcurrency(ctx context.Context, urls []string, concurrency int) ([]kxsstool.Result, error) {
	if len(urls) == 0 {
		return []kxsstool.Result{}, nil
	}

	// Limit concurrency
	if concurrency > len(urls) {
		concurrency = len(urls)
	}

	type job struct {
		url  string
		idx  int
	}

	jobs := make(chan job, len(urls))
	results := make(chan kxsstool.Result, len(urls))
	
	// Create worker pool
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check context cancellation
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Scan single URL
				urlResults, err := kxsstool.ScanURLs([]string{j.url})
				if err == nil && len(urlResults) > 0 {
					for _, r := range urlResults {
						select {
						case results <- r:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for i, u := range urls {
			select {
			case jobs <- job{url: u, idx: i}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for workers and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var allResults []kxsstool.Result
	for r := range results {
		allResults = append(allResults, r)
	}

	// Check if context was cancelled
	if ctx.Err() != nil {
		return allResults, ctx.Err()
	}

	return allResults, nil
}

func filterEmptyLines(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.Contains(trimmed, "Unfiltered: []") {
			filtered = append(filtered, line)
		}
	}

	return os.WriteFile(filePath, []byte(strings.Join(filtered, "\n")), 0644)
}

// readLines is a small helper to read non-empty lines from a file.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func countLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}
