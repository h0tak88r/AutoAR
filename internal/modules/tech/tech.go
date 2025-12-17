package tech

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/projectdiscovery/httpx/runner"
)

// Result holds tech detection results
type Result struct {
	Domain     string
	Hosts      int
	OutputFile string
}

// DetectTech runs technology detection using httpx
func DetectTech(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads == 0 {
		threads = 100
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	subsDir := filepath.Join(domainDir, "subs")
	subsFile := filepath.Join(subsDir, "live-subs.txt")
	outFile := filepath.Join(subsDir, "tech-detect.txt")

	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to create subs dir: %w", err)
	}

	// Ensure live hosts exist via Go livehosts module
	if _, err := os.Stat(subsFile); err != nil {
		log.Printf("[INFO] Live hosts file missing, filtering live hosts for %s", domain)
		_, err := livehosts.FilterLiveHosts(domain, threads, false)
		if err != nil {
			return nil, fmt.Errorf("failed to get live hosts for %s: %w", domain, err)
		}
	}

	if _, err := os.Stat(subsFile); err != nil {
		return nil, fmt.Errorf("live hosts file not found: %s", subsFile)
	}

	// Read live hosts from file
	file, err := os.Open(subsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open live hosts file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			// Extract host from URL if needed
			if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
				targets = append(targets, line)
			} else {
				// Assume it's a hostname, add both http and https
				targets = append(targets, "http://"+line, "https://"+line)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read live hosts file: %w", err)
	}

	if len(targets) == 0 {
		log.Printf("[WARN] No live hosts found")
		return &Result{
			Domain:     domain,
			Hosts:      0,
			OutputFile: outFile,
		}, nil
	}

	log.Printf("[INFO] Running technology detection with %d threads", threads)

	// Configure httpx options for tech detection
	options := runner.Options{
		InputTargetHost: targets,
		Threads:        threads,
		TechDetect:     true,
		ExtractTitle:   true,
		StatusCode:     true,
		OutputServerHeader: true,
		NoColor:        true,
		Silent:         true,
		FollowRedirects: true,
		FollowHostRedirects: true,
	}

	// Validate options
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("failed to validate httpx options: %w", err)
	}

	// Create output file
	out, err := os.Create(outFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer out.Close()

	writer := bufio.NewWriter(out)
	defer writer.Flush()

	var count int
	var mu sync.Mutex

	// Set callback in options
	options.OnResult = func(result runner.Result) {
		if result.URL != "" {
			mu.Lock()
			count++
			// Write tech detection result
			line := fmt.Sprintf("%s [%d] [%s] [%s] [%s]\n",
				result.URL,
				result.StatusCode,
				result.Title,
				result.WebServer,
				strings.Join(result.Technologies, ","))
			writer.WriteString(line)
			mu.Unlock()
		}
	}

	// Create httpx runner
	httpxRunner, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("failed to create httpx runner: %w", err)
	}
	defer httpxRunner.Close()

	// Run enumeration
	httpxRunner.RunEnumeration()

	log.Printf("[OK] Technology detection completed for %d hosts", count)

	return &Result{
		Domain:     domain,
		Hosts:      count,
		OutputFile: outFile,
	}, nil
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
