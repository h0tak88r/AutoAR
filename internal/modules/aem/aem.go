package aem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
)

// Options controls how the AEM scan runs
type Options struct {
	Domain        string   // Domain to scan
	LiveHostsFile string   // File with live hosts/URLs to scan
	OutputDir     string   // Output directory for results
	Threads       int      // Number of parallel workers
	SSRFHost      string   // Hostname/IP for SSRF detection (VPS required)
	SSRFPort      int      // Port for SSRF detection
	Proxy         string   // HTTP/HTTPS proxy
	Debug         bool     // Enable debug output
	Handlers      []string // Specific handlers to run (empty = all)
}

// Result contains the scan results
type Result struct {
	OutputDir       string
	ResultsFile     string
	LogFile         string
	DiscoveredFile  string // File with discovered AEM instances
	ScannedFile     string // File with scan results
	DiscoveredCount int
	Vulnerabilities  int
	Duration        time.Duration
}

// Finding represents a discovered vulnerability
type Finding struct {
	Name        string `json:"name"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Severity    string `json:"severity,omitempty"`
}

// DiscoverAEM scans URLs and discovers AEM webapps using native Go implementation
func DiscoverAEM(opts Options) ([]string, error) {
	// Create HTTP client
	client, err := NewHTTPClient(opts.Proxy, opts.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Get list of URLs to scan
	var urls []string
	if opts.LiveHostsFile != "" {
		file, err := os.Open(opts.LiveHostsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open live hosts file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				urls = append(urls, url)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("failed to read live hosts file: %w", err)
		}
	} else if opts.Domain != "" {
		// Add common protocol variations
		urls = []string{
			fmt.Sprintf("https://%s", opts.Domain),
			fmt.Sprintf("http://%s", opts.Domain),
		}
	} else {
		return nil, fmt.Errorf("either Domain or LiveHostsFile must be provided")
	}

	// Create output directory
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	outputDir := opts.OutputDir
	if outputDir == "" {
		if opts.Domain != "" {
			sanitizedDomain := sanitizeDomainForPath(opts.Domain)
			outputDir = filepath.Join(resultsDir, sanitizedDomain, "aem")
		} else {
			outputDir = filepath.Join(resultsDir, "aem")
		}
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	discoveredFile := filepath.Join(outputDir, "discovered-aem.txt")

	// Discover AEM instances using native Go implementation
	log.Printf("[AEM] Starting AEM discovery (native Go)...")
	discovered := DiscoverAEMFromURLs(urls, client, opts.Threads)

	// Always save discovered instances (even if empty)
	discoveredFH, err := os.Create(discoveredFile)
	if err == nil {
		if len(discovered) > 0 {
			for _, url := range discovered {
				fmt.Fprintln(discoveredFH, url)
			}
		} else {
			fmt.Fprintln(discoveredFH, "No AEM instances discovered.")
		}
		discoveredFH.Close()
	}
	
	// Don't send individual discovery messages - will be sent in consolidated file from Run()

	return discovered, nil
}

// ScanAEM scans a single AEM instance for vulnerabilities using native Go implementation
func ScanAEM(url string, opts Options) ([]Finding, error) {
	// Create HTTP client
	client, err := NewHTTPClient(opts.Proxy, opts.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Build SSRF host string if provided
	ssrfHost := ""
	if opts.SSRFHost != "" {
		if opts.SSRFPort > 0 {
			ssrfHost = fmt.Sprintf("%s:%d", opts.SSRFHost, opts.SSRFPort)
		} else {
			ssrfHost = opts.SSRFHost
		}
	}

	// Create output directory
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	outputDir := opts.OutputDir
	if outputDir == "" {
		sanitizedURL := sanitizeDomainForPath(url)
		outputDir = filepath.Join(resultsDir, "aem", sanitizedURL)
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	resultsFile := filepath.Join(outputDir, "findings.json")

	// Scan using native Go implementation
	log.Printf("[AEM] Scanning %s for vulnerabilities (native Go)...", url)
	findings := ScanAEMInstance(url, ssrfHost, client, opts.Handlers)

	// Always save findings as JSON (even if empty)
	var data []byte
	if len(findings) > 0 {
		if jsonData, err := json.MarshalIndent(findings, "", "  "); err == nil {
			data = jsonData
			os.WriteFile(resultsFile, data, 0644)
		}
	} else {
		// Save empty findings array
		if jsonData, err := json.MarshalIndent([]Finding{}, "", "  "); err == nil {
			data = jsonData
			os.WriteFile(resultsFile, data, 0644)
		}
	}
	
	// Don't send individual scan messages - will be sent in consolidated file from Run()

	return findings, nil
}

// Run executes the full AEM scan workflow: discovery + scanning
func Run(opts Options) (*Result, error) {
	startTime := time.Now()

	// Allow both Domain and LiveHostsFile
	if opts.LiveHostsFile == "" && opts.Domain == "" {
		return nil, fmt.Errorf("either Domain or LiveHostsFile must be provided")
	}

	// Set defaults
	if opts.Threads == 0 {
		opts.Threads = 50
	}

	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	// Determine output directory
	outputDir := opts.OutputDir
	if outputDir == "" {
		if opts.Domain != "" {
			sanitizedDomain := sanitizeDomainForPath(opts.Domain)
			outputDir = filepath.Join(resultsDir, sanitizedDomain, "aem")
		} else {
			outputDir = filepath.Join(resultsDir, "aem")
		}
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	resultsFile := filepath.Join(outputDir, "results.json")
	discoveredFile := filepath.Join(outputDir, "discovered-aem.txt")
	scannedFile := filepath.Join(outputDir, "scanned-results.json")
	logFile := filepath.Join(outputDir, "aem-scan.log")

	res := &Result{
		OutputDir:      outputDir,
		ResultsFile:    resultsFile,
		LogFile:        logFile,
		DiscoveredFile: discoveredFile,
		ScannedFile:     scannedFile,
	}

	// Step 1: Discover AEM instances
	log.Printf("[AEM] Step 1: Discovering AEM webapps...")
	discovered, err := DiscoverAEM(opts)
	if err != nil {
		log.Printf("[AEM] Discovery failed: %v", err)
		// Continue anyway, might have partial results
	}
	res.DiscoveredCount = len(discovered)

	// Always create consolidated result file even if no instances discovered
	if len(discovered) == 0 {
		log.Printf("[AEM] No AEM instances discovered")
		
		// Create consolidated file with "no results" message
		consolidatedFile := filepath.Join(outputDir, "aem-scan.txt")
		consolidatedF, err := os.Create(consolidatedFile)
		if err == nil {
			defer consolidatedF.Close()
			domain := opts.Domain
			if domain == "" && opts.LiveHostsFile != "" {
				domain = "targets"
			}
			fmt.Fprintf(consolidatedF, "AEM Scan Results for %s\n", domain)
			fmt.Fprintf(consolidatedF, "========================================\n\n")
			fmt.Fprintf(consolidatedF, "No AEM instances discovered.\n")
		}
		
		// Save empty results to JSON
		allResults := map[string]interface{}{
			"discovered_count": 0,
			"vulnerabilities":  0,
			"discovered":       []string{},
			"findings":         []Finding{},
			"scan_time":       time.Now().Format(time.RFC3339),
		}
		if data, err := json.MarshalIndent(allResults, "", "  "); err == nil {
			os.WriteFile(resultsFile, data, 0644)
		}
		
		// Send to Discord
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			domain := opts.Domain
			if domain == "" && opts.LiveHostsFile != "" {
				domain = "targets"
			}
			if info, err := os.Stat(consolidatedFile); err == nil && info.Size() > 0 {
				utils.SendWebhookFileAsync(consolidatedFile, fmt.Sprintf("AEM Scan Results: 0 AEM instances found for %s", domain))
			}
			utils.SendWebhookLogAsync(fmt.Sprintf("AEM scan completed for %s: 0 AEM instances discovered", domain))
		}
		
		res.Duration = time.Since(startTime)
		return res, nil
	}

	log.Printf("[AEM] Discovered %d AEM instances", len(discovered))

	// Step 2: Scan each discovered AEM instance
	log.Printf("[AEM] Step 2: Scanning discovered AEM instances for vulnerabilities...")
	allFindings := []Finding{}
	for i, url := range discovered {
		log.Printf("[AEM] Scanning %d/%d: %s", i+1, len(discovered), url)
		findings, err := ScanAEM(url, opts)
		if err != nil {
			log.Printf("[AEM] Failed to scan %s: %v", url, err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	res.Vulnerabilities = len(allFindings)

	// Save all results to JSON files
	allResults := map[string]interface{}{
		"discovered_count": res.DiscoveredCount,
		"vulnerabilities":  res.Vulnerabilities,
		"discovered":        discovered,
		"findings":          allFindings,
		"scan_time":        time.Now().Format(time.RFC3339),
	}

	if data, err := json.MarshalIndent(allResults, "", "  "); err == nil {
		os.WriteFile(resultsFile, data, 0644)
		os.WriteFile(scannedFile, data, 0644)
	}

	// Always create consolidated aem-scan.txt file (even with 0 findings)
	consolidatedFile := filepath.Join(outputDir, "aem-scan.txt")
	consolidatedF, err := os.Create(consolidatedFile)
	if err == nil {
		defer consolidatedF.Close()
		
		domain := opts.Domain
		if domain == "" && opts.LiveHostsFile != "" {
			domain = "targets"
		}
		
		fmt.Fprintf(consolidatedF, "AEM Scan Results for %s\n", domain)
		fmt.Fprintf(consolidatedF, "========================================\n\n")
		fmt.Fprintf(consolidatedF, "Discovered AEM Instances: %d\n", res.DiscoveredCount)
		fmt.Fprintf(consolidatedF, "Vulnerabilities Found: %d\n\n", res.Vulnerabilities)
		
		if len(discovered) > 0 {
			fmt.Fprintf(consolidatedF, "Discovered Instances:\n")
			for _, url := range discovered {
				fmt.Fprintf(consolidatedF, "  - %s\n", url)
			}
			fmt.Fprintf(consolidatedF, "\n")
		}
		
		if len(allFindings) > 0 {
			fmt.Fprintf(consolidatedF, "Vulnerabilities:\n")
			for _, finding := range allFindings {
				fmt.Fprintf(consolidatedF, "  - [%s] %s\n", finding.Name, finding.URL)
				if finding.Description != "" {
					fmt.Fprintf(consolidatedF, "    Description: %s\n", finding.Description)
				}
			}
		} else {
			fmt.Fprintf(consolidatedF, "No vulnerabilities found.\n")
		}
	}

	// Send findings to Discord webhook if configured (only the consolidated file)
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL != "" {
		domain := opts.Domain
		if domain == "" && opts.LiveHostsFile != "" {
			domain = "targets"
		}
		
		if info, err := os.Stat(consolidatedFile); err == nil && info.Size() > 0 {
			utils.SendWebhookFileAsync(consolidatedFile, fmt.Sprintf("AEM Scan Results: %d AEM instances, %d vulnerabilities for %s", res.DiscoveredCount, res.Vulnerabilities, domain))
		}
		
		if res.Vulnerabilities > 0 {
			utils.SendWebhookLogAsync(fmt.Sprintf("AEM scan completed: %d AEM instance(s), %d vulnerability/vulnerabilities found", res.DiscoveredCount, res.Vulnerabilities))
		} else {
			utils.SendWebhookLogAsync(fmt.Sprintf("AEM scan completed for %s: %d AEM instance(s), 0 vulnerabilities", domain, res.DiscoveredCount))
		}
	}

	res.Duration = time.Since(startTime)
	log.Printf("[AEM] Scan completed: %d AEM instances, %d vulnerabilities found", res.DiscoveredCount, res.Vulnerabilities)

	return res, nil
}

// Helper functions

func sanitizeDomainForPath(domain string) string {
	// Remove protocol
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	// Replace invalid filesystem characters
	domain = strings.ReplaceAll(domain, ":", "-")
	domain = strings.ReplaceAll(domain, "/", "-")
	domain = strings.ReplaceAll(domain, "?", "-")
	domain = strings.ReplaceAll(domain, "&", "-")
	domain = strings.ReplaceAll(domain, "=", "-")
	return domain
}

func extractFindingName(line string) string {
	// Try to extract finding name from log line
	// Format varies, but typically contains keywords
	keywords := []string{
		"Exposed DefaultGetServlet",
		"Exposed QueryBulderJsonServlet",
		"Exposed GQLServlet",
		"Ability to create new JCR nodes",
		"Exposed POSTServlet",
		"Exposed LoginStatusServlet",
		"Users with default password",
		"Exposed Felix Console",
		"Enabled WCMDebugFilter",
		"Exposed WCMSuggestionsServlet",
		"Exposed CRXDE",
		"SSRF",
		"Exposed Webdav",
		"Exposed Groovy Console",
		"Exposed ACS AEM Tools",
		"VULNERABLE",
		"EXPOSED",
	}

	for _, keyword := range keywords {
		if strings.Contains(line, keyword) {
			return keyword
		}
	}

	return "Unknown vulnerability"
}

