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

	// Save discovered instances
	if len(discovered) > 0 {
		discoveredFH, err := os.Create(discoveredFile)
		if err == nil {
			for _, url := range discovered {
				fmt.Fprintln(discoveredFH, url)
			}
			discoveredFH.Close()
		}
		
		// Send findings to Discord webhook if configured
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			if info, err := os.Stat(discoveredFile); err == nil && info.Size() > 0 {
				domain := opts.Domain
				if domain == "" && opts.LiveHostsFile != "" {
					domain = "targets"
				}
				utils.SendWebhookFileAsync(discoveredFile, fmt.Sprintf("AEM Discovery: AEM instances found (%d discovered)", len(discovered)))
				utils.SendWebhookLogAsync(fmt.Sprintf("AEM discovery: %d AEM instance(s) found", len(discovered)))
			}
		}
	} else {
		// No findings
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			utils.SendWebhookLogAsync("AEM discovery completed with 0 AEM instances found")
		}
	}

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

	// Save findings as JSON
	if len(findings) > 0 {
		if data, err := json.MarshalIndent(findings, "", "  "); err == nil {
			os.WriteFile(resultsFile, data, 0644)
		}
		
		// Send findings to Discord webhook if configured
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			if info, err := os.Stat(resultsFile); err == nil && info.Size() > 0 {
				utils.SendWebhookFileAsync(resultsFile, fmt.Sprintf("AEM Finding: Vulnerabilities found for %s (%d findings)", url, len(findings)))
			}
			utils.SendWebhookLogAsync(fmt.Sprintf("AEM scan completed for %s - %d vulnerability/vulnerabilities found", url, len(findings)))
		}
	} else {
		// No findings
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			utils.SendWebhookLogAsync(fmt.Sprintf("AEM scan completed for %s with 0 findings", url))
		}
	}

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

	if len(discovered) == 0 {
		log.Printf("[AEM] No AEM instances discovered")
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

	// Save all results
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

	// Send findings to Discord webhook if configured
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL != "" {
		if res.Vulnerabilities > 0 {
			if info, err := os.Stat(resultsFile); err == nil && info.Size() > 0 {
				domain := opts.Domain
				if domain == "" && opts.LiveHostsFile != "" {
					domain = "targets"
				}
				utils.SendWebhookFileAsync(resultsFile, fmt.Sprintf("AEM Scan Summary: %d AEM instances, %d vulnerabilities for %s", res.DiscoveredCount, res.Vulnerabilities, domain))
			}
			utils.SendWebhookLogAsync(fmt.Sprintf("AEM scan completed: %d AEM instance(s), %d vulnerability/vulnerabilities found", res.DiscoveredCount, res.Vulnerabilities))
		} else {
			domain := opts.Domain
			if domain == "" && opts.LiveHostsFile != "" {
				domain = "targets"
			}
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

