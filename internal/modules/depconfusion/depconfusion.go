package depconfusion

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	confused2 "github.com/h0tak88r/AutoAR/v3/internal/tools/confused2"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/subdomains"
	"github.com/projectdiscovery/httpx/runner"
)

type Options struct {
	Mode          string   // "web", "github"
	Target        string   // URL, domain, repo, or org
	Full          bool     // Enable full scan (subdomain enum + live hosts)
	GitHubRepo    string   // For github repo mode
	GitHubOrg     string   // For github org mode
	Targets       []string // Multiple URLs for web mode
	TargetFile    string   // File with targets
	Workers       int      // Number of workers
	Verbose       bool     // Verbose output
	OutputDir     string   // Output directory
	GitHubToken   string   // GitHub token
	Subdomain     string   // Subdomain for directory structure (optional)
}

// Run executes the dependency confusion scan based on options
func Run(opts Options) error {
	// Set output directory
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	var outputDir string
	var err error

	switch opts.Mode {
	case "web":
		if opts.Full {
			// Full scan: subdomain enum + live hosts + depconfusion
			err = runWebFull(opts, resultsDir)
		} else if opts.TargetFile != "" {
			// Scan from file
			err = runWebFromFile(opts, resultsDir)
		} else {
			// Single or multiple URLs
			err = runWeb(opts, resultsDir)
		}
	case "github":
		if opts.GitHubRepo != "" {
			err = runGitHubRepo(opts, resultsDir)
		} else if opts.GitHubOrg != "" {
			err = runGitHubOrg(opts, resultsDir)
		} else {
			return fmt.Errorf("github mode requires either repo or org")
		}
	default:
		return fmt.Errorf("invalid mode: %s. Use 'web' or 'github'", opts.Mode)
	}

	_ = outputDir // Suppress unused variable warning
	return err
}

func runWeb(opts Options, resultsDir string) error {
	outputDir := filepath.Join(resultsDir, "depconfusion", "web")
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	res, err := confused2.WebScan(confused2.WebOptions{
		Targets:   opts.Targets,
		Deep:      true,
		MaxDepth:  3,
		Workers:   opts.Workers,
		OutputDir: outputDir,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[OK] Web dependency confusion scan completed. Findings: %d. Results saved to %s\n", res.Findings, res.OutputFile)
	return nil
}

func runWebFromFile(opts Options, resultsDir string) error {
	if _, err := os.Stat(opts.TargetFile); os.IsNotExist(err) {
		return fmt.Errorf("target file not found: %s", opts.TargetFile)
	}

	// Use subdomain directory if provided, otherwise use default
	outputDir := opts.OutputDir
	if outputDir == "" {
		if opts.Subdomain != "" {
			outputDir = filepath.Join(resultsDir, opts.Subdomain, "depconfusion", "web-file")
		} else {
			outputDir = filepath.Join(resultsDir, "depconfusion", "web-file")
		}
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	res, err := confused2.WebScan(confused2.WebOptions{
		TargetFile: opts.TargetFile,
		Deep:       false,
		MaxDepth:   3,
		Workers:    opts.Workers,
		OutputDir:  outputDir,
	})
	if err != nil {
		return err
	}

	// Convert JSON to human-readable text file
	textFile := filepath.Join(outputDir, "depconfusion-results.txt")
	if err := convertJSONToText(res.OutputFile, textFile); err != nil {
		log.Printf("[WARN] Failed to convert JSON to text: %v", err)
	}

	fmt.Printf("[OK] Web file dependency confusion scan completed. Findings: %d. Results saved to %s\n", res.Findings, res.OutputFile)
	return nil
}

func runWebFull(opts Options, resultsDir string) error {
	domain := opts.Target
	if domain == "" {
		return fmt.Errorf("domain is required for full scan")
	}

	outputDir := filepath.Join(resultsDir, "depconfusion", fmt.Sprintf("web-full-%s", domain))
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	subsDir := filepath.Join(outputDir, "subs")
	if err := os.MkdirAll(subsDir, 0o755); err != nil {
		return fmt.Errorf("failed to create subs directory: %v", err)
	}

	// Step 1: Subdomain enumeration (using library-based subdomains module)
	fmt.Println("[INFO] Step 1: Enumerating subdomains...")
	subdomainsList, err := subdomains.EnumerateSubdomains(domain, opts.Workers)
	if err != nil {
		return fmt.Errorf("subdomain enumeration failed: %v", err)
	}
	if len(subdomainsList) == 0 {
		return fmt.Errorf("no subdomains found for %s", domain)
	}

	subsFile := filepath.Join(subsDir, "all-subs.txt")
	if err := os.WriteFile(subsFile, []byte(strings.Join(subdomainsList, "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write subs file: %v", err)
	}

	// Step 2: Live host detection
	fmt.Println("[INFO] Step 2: Detecting live hosts...")

	// Read subdomains from file
	subsFileHandle, err := os.Open(subsFile)
	if err != nil {
		return fmt.Errorf("failed to open subdomains file: %v", err)
	}
	defer subsFileHandle.Close()

	var targets []string
	scanner := bufio.NewScanner(subsFileHandle)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read subdomains file: %v", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no subdomains found for %s", domain)
	}

	liveFile := filepath.Join(subsDir, "live-subs.txt")
	f, err := os.Create(liveFile)
	if err != nil {
		return fmt.Errorf("failed to create live file: %v", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	defer writer.Flush()

	var liveHosts []string
	var mu sync.Mutex

	// Configure httpx options with callback
	httpxOptions := runner.Options{
		InputTargetHost: targets,
		Threads:        100,
		Silent:         true,
		NoColor:        true,
		FollowRedirects: true,
		FollowHostRedirects: true,
		OnResult: func(result runner.Result) {
			if result.URL != "" {
				mu.Lock()
				liveHosts = append(liveHosts, result.URL)
				mu.Unlock()
			}
		},
	}

	// Validate options
	if err := httpxOptions.ValidateOptions(); err != nil {
		return fmt.Errorf("failed to validate httpx options: %v", err)
	}

	// Create httpx runner
	httpxRunner, err := runner.New(&httpxOptions)
	if err != nil {
		return fmt.Errorf("failed to create httpx runner: %v", err)
	}
	defer httpxRunner.Close()

	// Run enumeration
	httpxRunner.RunEnumeration()

	// Write results to file
	for _, host := range liveHosts {
		writer.WriteString(host + "\n")
	}
	writer.Flush()

	// Check if we have live hosts
	data, _ := os.ReadFile(liveFile)
	if len(strings.TrimSpace(string(data))) == 0 {
		return fmt.Errorf("no live hosts found for %s", domain)
	}

	// Step 3: Dependency confusion scanning
	fmt.Println("[INFO] Step 3: Scanning live hosts for dependency confusion...")
	res, err := confused2.WebScan(confused2.WebOptions{
		TargetFile: liveFile,
		Deep:       false,
		MaxDepth:   3,
		Workers:    opts.Workers,
		OutputDir:  outputDir,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[OK] Full web dependency confusion scan completed. Findings: %d. Results saved to %s\n", res.Findings, res.OutputFile)
	return nil
}

func runGitHubRepo(opts Options, resultsDir string) error {
	outputDir := filepath.Join(resultsDir, "depconfusion", fmt.Sprintf("github-%s", strings.ReplaceAll(opts.GitHubRepo, "/", "-")))
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Resolve GitHub token
	token := opts.GitHubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	res, err := confused2.GitHubRepoScan(confused2.GitHubOptions{
		Repo:        opts.GitHubRepo,
		GitHubToken: token,
		OutputDir:   outputDir,
		Workers:     opts.Workers,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[OK] GitHub repository dependency confusion scan completed. Findings: %d. Results saved to %s\n", res.Findings, res.OutputFile)
	return nil
}

func runGitHubOrg(opts Options, resultsDir string) error {
	outputDir := filepath.Join(resultsDir, "depconfusion", fmt.Sprintf("github-org-%s", opts.GitHubOrg))
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Resolve GitHub token
	token := opts.GitHubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	res, err := confused2.GitHubOrgScan(confused2.GitHubOptions{
		Org:         opts.GitHubOrg,
		GitHubToken: token,
		OutputDir:   outputDir,
		Workers:     opts.Workers,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[OK] GitHub organization dependency confusion scan completed. Findings: %d. Results saved to %s\n", res.Findings, res.OutputFile)
	return nil
}

// convertJSONToText converts the JSON results file to a human-readable text file
func convertJSONToText(jsonFile, textFile string) error {
	// Read JSON file
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %w", err)
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Create text file
	f, err := os.Create(textFile)
	if err != nil {
		return fmt.Errorf("failed to create text file: %w", err)
	}
	defer f.Close()

	// Write header
	fmt.Fprintf(f, "=== Dependency Confusion Scan Results ===\n\n")
	fmt.Fprintf(f, "Total Findings: %d\n\n", len(results))

	// Write each finding
	for i, result := range results {
		fmt.Fprintf(f, "--- Finding %d ---\n", i+1)
		
		if target, ok := result["target"].(string); ok {
			// Fix target format: convert "www.fasttest.com:package.json" to "https://www.fasttest.com/package.json"
			normalizedTarget := normalizeTargetURL(target)
			fmt.Fprintf(f, "Target: %s\n", normalizedTarget)
		}
		
		if resultType, ok := result["type"].(string); ok {
			fmt.Fprintf(f, "Type: %s\n", resultType)
		}
		
		if language, ok := result["language"].(string); ok {
			fmt.Fprintf(f, "Language: %s\n", language)
		}
		
		if totalPkgs, ok := result["total_packages"].(float64); ok {
			fmt.Fprintf(f, "Total Packages: %.0f\n", totalPkgs)
		}
		
		if vulnPkgs, ok := result["vulnerable_packages"]; ok && vulnPkgs != nil {
			if vulnList, ok := vulnPkgs.([]interface{}); ok && len(vulnList) > 0 {
				fmt.Fprintf(f, "Vulnerable Packages:\n")
				for _, pkg := range vulnList {
					fmt.Fprintf(f, "  - %v\n", pkg)
				}
			} else {
				fmt.Fprintf(f, "Vulnerable Packages: None\n")
			}
		} else {
			fmt.Fprintf(f, "Vulnerable Packages: None\n")
		}
		
		fmt.Fprintf(f, "\n")
	}

	return nil
}

// normalizeTargetURL converts malformed target formats to proper URLs
// Examples:
//   - "www.fasttest.com:package.json" -> "https://www.fasttest.com/package.json"
//   - "https://www.fasttest.com:package.json" -> "https://www.fasttest.com/package.json"
//   - "www.fasttest.com/package.json" -> "https://www.fasttest.com/package.json"
func normalizeTargetURL(target string) string {
	if target == "" {
		return target
	}
	
	// If target already has protocol, check for colon separator issue
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		// Check if there's a colon after the domain (malformed format)
		// e.g., "https://www.fasttest.com:package.json"
		parts := strings.SplitN(target, "://", 2)
		if len(parts) == 2 {
			urlPart := parts[1]
			// Check for colon separator (should be slash)
			if idx := strings.Index(urlPart, ":"); idx > 0 {
				// Check if it's a port number (has numbers after colon) or a file path
				afterColon := urlPart[idx+1:]
				// If it doesn't look like a port (contains non-numeric chars or is a filename), it's malformed
				if !strings.Contains(afterColon, "/") && strings.Contains(afterColon, ".") {
					// This is likely "domain:filename" format, convert to "domain/filename"
					domain := urlPart[:idx]
					filename := afterColon
					return parts[0] + "://" + domain + "/" + filename
				}
			}
		}
		return target
	}
	
	// No protocol - check for colon separator
	if idx := strings.Index(target, ":"); idx > 0 {
		// Check if it's a port number or a filename
		afterColon := target[idx+1:]
		// If it contains a dot and no slash, it's likely a filename
		if strings.Contains(afterColon, ".") && !strings.Contains(afterColon, "/") {
			// Convert "domain:filename" to "https://domain/filename"
			domain := target[:idx]
			filename := afterColon
			return "https://" + domain + "/" + filename
		}
		// Otherwise it might be a port number, add protocol
		if !strings.HasPrefix(target, "http") {
			return "https://" + target
		}
	}
	
	// If no protocol and no colon, add https://
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	
	return target
}

