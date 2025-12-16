package depconfusion

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

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
}

// Run executes the dependency confusion scan based on options
func Run(opts Options) error {
	// Find confused2 binary
	confusedBin := findConfused2()
	if confusedBin == "" {
		return fmt.Errorf("confused2 tool not found. Please install it with: go install github.com/h0tak88r/confused2/cmd/confused2@latest")
	}

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
			err = runWebFull(confusedBin, opts, resultsDir)
		} else if opts.TargetFile != "" {
			// Scan from file
			err = runWebFromFile(confusedBin, opts, resultsDir)
		} else {
			// Single or multiple URLs
			err = runWeb(confusedBin, opts, resultsDir)
		}
	case "github":
		if opts.GitHubRepo != "" {
			err = runGitHubRepo(confusedBin, opts, resultsDir)
		} else if opts.GitHubOrg != "" {
			err = runGitHubOrg(confusedBin, opts, resultsDir)
		} else {
			return fmt.Errorf("github mode requires either repo or org")
		}
	default:
		return fmt.Errorf("invalid mode: %s. Use 'web' or 'github'", opts.Mode)
	}

	_ = outputDir // Suppress unused variable warning
	return err
}

func findConfused2() string {
	// Check common locations
	locations := []string{
		"confused2",
		"/home/sallam/go/bin/confused2",
		"/usr/local/bin/confused2",
		"/app/bin/confused2",
	}

	for _, loc := range locations {
		if _, err := exec.LookPath(loc); err == nil {
			return loc
		}
	}

	// Try PATH
	if path, err := exec.LookPath("confused2"); err == nil {
		return path
	}

	return ""
}

func runWeb(confusedBin string, opts Options, resultsDir string) error {
	outputDir := filepath.Join(resultsDir, "depconfusion", "web")
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build command
	cmd := exec.Command(confusedBin, "web", "--deep")
	cmd.Args = append(cmd.Args, opts.Targets...)
	cmd.Args = append(cmd.Args, "--output-dir", outputDir)

	// Run command
	outputFile := filepath.Join(outputDir, "web-scan-output.txt")
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("web scan failed: %v", err)
	}

	fmt.Printf("[OK] Web dependency confusion scan completed. Results saved to %s\n", outputFile)
	return nil
}

func runWebFromFile(confusedBin string, opts Options, resultsDir string) error {
	if _, err := os.Stat(opts.TargetFile); os.IsNotExist(err) {
		return fmt.Errorf("target file not found: %s", opts.TargetFile)
	}

	outputDir := filepath.Join(resultsDir, "depconfusion", "web-file")
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build command
	cmd := exec.Command(confusedBin, "web", "--target-file", opts.TargetFile)
	cmd.Args = append(cmd.Args, "--output-dir", outputDir)

	// Run command
	outputFile := filepath.Join(outputDir, "web-file-scan-output.txt")
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("web file scan failed: %v", err)
	}

	fmt.Printf("[OK] Web file dependency confusion scan completed. Results saved to %s\n", outputFile)
	return nil
}

func runWebFull(confusedBin string, opts Options, resultsDir string) error {
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

	// Step 1: Subdomain enumeration
	fmt.Println("[INFO] Step 1: Enumerating subdomains...")
	subfinderBin := findSubfinder()
	if subfinderBin == "" {
		return fmt.Errorf("subfinder not found. Please install it with: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
	}

	subsFile := filepath.Join(subsDir, "all-subs.txt")
	cmd := exec.Command(subfinderBin, "-d", domain, "-silent")
	f, err := os.Create(subsFile)
	if err != nil {
		return fmt.Errorf("failed to create subs file: %v", err)
	}
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		f.Close()
		return fmt.Errorf("subdomain enumeration failed: %v", err)
	}
	f.Close()

	// Check if we have subdomains
	data, _ := os.ReadFile(subsFile)
	if len(strings.TrimSpace(string(data))) == 0 {
		return fmt.Errorf("no subdomains found for %s", domain)
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
	f, err = os.Create(liveFile)
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
	data, _ = os.ReadFile(liveFile)
	if len(strings.TrimSpace(string(data))) == 0 {
		return fmt.Errorf("no live hosts found for %s", domain)
	}

	// Step 3: Dependency confusion scanning
	fmt.Println("[INFO] Step 3: Scanning live hosts for dependency confusion...")
	cmd = exec.Command(confusedBin, "web", "--target-file", liveFile)
	cmd.Args = append(cmd.Args, "--output-dir", outputDir)

	outputFile := filepath.Join(outputDir, "web-full-scan-output.txt")
	f, err = os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("full web scan failed: %v", err)
	}

	fmt.Printf("[OK] Full web dependency confusion scan completed. Results saved to %s\n", outputFile)
	return nil
}

func runGitHubRepo(confusedBin string, opts Options, resultsDir string) error {
	outputDir := filepath.Join(resultsDir, "depconfusion", fmt.Sprintf("github-%s", strings.ReplaceAll(opts.GitHubRepo, "/", "-")))
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build command
	cmd := exec.Command(confusedBin, "github", "repo", opts.GitHubRepo)
	cmd.Args = append(cmd.Args, "--output-dir", outputDir)

	// Add GitHub token if available
	if opts.GitHubToken != "" {
		cmd.Args = append(cmd.Args, "--github-token", opts.GitHubToken)
	} else if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		cmd.Args = append(cmd.Args, "--github-token", token)
	}

	// Run command
	outputFile := filepath.Join(outputDir, "github-scan-output.txt")
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("GitHub repo scan failed: %v", err)
	}

	fmt.Printf("[OK] GitHub repository dependency confusion scan completed. Results saved to %s\n", outputFile)
	return nil
}

func runGitHubOrg(confusedBin string, opts Options, resultsDir string) error {
	outputDir := filepath.Join(resultsDir, "depconfusion", fmt.Sprintf("github-org-%s", opts.GitHubOrg))
	if opts.OutputDir != "" {
		outputDir = opts.OutputDir
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build command
	cmd := exec.Command(confusedBin, "github", "org", opts.GitHubOrg)
	cmd.Args = append(cmd.Args, "--output-dir", outputDir)

	// Add GitHub token if available
	if opts.GitHubToken != "" {
		cmd.Args = append(cmd.Args, "--github-token", opts.GitHubToken)
	} else if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		cmd.Args = append(cmd.Args, "--github-token", token)
	}

	// Run command
	outputFile := filepath.Join(outputDir, "github-org-scan-output.txt")
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer f.Close()

	cmd.Stdout = f
	cmd.Stderr = f

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("GitHub org scan failed: %v", err)
	}

	fmt.Printf("[OK] GitHub organization dependency confusion scan completed. Results saved to %s\n", outputFile)
	return nil
}

func findSubfinder() string {
	locations := []string{
		"subfinder",
		"/home/sallam/go/bin/subfinder",
		"/usr/local/bin/subfinder",
		"/app/bin/subfinder",
	}

	for _, loc := range locations {
		if _, err := exec.LookPath(loc); err == nil {
			return loc
		}
	}

	if path, err := exec.LookPath("subfinder"); err == nil {
		return path
	}

	return ""
}

