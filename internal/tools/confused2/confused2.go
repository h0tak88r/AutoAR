package confused2

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	confconfig "github.com/h0tak88r/confused2/pkg/config"
	confgithub "github.com/h0tak88r/confused2/pkg/github"
	conflogger "github.com/h0tak88r/confused2/pkg/logger"
	confweb "github.com/h0tak88r/confused2/pkg/web"
)

// WebOptions controls how Confused2 web scans are run via the embedded engine.
// Either Targets or TargetFile must be provided.
type WebOptions struct {
	Targets    []string
	TargetFile string
	Deep       bool
	MaxDepth   int
	Languages  []string
	Workers    int
	OutputDir  string
}

// WebResult summarizes a Confused2 web scan.
type WebResult struct {
	OutputFile string
	Targets    int
	Findings   int
	Duration   time.Duration
}

// GitHubOptions controls Confused2 GitHub scans (repo or org).
type GitHubOptions struct {
	Repo       string
	Org        string
	Languages  []string
	SafeSpaces []string
	MaxRepos   int
	Deep       bool
	Workers    int
	GitHubToken string
	OutputDir  string
}

// GitHubResult summarizes a Confused2 GitHub scan.
type GitHubResult struct {
	OutputFile string
	Targets    int
	Findings   int
	Duration   time.Duration
}

// WebScan runs Confused2's web engine against the provided targets and writes
// a JSON summary file under OutputDir. It does not spawn the confused2 CLI.
func WebScan(opts WebOptions) (*WebResult, error) {
	if len(opts.Targets) == 0 && strings.TrimSpace(opts.TargetFile) == "" {
		return nil, fmt.Errorf("either Targets or TargetFile must be provided")
	}
	if opts.OutputDir == "" {
		opts.OutputDir = "."
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 3
	}
	if opts.Workers <= 0 {
		opts.Workers = 10
	}

	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", opts.OutputDir, err)
	}

	// Resolve targets from file if needed.
	targets := opts.Targets
	if len(targets) == 0 {
		var err error
		targets, err = readLines(opts.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read targets from %s: %w", opts.TargetFile, err)
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided for Confused2 web scan")
	}

	cfg := confconfig.Default()
	if len(opts.Languages) > 0 {
		cfg.Languages = opts.Languages
	}
	cfg.DeepScan = opts.Deep
	cfg.Workers = opts.Workers

	logPath := filepath.Join(opts.OutputDir, "confused2-web.log")
	log, err := conflogger.New(conflogger.INFO, false, logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Confused2 logger: %w", err)
	}
	defer log.Close()

	webScanner := confweb.New(log, cfg.UserAgent, cfg.GetTimeout())

	type finding struct {
		Target     string   `json:"target"`
		Type       string   `json:"type"`
		Language   string   `json:"language"`
		Vulnerable []string `json:"vulnerable_packages"`
		Total      int      `json:"total_packages"`
	}

	var allFindings []finding
	start := time.Now()

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		results, err := webScanner.ScanTarget(t, cfg.Languages, cfg.DeepScan, opts.MaxDepth)
		if err != nil {
			log.Warn("Failed to scan target %s: %v", t, err)
			continue
		}
		for _, r := range results {
			allFindings = append(allFindings, finding{
				Target:     r.Target,
				Type:       r.Type,
				Language:   r.Language,
				Vulnerable: append([]string(nil), r.Vulnerable...),
				Total:      r.Total,
			})
		}
	}

	outPath := filepath.Join(opts.OutputDir, "confused2-web-results.json")
	data, err := json.MarshalIndent(allFindings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Confused2 web results: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write Confused2 web results: %w", err)
	}

	return &WebResult{
		OutputFile: outPath,
		Targets:    len(targets),
		Findings:   len(allFindings),
		Duration:   time.Since(start),
	}, nil
}

// GitHubRepoScan runs Confused2's GitHub repository engine and writes a JSON
// summary under OutputDir.
func GitHubRepoScan(opts GitHubOptions) (*GitHubResult, error) {
	if strings.TrimSpace(opts.Repo) == "" {
		return nil, fmt.Errorf("repo is required for GitHubRepoScan")
	}
	return runGitHubScan(opts, true)
}

// GitHubOrgScan runs Confused2's GitHub organization engine and writes a JSON
// summary under OutputDir.
func GitHubOrgScan(opts GitHubOptions) (*GitHubResult, error) {
	if strings.TrimSpace(opts.Org) == "" {
		return nil, fmt.Errorf("org is required for GitHubOrgScan")
	}
	return runGitHubScan(opts, false)
}

func runGitHubScan(opts GitHubOptions, isRepo bool) (*GitHubResult, error) {
	if opts.OutputDir == "" {
		opts.OutputDir = "."
	}
	if opts.Workers <= 0 {
		opts.Workers = 10
	}
	if opts.MaxRepos <= 0 {
		opts.MaxRepos = 50
	}

	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory %s: %w", opts.OutputDir, err)
	}

	cfg := confconfig.Default()
	cfg.GitHubToken = opts.GitHubToken
	cfg.Workers = opts.Workers
	cfg.MaxRepos = opts.MaxRepos
	if len(opts.Languages) > 0 {
		cfg.Languages = opts.Languages
	}
	cfg.SafeSpaces = opts.SafeSpaces

	logPath := filepath.Join(opts.OutputDir, "confused2-github.log")
	log, err := conflogger.New(conflogger.INFO, false, logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Confused2 logger: %w", err)
	}
	defer log.Close()

	client, err := confgithub.New(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Confused2 GitHub client: %w", err)
	}

	type finding struct {
		Target     string   `json:"target"`
		Type       string   `json:"type"`
		Language   string   `json:"language"`
		Vulnerable []string `json:"vulnerable_packages"`
		Total      int      `json:"total_packages"`
	}

	var allFindings []finding
	start := time.Now()

	if isRepo {
		results, err := client.ScanRepository(opts.Repo, cfg.Languages, cfg.SafeSpaces, opts.Deep)
		if err != nil {
			return nil, fmt.Errorf("Confused2 GitHub repo scan failed: %w", err)
		}
		for _, r := range results {
			allFindings = append(allFindings, finding{
				Target:     r.Target,
				Type:       r.Type,
				Language:   r.Language,
				Vulnerable: append([]string(nil), r.Vulnerable...),
				Total:      r.Total,
			})
		}
	} else {
		results, err := client.ScanOrganization(opts.Org, cfg.Languages, cfg.SafeSpaces, cfg.MaxRepos, opts.Deep)
		if err != nil {
			return nil, fmt.Errorf("Confused2 GitHub org scan failed: %w", err)
		}
		for _, r := range results {
			allFindings = append(allFindings, finding{
				Target:     r.Target,
				Type:       r.Type,
				Language:   r.Language,
				Vulnerable: append([]string(nil), r.Vulnerable...),
				Total:      r.Total,
			})
		}
	}

	outPath := filepath.Join(opts.OutputDir, "confused2-github-results.json")
	data, err := json.MarshalIndent(allFindings, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Confused2 GitHub results: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write Confused2 GitHub results: %w", err)
	}

	return &GitHubResult{
		OutputFile: outPath,
		Targets:    len(allFindings),
		Findings:   len(allFindings),
		Duration:   time.Since(start),
	}, nil
}

// readLines reads non-empty trimmed lines from a file.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
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
