package githubscan

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Mode string

const (
	ModeRepo         Mode = "scan"
	ModeOrg          Mode = "org"
	ModeExperimental Mode = "experimental"
)

type Options struct {
	Mode    Mode
	Repo    string // owner/repo or full URL
	Org     string
	Verbose bool
}

type Result struct {
	BaseDir    string
	JSONPath   string
	TablePath  string
	LogPath    string
	TargetName string
}

// Run executes the appropriate TruffleHog command based on Options.
// It is a Go rewrite of modules/github_scan.sh focused on producing result files
// that the Discord bot can send; it delegates heavy work to the trufflehog binary.
func Run(opts Options) (*Result, error) {
	if _, err := exec.LookPath("trufflehog"); err != nil {
		return nil, fmt.Errorf("trufflehog not found in PATH; install it or ensure it is available in the Docker image")
	}

	resultsRoot := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsRoot == "" {
		resultsRoot = "new-results"
	}

	switch opts.Mode {
	case ModeRepo, ModeExperimental:
		if opts.Repo == "" {
			return nil, fmt.Errorf("repository (-r) is required")
		}
	case ModeOrg:
		if opts.Org == "" {
			return nil, fmt.Errorf("organization (-o) is required")
		}
	default:
		return nil, fmt.Errorf("unsupported github mode: %s", opts.Mode)
	}

	var baseDir, target string
	switch opts.Mode {
	case ModeRepo, ModeExperimental:
		target = normalizeRepo(opts.Repo)
		baseDir = filepath.Join(resultsRoot, "github", "repos", target)
	case ModeOrg:
		target = opts.Org
		baseDir = filepath.Join(resultsRoot, "github", "orgs", target)
	}

	if opts.Mode == ModeExperimental {
		baseDir = filepath.Join(resultsRoot, "github", "experimental", target)
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create github results dir: %w", err)
	}

	jsonPath := filepath.Join(baseDir, "secrets.json")
	tablePath := filepath.Join(baseDir, "secrets_table.txt") // reserved for future processing
	logPath := filepath.Join(baseDir, "trufflehog.log")

	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets.json: %w", err)
	}
	defer jsonFile.Close()

	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create trufflehog.log: %w", err)
	}
	defer logFile.Close()

	cmd, err := buildTrufflehogCommand(opts)
	if err != nil {
		return nil, err
	}
	cmd.Stdout = jsonFile
	cmd.Stderr = logFile

	if err := cmd.Run(); err != nil {
		// Still return paths so caller/bot can inspect logs
		return &Result{
			BaseDir:    baseDir,
			JSONPath:   jsonPath,
			TablePath:  tablePath,
			LogPath:    logPath,
			TargetName: target,
		}, fmt.Errorf("trufflehog command failed: %w", err)
	}

	return &Result{
		BaseDir:    baseDir,
		JSONPath:   jsonPath,
		TablePath:  tablePath,
		LogPath:    logPath,
		TargetName: target,
	}, nil
}

func buildTrufflehogCommand(opts Options) (*exec.Cmd, error) {
	// Disable auto-update to avoid noise
	env := append(os.Environ(),
		"TRUFFLEHOG_NO_UPDATE=true",
		"TRUFFLEHOG_AUTOUPDATE=false",
	)

	switch opts.Mode {
	case ModeRepo:
		repoURL := ensureRepoURL(opts.Repo)
		args := []string{"git", repoURL, "--json", "--no-update"}
		cmd := exec.Command("trufflehog", args...)
		cmd.Env = env
		return cmd, nil

	case ModeOrg:
		if os.Getenv("GITHUB_TOKEN") == "" {
			return nil, fmt.Errorf("GITHUB_TOKEN is required for organization scans")
		}
		args := []string{
			"github",
			fmt.Sprintf("--org=%s", opts.Org),
			"--issue-comments",
			"--pr-comments",
			"--json",
			"--no-update",
			"--token", os.Getenv("GITHUB_TOKEN"),
		}
		cmd := exec.Command("trufflehog", args...)
		cmd.Env = env
		return cmd, nil

	case ModeExperimental:
		repoURL := ensureRepoURL(opts.Repo)
		if !strings.HasSuffix(repoURL, ".git") {
			repoURL = repoURL + ".git"
		}
		args := []string{
			"github-experimental",
			"--repo", repoURL,
			"--object-discovery",
			"--json",
			"--no-update",
		}
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			args = append(args, "--token", token)
		}
		cmd := exec.Command("trufflehog", args...)
		cmd.Env = env
		return cmd, nil
	default:
		return nil, fmt.Errorf("unsupported github mode: %s", opts.Mode)
	}
}

func normalizeRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	repo = strings.TrimPrefix(repo, "https://github.com/")
	repo = strings.TrimPrefix(repo, "http://github.com/")
	repo = strings.TrimSuffix(repo, ".git")
	return repo
}

func ensureRepoURL(repo string) string {
	repo = strings.TrimSpace(repo)
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		return repo
	}
	return "https://github.com/" + repo
}
