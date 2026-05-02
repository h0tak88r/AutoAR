package githubscan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/utils"
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
	logPath := filepath.Join(baseDir, "trufflehog.log")

	cmd, err := buildTrufflehogCommand(opts)
	if err != nil {
		return nil, err
	}

	// Capture ALL output in one buffer. TruffleHog mixes JSON finding lines
	// and structured log lines (also JSON) on stdout; stderr is typically empty.
	rawOutput, runErr := cmd.CombinedOutput()

	// Split into JSON findings vs log/error lines.
	// A finding line starts with '{"SourceMetadata"' or just '{', while log
	// lines start with '{"level":'. We write them to separate files.
	var jsonLines, logLines []string
	for _, raw := range strings.Split(string(rawOutput), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// Log/error lines contain "level" key written by trufflehog's logger.
		if strings.Contains(line, `"level":`) || strings.Contains(line, `"logger":`) {
			logLines = append(logLines, line)
		} else if strings.HasPrefix(line, "{") {
			// Actual finding JSON
			jsonLines = append(jsonLines, line)
		} else {
			// Catch-all: plain text → log
			logLines = append(logLines, line)
		}
	}

	// Write separated files
	if err := utils.WriteFile(jsonPath, []byte(strings.Join(jsonLines, "\n")+"\n")); err != nil {
		return nil, fmt.Errorf("failed to write secrets.json: %w", err)
	}
	logContent := strings.Join(logLines, "\n")
	if runErr != nil {
		logContent = "ERROR: " + runErr.Error() + "\n\n" + logContent
	}
	if err := utils.WriteFile(logPath, []byte(logContent+"\n")); err != nil {
		return nil, fmt.Errorf("failed to write trufflehog.log: %w", err)
	}

	result := &Result{
		BaseDir:    baseDir,
		JSONPath:   jsonPath,
		LogPath:    logPath,
		TargetName: target,
	}

	// Write JSON results to scan directory (local-first)
	if scanID := utils.GetCurrentScanID(); scanID != "" && result != nil {
		data, readErr := os.ReadFile(result.JSONPath)
		if readErr == nil && len(data) > 0 {
			type githubFinding struct {
				TemplateID string `json:"template-id"`
				MatchedAt  string `json:"matched-at"`
				Severity   string `json:"severity"`
				Module     string `json:"module"`
				Detector   string `json:"detector,omitempty"`
				Verified   bool   `json:"verified"`
				SourceFile string `json:"source_file,omitempty"`
				Line       int    `json:"line,omitempty"`
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			findings := make([]githubFinding, 0, len(lines))
			seen := make(map[string]struct{}, len(lines))
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || !strings.HasPrefix(line, "{") {
					continue
				}
				var secret TruffleHogSecret
				if err := json.Unmarshal([]byte(line), &secret); err != nil {
					continue
				}
				template := strings.TrimSpace(secret.DetectorName)
				if template == "" {
					template = "GitHub Secret"
				}
				matchedAt := strings.TrimSpace(secret.SourceMetadata.Data.Link)
				if matchedAt == "" {
					matchedAt = strings.TrimSpace(secret.SourceMetadata.Data.File)
				}
				if matchedAt == "" {
					matchedAt = target
				}
				severity := "medium"
				if secret.Verified {
					severity = "high"
				}
				key := template + "|" + matchedAt + "|" + fmt.Sprint(secret.Verified)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, githubFinding{
					TemplateID: template,
					MatchedAt:  matchedAt,
					Severity:   severity,
					Module:     "github-secrets",
					Detector:   secret.DetectorName,
					Verified:   secret.Verified,
					SourceFile: secret.SourceMetadata.Data.File,
					Line:       secret.SourceMetadata.Data.Line,
				})
			}
			if len(findings) > 0 {
				if err := utils.WriteJSONToScanDir(scanID, "github-secrets.json", findings); err != nil {
					fmt.Printf("[WARN] Failed to write github JSON: %v\n", err)
				}
			} else {
				_ = utils.WriteNoFindingsJSON(scanID, target, "github-secrets", "github-secrets.json")
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, target, "github-secrets", "github-secrets.json")
		}
	}

	return result, nil
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
	repo = strings.TrimSuffix(repo, "/") // strip trailing slash e.g. "clerk/javascript/" -> "clerk/javascript"
	return repo
}

func ensureRepoURL(repo string) string {
	repo = strings.TrimSpace(repo)
	if strings.HasPrefix(repo, "http://") || strings.HasPrefix(repo, "https://") {
		return repo
	}
	return "https://github.com/" + repo
}

// TruffleHogSecret represents a secret found by TruffleHog
type TruffleHogSecret struct {
	DetectorName   string `json:"DetectorName"`
	Raw            string `json:"Raw"`
	Redacted       string `json:"Redacted"`
	Verified       bool   `json:"Verified"`
	SourceMetadata struct {
		Data struct {
			File string `json:"File"`
			Line int    `json:"Line"`
			Link string `json:"Link"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// generateSecretsTable parses the TruffleHog JSON output and generates a table
// with columns: secretname, secret, url
func generateSecretsTable(jsonPath, tablePath string) error {
	// Read JSON file
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to read JSON file: %w", err)
	}

	// Parse JSON (TruffleHog outputs one JSON object per line)
	lines := strings.Split(strings.TrimSpace(string(jsonData)), "\n")
	if len(lines) == 0 || (len(lines) == 1 && strings.TrimSpace(lines[0]) == "") {
		// No secrets found, create empty table
		return utils.WriteFile(tablePath, []byte("No secrets found.\n"))
	}

	var secrets []TruffleHogSecret
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var secret TruffleHogSecret
		if err := json.Unmarshal([]byte(line), &secret); err != nil {
			// Skip invalid JSON lines
			continue
		}
		secrets = append(secrets, secret)
	}

	if len(secrets) == 0 {
		return utils.WriteFile(tablePath, []byte("No secrets found.\n"))
	}

	// Generate table
	var table strings.Builder
	table.WriteString("Secret Name | Secret | URL\n")
	table.WriteString("------------|--------|-----\n")

	for _, secret := range secrets {
		secretName := secret.DetectorName
		if secretName == "" {
			secretName = "Unknown"
		}

		// Use Redacted if available, otherwise use Raw (truncated if too long)
		secretValue := secret.Redacted
		if secretValue == "" {
			secretValue = secret.Raw
			// Truncate long secrets for table display
			if len(secretValue) > 50 {
				secretValue = secretValue[:47] + "..."
			}
		}

		// Get URL from SourceMetadata
		url := secret.SourceMetadata.Data.Link
		if url == "" {
			// Construct GitHub URL from file path if available
			if secret.SourceMetadata.Data.File != "" {
				// Try to extract repo from file path or use a placeholder
				url = fmt.Sprintf("File: %s (Line %d)", secret.SourceMetadata.Data.File, secret.SourceMetadata.Data.Line)
			} else {
				url = "N/A"
			}
		}

		// Escape pipe characters in values
		secretName = strings.ReplaceAll(secretName, "|", "\\|")
		secretValue = strings.ReplaceAll(secretValue, "|", "\\|")
		url = strings.ReplaceAll(url, "|", "\\|")

		table.WriteString(fmt.Sprintf("%s | %s | %s\n", secretName, secretValue, url))
	}

	return utils.WriteFile(tablePath, []byte(table.String()))
}
