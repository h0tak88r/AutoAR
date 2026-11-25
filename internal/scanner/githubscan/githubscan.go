package githubscan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// trufflehogTimeout bounds a single TruffleHog invocation so a hung or huge
// org/repo can't pin the scan indefinitely.
const trufflehogTimeout = 30 * time.Minute

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
	ReconPath  string // recon.md digest (repo-mode scans only)
	ReconCount int    // recon pattern findings (0 in org mode)
}

// Run executes the appropriate TruffleHog command based on Options.
// It is a Go rewrite of modules/github_scan.sh focused on producing result files
// for the dashboard and webhook output; it delegates heavy work to the trufflehog binary.
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
		baseDir = filepath.Join(resultsRoot, "github", "repos", utils.SanitizeTargetSegment(target))
	case ModeOrg:
		target = opts.Org
		baseDir = filepath.Join(resultsRoot, "github", "orgs", utils.SanitizeTargetSegment(target))
	}

	if opts.Mode == ModeExperimental {
		baseDir = filepath.Join(resultsRoot, "github", "experimental", utils.SanitizeTargetSegment(target))
	}

	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create github results dir: %w", err)
	}

	jsonPath := filepath.Join(baseDir, "secrets.json")
	logPath := filepath.Join(baseDir, "trufflehog.log")

	ctx, cancel := context.WithTimeout(context.Background(), trufflehogTimeout)
	defer cancel()
	cmd, err := buildTrufflehogCommand(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Capture ALL output in one buffer. TruffleHog mixes JSON finding lines
	// and structured log lines (also JSON) on stdout; stderr is typically empty.
	rawOutput, runErr := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("trufflehog scan timed out after %s", trufflehogTimeout)
	}

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
			// Actual finding JSON — stripped of the plaintext secret before it
			// touches disk (secrets.json is indexed for org scans).
			if clean, ok := sanitizeTruffleHogLine(line); ok {
				jsonLines = append(jsonLines, clean)
			}
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

	// Repo-mode extra: pre-chewed recon pass over the actual source tree.
	// TruffleHog only reports secrets; this extracts the endpoints / infra /
	// debug surface / tech stack / comment leads a hunter would grep for by
	// hand. Failures are logged, never fatal — secrets results stand alone.
	if opts.Mode == ModeRepo || opts.Mode == ModeExperimental {
		sourceDir := filepath.Join(baseDir, "source")
		cloneURL := normalizeRepo(opts.Repo)
		if !strings.Contains(cloneURL, "://") {
			cloneURL = "https://github.com/" + cloneURL + ".git"
		}
		logger.GetLogger().Infof("[REPO-RECON] cloning %s for recon pass…", cloneURL)
		if cerr := shallowClone(cloneURL, sourceDir); cerr != nil {
			logger.GetLogger().Infof("[REPO-RECON] clone failed, recon skipped: %v", cerr)
		} else if n, digest, rerr := ReconScan(sourceDir, baseDir); rerr != nil {
			logger.GetLogger().Infof("[REPO-RECON] recon scan failed: %v", rerr)
		} else {
			result.ReconPath = digest
			result.ReconCount = n
			publishRecon(baseDir, reconIndexDir(utils.GetResultsDir(), opts.Repo))
		}
		// The checkout is only recon input: never leave a third-party repo
		// under results/ (the artifact indexer would copy and index every file).
		if rmErr := os.RemoveAll(sourceDir); rmErr != nil {
			logger.GetLogger().Infof("[REPO-RECON] could not remove clone %s: %v", sourceDir, rmErr)
		}
	}

	// Write JSON results to scan directory (local-first)
	if scanID := utils.GetCurrentScanID(); scanID != "" && result != nil {
		data, readErr := os.ReadFile(result.JSONPath)
		if readErr == nil && len(data) > 0 {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			findings := make([]map[string]interface{}, 0, len(lines))
			seen := make(map[string]struct{}, len(lines))
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || !strings.HasPrefix(line, "{") {
					continue
				}
				var native map[string]interface{}
				if err := json.Unmarshal([]byte(line), &native); err != nil {
					continue
				}
				stripPlaintextSecrets(native) // github-secrets.json → dashboard/DB/R2
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
				// Keep scanner-native payload, add dashboard-friendly helpers.
				native["severity"] = severity
				native["module"] = "github-secrets"
				native["templateId"] = template
				native["matchedAt"] = matchedAt
				if strings.TrimSpace(secret.Redacted) != "" {
					native["Redacted"] = secret.Redacted
				}
				findings = append(findings, native)
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

// plaintextSecretFields are the TruffleHog result fields that carry the secret
// itself. They are dropped before anything is persisted (secrets.json in the
// results tree, github-secrets.json → dashboard/DB/R2); detector, location,
// Verified and Redacted (or a masked stand-in) are kept.
var plaintextSecretFields = []string{"Raw", "RawV2"}

// stripPlaintextSecrets removes plaintextSecretFields from a TruffleHog result,
// filling an empty Redacted with a masked form of Raw so the finding still says
// which credential it is.
func stripPlaintextSecrets(native map[string]interface{}) {
	if red, _ := native["Redacted"].(string); strings.TrimSpace(red) == "" {
		if raw, _ := native["Raw"].(string); raw != "" {
			native["Redacted"] = utils.MaskSecret(raw)
		}
	}
	for _, k := range plaintextSecretFields {
		delete(native, k)
	}
}

// sanitizeTruffleHogLine re-encodes one TruffleHog JSON result without its
// plaintext secret fields. ok is false for lines that are not a JSON object
// (they cannot be sanitized, so they are not persisted).
func sanitizeTruffleHogLine(line string) (string, bool) {
	var native map[string]interface{}
	if err := json.Unmarshal([]byte(line), &native); err != nil {
		return "", false
	}
	stripPlaintextSecrets(native)
	b, err := json.Marshal(native)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// reconIndexDir is where the API's artifact indexer looks for a repo scan
// (indexScanArtifacts: <results>/github/repos/<repo as submitted>). The scan's
// own dir uses the sanitized "owner-repo" segment, so recon.md never reached
// the dashboard. Returns "" when the submitted repo would escape github/repos.
func reconIndexDir(resultsDir, repo string) string {
	root := filepath.Join(resultsDir, "github", "repos")
	dir := filepath.Join(root, strings.TrimSpace(repo))
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return dir
}

// publishRecon mirrors recon.md / recon.json (only those — not secrets.json or
// logs) from the scan dir into the indexer's dir.
func publishRecon(fromDir, indexDir string) {
	if indexDir == "" {
		return
	}
	if a, b := filepath.Clean(fromDir), filepath.Clean(indexDir); a == b {
		return
	}
	if err := os.MkdirAll(indexDir, 0o755); err != nil {
		logger.GetLogger().Infof("[REPO-RECON] could not create index dir %s: %v", indexDir, err)
		return
	}
	for _, name := range []string{"recon.md", "recon.json"} {
		data, err := os.ReadFile(filepath.Join(fromDir, name))
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(indexDir, name), data, 0o644); err != nil {
			logger.GetLogger().Infof("[REPO-RECON] could not publish %s: %v", name, err)
		}
	}
}

func buildTrufflehogCommand(ctx context.Context, opts Options) (*exec.Cmd, error) {
	// Disable auto-update to avoid noise
	env := append(os.Environ(),
		"TRUFFLEHOG_NO_UPDATE=true",
		"TRUFFLEHOG_AUTOUPDATE=false",
	)

	switch opts.Mode {
	case ModeRepo:
		repoURL := ensureRepoURL(opts.Repo)
		args := []string{"git", repoURL, "--json", "--no-update"}
		cmd := exec.CommandContext(ctx, "trufflehog", args...)
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
		cmd := exec.CommandContext(ctx, "trufflehog", args...)
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
		cmd := exec.CommandContext(ctx, "trufflehog", args...)
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
