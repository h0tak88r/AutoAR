// Package exposure scans live hosts for exposed API documentation endpoints
// (Swagger/OpenAPI/GraphQL) and exposed Docker artefacts (Dockerfile,
// docker-compose.yml, etc.).  Findings are written to a human-readable text
// file and returned for further processing.
package exposure

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// ---- probe lists -----------------------------------------------------------

var apiDocPaths = []string{
	"/swagger",
	"/swagger-ui",
	"/swagger-ui.html",
	"/swagger-ui/index.html",
	"/swagger.json",
	"/swagger.yaml",
	"/swagger.yml",
	"/openapi.json",
	"/openapi.yaml",
	"/openapi.yml",
	"/api-docs",
	"/api/docs",
	"/api/swagger",
	"/v1/api-docs",
	"/v2/api-docs",
	"/v3/api-docs",
	"/api/v1/docs",
	"/api/v2/docs",
	"/api/v3/docs",
	"/graphql",
	"/graphiql",
	"/altair",
	"/playground",
	"/__graphql",
	"/api/graphql",
}

var dockerPaths = []string{
	"/Dockerfile",
	"/docker-compose.yml",
	"/docker-compose.yaml",
	"/docker-compose.override.yml",
	"/docker-compose.prod.yml",
	"/.dockerignore",
	"/.docker/config.json",
	"/docker-entrypoint.sh",
	"/docker-entrypoint.d/",
}

// keywords for body confirmation
var apiDocKeywords = []string{"swagger", "openapi", "\"info\"", "\"paths\"", "graphql", "GraphQL", "introspection"}
var dockerKeywords = []string{"FROM ", "RUN ", "CMD ", "ENTRYPOINT ", "version:", "services:", "image:"}

// ---- public API ------------------------------------------------------------

// Finding describes a single exposure found on a host.
type Finding struct {
	Host       string
	Path       string
	Category   string // "api-docs" or "docker"
	StatusCode int
	Evidence   string // keyword that confirmed the finding
}

// String returns a one-line representation for report files.
func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s%s [HTTP %d] (matched: %s)", f.Category, f.Host, f.Path, f.StatusCode, f.Evidence)
}

// Options for the exposure scanner.
type Options struct {
	Domain         string
	LiveHostsFile  string        // path to a file with one URL/host per line
	Threads        int           // concurrency (default 50)
	Timeout        time.Duration // per-request timeout (default 8s)
	OutputDir      string        // override output directory
}

// Result holds all findings and the path to the written report.
type Result struct {
	Findings []Finding
	Output   string
}

// Run performs the exposure scan and returns the result.
func Run(opts Options) (*Result, error) {
	if opts.Threads <= 0 {
		opts.Threads = 50
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}

	hosts, err := loadHosts(opts)
	if err != nil {
		return nil, fmt.Errorf("exposure: %w", err)
	}
	if len(hosts) == 0 {
		log.Printf("[exposure] No hosts to scan")
		return &Result{}, nil
	}

	log.Printf("[exposure] Scanning %d hosts for exposed API docs and Docker artefacts (threads=%d)", len(hosts), opts.Threads)

	findings := scanAll(hosts, opts.Threads, opts.Timeout)

	outPath, err := writeOutput(opts, findings)
	if err != nil {
		log.Printf("[exposure] Warning: could not write output: %v", err)
	}

	// Write structured JSON for the dashboard (JSON-only pipeline).
	// Each Finding maps to: TARGET=host+path, VULN TYPE=category+path, SEV=derived, MODULE=Exposure.
	if scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID"); scanID != "" {
		type exposureFinding struct {
			TemplateID string `json:"template-id"` // VULN TYPE column: "api-docs: /swagger.json"
			MatchedAt  string `json:"matched-at"`  // TARGET column: full URL
			Severity   string `json:"severity"`
			Category   string `json:"category"`
			Evidence   string `json:"evidence"`
			StatusCode int    `json:"status_code"`
		}
		severityMap := map[string]string{
			"api-docs": "medium",
			"docker":   "high",
		}
		var jfindings []exposureFinding
		for _, f := range findings {
			sev := severityMap[f.Category]
			if sev == "" {
				sev = "medium"
			}
			jfindings = append(jfindings, exposureFinding{
				TemplateID: f.Category + ": " + f.Path,
				MatchedAt:  f.Host + f.Path,
				Severity:   sev,
				Category:   f.Category,
				Evidence:   f.Evidence,
				StatusCode: f.StatusCode,
			})
		}
		if len(findings) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "exposure-vulnerabilities.json", jfindings); err != nil {
				log.Printf("[exposure] Warning: could not write JSON output: %v", err)
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, opts.Domain, "exposure", "exposure-vulnerabilities.json")
		}
	}

	log.Printf("[exposure] Done. Found %d exposure(s)", len(findings))
	return &Result{Findings: findings, Output: outPath}, nil
}

// ---- internals -------------------------------------------------------------

func loadHosts(opts Options) ([]string, error) {
	filePath := opts.LiveHostsFile
	if filePath == "" && opts.Domain != "" {
		resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
		if resultsDir == "" {
			resultsDir = "new-results"
		}
		candidates := []string{
			filepath.Join(resultsDir, opts.Domain, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, opts.Domain, "subs", "subdomains.txt"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				filePath = c
				break
			}
		}
	}
	if filePath == "" {
		return nil, fmt.Errorf("no hosts file found for domain %q", opts.Domain)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "http") {
			line = "https://" + line
		}
		hosts = append(hosts, line)
	}
	return hosts, sc.Err()
}

type probeJob struct {
	host string
	path string
	cat  string
	kws  []string
}

func scanAll(hosts []string, threads int, timeout time.Duration) []Finding {
	// Build job queue
	var jobs []probeJob
	for _, host := range hosts {
		h := strings.TrimRight(host, "/")
		for _, p := range apiDocPaths {
			jobs = append(jobs, probeJob{h, p, "api-docs", apiDocKeywords})
		}
		for _, p := range dockerPaths {
			jobs = append(jobs, probeJob{h, p, "docker", dockerKeywords})
		}
	}

	jobCh := make(chan probeJob, threads*4)
	resultCh := make(chan Finding, 64)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobCh {
				if f, ok := probe(client, job); ok {
					resultCh <- f
				}
			}
		}()
	}

	go func() {
		for _, j := range jobs {
			jobCh <- j
		}
		close(jobCh)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var findings []Finding
	for f := range resultCh {
		findings = append(findings, f)
	}
	return findings
}

func probe(client *http.Client, job probeJob) (Finding, bool) {
	targetURL := job.host + job.path
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return Finding{}, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; AutoAR/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return Finding{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || (resp.StatusCode >= 400 && resp.StatusCode != 401 && resp.StatusCode != 403) {
		return Finding{}, false
	}

	// Read up to 16 KB of body for keyword confirmation
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	body := string(bodyBytes)

	for _, kw := range job.kws {
		if strings.Contains(body, kw) {
			log.Printf("[exposure] FOUND %s on %s%s [%d] keyword=%q", job.cat, job.host, job.path, resp.StatusCode, kw)
			return Finding{
				Host:       job.host,
				Path:       job.path,
				Category:   job.cat,
				StatusCode: resp.StatusCode,
				Evidence:   kw,
			}, true
		}
	}

	// If status 200 with no keyword match, still flag for manual review
	if resp.StatusCode == 200 && len(body) > 0 {
		log.Printf("[exposure] POSSIBLE %s on %s%s [%d] (no keyword matched)", job.cat, job.host, job.path, resp.StatusCode)
		return Finding{
			Host:       job.host,
			Path:       job.path,
			Category:   job.cat,
			StatusCode: resp.StatusCode,
			Evidence:   "(status 200 — manual review needed)",
		}, true
	}

	return Finding{}, false
}

func writeOutput(opts Options, findings []Finding) (string, error) {
	outDir := opts.OutputDir
	if outDir == "" {
		resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
		if resultsDir == "" {
			resultsDir = "new-results"
		}
		domain := opts.Domain
		if domain == "" {
			domain = "unknown"
		}
		outDir = filepath.Join(resultsDir, domain, "vulnerabilities", "exposure")
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return "", err
	}

	outPath := filepath.Join(outDir, "exposure-findings.txt")
	f, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if len(findings) == 0 {
		fmt.Fprintln(f, "# No exposed API docs or Docker artefacts found.")
		return outPath, nil
	}

	fmt.Fprintf(f, "# Exposed API Docs & Docker Artefacts\n")
	fmt.Fprintf(f, "# Found: %d exposure(s)\n", len(findings))
	fmt.Fprintf(f, "# Generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))

	// Group by category
	var apiFindings, dockerFindings []Finding
	for _, ff := range findings {
		if ff.Category == "api-docs" {
			apiFindings = append(apiFindings, ff)
		} else {
			dockerFindings = append(dockerFindings, ff)
		}
	}

	if len(apiFindings) > 0 {
		fmt.Fprintf(f, "## Exposed API Documentation (%d)\n\n", len(apiFindings))
		for _, ff := range apiFindings {
			fmt.Fprintln(f, ff.String())
		}
		fmt.Fprintln(f)
	}

	if len(dockerFindings) > 0 {
		fmt.Fprintf(f, "## Exposed Docker Artefacts (%d)\n\n", len(dockerFindings))
		for _, ff := range dockerFindings {
			fmt.Fprintln(f, ff.String())
		}
		fmt.Fprintln(f)
	}

	fmt.Fprintf(f, "\n# Report Template\n")
	for _, ff := range findings {
		fmt.Fprintf(f, `
### Exposed %s — %s%s
**URL:** %s%s
**Status:** %d
**Evidence:** %s

**Impact:** Exposed %s could allow an attacker to map the API surface, find undocumented endpoints or leak infrastructure details.
**Remediation:** Restrict access to this path (authentication/IP whitelist) or remove the file from the web root.
`,
			ff.Category, ff.Host, ff.Path,
			ff.Host, ff.Path,
			ff.StatusCode,
			ff.Evidence,
			ff.Category,
		)
	}

	return outPath, nil
}
