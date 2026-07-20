package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/nuclei"
	scopemod "github.com/h0tak88r/AutoAR/internal/scanner/scope"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/sw33tLie/bbscope/pkg/scope"
)

// RootPipelineReq configures an on-demand root-domain pipeline run. Every field
// is optional; sensible defaults are applied.
type RootPipelineReq struct {
	// Template: a nuclei template path/ID or raw YAML. Empty = the built-in default
	// (the operator's ~/nuclei-templates-custom dir if present, else http/cves).
	Template string `json:"template"`
	// NewRootsOnly (default true): only enumerate roots that have no subdomains in
	// the DB yet — the whole point of the pipeline is to fill gaps cheaply.
	NewRootsOnly *bool `json:"new_roots_only"`
	// Threads for subdomain enumeration and nuclei (default 30).
	Threads int `json:"threads"`
	// MaxRoots caps how many roots are enumerated this run (0 = no cap).
	MaxRoots int `json:"max_roots"`
}

// apiRunRootPipeline kicks off the on-demand pipeline:
//
//	all platform root domains → fast subdomain enum (only roots with no subs in
//	the DB) → store → nuclei on the freshly-found subs → Discord for every hit.
//
// It returns immediately with a scan_id; progress is visible on the Scans page
// and streamed live to the monitor webhook.
func apiRunRootPipeline(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var req RootPipelineReq
	_ = c.ShouldBindJSON(&req) // all fields optional — ignore bind errors

	newOnly := true
	if req.NewRootsOnly != nil {
		newOnly = *req.NewRootsOnly
	}
	threads := req.Threads
	if threads <= 0 {
		threads = 30
	}

	scanID := "pipeline-" + time.Now().Format("20060102150405")
	c.JSON(200, gin.H{
		"status":  "started",
		"scan_id": scanID,
		"message": "Root pipeline started — watch the Scans page and Discord.",
	})

	go RunScanInProcess(scanID, "pipeline", "root-pipeline", func() error {
		return runRootPipeline(scanID, req.Template, newOnly, threads, req.MaxRoots)
	})
}

func runRootPipeline(scanID, template string, newOnly bool, threads, maxRoots int) error {
	stdLog(scanID, "[INFO] Gathering root domains from all bug-bounty platforms…")
	utils.SendMonitorWebhook(" **Root Pipeline started** — gathering root domains from all platforms…")

	roots := gatherAllPlatformRoots()
	if len(roots) == 0 {
		return fmt.Errorf("no root domains found — configure platform API keys in Settings, or add domains first")
	}
	stdLog(scanID, "[INFO] %d unique root domain(s) across platforms", len(roots))

	// Keep only roots we haven't enumerated yet (no subdomains stored).
	targetRoots := roots
	if newOnly {
		targetRoots = targetRoots[:0]
		for _, r := range roots {
			if n, err := db.CountSubdomains(r); err == nil && n == 0 {
				targetRoots = append(targetRoots, r)
			}
		}
	}
	if maxRoots > 0 && len(targetRoots) > maxRoots {
		stdLog(scanID, "[INFO] capping to first %d of %d candidate roots", maxRoots, len(targetRoots))
		targetRoots = targetRoots[:maxRoots]
	}
	stdLog(scanID, "[INFO] %d root(s) need enumeration", len(targetRoots))
	if len(targetRoots) == 0 {
		utils.SendMonitorWebhook(" Root Pipeline: every known root already has subdomains — nothing new to enumerate.")
		return nil
	}
	utils.SendMonitorWebhook(fmt.Sprintf(" Root Pipeline: enumerating **%d** new root(s) of %d total…", len(targetRoots), len(roots)))

	// Enumerate roots concurrently (bounded), storing each root's subs as we go.
	var (
		mu      sync.Mutex
		allSubs []string
		done    int
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 5) // at most 5 roots enumerating at once
	)
	for _, r := range targetRoots {
		wg.Add(1)
		sem <- struct{}{}
		go func(root string) {
			defer wg.Done()
			defer func() { <-sem }()
			subs, err := subdomains.EnumerateSubdomains(root, threads)
			mu.Lock()
			defer mu.Unlock()
			done++
			if err != nil {
				stdLog(scanID, "[WARN] enum %s failed: %v", root, err)
				return
			}
			if len(subs) > 0 {
				if ierr := db.BatchInsertSubdomains(root, subs, false); ierr != nil {
					stdLog(scanID, "[WARN] store %s subs failed: %v", root, ierr)
				}
				allSubs = append(allSubs, subs...)
			}
			stdLog(scanID, "[OK] %s → %d subs (%d/%d roots)", root, len(subs), done, len(targetRoots))
		}(r)
	}
	wg.Wait()

	allSubs = uniqueStrings(allSubs)
	stdLog(scanID, "[INFO] enumeration complete: %d new subdomain(s)", len(allSubs))
	if len(allSubs) == 0 {
		utils.SendMonitorWebhook(" Root Pipeline: enumeration found no subdomains for the new roots.")
		return nil
	}
	utils.SendMonitorWebhook(fmt.Sprintf(" Root Pipeline: enumerated **%d** subdomains — running nuclei…", len(allSubs)))

	// Write the discovered subs to a temp target file for nuclei.
	tmpFile, err := os.CreateTemp("", "root-pipeline-targets-*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp target file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	for _, s := range allSubs {
		if s != "" {
			_, _ = tmpFile.WriteString(s + "\n")
		}
	}
	tmpFile.Close()

	templatePath, cleanup, tplName, err := resolvePipelineTemplate(template)
	if err != nil {
		return err
	}
	defer cleanup()

	outDir := filepath.Join(utils.GetResultsDir(), "root-pipeline", "vulnerabilities")
	_ = os.MkdirAll(outDir, 0o755)
	outPath := filepath.Join(outDir, "nuclei-"+scanID+".json")

	stdLog(scanID, "[INFO] running nuclei template %q on %d subdomains", tplName, len(allSubs))
	matches := 0
	err = nuclei.RunGlobalTemplate(tmpFile.Name(), templatePath, outPath, threads, func(event *output.ResultEvent) {
		if event == nil || event.TemplateID == "" {
			return
		}
		matches++
		msg := fmt.Sprintf(" **Root Pipeline Hit!**\n**Template:** `%s` (%s)\n**Target:** `%s`\n**Severity:** `%s`",
			event.TemplateID, event.Info.Name, event.Matched, event.Info.SeverityHolder.Severity.String())
		utils.SendMonitorWebhook(msg)
		stdLog(scanID, "[VULN] %s [%s] on %s", event.Info.Name, event.Info.SeverityHolder.Severity.String(), event.Matched)
	})
	if err != nil {
		return fmt.Errorf("nuclei scan failed: %w", err)
	}

	stdLog(scanID, "[OK] Root Pipeline complete — %d roots, %d subs, %d matches", len(targetRoots), len(allSubs), matches)
	utils.SendMonitorWebhook(fmt.Sprintf(" **Root Pipeline complete**\nTemplate: `%s`\nNew roots: %d\nSubdomains: %d\nMatches: %d",
		tplName, len(targetRoots), len(allSubs), matches))
	return nil
}

// gatherAllPlatformRoots returns the deduped set of in-scope root domains across
// every configured platform (via the same aggregation the Programs warmer uses),
// unioned with root domains already tracked in the tool.
func gatherAllPlatformRoots() []string {
	payload := buildProgramsPayload() // fetches H1/BC/IT/HackAdvisor scope with Assets populated
	var elems []scope.ScopeElement
	for _, p := range payload.Programs {
		for _, a := range p.Assets {
			elems = append(elems, scope.ScopeElement{Target: a})
		}
	}
	roots := scopemod.ScopeElementRoots(elems)
	// Union with roots already tracked (covers manually-added domains / imports).
	if existing, err := db.ListDomains(); err == nil {
		roots = append(roots, existing...)
	}
	return uniqueStrings(roots)
}

// resolvePipelineTemplate turns the request's template field into a concrete
// nuclei template path. Empty falls back to the operator's custom template dir
// (~/nuclei-templates-custom) if present, else the bundled http/cves set. Raw
// YAML (multi-line or starting with "id:") is written to a temp file.
func resolvePipelineTemplate(template string) (path string, cleanup func(), name string, err error) {
	cleanup = func() {}
	t := strings.TrimSpace(template)

	if t == "" {
		if home, herr := os.UserHomeDir(); herr == nil {
			custom := filepath.Join(home, "nuclei-templates-custom")
			if isDir(custom) {
				return custom, cleanup, "nuclei-templates-custom", nil
			}
		}
		cves := filepath.Join(utils.GetRootDir(), "nuclei-templates", "http", "cves")
		if isDir(cves) {
			return cves, cleanup, "http/cves", nil
		}
		return "", cleanup, "", fmt.Errorf("no template provided and no default template directory found")
	}

	if strings.Contains(t, "\n") || strings.HasPrefix(t, "id:") {
		f, ferr := os.CreateTemp("", "pipeline-template-*.yaml")
		if ferr != nil {
			return "", cleanup, "", fmt.Errorf("failed to create temp template: %w", ferr)
		}
		_, _ = f.WriteString(t)
		f.Close()
		return f.Name(), func() { os.Remove(f.Name()) }, "Custom Raw Template", nil
	}
	return t, cleanup, t, nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
