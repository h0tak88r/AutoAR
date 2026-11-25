package api

// Targeted passes: one template against a chosen host list — the hosts
// fingerprinted as the affected product — instead of the whole live corpus.
// They never take the fleet-wide sweep slot (a full sweep is ~2.6h over 622K
// hosts and queued sweeps used to stack into a ~10h backlog), and at most
// targetedPassSlots run at once. Used by the watcher's race pass, PoC-day,
// and MCP run_scan nuclei with a hosts filter. Every pass runs sandboxed and
// is tracked as a scan with target "race-pass" (Findings ingests those first).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/nuclei"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const targetedPassSlots = 2

var targetedPassSem = make(chan struct{}, targetedPassSlots)

// targetedPassSpec describes one pass.
type targetedPassSpec struct {
	ScanID       string
	CVE          string
	Raw          string // template YAML staged into the scan's template dir…
	TemplatePath string // …or an existing template path/ID when Raw is empty
	FileName     string // staged file name (default <cve>.yaml)
	Hosts        []string
	Threads      int
	Timeout      time.Duration
	Actor        string
	Name         string
	Description  string
}

// targetedPassResult is what a pass produced.
type targetedPassResult struct {
	ScanID  string
	Matches []raceMatch
	Ran     bool  // the scan record was created and the engine was invoked
	Err     error // engine error (deadline included); matches may still exist
}

// runTargetedPassFn is a seam for tests of the callers.
var runTargetedPassFn = runTargetedPass

// runTargetedPass runs the pass synchronously: the scan record is created,
// the engine runs (after a free slot), and the JSONL is indexed on the scan.
func runTargetedPass(spec targetedPassSpec) targetedPassResult {
	res := targetedPassResult{ScanID: spec.ScanID}
	if spec.Threads <= 0 {
		spec.Threads = 10
	}
	if spec.Timeout <= 0 {
		spec.Timeout = 10 * time.Minute
	}
	if spec.Actor == "" {
		spec.Actor = "system"
	}
	if len(spec.Hosts) == 0 {
		res.Err = fmt.Errorf("no hosts")
		return res
	}

	templateArg, cmdTemplate := spec.TemplatePath, spec.TemplatePath
	if strings.TrimSpace(spec.Raw) != "" {
		// Durable per-scan template dir: the exact template a pass ran stays
		// retrievable from the dashboard.
		tplDir := filepath.Join(utils.GetResultsDir(), "global-subdomains", "templates", spec.ScanID)
		if err := os.MkdirAll(tplDir, 0o755); err != nil {
			res.Err = fmt.Errorf("template dir: %w", err)
			return res
		}
		name := spec.FileName
		if name == "" {
			name = strings.ToLower(firstNonEmptyStr(spec.CVE, "template")) + ".yaml"
		}
		name = filepath.Base(name)
		templateArg = filepath.Join(tplDir, name)
		if err := os.WriteFile(templateArg, []byte(spec.Raw), 0o600); err != nil {
			res.Err = fmt.Errorf("template write: %w", err)
			return res
		}
		cmdTemplate = tplDir
	}
	if strings.TrimSpace(templateArg) == "" {
		res.Err = fmt.Errorf("no template")
		return res
	}

	targets, err := os.CreateTemp("", "targeted-*.txt")
	if err != nil {
		res.Err = fmt.Errorf("target file: %w", err)
		return res
	}
	for _, h := range spec.Hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if !strings.Contains(h, "://") {
			h = "https://" + h
		}
		targets.WriteString(h + "\n")
	}
	targets.Close()
	defer os.Remove(targets.Name())

	outDir := filepath.Join(utils.GetResultsDir(), "global-subdomains", "vulnerabilities")
	_ = os.MkdirAll(outDir, 0o755)
	outPath := filepath.Join(outDir, "nuclei-"+spec.ScanID+".json")

	var mu sync.Mutex
	onResult := func(event *output.ResultEvent) {
		if event == nil || event.TemplateID == "" {
			return
		}
		matched := event.Matched
		if matched == "" {
			matched = event.URL
		}
		mu.Lock()
		res.Matches = append(res.Matches, raceMatch{
			TemplateID: event.TemplateID,
			Matched:    matched,
			Curl:       strings.TrimSpace(event.CURLCommand),
			Severity:   event.Info.SeverityHolder.Severity.String(),
		})
		mu.Unlock()
	}

	recordScanInitiator(spec.ScanID, spec.Actor)
	if spec.Name != "" || spec.Description != "" {
		var n, d *string
		if spec.Name != "" {
			n = &spec.Name
		}
		if spec.Description != "" {
			d = &spec.Description
		}
		stashScanMeta(spec.ScanID, n, d)
	}
	command := fmt.Sprintf("inprocess:nuclei target=race-pass template=%s", cmdTemplate)
	RunScanInProcessWithCommand(spec.ScanID, "nuclei", "race-pass", command, func() error {
		mu.Lock()
		res.Ran = true
		mu.Unlock()
		select {
		case targetedPassSem <- struct{}{}:
		default:
			stdLog(spec.ScanID, "[INFO] Waiting for a targeted-pass slot (other passes running)")
			select {
			case targetedPassSem <- struct{}{}:
			case <-scanContext(spec.ScanID).Done():
				return fmt.Errorf("cancelled while waiting for a targeted-pass slot")
			}
		}
		defer func() { <-targetedPassSem }()
		ctx, cancel := context.WithTimeout(scanContext(spec.ScanID), spec.Timeout)
		defer cancel()
		// Index the JSONL + record the match count on every exit path, inside
		// the scan (the runner reads the stats right after fn returns).
		defer func() {
			mu.Lock()
			n := int64(len(res.Matches))
			mu.Unlock()
			persistNucleiScanOutput(spec.ScanID, outPath, n)
		}()
		stdLog(spec.ScanID, "[INFO] Targeted pass: %d host(s), template %s", len(spec.Hosts), filepath.Base(templateArg))
		err := nuclei.RunGlobalTemplateWithOptions(ctx, targets.Name(), templateArg, outPath, spec.Threads, nuclei.RunOptions{Sandbox: true}, onResult)
		mu.Lock()
		res.Err = err
		mu.Unlock()
		return err
	})
	mu.Lock()
	defer mu.Unlock()
	return res
}

// launchTargetedNuclei is the MCP/API launcher: run one template (raw YAML or
// a path/ID) against the live hosts whose fingerprint matches the patterns.
// Returns at once; the pass runs in the background.
func launchTargetedNuclei(template, patterns string, maxHosts int, name, actor string) (string, string, error) {
	template = strings.TrimSpace(template)
	if template == "" {
		return "", "", fmt.Errorf("template is required")
	}
	var kws []string
	for _, p := range strings.Split(patterns, ",") {
		if p = strings.TrimSpace(p); p != "" {
			kws = append(kws, p)
		}
	}
	if len(kws) == 0 {
		return "", "", fmt.Errorf("hosts needs at least one product pattern (e.g. gitlab, jira)")
	}
	if maxHosts <= 0 || maxHosts > 5000 {
		maxHosts = pocdayHostCap()
	}
	matched, total, err := db.MatchHostsByFingerprint(kws, maxHosts)
	if err != nil {
		return "", "", err
	}
	if len(matched) == 0 {
		return "", "", fmt.Errorf("no live host's tech/title/server matches %s", strings.Join(kws, ", "))
	}
	hosts := make([]string, 0, len(matched))
	for _, h := range matched {
		hosts = append(hosts, h.URL)
	}
	spec := targetedPassSpec{
		ScanID:  fmt.Sprintf("scan-%s-%s", time.Now().Format("20060102150405"), generateScanID(nil)[:8]),
		Hosts:   hosts,
		Threads: 25,
		Timeout: pocdayPassTimeout,
		Actor:   actor,
		Name:    firstNonEmptyStr(strings.TrimSpace(name), nucleiTemplateTitle(template)),
	}
	if strings.Contains(template, "\n") || strings.HasPrefix(template, "id:") {
		if why := nucleiTemplateUnsafeReason(template); why != "" {
			return "", "", fmt.Errorf("template refused: %s", why)
		}
		spec.Raw, spec.FileName = template, "template.yaml"
	} else {
		spec.TemplatePath = template
	}
	utils.SafeGo("targeted-pass:"+spec.ScanID, func() { runTargetedPassFn(spec) })
	msg := fmt.Sprintf("targeted nuclei pass launched on %d host(s) matching %s", len(hosts), strings.Join(kws, ", "))
	if total > len(hosts) {
		msg += fmt.Sprintf(" (first %d of %d matches)", len(hosts), total)
	}
	return spec.ScanID, msg, nil
}
