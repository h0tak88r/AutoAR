// Package jsmonitor watches a root domain's entire JavaScript surface:
// every cycle it re-collects the JS file URLs across the domain's subdomains
// (same URL collector the recon pipeline uses — gospider/wayback-class sources),
// fetches each file, and diffs against the stored inventory:
//
//   - NEW JS file discovered        → immediate alert
//   - file content changed (sha256) → re-extract endpoints + secrets from the
//     new body and alert only what's NEW (new secret / new endpoint)
//
// All fetches go through the SSRF-guarded public-HTTP client, bodies are
// size-capped, and requests are bounded per cycle — this is point-fetching of
// the domain's own scripts, not scanning.
package jsmonitor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/scanner/urls"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const (
	tickInterval    = 60 * time.Second // scheduler tick; per-domain cadence is interval_seconds
	maxBodyBytes    = 4 << 20          // 4MB cap per JS file
	maxFilesPerCycle = 800             // inventory safety cap per domain
	fetchTimeout    = 20 * time.Second
)

var (
	jsMonMu      sync.Mutex
	jsMonRunning bool
	jsMonStop    chan struct{}
	jsMonWg      sync.WaitGroup

	// endpointPattern: quoted absolute-ish API paths in JS source.
	endpointPattern = regexp.MustCompile(`["'` + "`" + `](/(?:api|v1|v2|v3|graphql|rest|services?|internal|admin|auth|user|account|billing)[A-Za-z0-9_\-/.%?&=]{2,120})["'` + "`" + `]`)

	secretPatternsOnce sync.Once
	secretPatterns     map[string][]*regexp.Regexp
	secretPatternsErr  error
)

// StartDaemon launches the scheduler goroutine (idempotent).
func StartDaemon() {
	jsMonMu.Lock()
	defer jsMonMu.Unlock()
	if jsMonRunning {
		return
	}
	jsMonStop = make(chan struct{})
	jsMonRunning = true
	jsMonWg.Add(1)
	go func() {
		defer jsMonWg.Done()
		defer utils.RecoverPanic("js-monitor:loop")
		defer func() {
			jsMonMu.Lock()
			jsMonRunning = false
			jsMonMu.Unlock()
		}()
		logger.GetLogger().Infof("[JS-MONITOR] Daemon started")
		checkDueTargets()
		t := time.NewTicker(tickInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				checkDueTargets()
			case <-jsMonStop:
				logger.GetLogger().Infof("[JS-MONITOR] Daemon stopped")
				return
			}
		}
	}()
}

// StopDaemon signals the scheduler to stop and waits.
func StopDaemon() {
	jsMonMu.Lock()
	if !jsMonRunning {
		jsMonMu.Unlock()
		return
	}
	close(jsMonStop)
	jsMonMu.Unlock()
	jsMonWg.Wait()
}

// IsDaemonRunning reports scheduler liveness.
func IsDaemonRunning() bool {
	jsMonMu.Lock()
	defer jsMonMu.Unlock()
	return jsMonRunning
}

func checkDueTargets() {
	targets, err := db.ListJSMonitorTargets()
	if err != nil {
		logger.GetLogger().Infof("[JS-MONITOR] failed to list targets: %v", err)
		return
	}
	for _, t := range targets {
		if !t.IsRunning {
			continue
		}
		due := t.LastRunAt == nil || time.Since(*t.LastRunAt) >= time.Duration(t.IntervalSeconds)*time.Second
		if !due {
			continue
		}
		// Serialized on purpose: one domain sweep at a time keeps egress polite.
		func(id int) {
			defer utils.RecoverPanic("js-monitor:sweep")
			monitorDomain(t)
		}(t.ID)
	}
}

// MonitorDomain runs one full sweep for a domain (exported for manual/API triggers).
func MonitorDomain(domain string) error {
	targets, err := db.ListJSMonitorTargets()
	if err != nil {
		return err
	}
	for _, t := range targets {
		if strings.EqualFold(t.Domain, domain) {
			monitorDomain(t)
			return nil
		}
	}
	return fmt.Errorf("js monitor target %q not found", domain)
}

func monitorDomain(t db.JSMonitorTarget) {
	start := time.Now()
	// Baseline sweep (target never ran): record the inventory silently —
	// alerting "new file" for every existing script would flood the channel.
	baseline := t.LastRunAt == nil
	logger.GetLogger().Infof("[JS-MONITOR] sweep start: %s (threads=%d, baseline=%v)", t.Domain, t.Threads, baseline)

	// 1. Discover the domain's current JS file URLs via the standard collector
	//    (writes new-results/<domain>/urls/js-urls.txt; sources include
	//    gospider/wayback-class archives over the domain's subdomains).
	urlRes, err := urls.CollectURLs(t.Domain, t.Threads, false)
	var jsURLs []string
	if err != nil {
		logger.GetLogger().Infof("[JS-MONITOR] URL collection failed for %s: %v (continuing with stored inventory fetch)", t.Domain, err)
	}
	if urlRes != nil && urlRes.JSFile != "" {
		jsURLs = readLinesSafe(urlRes.JSFile)
	}
	if len(jsURLs) > maxFilesPerCycle {
		logger.GetLogger().Infof("[JS-MONITOR] capping %s: %d→%d files", t.Domain, len(jsURLs), maxFilesPerCycle)
		jsURLs = jsURLs[:maxFilesPerCycle]
	}

	client := utils.NewPublicHTTPClient(fetchTimeout)
	sem := make(chan struct{}, max(1, min(t.Threads, 20)))
	var wg sync.WaitGroup
	var mu sync.Mutex
	newFiles, changedFiles, unchanged, failed := 0, 0, 0, 0

	for _, u := range jsURLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		wg.Add(1)
		go func(jsURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer utils.RecoverPanic("js-monitor:file:" + jsURL)
			status, body, ferr := fetchJS(client, jsURL)
			if ferr != nil || status != 200 {
				mu.Lock()
				failed++
				mu.Unlock()
				// Keep last_seen honest for files we know about that vanished.
				if prev, _ := db.GetJSMonitorFileByURL(jsURL); prev != nil && status > 0 {
					_ = db.MarkJSMonitorFileSeen(prev.ID, status)
				}
				return
			}
			sum := sha256.Sum256(body)
			sha := hex.EncodeToString(sum[:])
			prev, perr := db.GetJSMonitorFileByURL(jsURL)
			if perr != nil {
				return
			}
			if prev == nil {
				// NEW file discovered.
				eps := extractEndpoints(body)
				secs := extractSecrets(body)
				_ = db.UpsertJSMonitorFile(db.JSMonitorFile{
					TargetID: t.ID, Domain: t.Domain, URL: jsURL, SHA256: sha,
					Endpoints: mustJSON(eps), Secrets: mustJSON(secs),
					ContentLength: int64(len(body)), LastStatus: status,
				})
				mu.Lock()
				newFiles++
				mu.Unlock()
				if !baseline {
					alertNewFile(t.Domain, jsURL, int64(len(body)), len(eps), len(secs), secs)
				}
				return
			}
			if prev.SHA256 == sha {
				_ = db.MarkJSMonitorFileSeen(prev.ID, status)
				mu.Lock()
				unchanged++
				mu.Unlock()
				return
			}
			// CHANGED file: diff extractions, alert only new stuff.
			var oldEps, oldSecs []string
			_ = json.Unmarshal([]byte(prev.Endpoints), &oldEps)
			_ = json.Unmarshal([]byte(prev.Secrets), &oldSecs)
			eps := extractEndpoints(body)
			secs := extractSecrets(body)
			freshEps := diffLists(oldEps, eps)
			freshSecs := diffLists(oldSecs, secs)
			_ = db.UpsertJSMonitorFile(db.JSMonitorFile{
				TargetID: t.ID, Domain: t.Domain, URL: jsURL, SHA256: sha,
				Endpoints: mustJSON(eps), Secrets: mustJSON(secs),
				ContentLength: int64(len(body)), LastStatus: status,
			})
			mu.Lock()
			changedFiles++
			mu.Unlock()
			alertChangedFile(t.Domain, jsURL, int64(len(body)), freshEps, freshSecs)
		}(u)
	}
	wg.Wait()
	_ = db.TouchJSMonitorRun(t.ID)
	logger.GetLogger().Infof("[JS-MONITOR] sweep done: %s in %s — %d js urls, new=%d changed=%d unchanged=%d failed=%d (baseline=%v)",
		t.Domain, time.Since(start).Round(time.Second), len(jsURLs), newFiles, changedFiles, unchanged, failed, baseline)
}

func fetchJS(client *http.Client, jsURL string) (int, []byte, error) {
	if err := utils.ValidatePublicHTTPURL(jsURL); err != nil {
		return 0, nil, err
	}
	resp, err := client.Get(jsURL)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return resp.StatusCode, body, err
}

func extractEndpoints(body []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range endpointPattern.FindAllSubmatch(body, 200) {
		ep := string(m[1])
		if !seen[ep] {
			seen[ep] = true
			out = append(out, ep)
		}
	}
	return out
}

func extractSecrets(body []byte) []string {
	secretPatternsOnce.Do(func() {
		secretPatterns, secretPatternsErr = utils.LoadSecretPatterns("regexes")
	})
	if secretPatternsErr != nil || secretPatterns == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for typ, pats := range secretPatterns {
		for _, re := range pats {
			for _, m := range re.FindAll(body, 5) {
				s := fmt.Sprintf("%s: %s", typ, truncate(string(m), 80))
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func alertNewFile(domain, jsURL string, size int64, eps, secs int, secSamples []string) {
	msg := fmt.Sprintf(" 🆕 **JS Monitor — new JS file**\n**Domain:** `%s`\n**File:** `%s`\n**Size:** %d bytes\n**Extracted:** %d endpoints, %d secret candidate(s)",
		domain, jsURL, size, eps, secs)
	if len(secSamples) > 0 {
		msg += "\n**Secrets:**\n" + strings.Join(prefixEach("- `", secSamples[:min(5, len(secSamples))], "`"), "\n")
	}
	utils.SendMonitorWebhook(msg)
}

func alertChangedFile(domain, jsURL string, size int64, freshEps, freshSecs []string) {
	if len(freshEps) == 0 && len(freshSecs) == 0 {
		// Content churn with nothing new worth reporting — stay quiet.
		return
	}
	msg := fmt.Sprintf(" 🔄 **JS Monitor — file changed**\n**Domain:** `%s`\n**File:** `%s`\n**New size:** %d bytes", domain, jsURL, size)
	if len(freshSecs) > 0 {
		msg += fmt.Sprintf("\n**🚨 NEW secrets (%d):**\n", len(freshSecs)) + strings.Join(prefixEach("- `", freshSecs[:min(5, len(freshSecs))], "`"), "\n")
	}
	if len(freshEps) > 0 {
		msg += fmt.Sprintf("\n**New endpoints (%d):**\n", len(freshEps)) + strings.Join(prefixEach("- `", freshEps[:min(10, len(freshEps))], "`"), "\n")
	}
	utils.SendMonitorWebhook(msg)
}

func diffLists(old, cur []string) []string {
	seen := map[string]bool{}
	for _, o := range old {
		seen[o] = true
	}
	var out []string
	for _, c := range cur {
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}

func mustJSON(list []string) string {
	if list == nil {
		return "[]"
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func prefixEach(pre string, items []string, post string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = pre + s + post
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func readLinesSafe(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
