package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─── Nuclei template watch ─────────────────────────────────────────────────────
// Polls the ProjectDiscovery Cloud (PDCP) template search API for newly
// published nuclei templates. On each new batch it:
//
//  1. Posts a Discord alert (MONITOR_WEBHOOK_URL) listing the new templates
//     (name, severity, CVE, link).
//  2. Auto-runs them against every live host in the DB — the same code path as
//     the dashboard's "Run Nuclei Template" feature (runGlobalNucleiScan) — by
//     writing the raw template YAML from the API response into a temp dir and
//     pointing nuclei at it, so a brand-new template works even before the
//     local nuclei-templates checkout knows about it.
//
// The watermark (latest created_at + recently-seen template IDs) lives in the
// settings table so it survives redeploys. First-ever run baselines silently
// (no alert, no scan — otherwise a fresh install would "discover" the whole
// catalogue at once).
//
// Config (env):
//   PDCP_API_KEY                             — ProjectDiscovery Cloud key (falls
//                                              back to CHAOS_API_KEY, same key)
//   NUCLEI_TEMPLATE_WATCH=off                — disable the watcher entirely
//   NUCLEI_TEMPLATE_AUTORUN=off              — notify only, don't scan
//   NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES   — poll interval (default 30, min 5)

const (
	nucleiWatchSearchURL    = "https://api.projectdiscovery.io/v2/template/search"
	nucleiWatchRepoURL      = "https://github.com/projectdiscovery/nuclei-templates"
	nucleiWatchWatermarkKey = "nuclei_templates_last_created_at"
	nucleiWatchSeenKey      = "nuclei_templates_seen_ids"
	// Cap how many templates one cycle auto-runs so a bulk template drop can't
	// stampede the box. Extras are still listed in the Discord alert.
	nucleiWatchMaxTemplates = 10
	// How many of the newest templates to inspect per poll, and how many seen
	// IDs to remember (tie-breaker when several share one created_at second).
	nucleiWatchPageSize  = 25
	nucleiWatchSeenCap   = 300
	nucleiWatchListLimit = 10 // max templates linked in one Discord alert
)

var (
	nucleiWatchMu      sync.Mutex
	nucleiWatchStarted bool
	nucleiWatchLastRun time.Time
)

// pdcpTemplate is the subset of the PDCP search document the watch uses.
type pdcpTemplate struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Severity  string   `json:"severity"`
	CreatedAt string   `json:"created_at"`
	URI       string   `json:"uri"` // repo path, e.g. http/cves/2026/CVE-2026-1234.yaml
	Tags      []string `json:"tags"`
	Raw       string   `json:"raw"`
	IsNew     bool     `json:"is_new"`
	Class     struct {
		CVEs []string `json:"cve-id"`
	} `json:"classification"`
}

func nucleiTemplateAPIKey() string {
	if k := strings.TrimSpace(os.Getenv("PDCP_API_KEY")); k != "" {
		return k
	}
	// Chaos and the template API are the same PDCP key — reuse it.
	return strings.TrimSpace(os.Getenv("CHAOS_API_KEY"))
}

func nucleiTemplateWatchEnabled() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATE_WATCH")), "off") {
		return false
	}
	return nucleiTemplateAPIKey() != ""
}

func nucleiTemplateAutoRunEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATE_AUTORUN")), "off")
}

func nucleiTemplateWatchInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 5 {
			return time.Duration(n) * time.Minute
		}
	}
	return 30 * time.Minute
}

// StartNucleiTemplateWatch launches the watcher goroutine once per process.
// Requires the DB (watermark) — call only when DB_HOST is configured.
func StartNucleiTemplateWatch() {
	nucleiWatchMu.Lock()
	if nucleiWatchStarted {
		nucleiWatchMu.Unlock()
		return
	}
	nucleiWatchStarted = true
	nucleiWatchMu.Unlock()

	if !nucleiTemplateWatchEnabled() {
		logger.GetLogger().Infof("[NUCLEI-WATCH] disabled (NUCLEI_TEMPLATE_WATCH=off or no PDCP_API_KEY/CHAOS_API_KEY)")
		return
	}

	go func() {
		defer utils.RecoverPanic("nuclei-template-watch:loop")
		logger.GetLogger().Infof("[NUCLEI-WATCH] watcher started (interval %s, autorun=%v)",
			nucleiTemplateWatchInterval(), nucleiTemplateAutoRunEnabled())
		// First tick shortly after boot (baseline seed or catch-up after downtime).
		time.Sleep(30 * time.Second)
		nucleiTemplateWatchCycle()
		ticker := time.NewTicker(nucleiTemplateWatchInterval())
		defer ticker.Stop()
		for range ticker.C {
			nucleiTemplateWatchCycle()
		}
	}()
}

// nucleiTemplateWatchCycle runs one poll: fetch the newest templates, alert on
// ones newer than the watermark, auto-run them, advance the watermark.
func nucleiTemplateWatchCycle() {
	nucleiWatchMu.Lock()
	nucleiWatchLastRun = time.Now()
	nucleiWatchMu.Unlock()

	// raw is requested too when autorun is on, so the scan needs no extra fetch.
	withRaw := nucleiTemplateAutoRunEnabled()
	templates, err := nucleiWatchSearch(nucleiWatchPageSize, withRaw)
	if err != nil {
		logger.GetLogger().Infof("[NUCLEI-WATCH] search failed: %v", err)
		return
	}
	if len(templates) == 0 || templates[0].CreatedAt == "" {
		if len(templates) > 0 {
			// Without a created_at on the newest result the watermark can never
			// advance — log it instead of silently looping forever.
			logger.GetLogger().Infof("[NUCLEI-WATCH] newest template %q has no created_at — skipping cycle", templates[0].ID)
		}
		return
	}

	watermark, _ := db.GetSetting(nucleiWatchWatermarkKey)
	seen := nucleiWatchLoadSeen()

	if watermark == "" {
		// First-ever run: baseline silently so a fresh install doesn't "discover"
		// the whole catalogue. One intro message so the operator knows it's alive.
		nucleiWatchSaveState(templates[0].CreatedAt, templates)
		logger.GetLogger().Infof("[NUCLEI-WATCH] baseline set to %s", templates[0].CreatedAt)
		if utils.MonitorWebhookConfigured() {
			utils.SendMonitorWebhook(fmt.Sprintf(
				"📡 **Nuclei template watch active** — baseline `%s`. New templates will be announced here%s.",
				templates[0].CreatedAt, ternaryStr(nucleiTemplateAutoRunEnabled(), " and auto-run against all live hosts", "")))
		}
		return
	}

	// New = newer than the watermark, or same second but not in the seen set
	// (several templates can share one created_at timestamp).
	var fresh []pdcpTemplate
	for _, t := range templates {
		if t.CreatedAt > watermark || (t.CreatedAt == watermark && !seen[t.ID]) {
			fresh = append(fresh, t)
		}
	}
	if len(fresh) == 0 {
		return
	}

	// The PDCP index returns BOTH the public and the draft document for the same
	// template (same id/uri, different raw revision). Dedupe within the batch —
	// otherwise every alert lists the template twice and nuclei runs it twice.
	deduped := fresh[:0]
	seenIDs := make(map[string]bool, len(fresh))
	for _, t := range fresh {
		if t.ID == "" || seenIDs[t.ID] {
			continue
		}
		seenIDs[t.ID] = true
		deduped = append(deduped, t)
	}
	fresh = deduped

	logger.GetLogger().Infof("[NUCLEI-WATCH] %d new template(s) since %s", len(fresh), watermark)
	nucleiWatchNotify(fresh)

	// Persist the watermark/seen-IDs BEFORE the (potentially hours-long) scan: a
	// restart mid-scan must not re-announce and re-run the whole batch, and the
	// poll interval should measure from the poll, not from scan completion.
	nucleiWatchSaveState(fresh[0].CreatedAt, fresh)

	if nucleiTemplateAutoRunEnabled() {
		dir, downloaded, cleanup, err := nucleiWatchStage(fresh)
		if err != nil || len(downloaded) == 0 {
			cleanup()
			logger.GetLogger().Infof("[NUCLEI-WATCH] staging templates failed: %v", err)
			utils.SendMonitorWebhook("⚠️ **Nuclei template watch** — failed to stage the new templates, skipping auto-run.")
		} else {
			scanID := "nuclei-watch-" + time.Now().Format("20060102150405")
			utils.SendMonitorWebhook(fmt.Sprintf(
				"⚡ **Auto-running %d new template(s)** against all live hosts (scan `%s`)…", len(downloaded), scanID))
			fnRan := false
			RunScanInProcess(scanID, "nuclei", "nuclei-templates-watch", func() error {
				fnRan = true
				defer cleanup()
				return runGlobalNucleiScan(scanID, dir)
			})
			// RunScanInProcess aborts WITHOUT calling fn when the DB record can't be
			// created — the staged dir would leak in $TMPDIR on every DB hiccup.
			if !fnRan {
				cleanup()
			}
		}
	}
}

// nucleiWatchSearch fetches the newest public templates, sorted by creation
// time descending. withRaw includes the full YAML in each result.
func nucleiWatchSearch(limit int, withRaw bool) ([]pdcpTemplate, error) {
	fields := "id,name,severity,created_at,uri,tags,is_new,classification"
	if withRaw {
		fields += ",raw"
	}
	q := url.Values{
		"scope":     {"public"},
		"limit":     {strconv.Itoa(limit)},
		"sort_desc": {"created_at"},
		"fields":    {fields},
	}
	req, err := http.NewRequest("GET", nucleiWatchSearchURL+"?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", nucleiTemplateAPIKey())

	client := &http.Client{Timeout: 25 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pdcp template search -> %d: %s", resp.StatusCode, strings.TrimSpace(string(body[:min(len(body), 200)])))
	}
	var out struct {
		Results []pdcpTemplate `json:"results"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode search response: %w", err)
	}
	// Defensive: API should honour sort_desc=created_at, but don't trust it for
	// watermark math.
	for i := 1; i < len(out.Results); i++ {
		if out.Results[i].CreatedAt > out.Results[0].CreatedAt {
			out.Results[0], out.Results[i] = out.Results[i], out.Results[0]
		}
	}
	return out.Results, nil
}

// nucleiWatchLoadSeen reads the recently-announced template ID set.
func nucleiWatchLoadSeen() map[string]bool {
	seen := map[string]bool{}
	if v, _ := db.GetSetting(nucleiWatchSeenKey); v != "" {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				seen[id] = true
			}
		}
	}
	return seen
}

// nucleiWatchSaveState persists the new watermark and merges the batch's IDs
// into the seen set (capped at nucleiWatchSeenCap, newest first).
func nucleiWatchSaveState(watermark string, batch []pdcpTemplate) {
	if watermark != "" {
		_ = db.SetSetting(nucleiWatchWatermarkKey, watermark)
	}
	ids := make([]string, 0, len(batch))
	for _, t := range batch {
		ids = append(ids, t.ID)
	}
	if v, _ := db.GetSetting(nucleiWatchSeenKey); v != "" {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) > nucleiWatchSeenCap {
		ids = ids[:nucleiWatchSeenCap]
	}
	_ = db.SetSetting(nucleiWatchSeenKey, strings.Join(ids, ","))
}

// nucleiWatchNotify posts the Discord alert listing the new templates.
func nucleiWatchNotify(fresh []pdcpTemplate) {
	if !utils.MonitorWebhookConfigured() {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "🆕 **%d new Nuclei template(s) published**\n", len(fresh))
	listed := fresh
	if len(listed) > nucleiWatchListLimit {
		listed = listed[:nucleiWatchListLimit]
	}
	for _, t := range listed {
		sev := strings.ToUpper(strings.TrimSpace(t.Severity))
		if sev == "" {
			sev = "INFO"
		}
		label := t.Name
		if label == "" {
			label = t.ID
		}
		fmt.Fprintf(&b, "• **%s** [`%s`](%s/blob/main/%s) — `%s`", label, t.ID, nucleiWatchRepoURL, t.URI, sev)
		if len(t.Class.CVEs) > 0 {
			fmt.Fprintf(&b, " · %s", strings.Join(t.Class.CVEs, ", "))
		}
		b.WriteString("\n")
	}
	if len(fresh) > len(listed) {
		fmt.Fprintf(&b, "• …and %d more\n", len(fresh)-len(listed))
	}
	utils.SendMonitorWebhook(b.String())
}

// nucleiWatchStage writes the raw YAML of up to nucleiWatchMaxTemplates
// templates into a fresh temp dir (nuclei accepts a directory as -t).
// Templates without a raw body are skipped. Returns the dir, the template IDs
// staged, and a cleanup func.
func nucleiWatchStage(fresh []pdcpTemplate) (dir string, staged []string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "nuclei-watch-templates-*")
	if err != nil {
		return "", nil, func() {}, fmt.Errorf("create temp dir: %w", err)
	}
	cleanup = func() { os.RemoveAll(dir) }

	toStage := fresh
	if len(toStage) > nucleiWatchMaxTemplates {
		toStage = toStage[:nucleiWatchMaxTemplates]
	}
	usedNames := map[string]bool{}
	for _, t := range toStage {
		if strings.TrimSpace(t.Raw) == "" {
			logger.GetLogger().Infof("[NUCLEI-WATCH] %s has no raw body, skipping", t.ID)
			continue
		}
		base := path.Base(t.URI)
		if base == "." || base == "/" || base == "" {
			base = t.ID + ".yaml"
		}
		if usedNames[base] {
			base = strings.ReplaceAll(strings.TrimSuffix(t.URI, ".yaml"), "/", "_") + ".yaml"
		}
		usedNames[base] = true
		if werr := os.WriteFile(path.Join(dir, base), []byte(t.Raw), 0o600); werr != nil {
			logger.GetLogger().Infof("[NUCLEI-WATCH] write %s failed: %v", base, werr)
			continue
		}
		staged = append(staged, t.ID)
	}
	return dir, staged, cleanup, nil
}

func ternaryStr(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
