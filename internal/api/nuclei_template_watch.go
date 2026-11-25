package api

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
	"gopkg.in/yaml.v3"
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
	nucleiWatchSearchURL     = "https://api.projectdiscovery.io/v2/template/search"
	nucleiWatchRepoURL       = "https://github.com/projectdiscovery/nuclei-templates"
	nucleiWatchWatermarkKey  = "nuclei_templates_last_created_at"
	nucleiWatchStaleAlertKey = "nuclei_templates_stale_alert_at"
	nucleiWatchSeenKey       = "nuclei_templates_seen_ids"
	// Cap how many templates one cycle auto-runs so a bulk template drop can't
	// stampede the box. Extras are still listed in the Discord alert.
	nucleiWatchMaxTemplates = 10
	// How many of the newest templates to inspect per poll, and how many seen
	// IDs to remember (tie-breaker when several share one created_at second).
	nucleiWatchPageSize  = 25
	nucleiWatchSeenCap   = 600 // paged batches, two stage keys per merged template
	nucleiWatchListLimit = 10  // max templates linked in one Discord alert
)

// Pagination: page the newest-first search until it reaches the watermark, so
// a burst of more than one page between polls (or a catch-up after downtime)
// isn't silently skipped when the watermark jumps to the newest result.
const nucleiWatchMaxPages = 8

// nucleiWatchSearchEndpoint is the search URL in use (a var for test stubs).
var nucleiWatchSearchEndpoint = nucleiWatchSearchURL

var (
	nucleiWatchMu      sync.Mutex
	nucleiWatchStarted bool
	nucleiWatchLastRun time.Time

	// nucleiWatchSweepBusy is the watcher's own full-host sweep (single-flight):
	// it runs in its own goroutine so the poll loop keeps ticking during a sweep
	// that can last up to the 24h scan budget.
	nucleiWatchSweepBusy atomic.Bool
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
	// Stage fields: PDCP lists community submissions (pull-request/draft) side
	// by side with templates merged into the official repo. template_id carries
	// a "-draft" suffix for PR-stage revisions; is_github=false means the file
	// is NOT on the repo main branch yet — linking the blob URL for those 404s.
	TemplateID string `json:"template_id"`
	IsDraft    bool   `json:"is_draft"`
	IsEarly    bool   `json:"is_early"`
	IsGithub   bool   `json:"is_github"`
	Class      struct {
		CVEs []string `json:"cve-id"`
	} `json:"classification"`
}

// merged reports whether the document is a template published into the
// official repo (not a PR/draft revision). PR-stage docs carry is_draft=true
// and/or a "-draft" template_id; is_early docs are pre-merge previews.
//
// PDCP's is_github flag is NOT trusted anymore: it reads false for ~every
// document in the index (verified 2026-10-14 — GitHub-merged templates like
// CVE-2026-91136/CVE-2024-54772 are indexed is_github=false at their merge
// timestamps), which silently disqualified every template from auto-run since
// the gate shipped. The draft discriminators above are the real signal.
func (t pdcpTemplate) merged() bool {
	if t.IsDraft || t.IsEarly {
		return false
	}
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(t.TemplateID)), "-draft") ||
		strings.HasSuffix(strings.ToLower(strings.TrimSpace(t.ID)), "-draft") {
		return false
	}
	return true
}

// seenKey identifies a document in the seen/announced sets. A draft and the
// later merged revision of the same template are distinct events — the merged
// one must not be suppressed because its draft was already seen.
func (t pdcpTemplate) seenKey() string {
	if t.merged() {
		return t.ID
	}
	return t.ID + "#draft"
}

// seenKeys are the keys recorded once a document was processed: a merged
// revision supersedes its draft (the draft doc of the same template must not
// resurface as "new"), a draft marks only itself.
func (t pdcpTemplate) seenKeys() []string {
	if t.merged() {
		return []string{t.ID, t.ID + "#draft"}
	}
	return []string{t.ID + "#draft"}
}

// nucleiTemplateRevKey keys a template by ID plus a short hash of its raw YAML,
// so a mass-FP verdict sticks to the broken revision only: a later, fixed
// revision of the same template ID auto-runs again.
func nucleiTemplateRevKey(id, raw string) string {
	if strings.TrimSpace(raw) == "" {
		return id
	}
	sum := sha256.Sum256([]byte(raw))
	return id + "@" + hex.EncodeToString(sum[:])[:12]
}

// nucleiWatchAutoRunBlock returns why a watched template must NOT be
// auto-run against the fleet ("" = OK). Owner directive 2026-10-14: EVERY
// template runs — merged, PR or draft — as long as it is statically safe.
// The protections that remain: the static screen below (no code/javascript/
// headless/file/workflows, no self-contained, no @Host, no fixed
// destinations), the info-severity alert-only rule, the mass-FP revision
// blocklist, sandboxing and the post-sweep FP tally.
func nucleiWatchAutoRunBlock(t pdcpTemplate) string {
	if strings.TrimSpace(t.Raw) == "" {
		return "" // nothing to stage; the staging step skips it
	}
	return nucleiTemplateUnsafeReason(t.Raw)
}

// nucleiAutoRunBlockedKeys are top-level template sections never auto-run:
// local code execution, JS runtime (arbitrary sockets), a headless browser,
// local file reads, and workflows (which pull in other templates).
var nucleiAutoRunBlockedKeys = []string{"code", "javascript", "headless", "file", "workflows"}

// nucleiHostAnnotationRE finds the raw-request @Host: annotation, which sends
// the request to an arbitrary destination instead of the scanned target.
// Matched anywhere in the YAML (block or quoted raw strings) — fail closed.
var nucleiHostAnnotationRE = regexp.MustCompile(`(?i)@host\s*:`)

// nucleiTemplateUnsafeReason statically screens raw template YAML for
// constructs that reach beyond the scanned target. "" = nothing found.
// Unparseable YAML fails closed.
func nucleiTemplateUnsafeReason(raw string) string {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil || doc == nil {
		return "unparseable template YAML"
	}
	for _, k := range nucleiAutoRunBlockedKeys {
		if _, ok := doc[k]; ok {
			return "uses the " + k + " protocol"
		}
	}
	if sc, _ := doc["self-contained"].(bool); sc {
		return "self-contained (requests ignore the target)"
	}
	if nucleiHostAnnotationRE.MatchString(raw) {
		return "raw request with an @Host: annotation"
	}
	// Destinations must be derived from the target ({{BaseURL}}, {{Hostname}},
	// …): a literal host/address/path sends traffic somewhere else entirely.
	fixedDest := func(section string, fields ...string) string {
		reqs, _ := doc[section].([]any)
		for _, r := range reqs {
			m, _ := r.(map[string]any)
			for _, f := range fields {
				var vals []any
				switch v := m[f].(type) {
				case string:
					vals = []any{v}
				case []any:
					vals = v
				}
				for _, v := range vals {
					if s, ok := v.(string); ok && !strings.Contains(s, "{{") {
						return fmt.Sprintf("%s request to a fixed destination (%s)", section, utils.DiscordEscapeTrunc(s, 60))
					}
				}
			}
		}
		return ""
	}
	for _, c := range []struct {
		section string
		fields  []string
	}{
		{"http", []string{"path"}}, {"requests", []string{"path"}},
		{"network", []string{"host"}}, {"tcp", []string{"host"}},
		{"ssl", []string{"address"}}, {"websocket", []string{"address"}},
	} {
		if why := fixedDest(c.section, c.fields...); why != "" {
			return why
		}
	}
	return ""
}

// pdcpTime parses a PDCP created_at timestamp (RFC3339 with optional
// fractional seconds; zone-less values are taken as UTC).
func pdcpTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// pdcpCompare orders two created_at values (-1, 0, 1) as TIMES — string order
// breaks on fractional seconds ("…:00.5Z" sorts before "…:00Z") — falling back
// to string order when either side doesn't parse.
func pdcpCompare(a, b string) int {
	ta, okA := pdcpTime(a)
	tb, okB := pdcpTime(b)
	if okA && okB {
		return ta.Compare(tb)
	}
	return strings.Compare(a, b)
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
	// DB setting wins over env so the operator can stop wide auto-scans without
	// a redeploy ( abuse-complaint kill switch: set NUCLEI_TEMPLATE_AUTORUN=off
	// in the settings table and the watcher keeps catalog intel but never
	// launches a global scan ).
	if v, _ := db.GetSetting("NUCLEI_TEMPLATE_AUTORUN"); strings.EqualFold(strings.TrimSpace(v), "off") {
		return false
	}
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
		utils.GuardedRun("nuclei-watch:first-tick", nucleiTemplateWatchCycle)
		ticker := time.NewTicker(nucleiTemplateWatchInterval())
		defer ticker.Stop()
		for range ticker.C {
			utils.GuardedRun("nuclei-watch:tick", nucleiTemplateWatchCycle)
		}
	}()
}

// nucleiTemplateWatchCycle runs one poll: fetch the newest templates, alert on
// ones newer than the watermark, auto-run them, advance the watermark.
func nucleiTemplateWatchCycle() {
	nucleiWatchMu.Lock()
	nucleiWatchLastRun = time.Now()
	nucleiWatchMu.Unlock()

	watermark, _ := db.GetSetting(nucleiWatchWatermarkKey)
	seen := nucleiWatchLoadSeen()

	// raw is requested too when autorun is on, so the scan needs no extra fetch.
	autorun := nucleiTemplateAutoRunEnabled()
	templates, err := nucleiWatchSearchSince(watermark, autorun)
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

	if watermark == "" {
		// First-ever run: baseline silently so a fresh install doesn't "discover"
		// the whole catalogue. One intro message so the operator knows it's alive.
		nucleiWatchSaveState(templates[0].CreatedAt, templates)
		logger.GetLogger().Infof("[NUCLEI-WATCH] baseline set to %s", templates[0].CreatedAt)
		if utils.MonitorWebhookConfigured() {
			utils.SendMonitorWebhook(fmt.Sprintf(
				"📡 **Nuclei template watch active** — baseline `%s`. New templates will be announced here%s.",
				templates[0].CreatedAt, ternaryStr(autorun, " and merged ones auto-run against all live hosts", "")))
		}
		return
	}

	fresh := nucleiWatchFresh(templates, watermark, seen)
	if len(fresh) == 0 {
		// Heartbeat: without this line a quiet upstream (or a silently lagging
		// PDCP index) is indistinguishable from a dead watcher after the fact —
		// the CVE-2026-21589 template sat ~15h upstream before we saw it and the
		// log had zero evidence of what the cycle observed.
		logger.GetLogger().Infof("[NUCLEI-WATCH] 0 new (watermark %s, newest upstream %s)", watermark, templates[0].CreatedAt)
		nucleiWatchStalenessAlert(templates[0].CreatedAt)
		nucleiWatchCatchupOnce()
		return
	}

	logger.GetLogger().Infof("[NUCLEI-WATCH] %d new template(s) since %s", len(fresh), watermark)
	nucleiWatchNotifyOnce(fresh)

	// Auto-run candidates: statically safe, non-info, not blocklisted, not a
	// known mass-FP revision. Owner directive 2026-10-14: PR/draft stage no
	// longer disqualifies — every safe template runs.
	var runnable []pdcpTemplate
	if autorun {
		for _, t := range fresh {
			if !nucleiWatchRunnable(t) {
				continue
			}
			if why := nucleiWatchAutoRunBlock(t); why != "" {
				logger.GetLogger().Infof("[NUCLEI-WATCH] %s not auto-run: %s", t.ID, why)
				continue
			}
			runnable = append(runnable, t)
		}
		// Mass-FP guard: revisions previously flagged over the hit threshold skip
		// auto-run (still announced above). Cleared via the NUCLEI_SUSPECT_FP_IDS
		// setting once validated.
		runnable = suspectFPExcluded(runnable)
	}

	// Race pass: high/critical CVE templates get an immediate fingerprint-scoped
	// run against just the hosts that look like that technology — minutes ahead
	// of the full-host auto-run. Tiny footprint, so it is queued BEFORE (and
	// regardless of) the global-sweep gate below; re-discovered deferred batches
	// are deduped inside racePassEnqueue. It stages drafts and alerts only;
	// NOTHING is ever submitted to a platform automatically.
	if autorun && racePassEnabled() {
		racePassEnqueue(runnable)
	}

	// Auto-run gate: one fleet-wide sweep at a time. If one is already in
	// flight, defer this batch WITHOUT advancing the watermark — the next tick
	// re-discovers the same templates and retries once the box is free.
	// (NotifyOnce above suppresses re-announcing on those retry ticks.)
	if len(runnable) > 0 {
		if busy := globalNucleiSweepBusy(); busy != "" {
			logger.GetLogger().Infof("[NUCLEI-WATCH] global sweep in flight (%s) — deferring auto-run of %d template(s) to next cycle", busy, len(runnable))
			return
		}
	}

	// Persist the watermark/seen-IDs BEFORE the (potentially hours-long) scan: a
	// restart mid-scan must not re-announce and re-run the whole batch, and the
	// poll interval should measure from the poll, not from scan completion.
	// The newest fetched document (time-sorted) — the merged-wins dedupe can
	// drop or reorder entries of the batch, so fresh[0] isn't necessarily it.
	nucleiWatchSaveState(templates[0].CreatedAt, fresh)

	if len(runnable) == 0 {
		if autorun {
			logger.GetLogger().Infof("[NUCLEI-WATCH] none of the %d new template(s) qualify for auto-run (info/unsafe/suspect) — alert sent, auto-run skipped", len(fresh))
		}
		return
	}
	nucleiWatchLaunchSweep(runnable)
}

// nucleiWatchCatchupKey guards the one-time missed-templates sweep. Auto-run
// never fired before v4.6.2 (the PDCP is_github gate disqualified everything,
// and pre-merge drafts were alert-only), so every qualifying template in the
// recent window was announced but never swept. This backfill stages the
// newest nucleiWatchCatchupDocs documents once and sweeps them together.
const (
	nucleiWatchCatchupKey  = "nuclei_templates_catchup_done"
	nucleiWatchCatchupDocs = 250
)

// nucleiWatchCatchupOnce sweeps missed templates, once ever. Called at the
// END of a tick (fresh batches take priority); retries on later ticks while a
// global sweep is in flight, and marks itself done only once launched.
func nucleiWatchCatchupOnce() {
	if v, _ := db.GetSetting(nucleiWatchCatchupKey); strings.TrimSpace(v) != "" {
		return
	}
	if !nucleiTemplateAutoRunEnabled() {
		return
	}
	if busy := globalNucleiSweepBusy(); busy != "" {
		logger.GetLogger().Infof("[NUCLEI-WATCH] catch-up waiting: global sweep in flight (%s)", busy)
		return
	}
	var missed []pdcpTemplate
	seen := map[string]bool{}
	for page := 0; page*nucleiWatchPageSize < nucleiWatchCatchupDocs; page++ {
		batch, err := nucleiWatchSearch(nucleiWatchPageSize, page*nucleiWatchPageSize, true)
		if err != nil || len(batch) == 0 {
			break
		}
		for _, t := range batch {
			if seen[t.ID] || !nucleiWatchRunnable(t) || nucleiWatchAutoRunBlock(t) != "" {
				continue
			}
			seen[t.ID] = true
			missed = append(missed, t)
		}
		if len(batch) < nucleiWatchPageSize {
			break
		}
	}
	if len(missed) == 0 {
		_ = db.SetSetting(nucleiWatchCatchupKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
		logger.GetLogger().Infof("[NUCLEI-WATCH] catch-up: nothing to sweep — done")
		return
	}
	missed = suspectFPExcluded(missed)
	if len(missed) == 0 {
		_ = db.SetSetting(nucleiWatchCatchupKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
		return
	}
	// Cap the batch: staging is capped at nucleiWatchMaxTemplates anyway, and
	// one sweep with a few hundred safe templates is exactly what the watcher
	// would have done with them had the gate worked.
	_ = db.SetSetting(nucleiWatchCatchupKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	logger.GetLogger().Infof("[NUCLEI-WATCH] catch-up: sweeping %d template(s) auto-run missed", len(missed))
	utils.SendMonitorWebhook(fmt.Sprintf(
		"♻️ **Template catch-up** — auto-run was broken before v4.6.2; sweeping **%d** previously announced template(s) that never ran…", len(missed)))
	nucleiWatchLaunchSweep(missed)
}

// nucleiWatchFresh selects the documents newer than the watermark (or at the
// watermark but not yet seen — several share one created_at), then dedupes:
// the PDCP index returns BOTH the public and the draft document for the same
// template (same id/uri, different raw revision). One entry per ID, and the
// MERGED revision wins whatever order the index returned them in — otherwise
// the unreviewed draft revision could be the one that gets staged and run.
func nucleiWatchFresh(templates []pdcpTemplate, watermark string, seen map[string]bool) []pdcpTemplate {
	var out []pdcpTemplate
	idx := map[string]int{}
	for _, t := range templates {
		c := pdcpCompare(t.CreatedAt, watermark)
		if t.ID == "" || c < 0 || (c == 0 && seen[t.seenKey()]) {
			continue
		}
		if i, dup := idx[t.ID]; dup {
			if t.merged() && !out[i].merged() {
				out[i] = t
			}
			continue
		}
		idx[t.ID] = len(out)
		out = append(out, t)
	}
	return out
}

// nucleiWatchLaunchSweep stages the batch and starts the full-host auto-run in
// its own goroutine. RunScanInProcessWithCommand is synchronous for the whole
// sweep (up to the 24h scan budget); running it inline froze the poll loop —
// no polls, no alerts, ticks dropped — for that long. Single-flight via
// nucleiWatchSweepBusy (the caller's globalNucleiSweepBusy gate already saw
// it clear).
func nucleiWatchLaunchSweep(runnable []pdcpTemplate) {
	if !nucleiWatchSweepBusy.CompareAndSwap(false, true) {
		logger.GetLogger().Infof("[NUCLEI-WATCH] watcher sweep already running — %d template(s) not auto-run this cycle", len(runnable))
		return
	}
	// Scan ID up front so the staged template dir is per-scan and durable —
	// the stored command records the path, making these scans rescanable
	// (temp-dir staging made every watcher scan un-rescanable before).
	scanID := "nuclei-watch-" + time.Now().Format("20060102150405")
	// allowUnmerged: owner directive 2026-10-14 — every statically-safe new
	// template runs against the corpus, PR/draft stage included.
	dir, downloaded, cleanup, err := nucleiWatchStage(scanID, runnable, true)
	if err != nil || len(downloaded) == 0 {
		nucleiWatchSweepBusy.Store(false)
		cleanup()
		logger.GetLogger().Infof("[NUCLEI-WATCH] staging templates failed: %v", err)
		utils.SendMonitorWebhook("⚠️ **Nuclei template watch** — failed to stage the new templates, skipping auto-run.")
		return
	}
	// Revision keys of what was staged: mass-FP verdicts stick to these exact
	// revisions (a fixed re-publish of the same ID runs again).
	revs := make(map[string]string, len(runnable))
	for _, t := range runnable {
		revs[t.ID] = nucleiTemplateRevKey(t.ID, t.Raw)
	}
	recordScanInitiator(scanID, "system") // automated watcher, not a user
	command := fmt.Sprintf("inprocess:nuclei target=global-subdomains template=%s", dir)
	// Radar-page tracking: CVE-named templates get a row update so the CVE
	// page reflects "merged template + swept". Non-CVE templates have no row.
	for _, t := range runnable {
		if id := strings.TrimSpace(t.ID); strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			_ = db.MarkCVEScanState(id, "merged", scanID)
		}
	}
	utils.SendMonitorWebhook(fmt.Sprintf(
		"⚡ **Auto-running %d new merged template(s)** against all live hosts (scan `%s`)…", len(downloaded), scanID))
	utils.SafeGo("nuclei-watch:sweep", func() {
		defer nucleiWatchSweepBusy.Store(false)
		var fnRan atomic.Bool
		RunScanInProcessWithCommand(scanID, "nuclei", "nuclei-templates-watch", command, func() error {
			fnRan.Store(true)
			// Intentionally NO cleanup: the staged templates are the scan's
			// durable record (rescan input + retrievable from the dashboard).
			return runGlobalNucleiScanOpts(scanID, dir, globalScanOpts{
				Sandbox: true, // unreviewed community YAML: no local network / files
				// Disk-truth mass-FP tally once the sweep ends (any exit path):
				// flag + announce templates over the corpus-scaled threshold.
				OnFinish: func(totalHosts int) {
					utils.GuardedRun("nuclei-watch:quantify", func() { suspectFPQuantify(scanID, totalHosts, revs) })
				},
			})
		})
		// RunScanInProcess aborts WITHOUT calling fn when the DB record can't be
		// created — the staged dir would leak; remove it in that case only.
		if !fnRan.Load() {
			cleanup()
		}
	})
}

// globalScanOpts tunes runGlobalNucleiScanOpts for automated runs.
type globalScanOpts struct {
	// Sandbox builds every batch engine with local network/file access
	// restricted (auto-runs of templates nobody reviewed).
	Sandbox bool
	// OnFinish, when set, runs once the sweep ends (any exit path after the
	// host dump) with the number of hosts targeted.
	OnFinish func(totalHosts int)
	// Hosts, when set, is a pre-resolved list of target URLs (fingerprint-
	// targeted mode): the sweep runs against exactly these instead of dumping
	// the whole live corpus, skips the fleet-wide sweep lock (it runs alongside
	// a full sweep, like a race pass), and is not checkpoint-resumed.
	Hosts []string
}

var (
	// globalSweepSem admits one fleet-wide nuclei sweep at a time, whoever
	// launched it: manual "Run Nuclei Template", watcher auto-run, or a rescan
	// of either (all go through runGlobalNucleiScanOpts). Overlapping full
	// sweeps were the OOM history; a second one now queues instead of stacking.
	globalSweepSem = make(chan struct{}, 1)
	// globalSweepActive counts sweeps running or queued on globalSweepSem.
	globalSweepActive atomic.Int64
)

// acquireGlobalSweep takes the fleet-wide sweep slot, waiting (cancellably,
// on the scan's own context) while another sweep holds it.
func acquireGlobalSweep(scanID string) (release func(), err error) {
	globalSweepActive.Add(1)
	select {
	case globalSweepSem <- struct{}{}:
	default:
		stdLog(scanID, "[INFO] Another global nuclei sweep is running — this scan is queued until it finishes (cancel it to drop it)")
		ctx := scanContext(scanID)
		select {
		case globalSweepSem <- struct{}{}:
		case <-ctx.Done():
			globalSweepActive.Add(-1)
			return nil, fmt.Errorf("cancelled while queued behind another global sweep: %w", ctx.Err())
		}
	}
	return func() {
		<-globalSweepSem
		globalSweepActive.Add(-1)
	}, nil
}

// globalNucleiSweepBusy describes the fleet-wide nuclei sweeps in flight (""
// = none): every runGlobalNucleiScanOpts call (running or queued), the
// watcher's own sweep, root pipelines (nuclei over every platform root), and
// DB rows of the sweep targets — not only target='global-subdomains', which
// missed watcher scans and pipelines and let full sweeps overlap. Race passes
// (target race-pass, ≤250 hosts) deliberately don't count.
func globalNucleiSweepBusy() string {
	var parts []string
	if n := globalSweepActive.Load(); n > 0 {
		parts = append(parts, fmt.Sprintf("%d global sweep(s) running/queued", n))
	}
	if nucleiWatchSweepBusy.Load() {
		parts = append(parts, "watcher sweep")
	}
	pipelines := 0
	ScansMutex.RLock()
	for _, si := range ActiveScans {
		if si != nil && si.ScanType == "pipeline" && si.Status == "running" {
			pipelines++
		}
	}
	ScansMutex.RUnlock()
	if pipelines > 0 {
		parts = append(parts, fmt.Sprintf("%d root pipeline(s)", pipelines))
	}
	for _, target := range []string{"global-subdomains", "nuclei-templates-watch"} {
		if n, err := db.CountRunningScansForTarget(target); err == nil && n > 0 {
			parts = append(parts, fmt.Sprintf("%d running %s scan(s)", n, target))
		}
	}
	return strings.Join(parts, ", ")
}

// persistNucleiScanOutput makes a sweep/race-pass JSONL visible on the scan:
// copied into the scan's own results dir (loadFileContent serves files from
// <resultsDir>/<scanID>/, not from the artifact's LocalPath), indexed as an
// artifact, and the match count recorded. Safe on every exit path; a no-op
// without matches. The copy STREAMS — sweep outputs reach GBs and the old
// os.ReadFile pulled the whole file into memory.
func persistNucleiScanOutput(scanID, outPath string, matches int64) {
	if matches == 0 {
		return
	}
	scanDir := utils.GetScanResultsDir(scanID)
	if mkErr := os.MkdirAll(scanDir, 0o755); mkErr == nil {
		dest := filepath.Join(scanDir, filepath.Base(outPath))
		if _, statErr := os.Stat(dest); statErr != nil {
			if cpErr := copyFileStreaming(outPath, dest); cpErr != nil {
				stdLog(scanID, "[WARN] failed to copy nuclei output into the scan dir: %v", cpErr)
			}
		}
	}
	if _, idxErr := utils.IndexExistingResultFile(scanID, outPath); idxErr != nil {
		stdLog(scanID, "[WARN] failed to index nuclei output %s: %v", outPath, idxErr)
	}
	_ = db.UpdateScanStats(scanID, int(matches), 0)
}

// copyFileStreaming copies src to dest without loading it into memory (result
// files can be hundreds of MB), via a temp file + rename so readers never see
// a half-written file.
func copyFileStreaming(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// discordCode renders untrusted text as a Discord inline code span: backticks
// (which would close the span and re-enable markdown / masked links) become
// quotes, newlines become spaces, and the value is capped at n runes.
func discordCode(s string, n int) string {
	s = strings.NewReplacer("`", "'", "\r", " ", "\n", " ").Replace(s)
	if r := []rune(s); n > 0 && len(r) > n {
		s = string(r[:n]) + "…"
	}
	if s == "" {
		s = "-"
	}
	return "`" + s + "`"
}

// nucleiWatchRunnable reports whether a newly published template should be
// auto-run against all live hosts. info-severity templates (panels,
// tech-detects) are alert-only, and IDs listed in NUCLEI_TEMPLATE_IGNORE
// (comma-separated) are skipped entirely — that blocklist is for templates
// whose matchers are known-broken (mass false positives against every live
// host). Empty/unknown severity runs (fail-open).
func nucleiWatchRunnable(t pdcpTemplate) bool {
	if strings.EqualFold(strings.TrimSpace(t.Severity), "info") {
		return false
	}
	return !nucleiTemplateBlocked(t.ID)
}

// nucleiTemplateBlocked reports whether a template ID is listed in the
// NUCLEI_TEMPLATE_IGNORE blocklist (comma-separated, case-insensitive).
func nucleiTemplateBlocked(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	list := strings.TrimSpace(utils.GetEnv("NUCLEI_TEMPLATE_IGNORE", ""))
	if list == "" {
		return false
	}
	for _, item := range strings.Split(list, ",") {
		if item = strings.TrimSpace(item); item != "" && strings.EqualFold(item, id) {
			return true
		}
	}
	return false
}

// nucleiWatchSearchSince fetches the newest public templates newest-first and,
// when a watermark is set, keeps paging (nucleiWatchPageSize per page, at most
// nucleiWatchMaxPages) until a page reaches back past the watermark. One page
// used to be the whole view: >25 publications between two polls (bulk drops,
// catch-up after downtime) and everything below the first page was skipped
// for good once the watermark jumped to the newest result. A failing or
// offset-ignoring later page degrades to what was fetched (never worse than
// the single-page behaviour); a first-page failure keeps the watermark.
func nucleiWatchSearchSince(watermark string, withRaw bool) ([]pdcpTemplate, error) {
	all, err := nucleiWatchSearch(nucleiWatchPageSize, 0, withRaw)
	if err != nil || watermark == "" {
		return all, err
	}
	page := all
	for n := 1; n < nucleiWatchMaxPages; n++ {
		if len(page) < nucleiWatchPageSize || pdcpCompare(page[len(page)-1].CreatedAt, watermark) < 0 {
			break // short page = end of index; oldest entry already below the watermark
		}
		next, err := nucleiWatchSearch(nucleiWatchPageSize, n*nucleiWatchPageSize, withRaw)
		if err != nil {
			logger.GetLogger().Infof("[NUCLEI-WATCH] page %d failed (%v) — continuing with %d template(s)", n+1, err, len(all))
			break
		}
		if len(next) == 0 || (next[0].ID == all[0].ID && next[0].CreatedAt == all[0].CreatedAt) {
			if len(next) > 0 {
				logger.GetLogger().Infof("[NUCLEI-WATCH] PDCP ignored offset=%d — single-page view this cycle", n*nucleiWatchPageSize)
			}
			break
		}
		all = append(all, next...)
		page = next
		if n == nucleiWatchMaxPages-1 && pdcpCompare(page[len(page)-1].CreatedAt, watermark) >= 0 {
			logger.GetLogger().Infof("[NUCLEI-WATCH] >%d templates since watermark %s — older ones beyond the page cap are skipped", len(all), watermark)
		}
	}
	// Defensive: the API should honour sort_desc=created_at, but don't trust it
	// (or page boundaries) for watermark math — order by parsed time.
	sort.SliceStable(all, func(i, j int) bool { return pdcpCompare(all[i].CreatedAt, all[j].CreatedAt) > 0 })
	return all, nil
}

// nucleiWatchSearch fetches one page of the newest public templates, sorted by
// creation time descending. withRaw includes the full YAML in each result.
func nucleiWatchSearch(limit, offset int, withRaw bool) ([]pdcpTemplate, error) {
	fields := "id,name,severity,created_at,uri,tags,is_new,classification,template_id,is_draft,is_early,is_github"
	if withRaw {
		fields += ",raw"
	}
	q := url.Values{
		"scope":     {"public"},
		"limit":     {strconv.Itoa(limit)},
		"sort_desc": {"created_at"},
		"fields":    {fields},
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	return pdcpSearchQuery(q)
}

// pdcpSearchQuery runs a PDCP template-search request (shared by the watcher
// feed and the PoC→Scan bridge's query-by-CVE lookups).
func pdcpSearchQuery(q url.Values) ([]pdcpTemplate, error) {
	req, err := http.NewRequest("GET", nucleiWatchSearchEndpoint+"?"+q.Encode(), nil)
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
	// watermark math (parsed-time order; strings break on fractional seconds).
	sort.SliceStable(out.Results, func(i, j int) bool {
		return pdcpCompare(out.Results[i].CreatedAt, out.Results[j].CreatedAt) > 0
	})
	return out.Results, nil
}

// nucleiWatchLoadSeen reads the recently-announced template ID set.
// nucleiWatchStalenessAlert pages the monitoring channel when the newest
// template the index returns is unusually old — meaning upstream/PDCP has gone
// quiet or the index is lagging. Nuclei templates land around the clock; a
// quiet window of hours is a signal, not silence to ignore. Rate-limited to
// once per 12h via a settings timestamp.
func nucleiWatchStalenessAlert(newestUpstream string) {
	t, ok := pdcpTime(newestUpstream)
	if !ok {
		return
	}
	quiet := time.Since(t)
	if quiet < 6*time.Hour {
		return
	}
	last := cveRadarParseWatermarkSetting(nucleiWatchStaleAlertKey)
	if !last.IsZero() && time.Since(last) < 12*time.Hour {
		return
	}
	_ = db.SetSetting(nucleiWatchStaleAlertKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	_ = utils.SendPurposeWebhookErr("monitoring", fmt.Sprintf(
		"⚠️ **Nuclei template watch: no new templates for %s** (newest upstream created %s). Either the PDCP index is lagging or template publishing stalled — if a fresh CVE PoC is expected, verify manually.",
		quiet.Round(time.Minute), newestUpstream))
}

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
	ids := make([]string, 0, 2*len(batch))
	for _, t := range batch {
		ids = append(ids, t.seenKeys()...)
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

// nucleiWatchNotifyOnce announces only templates not yet announced this
// process. Deferred batches (global scan in flight) retry on later ticks
// without advancing the watermark — without this dedup they would re-alert
// every cycle until the box frees up.
var nucleiWatchAnnouncedMu sync.Mutex
var nucleiWatchAnnounced = make(map[string]bool)

func nucleiWatchNotifyOnce(fresh []pdcpTemplate) {
	nucleiWatchAnnouncedMu.Lock()
	pending := make([]pdcpTemplate, 0, len(fresh))
	for _, t := range fresh {
		// Keyed by stage: a template announced as an unmerged PR is announced
		// again once its merged revision shows up (that one may auto-run).
		if !nucleiWatchAnnounced[t.seenKey()] {
			for _, k := range t.seenKeys() {
				nucleiWatchAnnounced[k] = true
			}
			pending = append(pending, t)
		}
	}
	nucleiWatchAnnouncedMu.Unlock()
	if len(pending) == 0 {
		return
	}
	nucleiWatchNotify(pending)
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
	autorun := nucleiTemplateAutoRunEnabled()
	for _, t := range listed {
		// Everything here is third-party text (community PR titles included):
		// escaped for Discord markdown, mentions off at the payload level.
		sev := nucleiSafeToken(strings.ToUpper(strings.TrimSpace(t.Severity)))
		if sev == "" {
			sev = "INFO"
		}
		id := nucleiSafeToken(t.ID)
		label := utils.DiscordEscapeTrunc(t.Name, 120)
		if label == "" {
			label = id
		}
		// Link by merge stage: PDCP lists PR-stage community submissions
		// (is_github=false, template_id suffixed "-draft") next to templates
		// already on the repo main branch. The blob URL only exists for the
		// latter — drafts get a GitHub code-search link for the ID instead
		// (valid immediately, finds the template the moment its PR merges).
		link := fmt.Sprintf("%s/blob/main/%s", nucleiWatchRepoURL, t.URI)
		if !nucleiSafeURIRE.MatchString(t.URI) {
			link = nucleiWatchRepoURL // a hostile uri must not reshape the masked link
		}
		stage := ""
		if !t.merged() {
			link = fmt.Sprintf("https://github.com/search?q=repo%%3Aprojectdiscovery%%2Fnuclei-templates+%s&type=code", url.PathEscape(id))
			stage = " · 📝 PR/draft"
		}
		if autorun && strings.TrimSpace(t.Raw) != "" {
			if why := nucleiWatchAutoRunBlock(t); why != "" {
				stage = " · 🚫 not auto-run: " + why
			}
		}
		fmt.Fprintf(&b, "• **%s** [`%s`](%s) — `%s`%s", label, id, link, sev, stage)
		var cves []string
		for _, c := range t.Class.CVEs {
			if m := cveRE.FindString(c); m != "" {
				cves = append(cves, m)
			}
		}
		if len(cves) > 0 {
			fmt.Fprintf(&b, " · %s", strings.Join(cves, ", "))
		}
		b.WriteString("\n")
	}
	if len(fresh) > len(listed) {
		fmt.Fprintf(&b, "• …and %d more\n", len(fresh)-len(listed))
	}
	utils.SendMonitorWebhook(b.String())
}

// nucleiUnsafeNameRE matches every character not allowed in a staged template
// file name or an ID rendered into an alert.
var nucleiUnsafeNameRE = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// nucleiSafeURIRE accepts repo-relative template paths (http/cves/2026/x.yaml)
// that can be spliced into a GitHub blob URL / masked link as-is.
var nucleiSafeURIRE = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// nucleiSafeToken reduces untrusted short identifiers (template IDs,
// severities) to [A-Za-z0-9._-], capped — safe inside code spans and links.
func nucleiSafeToken(s string) string {
	s = nucleiUnsafeNameRE.ReplaceAllString(strings.TrimSpace(s), "_")
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

// nucleiWatchStageName picks the file name for a staged template: the URI's
// base name (or <id>.yaml), disambiguated, reduced to [A-Za-z0-9._-] with no
// leading dots and a .yaml suffix — a PDCP id/uri like "../../x" can never
// escape the per-scan dir.
func nucleiWatchStageName(t pdcpTemplate, used map[string]bool) string {
	base := path.Base(t.URI)
	if base == "." || base == "/" || base == "" {
		base = t.ID + ".yaml"
	}
	if used[base] {
		base = strings.ReplaceAll(strings.TrimSuffix(t.URI, ".yaml"), "/", "_") + ".yaml"
	}
	base = strings.TrimLeft(nucleiUnsafeNameRE.ReplaceAllString(base, "_"), ".")
	base = strings.TrimSuffix(base, ".yaml")
	if base == "" {
		base = "template"
	}
	name := base + ".yaml"
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s_%d.yaml", base, i)
	}
	used[name] = true
	return name
}

// nucleiWatchStage writes the raw YAML of up to nucleiWatchMaxTemplates
// templates into a DURABLE per-scan dir under
// new-results/global-subdomains/templates/<scanID>/ (nuclei accepts a
// directory as -t). Durable — not a deleted temp dir — so the exact templates
// a watcher scan ran are always retrievable from the dashboard and the scan
// can be re-run via rescan (the stored command records this path).
// Templates without a raw body are skipped. Returns the dir, the template IDs
// staged, and a cleanup func that must be called when the scan never runs.
//
// allowUnmerged relaxes the watcher's merged-only auto-run rule for the
// PoC→Scan bridge, whose candidates are corroborated by a radar-confirmed
// public PoC and run sandboxed. Every static safety gate still applies —
// only the merge requirement is lifted.
func nucleiWatchStage(scanID string, fresh []pdcpTemplate, allowUnmerged bool) (dir string, staged []string, cleanup func(), err error) {
	dir = filepath.Join(utils.GetResultsDir(), "global-subdomains", "templates", scanID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, func() {}, fmt.Errorf("create template dir: %w", err)
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
		// Defense in depth: the caller already filtered, but nothing statically
		// unsafe is ever written where the engine will load it. Unmerged
		// templates are staged only when the caller explicitly allows them
		// (bridge mode); the watcher never auto-runs them.
		why := nucleiTemplateUnsafeReason(t.Raw)
		if why == "" && !allowUnmerged && !t.merged() {
			why = "unmerged PR — not run"
		}
		if why != "" {
			logger.GetLogger().Infof("[NUCLEI-WATCH] %s not staged: %s", t.ID, why)
			continue
		}
		base := nucleiWatchStageName(t, usedNames)
		dest := filepath.Join(dir, base)
		if rel, rerr := filepath.Rel(dir, dest); rerr != nil || rel != base {
			logger.GetLogger().Infof("[NUCLEI-WATCH] %s: staged name %q escapes the template dir, skipping", t.ID, base)
			continue
		}
		if werr := os.WriteFile(dest, []byte(t.Raw), 0o600); werr != nil {
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

// ─── Mass-FP quantifier ───────────────────────────────────────────────────────
// Owner-approved feature 2026-10-04: watcher batches that match an implausible
// number of hosts are almost always broken matchers (Gridbox 428, BIG-IP
// 94127 76k, Cisco SD-WAN 135 — all lacked product fingerprints). After each
// watcher auto-run ends, the per-template DISTINCT-HOST counts are tallied
// from the scan's JSONL (disk truth); any template over the threshold is
// recorded in the NUCLEI_SUSPECT_FP_IDS setting — keyed id@<raw-yaml hash>, so
// only that revision is suspect and a fixed re-publish runs again — announced
// on the monitoring webhook, and excluded from FUTURE auto-runs (still
// announced, never silently dropped). Clearing the setting re-enables
// auto-run. During the sweep, runGlobalNucleiScan applies the same threshold
// after every host batch to mute a suspect's hit alerts for the rest of the
// scan.
//
// Threshold: max(NUCLEI_SUSPECT_FP_THRESHOLD (default 100 distinct hosts),
// NUCLEI_SUSPECT_FP_PCT % of the hosts scanned (default 0 = flat)). The flat
// default is deliberate: the real mass-FP templates seen so far matched a few
// hundred hosts (Gridbox 428, Cisco SD-WAN 135) — a 2% scale on the ~430K
// corpus (≈8,600) would stop flagging them. Raise the percentage only if a
// popular-product CVE keeps getting muted.

const (
	suspectFPIDsKey       = "NUCLEI_SUSPECT_FP_IDS"
	suspectFPThresholdKey = "NUCLEI_SUSPECT_FP_THRESHOLD"
	suspectFPPctKey       = "NUCLEI_SUSPECT_FP_PCT"
	suspectFPDefault      = 100
	suspectFPDefaultPct   = 0.0
	suspectFPMaxFileBytes = 256 << 20 // cap JSONL pass (76k-hit files ran 1.5GB)
)

func suspectFPThreshold() int {
	if n, err := strconv.Atoi(strings.TrimSpace(db.GetSettingOr(suspectFPThresholdKey, ""))); err == nil && n > 0 {
		return n
	}
	return suspectFPDefault
}

// suspectFPThresholdFor scales the mass-FP threshold to the corpus size.
func suspectFPThresholdFor(totalHosts int) int {
	pct := suspectFPDefaultPct
	if v, err := strconv.ParseFloat(strings.TrimSpace(db.GetSettingOr(suspectFPPctKey, "")), 64); err == nil && v >= 0 {
		pct = v
	}
	return suspectFPScaledThreshold(suspectFPThreshold(), pct, totalHosts)
}

// suspectFPScaledThreshold is the pure core of suspectFPThresholdFor.
func suspectFPScaledThreshold(base int, pct float64, totalHosts int) int {
	if scaled := int(float64(totalHosts) * pct / 100); scaled > base {
		return scaled
	}
	return base
}

func suspectFPIDs() map[string]bool {
	m := map[string]bool{}
	for _, id := range strings.Split(db.GetSettingOr(suspectFPIDsKey, ""), ",") {
		if id = strings.TrimSpace(id); id != "" {
			m[id] = true
		}
	}
	return m
}

func addSuspectFPIDs(ids []string) {
	if len(ids) == 0 {
		return
	}
	existing := suspectFPIDs()
	for _, id := range ids {
		existing[id] = true
	}
	out := make([]string, 0, len(existing))
	for id := range existing {
		out = append(out, id)
	}
	sort.Strings(out)
	_ = db.SetSetting(suspectFPIDsKey, strings.Join(out, ","))
}

// suspectFPExcluded filters auto-run candidates down to non-suspect templates.
func suspectFPExcluded(templates []pdcpTemplate) []pdcpTemplate {
	return suspectFPFilter(suspectFPIDs(), templates)
}

// suspectFPFilter is the pure core of suspectFPExcluded (unit-testable
// without the settings DB). Entries are id@hash revision keys; a bare id
// (legacy entries, or an operator listing one by hand) suspects every revision.
func suspectFPFilter(suspects map[string]bool, templates []pdcpTemplate) []pdcpTemplate {
	if len(suspects) == 0 {
		return templates
	}
	var out []pdcpTemplate
	for _, t := range templates {
		if suspects[t.ID] || suspects[nucleiTemplateRevKey(t.ID, t.Raw)] {
			logger.GetLogger().Infof("[NUCLEI-WATCH] %s is a suspected mass-FP template — auto-run skipped (clear %s to re-enable)", t.ID, suspectFPIDsKey)
			continue
		}
		out = append(out, t)
	}
	return out
}

// suspectFPTally counts DISTINCT hosts per template-id in a scan's JSONL with
// a bounded streaming pass (lines can exceed 100KB — base64 template bodies;
// total read capped at suspectFPMaxFileBytes).
func suspectFPTally(scanID string) map[string]int {
	return suspectFPTallyPath(filepath.Join(utils.GetResultsDir(), "global-subdomains", "vulnerabilities", "nuclei-"+scanID+".json"))
}

// suspectFPTallyPath is the pure core of suspectFPTally (unit-testable). One
// host matched by several matchers/paths emits several events — those count
// once (the alert says "N distinct hosts", which is what it now measures).
func suspectFPTallyPath(path string) map[string]int {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	hosts := map[string]map[string]struct{}{}
	reader := bufio.NewReaderSize(f, 1<<20)
	var read int64
	for {
		line, err := reader.ReadString('\n')
		read += int64(len(line))
		var ev struct {
			TemplateID string `json:"template-id"`
			Host       string `json:"host"`
			Matched    string `json:"matched-at"`
		}
		if strings.HasPrefix(strings.TrimSpace(line), "{") && json.Unmarshal([]byte(line), &ev) == nil && ev.TemplateID != "" {
			h := ev.Host
			if h == "" {
				h = ev.Matched
			}
			set := hosts[ev.TemplateID]
			if set == nil {
				set = map[string]struct{}{}
				hosts[ev.TemplateID] = set
			}
			set[strings.ToLower(raceHostOf(h))] = struct{}{}
		}
		if err != nil || read > suspectFPMaxFileBytes {
			break
		}
	}
	tally := make(map[string]int, len(hosts))
	for id, set := range hosts {
		tally[id] = len(set)
	}
	return tally
}

// suspectFPQuantify runs after a watcher auto-run scan ends: tallies
// per-template distinct hosts, records+announces templates over the
// corpus-scaled threshold. revs maps template ID -> staged revision key.
func suspectFPQuantify(scanID string, totalHosts int, revs map[string]string) {
	threshold := suspectFPThresholdFor(totalHosts)
	type flag struct {
		id, key string
		hosts   int
	}
	var flagged []flag
	for id, n := range suspectFPTally(scanID) {
		if n < threshold {
			continue
		}
		key := revs[id]
		if key == "" {
			key = id
		}
		flagged = append(flagged, flag{id: id, key: key, hosts: n})
		logger.GetLogger().Infof("[NUCLEI-WATCH] mass-FP suspect: %s matched %d distinct host(s) (threshold %d of %d targets)", key, n, threshold, totalHosts)
	}
	if len(flagged) == 0 {
		return
	}
	sort.Slice(flagged, func(i, j int) bool { return flagged[i].hosts > flagged[j].hosts })
	keys := make([]string, 0, len(flagged))
	for _, f := range flagged {
		keys = append(keys, f.key)
	}
	addSuspectFPIDs(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "🧪 **Suspected mass-FP template(s)** — ≥%d distinct hosts (of %d scanned) in scan `%s`:\n", threshold, totalHosts, scanID)
	for _, f := range flagged {
		fmt.Fprintf(&b, "• `%s` matched **%d** distinct host(s) — this revision is SKIPPED on future auto-runs until validated\n", nucleiSafeToken(f.key), f.hosts)
	}
	b.WriteString("Validate before trusting these hits (fingerprint discriminators). To permanently block: add to NUCLEI_TEMPLATE_IGNORE. To re-enable auto-run: clear NUCLEI_SUSPECT_FP_IDS in Settings.")
	utils.SendMonitorWebhook(b.String())
}
