package api

// AI triage wiring: config + daily budget in the settings table, findings read
// from each scan's indexed nuclei result files, a single-worker job queue, and
// a poller that queues every scan that finishes (race passes first). The
// engine itself — prompt, policy, Discord delivery — lives in internal/triage.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/r2storage"
	"github.com/h0tak88r/AutoAR/internal/triage"
)

const (
	triageConfigKey    = "ai_triage_config"
	triageWatermarkKey = "ai_triage_scan_watermark" // unix seconds of the newest scan already queued
	triageUsedPrefix   = "ai_triage_used_"          // + YYYYMMDD (UTC) → AI calls made that day
	triageMaxFindings  = 50000                      // per scan, after the severity filter
	triagePollInterval = time.Minute
)

// ── config & budget ──────────────────────────────────────────────────────────

func loadTriageConfig() triage.Config {
	cfg := triage.DefaultConfig()
	if raw, err := db.GetSetting(triageConfigKey); err == nil && strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg.Normalize()
}

func saveTriageConfig(cfg triage.Config) error {
	b, _ := json.Marshal(cfg.Normalize())
	return db.SetSetting(triageConfigKey, string(b))
}

var triageBudgetMu sync.Mutex

func triageUsedKey(t time.Time) string { return triageUsedPrefix + t.UTC().Format("20060102") }

func triageUsedToday() int { return db.GetSettingInt(triageUsedKey(time.Now()), 0) }

// triageAllow takes one AI call from today's budget.
func triageAllow() bool {
	triageBudgetMu.Lock()
	defer triageBudgetMu.Unlock()
	key := triageUsedKey(time.Now())
	used := db.GetSettingInt(key, 0)
	if used >= loadTriageConfig().DailyLimit {
		return false
	}
	return db.SetSetting(key, strconv.Itoa(used+1)) == nil
}

// ── engine deps ──────────────────────────────────────────────────────────────

type dbTriageStore struct{}

func (dbTriageStore) Get(id string) (*db.TriageRecord, error) {
	r, err := db.GetTriage(id)
	if errors.Is(err, db.ErrTriageNotFound) {
		return nil, nil
	}
	return r, err
}
func (dbTriageStore) Upsert(r *db.TriageRecord) error { return db.UpsertTriage(r) }
func (dbTriageStore) SetNotified(id string, at int64, note string) error {
	return db.SetTriageNotified(id, at, note)
}

// triageScopeFor maps the catalog's program match for a host (exact host or
// covering wildcard; out-of-scope entries win) to a scope verdict, including
// programs the watcher has seen paused or closed.
func triageScopeFor(host string) triage.Scope {
	programs := raceProgramsForHost(host)
	if len(programs) == 0 {
		return triage.Scope{Status: "unknown"}
	}
	p := programs[0]
	label := strings.TrimSpace(p.Source + " " + p.Handle)
	if !p.InScope {
		return triage.Scope{Status: "out", Program: label}
	}
	if st := catalogProgramInactive(programPauseStates(), p); st != "" {
		return triage.Scope{Status: "paused", Program: label + " (" + st + ")"}
	}
	return triage.Scope{Status: "in", Program: label}
}

var triageEngine = triage.New(triage.Deps{
	Store:    dbTriageStore{},
	Complete: brain.Complete,
	Scope:    triageScopeFor,
	Allow:    triageAllow,
	Replay:   triage.SafeReplay,
	Notify:   triage.NotifyDiscord,
})

// ── findings source ──────────────────────────────────────────────────────────

func isNucleiResultFile(a *db.ScanArtifact) bool {
	name := strings.ToLower(filepath.Base(a.FileName))
	if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".jsonl") {
		return false
	}
	return strings.Contains(name, "nuclei") || strings.EqualFold(a.Module, "nuclei")
}

// openArtifact returns a reader for an indexed result file: the local copy
// when present, else the R2 object (size-capped).
func openArtifact(scanID string, a *db.ScanArtifact) (io.ReadCloser, error) {
	for _, p := range []string{a.LocalPath, filepath.Join(getScanResultsDir(scanID), filepath.Base(a.FileName))} {
		if p == "" {
			continue
		}
		if f, err := os.Open(p); err == nil {
			return f, nil
		}
	}
	if a.R2Key == "" || !r2storage.IsEnabled() {
		return nil, fmt.Errorf("%s: not available locally or in R2", a.FileName)
	}
	if a.SizeBytes > 512<<20 {
		return nil, fmt.Errorf("%s: too large to triage from R2 (%d bytes)", a.FileName, a.SizeBytes)
	}
	b, err := r2storage.GetObjectBytes(a.R2Key)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// collectScanFindings streams a scan's nuclei result files (JSONL or a JSON
// array) and returns the findings at or above minSeverity.
func collectScanFindings(scanID, minSeverity string) ([]triage.Finding, error) {
	arts, err := db.ListScanArtifacts(scanID)
	if err != nil {
		return nil, err
	}
	minRank := triage.SeverityRank(minSeverity)
	seen := map[string]bool{}
	var out []triage.Finding
	keep := func(line []byte) {
		f, ok := triage.ParseNucleiLine(line, scanID)
		if !ok || triage.SeverityRank(f.Severity) < minRank || seen[f.Key()] || len(out) >= triageMaxFindings {
			return
		}
		seen[f.Key()] = true
		out = append(out, f)
	}
	files := map[string]bool{}
	for _, a := range arts {
		if a == nil || !isNucleiResultFile(a) || files[filepath.Base(a.FileName)] {
			continue
		}
		files[filepath.Base(a.FileName)] = true
		rc, err := openArtifact(scanID, a)
		if err != nil {
			log.Printf("[triage] %s: %v", scanID, err)
			continue
		}
		br := bufio.NewReaderSize(rc, 64<<10)
		if first, _ := br.Peek(1); len(first) == 1 && first[0] == '[' {
			var arr []json.RawMessage
			if json.NewDecoder(io.LimitReader(br, 512<<20)).Decode(&arr) == nil {
				for _, item := range arr {
					keep(item)
				}
			}
		} else {
			sc := bufio.NewScanner(br)
			sc.Buffer(make([]byte, 64<<10), 16<<20)
			for sc.Scan() {
				if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
					keep(line)
				}
			}
		}
		rc.Close()
	}
	return out, nil
}

// ── queue ────────────────────────────────────────────────────────────────────

type triageJob struct {
	ScanID      string `json:"scan_id"`
	Force       bool   `json:"force"`
	Reason      string `json:"reason"`
	AI          bool   `json:"ai"`           // run the AI review after importing findings
	IncludeInfo bool   `json:"include_info"` // also import info-level nuclei detections
}

type triageQueueState struct {
	mu      sync.Mutex
	pending []triageJob
	running *triageJob
	recent  []triage.Summary // newest last, bounded
	wake    chan struct{}
}

var triageQ = &triageQueueState{wake: make(chan struct{}, 1)}

// enqueueTriage adds a scan to the queue (deduplicated). front puts it ahead
// of everything waiting — used for race passes, where minutes matter.
func enqueueTriage(job triageJob, front bool) {
	q := triageQ
	q.mu.Lock()
	for i := range q.pending {
		if q.pending[i].ScanID == job.ScanID {
			q.pending[i].Force = q.pending[i].Force || job.Force
			q.pending[i].AI = q.pending[i].AI || job.AI
			q.pending[i].IncludeInfo = q.pending[i].IncludeInfo || job.IncludeInfo
			q.mu.Unlock()
			return
		}
	}
	if front {
		q.pending = append([]triageJob{job}, q.pending...)
	} else {
		q.pending = append(q.pending, job)
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *triageQueueState) next() (triageJob, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return triageJob{}, false
	}
	j := q.pending[0]
	q.pending = q.pending[1:]
	q.running = &j
	return j, true
}

func (q *triageQueueState) finish(s triage.Summary) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.running = nil
	q.recent = append(q.recent, s)
	if len(q.recent) > 30 {
		q.recent = q.recent[len(q.recent)-30:]
	}
}

func runTriageJob(j triageJob) (sum triage.Summary) {
	sum = triage.Summary{ScanID: j.ScanID, StartedAt: time.Now().Unix()}
	defer func() {
		if r := recover(); r != nil {
			sum.Error = fmt.Sprintf("panic: %v", r)
			log.Printf("[triage] panic triaging %s: %v", j.ScanID, r)
		}
		if sum.FinishedAt == 0 {
			sum.FinishedAt = time.Now().Unix()
		}
	}()
	cfg := loadTriageConfig()
	// Every finished scan feeds Findings; the AI review is a second step.
	findings, created, err := ingestScanFindings(j.ScanID, j.IncludeInfo)
	if err != nil {
		sum.Error = err.Error()
		return sum
	}
	sum.Ingested, sum.NewFindings = len(findings), created
	// Race-pass hits go to the agent once this job (and its AI review, whose
	// verdict the agent reads) is done.
	defer raceAutoValidateFn(j.ScanID)
	// AI is only set by callers that checked a provider is configured.
	if !j.AI || len(findings) == 0 {
		log.Printf("[findings] %s (%s): ingested=%d new=%d (no AI review)", j.ScanID, j.Reason, sum.Ingested, sum.NewFindings)
		return sum
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	ingested, fresh := sum.Ingested, sum.NewFindings
	sum = triageEngine.TriageScan(ctx, cfg, j.ScanID, findings, j.Force)
	sum.Ingested, sum.NewFindings = ingested, fresh
	log.Printf("[triage] %s (%s): ingested=%d new=%d considered=%d triaged=%d cached=%d reportable=%d notified=%d errors=%d %s",
		j.ScanID, j.Reason, sum.Ingested, sum.NewFindings, sum.Considered, sum.Triaged, sum.Cached, sum.Reportable, sum.Notified, sum.Errors, sum.Error)
	return sum
}

func triageWorker() {
	for {
		j, ok := triageQ.next()
		if !ok {
			<-triageQ.wake
			continue
		}
		triageQ.finish(runTriageJob(j))
	}
}

// triagePollOnce queues scans that finished since the watermark. The first run
// only sets the watermark, so enabling triage never back-fills old scans.
func triagePollOnce() {
	cfg := loadTriageConfig()
	// Findings import always runs; the AI review only when auto-triage is on
	// and a provider is configured.
	withAI := cfg.AutoAfterScan && brain.Available()
	wm := int64(db.GetSettingInt(triageWatermarkKey, 0))
	if wm == 0 {
		_ = db.SetSetting(triageWatermarkKey, strconv.FormatInt(time.Now().Unix(), 10))
		return
	}
	scans, err := db.ListRecentScans(200)
	if err != nil {
		return
	}
	var done []*db.ScanRecord
	for _, s := range scans {
		if s == nil || s.CompletedAt == nil || s.CompletedAt.Unix() <= wm {
			continue
		}
		switch strings.ToLower(s.Status) {
		case "completed", "done", "timed_out":
			done = append(done, s)
		}
	}
	sort.Slice(done, func(i, j int) bool { return done[i].CompletedAt.Before(*done[j].CompletedAt) })
	for _, s := range done {
		enqueueTriage(triageJob{ScanID: s.ScanID, Reason: "auto: " + s.ScanType + " " + s.Target, AI: withAI}, s.Target == "race-pass")
		if t := s.CompletedAt.Unix(); t > wm {
			wm = t
		}
	}
	if len(done) > 0 {
		_ = db.SetSetting(triageWatermarkKey, strconv.FormatInt(wm, 10))
	}
}

var triageStartOnce sync.Once

func startTriage() {
	triageStartOnce.Do(func() {
		// One-time: every existing AI verdict becomes a Findings row.
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[findings] merge panic: %v", r)
				}
			}()
			created, linked, err := db.MergeTriageIntoFindings()
			if err != nil {
				log.Printf("[findings] merging AI triage into findings: %v", err)
			} else if created+linked > 0 {
				log.Printf("[findings] merged AI triage into findings: %d created, %d linked", created, linked)
			}
		}()
		go triageWorker()
		go func() {
			t := time.NewTicker(triagePollInterval)
			defer t.Stop()
			for range t.C {
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[triage] poll panic: %v", r)
						}
					}()
					triagePollOnce()
				}()
			}
		}()
	})
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

// registerTriageRoutes mounts the triage API on the authenticated /api group
// and starts the background worker + poller.
func registerTriageRoutes(g *gin.RouterGroup) {
	g.GET("/triage", apiTriageList)
	g.GET("/triage/status", apiTriageStatus)
	g.GET("/triage/item/:id", apiTriageGet)
	g.GET("/triage/config", requireAdmin(), apiTriageGetConfig)
	g.POST("/triage/config", requireAdmin(), apiTriageSaveConfig)
	g.POST("/triage/scans/:id", requireAdmin(), apiTriageScan)
	g.POST("/triage/item/:id/notify", requireAdmin(), apiTriageNotify)
	g.POST("/triage/item/:id/verdict", requireAdmin(), apiTriageVerdict)
	g.POST("/triage/bulk-delete", requireAdmin(), apiTriageBulkDelete)
	startTriage()
}

// GET /api/triage?scan_id=&verdict=&reportable=1&limit=&offset=
func apiTriageList(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	rows, err := db.ListTriage(db.TriageFilter{
		ScanID:         strings.TrimSpace(c.Query("scan_id")),
		Verdict:        strings.TrimSpace(c.Query("verdict")),
		ReportableOnly: c.Query("reportable") == "1" || c.Query("reportable") == "true",
		Limit:          limit,
		Offset:         offset,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, r := range rows {
		r.Evidence = "" // list view stays light; GET /triage/item/:id has it
	}
	c.JSON(http.StatusOK, gin.H{"items": rows})
}

// GET /api/triage/item/:id
func apiTriageGet(c *gin.Context) {
	r, err := db.GetTriage(c.Param("id"))
	if errors.Is(err, db.ErrTriageNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, r)
}

// GET /api/triage/status
func apiTriageStatus(c *gin.Context) {
	cfg := loadTriageConfig()
	p := brain.Active()
	q := triageQ
	q.mu.Lock()
	pending := append([]triageJob(nil), q.pending...)
	var running *triageJob
	if q.running != nil {
		r := *q.running
		running = &r
	}
	recent := append([]triage.Summary(nil), q.recent...)
	q.mu.Unlock()
	for i, j := 0, len(recent)-1; i < j; i, j = i+1, j-1 {
		recent[i], recent[j] = recent[j], recent[i] // newest first
	}
	counts, _ := db.TriageCounts()
	c.JSON(http.StatusOK, gin.H{
		"ai_available": p.Configured(),
		"provider":     p.Name,
		"model":        p.Model(),
		"auto":         cfg.AutoAfterScan,
		"notify":       cfg.Notify,
		"used_today":   triageUsedToday(),
		"daily_limit":  cfg.DailyLimit,
		"pending":      pending,
		"running":      running,
		"recent":       recent,
		"counts":       counts,
	})
}

func apiTriageGetConfig(c *gin.Context) { c.JSON(http.StatusOK, loadTriageConfig()) }

// POST /api/triage/config — full config object (missing fields keep defaults).
func apiTriageSaveConfig(c *gin.Context) {
	cfg := loadTriageConfig()
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid config"})
		return
	}
	if err := saveTriageConfig(cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	saved := loadTriageConfig()
	audit(c, "triage.config", "", fmt.Sprintf("auto=%v notify=%v min_sev=%s min_conf=%d daily=%d",
		saved.AutoAfterScan, saved.Notify, saved.MinSeverity, saved.MinConfidence, saved.DailyLimit))
	c.JSON(http.StatusOK, saved)
}

// POST /api/triage/scans/:id {"force":bool} — queue one scan for triage.
func apiTriageScan(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan id required"})
		return
	}
	if !brain.Available() {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "no AI provider key configured — add one in Settings ▸ AI Providers"})
		return
	}
	if rec, err := db.GetScan(id); err != nil || rec == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	var body struct {
		Force bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&body)
	enqueueTriage(triageJob{ScanID: id, Force: body.Force, Reason: "manual", AI: true}, true)
	audit(c, "triage.scan", id, fmt.Sprintf("force=%v", body.Force))
	c.JSON(http.StatusAccepted, gin.H{"queued": true, "scan_id": id})
}

// POST /api/triage/item/:id/notify — (re)send one verdict to Discord.
func apiTriageNotify(c *gin.Context) {
	r, err := db.GetTriage(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if r.ReportMD == "" {
		r.ReportMD = "## Title\n" + r.Title + "\n\n## Summary\n" + r.Reason + "\n\n## Steps to Reproduce\n1. " + r.MatchedAt + "\n"
	}
	cfg := loadTriageConfig()
	if err := triage.NotifyDiscord(c.Request.Context(), r, cfg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	now := time.Now().Unix()
	_ = db.SetTriageNotified(r.ID, now, "sent to Discord by "+currentUsername(c))
	audit(c, "triage.notify", r.ID, r.Host)
	c.JSON(http.StatusOK, gin.H{"ok": true, "notified_at": now})
}

// POST /api/triage/item/:id/verdict {"verdict":"true_positive"|"false_positive"|""}
func apiTriageVerdict(c *gin.Context) {
	var body struct {
		Verdict string `json:"verdict"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	switch body.Verdict {
	case "true_positive", "false_positive", "":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "verdict must be true_positive, false_positive or empty"})
		return
	}
	id := c.Param("id")
	if _, err := db.GetTriage(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := db.SetTriageHumanVerdict(id, body.Verdict, time.Now().Unix()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	audit(c, "triage.verdict", id, body.Verdict)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/triage/bulk-delete {"ids":["..."]} — remove selected verdict rows.
// Admin-only housekeeping for the triage table's bulk actions.
func apiTriageBulkDelete(c *gin.Context) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids required"})
		return
	}
	for _, id := range body.IDs {
		if len(id) > 128 || strings.ContainsAny(id, " \t\r\n") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id in list"})
			return
		}
	}
	n, err := db.DeleteTriage(body.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	audit(c, "triage.bulk_delete", strings.Join(body.IDs, ","), fmt.Sprintf("%d rows", n))
	c.JSON(http.StatusOK, gin.H{"ok": true, "deleted": n})
}
