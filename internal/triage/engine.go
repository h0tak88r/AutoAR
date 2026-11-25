package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// Config is the operator-tunable triage policy (Settings ▸ AI Providers).
type Config struct {
	AutoAfterScan      bool   `json:"auto_after_scan"`      // triage every finished scan automatically
	MinSeverity        string `json:"min_severity"`         // only triage/report at or above this
	MinConfidence      int    `json:"min_confidence"`       // 0-100, needed to be reportable
	DailyLimit         int    `json:"daily_limit"`          // max AI calls per UTC day
	MaxPerScan         int    `json:"max_per_scan"`         // max AI calls per scan
	SamplesPerTemplate int    `json:"samples_per_template"` // FP samples before giving up on a template
	Notify             bool   `json:"notify"`               // post reportable verdicts to Discord
	RequireInScope     bool   `json:"require_in_scope"`     // only notify hosts matched to an in-scope program
	Replay             bool   `json:"replay"`               // one safe GET re-check of GET hits
	DashboardURL       string `json:"dashboard_url"`        // e.g. https://autoar.example.com (links in alerts)
}

// DefaultConfig is used until the operator saves their own.
func DefaultConfig() Config {
	return Config{
		AutoAfterScan:      true,
		MinSeverity:        "medium",
		MinConfidence:      75,
		DailyLimit:         200,
		MaxPerScan:         40,
		SamplesPerTemplate: 3,
		Notify:             true,
		RequireInScope:     false,
		Replay:             true,
	}
}

// Normalize clamps every field into its valid range.
func (c Config) Normalize() Config {
	c.MinSeverity = NormalizeSeverity(c.MinSeverity)
	if c.MinSeverity == "unknown" || c.MinSeverity == "info" {
		c.MinSeverity = "low"
	}
	c.MinConfidence = clampInt(c.MinConfidence, 0, 100)
	c.DailyLimit = clampInt(c.DailyLimit, 1, 5000)
	c.MaxPerScan = clampInt(c.MaxPerScan, 1, 500)
	c.SamplesPerTemplate = clampInt(c.SamplesPerTemplate, 1, 20)
	c.DashboardURL = strings.TrimRight(strings.TrimSpace(c.DashboardURL), "/")
	if c.DashboardURL != "" && !strings.HasPrefix(c.DashboardURL, "https://") && !strings.HasPrefix(c.DashboardURL, "http://") {
		c.DashboardURL = ""
	}
	return c
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Scope is the bug-bounty program verdict for a host.
type Scope struct {
	Status  string // in | out | paused | unknown
	Program string // "h1 acme"
}

// Store persists verdicts (db.* in production, a fake in tests).
type Store interface {
	Get(id string) (*db.TriageRecord, error)
	Upsert(*db.TriageRecord) error
	SetNotified(id string, at int64, note string) error
}

// Deps wires the engine to the outside world.
type Deps struct {
	Store    Store
	Complete func(ctx context.Context, system, user string, opt brain.Options) (string, error)
	Provider func() (id, model string)
	Scope    func(host string) Scope
	Allow    func() bool // takes one unit of the daily AI budget
	Replay   func(ctx context.Context, f Finding) *ReplayResult
	Notify   func(ctx context.Context, rec *db.TriageRecord, cfg Config) error
	Now      func() time.Time
}

// Engine triages findings with Deps under a Config.
type Engine struct{ d Deps }

// New builds an engine; nil optional deps get safe defaults.
func New(d Deps) *Engine {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Scope == nil {
		d.Scope = func(string) Scope { return Scope{Status: "unknown"} }
	}
	if d.Allow == nil {
		d.Allow = func() bool { return true }
	}
	if d.Provider == nil {
		d.Provider = func() (string, string) { p := brain.Active(); return p.ID, p.Model() }
	}
	return &Engine{d: d}
}

// Summary reports what one TriageScan run did.
type Summary struct {
	ScanID            string `json:"scan_id"`
	Considered        int    `json:"considered"`          // findings at/above MinSeverity
	BelowSeverity     int    `json:"below_severity"`      // ignored by severity
	Cached            int    `json:"cached"`              // already triaged earlier
	Triaged           int    `json:"triaged"`             // AI calls made
	TemplateFPSkipped int    `json:"template_fp_skipped"` // skipped: template judged FP on samples
	CapSkipped        int    `json:"cap_skipped"`         // skipped: per-scan cap
	Reportable        int    `json:"reportable"`
	Notified          int    `json:"notified"`
	Errors            int    `json:"errors"`
	Ingested          int    `json:"ingested"`     // scan hits recorded as findings
	NewFindings       int    `json:"new_findings"` // of those, first time seen
	BudgetExhausted   bool   `json:"budget_exhausted"`
	Error             string `json:"error,omitempty"`
	StartedAt         int64  `json:"started_at"`
	FinishedAt        int64  `json:"finished_at"`
}

// TriageScan validates a scan's findings. force re-triages findings that
// already have a verdict (operator overrides are always kept).
func (e *Engine) TriageScan(ctx context.Context, cfg Config, scanID string, findings []Finding, force bool) Summary {
	cfg = cfg.Normalize()
	sum := Summary{ScanID: scanID, StartedAt: e.d.Now().Unix()}
	defer func() { sum.FinishedAt = e.d.Now().Unix() }()

	minRank := SeverityRank(cfg.MinSeverity)
	var work []Finding
	seen := map[string]bool{}
	for _, f := range findings {
		if SeverityRank(f.Severity) < minRank {
			sum.BelowSeverity++
			continue
		}
		if k := f.Key(); !seen[k] {
			seen[k] = true
			work = append(work, f)
		}
	}
	sum.Considered = len(work)
	// Most severe first; CVE templates before generic ones; stable within.
	sort.SliceStable(work, func(i, j int) bool {
		ri, rj := SeverityRank(work[i].Severity), SeverityRank(work[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if (len(work[i].CVE) > 0) != (len(work[j].CVE) > 0) {
			return len(work[i].CVE) > 0
		}
		return work[i].TemplateID < work[j].TemplateID
	})

	type tplStat struct{ sampled, fp int }
	stats := map[string]*tplStat{}
	for _, f := range work {
		if ctx.Err() != nil {
			sum.Error = ctx.Err().Error()
			return sum
		}
		st := stats[f.TemplateID]
		if st == nil {
			st = &tplStat{}
			stats[f.TemplateID] = st
		}
		// A template whose first N hits were all confident false positives is
		// a broken matcher on this corpus — don't spend budget on the rest.
		if st.sampled >= cfg.SamplesPerTemplate && st.fp == st.sampled {
			sum.TemplateFPSkipped++
			continue
		}
		prev, _ := e.d.Store.Get(f.Key())
		if prev != nil && prev.Status == "done" && (!force || prev.HumanVerdict != "") {
			sum.Cached++
			st.sampled++
			if prev.Verdict == "false_positive" {
				st.fp++
			}
			continue
		}
		if sum.Triaged >= cfg.MaxPerScan {
			sum.CapSkipped++
			continue
		}
		if !e.d.Allow() {
			sum.BudgetExhausted = true
			sum.Error = ErrBudget.Error()
			return sum
		}
		sum.Triaged++
		rec, err := e.triageOne(ctx, cfg, f, prev)
		if err != nil {
			sum.Errors++
			if brain.IsNotConfigured(err) {
				sum.Error = err.Error()
				return sum
			}
			continue
		}
		st.sampled++
		if rec.Verdict == "false_positive" && rec.Confidence >= 60 {
			st.fp++
		}
		if rec.Reportable {
			sum.Reportable++
			if rec.NotifiedAt > 0 {
				sum.Notified++
			}
		}
	}
	return sum
}

// ErrBudget means the daily AI review budget is used up.
var ErrBudget = errors.New("daily AI triage limit reached")

// ReviewOne reviews a single finding on the operator's request: no severity
// floor and no per-template false-positive shortcut. The daily budget still
// applies, and a finished review is reused unless force is set (an operator
// override is always kept).
func (e *Engine) ReviewOne(ctx context.Context, cfg Config, f Finding, force bool) (*db.TriageRecord, error) {
	cfg = cfg.Normalize()
	prev, _ := e.d.Store.Get(f.Key())
	if prev != nil && prev.Status == "done" && !force {
		return prev, nil
	}
	if !e.d.Allow() {
		return nil, ErrBudget
	}
	return e.triageOne(ctx, cfg, f, prev)
}

// triageOne runs the model on one finding, applies the policy, persists and
// (when reportable) notifies. prev is the existing record, if any.
func (e *Engine) triageOne(ctx context.Context, cfg Config, f Finding, prev *db.TriageRecord) (*db.TriageRecord, error) {
	now := e.d.Now().Unix()
	scope := e.d.Scope(f.Host)
	var replay *ReplayResult
	if cfg.Replay && e.d.Replay != nil {
		replay = e.d.Replay(ctx, f)
	}
	provider, model := e.d.Provider()
	rec := &db.TriageRecord{
		ID: f.Key(), ScanID: f.ScanID, TemplateID: f.TemplateID, Title: f.Title(), Host: f.Host,
		MatchedAt: f.MatchedAt, Severity: f.Severity, Scope: scope.Status, ScopeProgram: scope.Program,
		Evidence: evidenceJSON(f, replay), Provider: provider, Model: model, CreatedAt: now, UpdatedAt: now,
	}
	if replay != nil {
		rec.ReplayStatus = replay.Status
	}
	if prev != nil {
		rec.CreatedAt = prev.CreatedAt
		rec.HumanVerdict = prev.HumanVerdict
		rec.NotifiedAt = prev.NotifiedAt
		rec.NotifyNote = prev.NotifyNote
	}

	reply, err := e.d.Complete(ctx, systemPrompt, buildPrompt(f, replay, scope),
		brain.Options{JSON: true, MaxTokens: 4096, Timeout: 3 * time.Minute, Feature: "triage"})
	if err != nil {
		if brain.IsNotConfigured(err) {
			return nil, err
		}
		rec.Status, rec.Error = "error", clip(err.Error(), 500)
		_ = e.d.Store.Upsert(rec)
		return nil, err
	}
	v, err := parseVerdict(reply)
	if err != nil {
		rec.Status, rec.Error = "error", "unparseable model reply: "+clip(err.Error(), 200)
		_ = e.d.Store.Upsert(rec)
		return nil, err
	}

	rec.Status = "done"
	rec.Verdict, rec.Confidence, rec.Reason = v.Verdict, v.Confidence, clip(v.Reason, 2000)
	rec.AISeverity = NormalizeSeverity(v.Severity)
	if t := strings.TrimSpace(v.Title); t != "" {
		rec.Title = clip(t, 200)
	}
	rec.Reportable, rec.NotifyNote = Decide(cfg, v, f, scope, rec.HumanVerdict)
	if rec.Reportable {
		rec.ReportMD = strings.TrimSpace(v.ReportMarkdown)
		if rec.ReportMD == "" {
			rec.ReportMD = fallbackReport(f, rec)
		}
		rec.ReportMD = clip(rec.ReportMD, 20000)
	}
	if err := e.d.Store.Upsert(rec); err != nil {
		return nil, err
	}

	if rec.Reportable && cfg.Notify && rec.NotifiedAt == 0 && e.d.Notify != nil {
		if err := e.d.Notify(ctx, rec, cfg); err != nil {
			rec.NotifyNote = "Discord delivery failed: " + clip(err.Error(), 200)
			_ = e.d.Store.SetNotified(rec.ID, 0, rec.NotifyNote)
		} else {
			rec.NotifiedAt = e.d.Now().Unix()
			rec.NotifyNote = "sent to Discord"
			_ = e.d.Store.SetNotified(rec.ID, rec.NotifiedAt, rec.NotifyNote)
		}
	}
	return rec, nil
}

// Decide is the deterministic reportability policy. The model's opinion is one
// input; scope, severity, confidence and the operator's override are hard gates.
func Decide(cfg Config, v Verdict, f Finding, scope Scope, human string) (bool, string) {
	cfg = cfg.Normalize()
	switch {
	case human == "false_positive":
		return false, "operator marked false positive"
	case v.Verdict != "true_positive" && v.Verdict != "likely":
		return false, "model verdict: " + v.Verdict
	case !v.Reportable:
		return false, "model judged it not worth reporting"
	case v.Confidence < cfg.MinConfidence:
		return false, fmt.Sprintf("confidence %d%% below %d%%", v.Confidence, cfg.MinConfidence)
	}
	sev := NormalizeSeverity(v.Severity)
	if sev == "unknown" {
		sev = f.Severity
	}
	if SeverityRank(sev) < SeverityRank(cfg.MinSeverity) {
		return false, "assessed severity " + sev + " below " + cfg.MinSeverity
	}
	switch scope.Status {
	case "out":
		return false, "host is out of scope (" + scope.Program + ")"
	case "paused":
		return false, "program is paused (" + scope.Program + ")"
	case "in":
		return true, "in scope: " + scope.Program
	}
	if cfg.RequireInScope {
		return false, "no in-scope program matched this host"
	}
	return true, "scope unverified — check the program before filing"
}

// Verdict is the model's structured answer.
type Verdict struct {
	Verdict        string `json:"verdict"`
	Confidence     int    `json:"-"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Reason         string `json:"reason"`
	Reportable     bool   `json:"reportable"`
	ReportMarkdown string `json:"report_markdown"`
}

var validVerdicts = map[string]bool{"true_positive": true, "likely": true, "false_positive": true, "needs_manual_review": true}

// parseVerdict extracts and validates the JSON object from a model reply.
func parseVerdict(reply string) (Verdict, error) {
	s := strings.TrimSpace(reply)
	if i, j := strings.IndexByte(s, '{'), strings.LastIndexByte(s, '}'); i >= 0 && j > i {
		s = s[i : j+1]
	} else {
		return Verdict{}, fmt.Errorf("no JSON object in reply")
	}
	var raw struct {
		Verdict
		Confidence json.RawMessage `json:"confidence"`
		Reportable json.RawMessage `json:"reportable"`
	}
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		return Verdict{}, err
	}
	v := raw.Verdict
	v.Verdict = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v.Verdict, " ", "_")))
	if !validVerdicts[v.Verdict] {
		return Verdict{}, fmt.Errorf("unknown verdict %q", v.Verdict)
	}
	c := strings.Trim(strings.TrimSpace(string(raw.Confidence)), `"%`)
	if n, err := strconv.ParseFloat(strings.TrimSuffix(c, "%"), 64); err == nil {
		if n > 0 && n <= 1 {
			n *= 100 // 0.92 → 92
		}
		v.Confidence = clampInt(int(n+0.5), 0, 100)
	}
	r := strings.ToLower(strings.Trim(strings.TrimSpace(string(raw.Reportable)), `"`))
	v.Reportable = r == "true" || r == "yes" || r == "1"
	return v, nil
}

func evidenceJSON(f Finding, r *ReplayResult) string {
	ev := struct {
		Finding
		Replay *ReplayResult `json:"replay,omitempty"`
	}{f, r}
	ev.Request = clip(ev.Request, 4000)
	ev.Response = clip(ev.Response, 6000)
	b, _ := json.Marshal(ev)
	return string(b)
}

// fallbackReport is used when the model marked a finding reportable but
// returned no report body.
func fallbackReport(f Finding, rec *db.TriageRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Title\n%s on %s\n\n", rec.Title, f.Host)
	fmt.Fprintf(&b, "## Summary\n%s\n\n", rec.Reason)
	fmt.Fprintf(&b, "## Steps to Reproduce\n1. Request: `%s`\n", f.MatchedAt)
	if f.Curl != "" {
		fmt.Fprintf(&b, "\n```\n%s\n```\n", clip(f.Curl, 1500))
	}
	fmt.Fprintf(&b, "\n## Impact\nSee summary. Template: %s\n", f.TemplateID)
	return b.String()
}
