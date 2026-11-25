package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Finding is one security finding moving through the report pipeline:
// discovered → validated → drafted → approved → submitted → resolved
// (terminal alternatives: dup, rejected, wontfix).
// Seeded from scan hits + operator entries; the weekly digest reads the
// non-terminal rows older than a threshold to force decisions.
type Finding struct {
	ID        int64   `json:"id"`
	Title     string  `json:"title"`
	CVE       string  `json:"cve,omitempty"`
	Host      string  `json:"host,omitempty"`
	Program   string  `json:"program,omitempty"`
	Platform  string  `json:"platform,omitempty"` // h1 | bc | ywh | bizone | other
	Severity  string  `json:"severity,omitempty"`
	CVSS      float64 `json:"cvss,omitempty"`
	Source    string  `json:"source,omitempty"` // scan id / template / manual
	Status    string  `json:"status"`
	ReportRef string  `json:"report_ref,omitempty"` // platform report id/URL
	Notes     string  `json:"notes,omitempty"`
	ReportMD  string  `json:"report_md,omitempty"`
	FirstSeen int64   `json:"first_seen"`
	UpdatedAt int64   `json:"updated_at"`

	// Scan provenance. FKey is the scanner hit's stable identity (the same
	// key the AI triage engine stores its verdict under), so one finding =
	// one hit across every scan that sees it, and the AI label joins on it.
	FKey       string `json:"fkey,omitempty"`
	ScanID     string `json:"scan_id,omitempty"`
	Module     string `json:"module,omitempty"` // nuclei | zerodays | misconfig | dns-takeover | …
	TemplateID string `json:"template_id,omitempty"`
	MatchedAt  string `json:"matched_at,omitempty"`
	Evidence   string `json:"evidence,omitempty"` // JSON; only on GetFinding
	LastSeen   int64  `json:"last_seen,omitempty"`
	// RemindAt is a unix time to resurface this finding (0 = none) — e.g. a CVE
	// a program only accepts 30-90 days after publication.
	RemindAt   int64  `json:"remind_at,omitempty"`

	// ProgramMatch says how Program was found for a scan hit: in / out /
	// paused (the catalog lists the host or a covering wildcard), related
	// (only the root domain is listed — the host is not explicitly in
	// scope), guess (a program named like the root domain). "" = set by
	// hand or not found.
	ProgramMatch string `json:"program_match,omitempty"`
	// ProgramURL is the program's page; not stored — the API fills it in.
	ProgramURL string `json:"program_url,omitempty"`
	// ProgramAccounts are the stored account labels that can see this program
	// (which account to submit from); not stored — the API fills it in.
	ProgramAccounts []string `json:"program_accounts,omitempty"`

	AI *FindingAI `json:"ai,omitempty"` // nil = never reviewed by the AI

	// Validation is the AI agent's tool-backed check (finding_validations),
	// attached by the API layer; nil = never sent to the agent.
	Validation *FindingValidation `json:"validation,omitempty"`
}

// FindingAI is the AI review of a finding (ai_triage row joined on FKey).
type FindingAI struct {
	Verdict      string `json:"verdict"` // true_positive | likely | needs_manual_review | false_positive
	Confidence   int    `json:"confidence"`
	Severity     string `json:"severity,omitempty"` // the model's assessed severity
	Reason       string `json:"reason,omitempty"`
	Status       string `json:"status"` // done | error | human
	Error        string `json:"error,omitempty"`
	Reportable   bool   `json:"reportable"`
	Scope        string `json:"scope,omitempty"`
	ScopeProgram string `json:"scope_program,omitempty"`
	HumanVerdict string `json:"human_verdict,omitempty"`
	NotifiedAt   int64  `json:"notified_at,omitempty"`
	NotifyNote   string `json:"notify_note,omitempty"`
	Provider     string `json:"provider,omitempty"`
	Model        string `json:"model,omitempty"`
	ReplayStatus int    `json:"replay_status,omitempty"`
	UpdatedAt    int64  `json:"updated_at,omitempty"`
	HasReport    bool   `json:"has_report"`
	ReportMD     string `json:"report_md,omitempty"` // the AI's draft; only on GetFinding
}

// FindingFilter narrows ListFindings.
type FindingFilter struct {
	Status   string
	Platform string
	MinAgeH  int // only rows older than this many hours (0 = any)
	Limit    int
	Offset   int

	AI       string // reportable | true_positive | likely | needs_manual_review | false_positive | unreviewed | error
	Severity string // effective severity (the model's when it has one)
	Module   string
	Program  string // program handle; NoProgram = findings without one
	Report   string // "1" = has a report link, "0" = none
	ScanID   string
	Q        string // substring of title / host / template / CVE
	FKey     string // exact scan key (Discord deep links carry it)

	// HideClosed leaves out rejected / duplicate / won't-fix findings unless
	// Status asks for one of them (the dashboard's default view).
	HideClosed bool

	// RemindDueBefore > 0 keeps only findings with a reminder at or before that
	// unix time (due reminders). RemindSet keeps any finding with a reminder.
	RemindDueBefore int64
	RemindSet       bool
}

const findingCols = `f.id, f.title, f.cve, f.host, f.program, f.platform, f.severity, f.cvss, f.source, f.status, f.report_ref, f.notes, f.report_md, f.first_seen, f.updated_at, f.fkey, f.scan_id, f.module, f.template_id, f.matched_at, f.last_seen, f.program_match, f.remind_at`

// The AI review joined onto a finding. ai_triage is created alongside
// findings (see findingDB) so the join never meets a missing table.
const findingAICols = `COALESCE(t.id, ''), COALESCE(t.verdict, ''), COALESCE(t.confidence, 0), COALESCE(t.ai_severity, ''),
	COALESCE(t.reason, ''), COALESCE(t.status, ''), COALESCE(t.error, ''), COALESCE(t.reportable, 0), COALESCE(t.scope, ''),
	COALESCE(t.scope_program, ''), COALESCE(t.human_verdict, ''), COALESCE(t.notified_at, 0), COALESCE(t.notify_note, ''),
	COALESCE(t.provider, ''), COALESCE(t.model, ''), COALESCE(t.replay_status, 0), COALESCE(t.updated_at, 0),
	CASE WHEN COALESCE(t.report_md, '') = '' THEN 0 ELSE 1 END`

const findingFrom = ` FROM findings f LEFT JOIN ai_triage t ON f.fkey <> '' AND t.id = f.fkey `

// findingEffectiveVerdict is one verdict per finding, the operator first:
// an explicit label (human_verdict); else what the workflow status says — a
// finding moved to validated … resolved, dup or wontfix is a confirmed bug,
// rejected is not; else, for an untouched (discovered) finding, the model's
// verdict. The AI filters, the counts and the row pill all use it, so a
// submitted finding the AI never saw no longer sits under "Not reviewed".
const findingEffectiveVerdict = `CASE
	WHEN COALESCE(t.human_verdict, '') <> '' THEN t.human_verdict
	WHEN f.status IN ('validated', 'drafted', 'approved', 'submitted', 'resolved', 'dup', 'wontfix') THEN 'true_positive'
	WHEN f.status = 'rejected' THEN 'false_positive'
	ELSE COALESCE(t.verdict, '') END`

// findingReportableCond is "confirmed and not yet filed": validated, drafted
// or approved by the operator, or an untouched finding the AI judged
// reportable — never one labelled a false positive.
const findingReportableCond = `(` + findingEffectiveVerdict + `) <> 'false_positive' AND (f.status IN ('validated', 'drafted', 'approved')
	OR (f.status = 'discovered' AND COALESCE(t.reportable, 0) = 1))`

// findingUnreviewedCond is an untouched finding no one has judged yet.
const findingUnreviewedCond = `f.status = 'discovered' AND COALESCE(t.human_verdict, '') = ''
	AND (t.id IS NULL OR COALESCE(t.status, '') NOT IN ('done', 'error'))`

// ClosedFindingStatuses are the "not pursuing" outcomes the dashboard hides
// by default: they stay in the table so a scan that sees the hit again
// keeps it closed instead of reporting it as new.
var ClosedFindingStatuses = []string{"rejected", "dup", "wontfix"}

const closedStatusList = `'rejected','dup','wontfix'`

// findingAIErrorCond is an untouched finding whose AI review failed.
const findingAIErrorCond = `f.status = 'discovered' AND t.status = 'error' AND COALESCE(t.human_verdict, '') = ''`

var findingSchema = []string{
	`CREATE TABLE IF NOT EXISTS findings (
		id BIGSERIAL PRIMARY KEY,
		title TEXT NOT NULL,
		cve TEXT NOT NULL DEFAULT '',
		host TEXT NOT NULL DEFAULT '',
		program TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		cvss REAL NOT NULL DEFAULT 0,
		source TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'discovered',
		report_ref TEXT NOT NULL DEFAULT '',
		notes TEXT NOT NULL DEFAULT '',
		report_md TEXT NOT NULL DEFAULT '',
		first_seen BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0,
		fkey TEXT NOT NULL DEFAULT '',
		scan_id TEXT NOT NULL DEFAULT '',
		module TEXT NOT NULL DEFAULT '',
		template_id TEXT NOT NULL DEFAULT '',
		matched_at TEXT NOT NULL DEFAULT '',
		evidence TEXT NOT NULL DEFAULT '',
		last_seen BIGINT NOT NULL DEFAULT 0,
		remind_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_updated ON findings(updated_at)`,
}

var (
	findingReadyOn   DB
	findingReadyOnce bool
)

// sqlite has no BIGSERIAL: INTEGER PRIMARY KEY autoincrements equivalently.
var findingSchemaSQLite = []string{
	`CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		title TEXT NOT NULL,
		cve TEXT NOT NULL DEFAULT '',
		host TEXT NOT NULL DEFAULT '',
		program TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		cvss REAL NOT NULL DEFAULT 0,
		source TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'discovered',
		report_ref TEXT NOT NULL DEFAULT '',
		notes TEXT NOT NULL DEFAULT '',
		report_md TEXT NOT NULL DEFAULT '',
		first_seen BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0,
		fkey TEXT NOT NULL DEFAULT '',
		scan_id TEXT NOT NULL DEFAULT '',
		module TEXT NOT NULL DEFAULT '',
		template_id TEXT NOT NULL DEFAULT '',
		matched_at TEXT NOT NULL DEFAULT '',
		evidence TEXT NOT NULL DEFAULT '',
		last_seen BIGINT NOT NULL DEFAULT 0,
		remind_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)`,
	`CREATE INDEX IF NOT EXISTS idx_findings_updated ON findings(updated_at)`,
}

func findingsMigrate(c triageConn) {
	// CREATE TABLE IF NOT EXISTS does not extend an existing findings table;
	// "already exists" errors on re-runs are expected and ignored.
	_ = c.exec(`ALTER TABLE findings ADD COLUMN report_md TEXT NOT NULL DEFAULT ''`)
	for _, col := range []string{"fkey", "scan_id", "module", "template_id", "matched_at", "evidence", "program_match"} {
		_ = c.exec(`ALTER TABLE findings ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`)
	}
	_ = c.exec(`ALTER TABLE findings ADD COLUMN last_seen BIGINT NOT NULL DEFAULT 0`)
	_ = c.exec(`ALTER TABLE findings ADD COLUMN remind_at BIGINT NOT NULL DEFAULT 0`)
	// One finding per scanner hit; manual findings (fkey '') are exempt.
	_ = c.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fkey ON findings(fkey) WHERE fkey <> ''`)
	_ = c.exec(`CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)`)
}

func findingDB() (triageConn, []string, error) {
	if err := Init(); err != nil {
		return nil, nil, err
	}
	_, isPG := dbInstance.(*PostgresDB)
	schema := findingSchema
	if !isPG {
		schema = findingSchemaSQLite
	}
	if !findingReadyOnce || findingReadyOn != dbInstance {
		var c triageConn
		switch d := dbInstance.(type) {
		case *PostgresDB:
			c = pgTriage{p: d}
		case *SQLiteDB:
			c = sqliteTriage{s: d}
		default:
			return nil, nil, errors.New("findings: unsupported backend")
		}
		for _, q := range schema {
			if err := c.exec(q); err != nil {
				return nil, nil, fmt.Errorf("findings schema: %w", err)
			}
		}
		findingsMigrate(c)
		// The AI-review table is joined on every read.
		if _, err := triageDB(); err != nil {
			return nil, nil, fmt.Errorf("findings: ai_triage: %w", err)
		}
		findingReadyOn, findingReadyOnce = dbInstance, true
	}
	switch d := dbInstance.(type) {
	case *PostgresDB:
		return pgTriage{p: d}, schema, nil
	case *SQLiteDB:
		return sqliteTriage{s: d}, schema, nil
	}
	return nil, nil, errors.New("findings: unsupported backend")
}

var ValidFindingStatuses = map[string]bool{
	"discovered": true, "validated": true, "drafted": true, "approved": true,
	"submitted": true, "resolved": true, "dup": true, "rejected": true, "wontfix": true,
}

// CreateFinding inserts a finding (status defaults to discovered).
func CreateFinding(f *Finding) error {
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	if f.FirstSeen == 0 {
		f.FirstSeen = now
	}
	f.UpdatedAt = now
	if f.Status == "" || !ValidFindingStatuses[f.Status] {
		f.Status = "discovered"
	}
	// RETURNING id works as a result query on both Postgres and modernc SQLite.
	if f.LastSeen == 0 {
		f.LastSeen = f.FirstSeen
	}
	return c.query(`INSERT INTO findings (title, cve, host, program, platform, severity, cvss, source, status, report_ref, notes, first_seen, updated_at,
		fkey, scan_id, module, template_id, matched_at, evidence, last_seen, program_match)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`, func(r rowScanner) error {
		return r.Scan(&f.ID)
	}, f.Title, f.CVE, f.Host, f.Program, f.Platform, f.Severity, f.CVSS, f.Source, f.Status, f.ReportRef, f.Notes, f.FirstSeen, f.UpdatedAt,
		f.FKey, f.ScanID, f.Module, f.TemplateID, f.MatchedAt, clipText(f.Evidence, 60000), f.LastSeen, f.ProgramMatch)
}

// UpdateFindingStatus transitions a finding and stamps updated_at.
func UpdateFindingStatus(id int64, status, reportRef, notes string) error {
	if !ValidFindingStatuses[status] {
		return fmt.Errorf("invalid status %q", status)
	}
	if err := ValidReportRef(reportRef); err != nil {
		return err
	}
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE findings SET status = ?,
		report_ref = CASE WHEN ? <> '' THEN ? ELSE report_ref END,
		notes = CASE WHEN ? <> '' THEN ? ELSE notes END,
		updated_at = ? WHERE id = ?`,
		status, reportRef, reportRef, notes, notes, time.Now().UTC().Unix(), id)
}

// ErrFindingNotFound is returned for unknown ids.
var ErrFindingNotFound = errors.New("finding not found")

// GetFinding loads one row.
func GetFinding(id int64) (*Finding, error) {
	c, _, err := findingDB()
	if err != nil {
		return nil, err
	}
	var out *Finding
	err = c.query(`SELECT `+findingCols+`, `+findingAICols+`, f.evidence, COALESCE(t.report_md, '')`+findingFrom+`WHERE f.id = ? LIMIT 1`, func(r rowScanner) error {
		f, err := scanFinding(r, true)
		out = f
		return err
	}, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrFindingNotFound
		}
		return nil, err
	}
	if out == nil {
		return nil, ErrFindingNotFound
	}
	return out, nil
}

// ListFindings returns filtered rows (newest activity first) plus the total.
func ListFindings(f FindingFilter) ([]*Finding, int, error) {
	c, _, err := findingDB()
	if err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	wsql, args, err := findingWhere(f)
	if err != nil {
		return nil, 0, err
	}
	total := 0
	if err := c.query(`SELECT COUNT(*)`+findingFrom+`WHERE `+wsql, func(r rowScanner) error {
		return r.Scan(&total)
	}, args...); err != nil {
		return nil, 0, err
	}
	var out []*Finding
	err = c.query(`SELECT `+findingCols+`, `+findingAICols+findingFrom+`WHERE `+wsql+
		` ORDER BY CASE WHEN f.last_seen > f.updated_at THEN f.last_seen ELSE f.updated_at END DESC, f.id DESC LIMIT ? OFFSET ?`,
		func(r rowScanner) error {
			rec, err := scanFinding(r, false)
			if err != nil {
				return err
			}
			out = append(out, rec)
			return nil
		}, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// findingWhere builds the WHERE clause (aliases: f = findings, t = ai_triage).
func findingWhere(f FindingFilter) (string, []any, error) {
	where := []string{"1=1"}
	var args []any
	add := func(clause string, a ...any) { where = append(where, clause); args = append(args, a...) }
	if f.Status != "" {
		add("f.status = ?", f.Status)
	} else if f.HideClosed {
		add("f.status NOT IN (" + closedStatusList + ")")
	}
	if f.Platform != "" {
		add("f.platform = ?", f.Platform)
	}
	if f.MinAgeH > 0 {
		add("f.updated_at < ?", time.Now().UTC().Unix()-int64(f.MinAgeH)*3600)
	}
	if f.ScanID != "" {
		add("f.scan_id = ?", f.ScanID)
	}
	switch f.Module {
	case "":
	case "race": // PoC-day and template-watch race passes (scan ids race-cve-…)
		add("f.scan_id LIKE ?", "race-cve-%")
	default:
		add("f.module = ?", f.Module)
	}
	if f.FKey != "" {
		add("f.fkey = ?", f.FKey)
	}
	switch {
	case f.Program == NoProgram:
		add("f.program = ''")
	case f.Program != "":
		add("LOWER(f.program) = ?", strings.ToLower(f.Program))
	}
	switch f.Report {
	case "1":
		add("f.report_ref <> ''")
	case "0":
		add("f.report_ref = ''")
	}
	switch {
	case f.RemindDueBefore > 0:
		add("f.remind_at > 0 AND f.remind_at <= ?", f.RemindDueBefore)
	case f.RemindSet:
		add("f.remind_at > 0")
	}
	if f.Severity != "" {
		add(`LOWER(COALESCE(NULLIF(NULLIF(t.ai_severity, ''), 'unknown'), f.severity)) = ?`, strings.ToLower(f.Severity))
	}
	if q := strings.ToLower(strings.TrimSpace(f.Q)); q != "" {
		like := "%" + q + "%"
		add("(LOWER(f.title) LIKE ? OR LOWER(f.host) LIKE ? OR LOWER(f.template_id) LIKE ? OR LOWER(f.cve) LIKE ? OR LOWER(f.matched_at) LIKE ?)",
			like, like, like, like, like)
	}
	switch f.AI {
	case "":
	case "reportable":
		add(findingReportableCond)
	case "true_positive", "likely", "needs_manual_review", "false_positive":
		add("("+findingEffectiveVerdict+") = ?", f.AI)
	case "unreviewed":
		add(findingUnreviewedCond)
	case "error":
		add(findingAIErrorCond)
	default:
		return "", nil, fmt.Errorf("unknown AI filter %q", f.AI)
	}
	return strings.Join(where, " AND "), args, nil
}

func scanFinding(r rowScanner, detail bool) (*Finding, error) {
	var f Finding
	var ai FindingAI
	var aiID string
	var reportable, hasReport int64
	dest := []any{&f.ID, &f.Title, &f.CVE, &f.Host, &f.Program, &f.Platform,
		&f.Severity, &f.CVSS, &f.Source, &f.Status, &f.ReportRef, &f.Notes, &f.ReportMD,
		&f.FirstSeen, &f.UpdatedAt, &f.FKey, &f.ScanID, &f.Module, &f.TemplateID, &f.MatchedAt, &f.LastSeen,
		&f.ProgramMatch, &f.RemindAt, &aiID, &ai.Verdict, &ai.Confidence, &ai.Severity, &ai.Reason, &ai.Status, &ai.Error, &reportable,
		&ai.Scope, &ai.ScopeProgram, &ai.HumanVerdict, &ai.NotifiedAt, &ai.NotifyNote, &ai.Provider, &ai.Model,
		&ai.ReplayStatus, &ai.UpdatedAt, &hasReport}
	if detail {
		dest = append(dest, &f.Evidence, &ai.ReportMD)
	}
	if err := r.Scan(dest...); err != nil {
		return nil, err
	}
	if aiID != "" {
		ai.Reportable, ai.HasReport = reportable == 1, hasReport == 1
		f.AI = &ai
	}
	return &f, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Port-surface corpus (host_ports)
// ─────────────────────────────────────────────────────────────────────────────

// HostPort is one open port on one live host.
type HostPort struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

var hostPortSchema = []string{
	`CREATE TABLE IF NOT EXISTS host_ports (
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL DEFAULT 'tcp',
		first_seen BIGINT NOT NULL DEFAULT 0,
		last_seen BIGINT NOT NULL DEFAULT 0,
		PRIMARY KEY (host, port)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_host_ports_port ON host_ports(port)`,
}

var hostPortReadyOnce bool

func ensureHostPorts() error {
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	if hostPortReadyOnce {
		return nil
	}
	for _, q := range hostPortSchema {
		if err := c.exec(q); err != nil {
			return fmt.Errorf("host_ports schema: %w", err)
		}
	}
	hostPortReadyOnce = true
	return nil
}

// UpsertHostPort records an open port, refreshing last_seen.
func UpsertHostPort(host string, port int, protocol string, now int64) error {
	if host == "" || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid host/port")
	}
	if err := ensureHostPorts(); err != nil {
		return err
	}
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	return c.exec(`INSERT INTO host_ports (host, port, protocol, first_seen, last_seen)
		VALUES (?,?,?,?,?)
		ON CONFLICT (host, port) DO UPDATE SET last_seen = excluded.last_seen`,
		host, port, protocol, now, now)
}

// ListHostPorts queries the port surface (newest last_seen first).
func ListHostPorts(host string, port, limit int) ([]*HostPort, int, error) {
	if err := ensureHostPorts(); err != nil {
		return nil, 0, err
	}
	c, _, err := findingDB()
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	where := []string{"1=1"}
	var args []any
	if host != "" {
		where = append(where, "host LIKE ?")
		args = append(args, "%"+host+"%")
	}
	if port > 0 {
		where = append(where, "port = ?")
		args = append(args, port)
	}
	wsql := strings.Join(where, " AND ")
	total := 0
	if err := c.query(`SELECT COUNT(*) FROM host_ports WHERE `+wsql, func(r rowScanner) error {
		return r.Scan(&total)
	}, args...); err != nil {
		return nil, 0, err
	}
	var out []*HostPort
	err = c.query(`SELECT host, port, protocol, first_seen, last_seen FROM host_ports WHERE `+wsql+` ORDER BY last_seen DESC LIMIT ?`,
		func(r rowScanner) error {
			var h HostPort
			if err := r.Scan(&h.Host, &h.Port, &h.Protocol, &h.FirstSeen, &h.LastSeen); err != nil {
				return err
			}
			out = append(out, &h)
			return nil
		}, append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// UpdateFindingReport stores the report markdown for a finding.
func UpdateFindingReport(id int64, reportMD string) error {
	c, _, err := findingDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE findings SET report_md = ?, updated_at = ? WHERE id = ?`,
		clipText(reportMD, 100000), time.Now().UTC().Unix(), id)
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
