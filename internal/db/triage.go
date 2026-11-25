package db

// AI triage store: one row per triaged finding (see internal/triage). The table
// is created lazily on first use rather than in InitSchema, and both backends
// are implemented here with portable SQL (TEXT/INTEGER/BIGINT, ON CONFLICT
// upserts) so the feature stays self-contained.

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
)

// TriageRecord is one AI verdict on one scanner finding.
type TriageRecord struct {
	ID           string `json:"id"` // stable finding key (hash of template + location)
	ScanID       string `json:"scan_id"`
	TemplateID   string `json:"template_id"`
	Title        string `json:"title"`
	Host         string `json:"host"`
	MatchedAt    string `json:"matched_at"`
	Severity     string `json:"severity"`    // scanner severity
	AISeverity   string `json:"ai_severity"` // severity as assessed by the model
	Verdict      string `json:"verdict"`     // true_positive | likely | false_positive | needs_manual_review
	Confidence   int    `json:"confidence"`  // 0-100
	Reportable   bool   `json:"reportable"`  // passed the notify policy
	Scope        string `json:"scope"`       // in | out | paused | unknown
	ScopeProgram string `json:"scope_program"`
	Reason       string `json:"reason"`
	ReportMD     string `json:"report_md"`
	Evidence     string `json:"evidence"` // JSON snapshot of what the model saw
	ReplayStatus int    `json:"replay_status"`
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	Status       string `json:"status"` // done | error | skipped
	Error        string `json:"error,omitempty"`
	HumanVerdict string `json:"human_verdict"` // operator override: true_positive | false_positive | ""
	NotifyNote   string `json:"notify_note"`   // why it was / wasn't sent to Discord
	NotifiedAt   int64  `json:"notified_at"`   // unix seconds, 0 = never
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

// TriageFilter narrows ListTriage.
type TriageFilter struct {
	ScanID         string
	Host           string
	Verdict        string
	ReportableOnly bool
	Limit          int
	Offset         int
}

const triageCols = `id, scan_id, template_id, title, host, matched_at, severity, ai_severity,
	verdict, confidence, reportable, scope, scope_program, reason, report_md, evidence,
	replay_status, provider, model, status, error, human_verdict, notify_note,
	notified_at, created_at, updated_at`

var triageSchema = []string{
	`CREATE TABLE IF NOT EXISTS ai_triage (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL DEFAULT '',
		template_id TEXT NOT NULL DEFAULT '',
		title TEXT NOT NULL DEFAULT '',
		host TEXT NOT NULL DEFAULT '',
		matched_at TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		ai_severity TEXT NOT NULL DEFAULT '',
		verdict TEXT NOT NULL DEFAULT '',
		confidence INTEGER NOT NULL DEFAULT 0,
		reportable INTEGER NOT NULL DEFAULT 0,
		scope TEXT NOT NULL DEFAULT '',
		scope_program TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		report_md TEXT NOT NULL DEFAULT '',
		evidence TEXT NOT NULL DEFAULT '',
		replay_status INTEGER NOT NULL DEFAULT 0,
		provider TEXT NOT NULL DEFAULT '',
		model TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		human_verdict TEXT NOT NULL DEFAULT '',
		notify_note TEXT NOT NULL DEFAULT '',
		notified_at BIGINT NOT NULL DEFAULT 0,
		created_at BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ai_triage_scan ON ai_triage(scan_id)`,
	`CREATE INDEX IF NOT EXISTS idx_ai_triage_created ON ai_triage(created_at)`,
}

// triageConn adapts the two backends to the handful of calls the store needs.
type triageConn interface {
	exec(q string, args ...any) error
	query(q string, scan func(rowScanner) error, args ...any) error
}

type rowScanner interface{ Scan(dest ...any) error }

type pgTriage struct{ p *PostgresDB }

// rebind turns ? placeholders into $1..$n for Postgres.
func rebind(q string) string {
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (c pgTriage) exec(q string, args ...any) error {
	_, err := c.p.pool.Exec(c.p.ctx, rebind(q), args...)
	return err
}

func (c pgTriage) query(q string, scan func(rowScanner) error, args ...any) error {
	rows, err := c.p.pool.Query(c.p.ctx, rebind(q), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

type sqliteTriage struct{ s *SQLiteDB }

func (c sqliteTriage) exec(q string, args ...any) error {
	_, err := c.s.db.Exec(q, args...)
	return err
}

func (c sqliteTriage) query(q string, scan func(rowScanner) error, args ...any) error {
	rows, err := c.s.db.Query(q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

var (
	triageMu      sync.Mutex
	triageReadyOn DB // instance the schema was last ensured on (tests swap instances)
)

func triageDB() (triageConn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	var c triageConn
	switch d := dbInstance.(type) {
	case *PostgresDB:
		c = pgTriage{d}
	case *SQLiteDB:
		c = sqliteTriage{d}
	default:
		return nil, fmt.Errorf("ai triage: unsupported database backend %T", dbInstance)
	}
	triageMu.Lock()
	defer triageMu.Unlock()
	if triageReadyOn != dbInstance {
		for _, stmt := range triageSchema {
			if err := c.exec(stmt); err != nil {
				return nil, fmt.Errorf("ai triage schema: %w", err)
			}
		}
		triageReadyOn = dbInstance
	}
	return c, nil
}

func scanTriage(r rowScanner) (*TriageRecord, error) {
	var t TriageRecord
	var reportable int64
	err := r.Scan(&t.ID, &t.ScanID, &t.TemplateID, &t.Title, &t.Host, &t.MatchedAt, &t.Severity,
		&t.AISeverity, &t.Verdict, &t.Confidence, &reportable, &t.Scope, &t.ScopeProgram, &t.Reason,
		&t.ReportMD, &t.Evidence, &t.ReplayStatus, &t.Provider, &t.Model, &t.Status, &t.Error,
		&t.HumanVerdict, &t.NotifyNote, &t.NotifiedAt, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.Reportable = reportable != 0
	return &t, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// UpsertTriage inserts or refreshes a verdict. A re-triage overwrites the AI
// fields but keeps the operator's override, the notification state and the
// original creation time.
func UpsertTriage(t *TriageRecord) error {
	c, err := triageDB()
	if err != nil {
		return err
	}
	return c.exec(`INSERT INTO ai_triage (`+triageCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (id) DO UPDATE SET
			scan_id = excluded.scan_id, template_id = excluded.template_id, title = excluded.title,
			host = excluded.host, matched_at = excluded.matched_at, severity = excluded.severity,
			ai_severity = excluded.ai_severity, verdict = excluded.verdict, confidence = excluded.confidence,
			reportable = excluded.reportable, scope = excluded.scope, scope_program = excluded.scope_program,
			reason = excluded.reason, report_md = excluded.report_md, evidence = excluded.evidence,
			replay_status = excluded.replay_status, provider = excluded.provider, model = excluded.model,
			status = excluded.status, error = excluded.error, notify_note = excluded.notify_note,
			updated_at = excluded.updated_at`,
		t.ID, t.ScanID, t.TemplateID, t.Title, t.Host, t.MatchedAt, t.Severity, t.AISeverity,
		t.Verdict, t.Confidence, boolInt(t.Reportable), t.Scope, t.ScopeProgram, t.Reason, t.ReportMD,
		t.Evidence, t.ReplayStatus, t.Provider, t.Model, t.Status, t.Error, t.HumanVerdict,
		t.NotifyNote, t.NotifiedAt, t.CreatedAt, t.UpdatedAt)
}

// ErrTriageNotFound is returned by GetTriage for an unknown id.
var ErrTriageNotFound = errors.New("triage record not found")

// GetTriage loads one verdict by id.
func GetTriage(id string) (*TriageRecord, error) {
	c, err := triageDB()
	if err != nil {
		return nil, err
	}
	var out *TriageRecord
	err = c.query(`SELECT `+triageCols+` FROM ai_triage WHERE id = ? LIMIT 1`, func(r rowScanner) error {
		t, err := scanTriage(r)
		out = t
		return err
	}, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTriageNotFound
		}
		return nil, err
	}
	if out == nil {
		return nil, ErrTriageNotFound
	}
	return out, nil
}

// ListTriage returns verdicts newest first.
func ListTriage(f TriageFilter) ([]*TriageRecord, error) {
	c, err := triageDB()
	if err != nil {
		return nil, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{"1=1"}
	var args []any
	if f.Host != "" {
		where = append(where, "host LIKE ?")
		args = append(args, "%"+f.Host+"%")
	}
	if f.ScanID != "" {
		where = append(where, "scan_id = ?")
		args = append(args, f.ScanID)
	}
	if f.Verdict != "" {
		where = append(where, "verdict = ?")
		args = append(args, f.Verdict)
	}
	if f.ReportableOnly {
		where = append(where, "reportable = 1")
	}
	args = append(args, f.Limit, f.Offset)
	out := []*TriageRecord{}
	err = c.query(`SELECT `+triageCols+` FROM ai_triage WHERE `+strings.Join(where, " AND ")+
		` ORDER BY created_at DESC, id LIMIT ? OFFSET ?`, func(r rowScanner) error {
		t, err := scanTriage(r)
		if err == nil {
			out = append(out, t)
		}
		return err
	}, args...)
	return out, err
}

// TriageCounts returns how many verdicts exist per verdict value, plus
// "reportable" and "total".
func TriageCounts() (map[string]int, error) {
	c, err := triageDB()
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	err = c.query(`SELECT verdict, reportable, COUNT(*) FROM ai_triage GROUP BY verdict, reportable`, func(r rowScanner) error {
		var v string
		var rep, n int64
		if err := r.Scan(&v, &rep, &n); err != nil {
			return err
		}
		out[v] += int(n)
		out["total"] += int(n)
		if rep != 0 {
			out["reportable"] += int(n)
		}
		return nil
	})
	return out, err
}

// SetTriageNotified records that (and why) a verdict was sent to Discord.
func SetTriageNotified(id string, at int64, note string) error {
	c, err := triageDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE ai_triage SET notified_at = ?, notify_note = ? WHERE id = ?`, at, note, id)
}

// SetTriageHumanVerdict stores the operator's override ("" clears it).
func SetTriageHumanVerdict(id, verdict string, at int64) error {
	c, err := triageDB()
	if err != nil {
		return err
	}
	return c.exec(`UPDATE ai_triage SET human_verdict = ?, updated_at = ? WHERE id = ?`, verdict, at, id)
}

// DeleteTriage removes verdict rows by id (bulk cleanup from the triage page).
// Returns how many rows were deleted so the UI can confirm what it removed.
func DeleteTriage(ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) > 500 {
		ids = ids[:500]
	}
	c, err := triageDB()
	if err != nil {
		return 0, err
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	in := strings.Join(ph, ",")
	var n int64
	err = c.query(`DELETE FROM ai_triage WHERE id IN (`+in+`) RETURNING 1`,
		func(r rowScanner) error { n++; return nil }, args...)
	if err != nil {
		// RETURNING on DELETE needs SQLite >= 3.35 / any current Postgres;
		// fall back to a plain delete and report the requested count.
		if err := c.exec(`DELETE FROM ai_triage WHERE id IN (`+in+`)`, args...); err != nil {
			return 0, err
		}
		return int64(len(ids)), nil
	}
	return n, nil
}
