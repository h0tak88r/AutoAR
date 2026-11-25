package db

// PoC-day runs: one row per CVE the PoC-day pipeline has picked up — from the
// moment a public PoC is confirmed, through template resolution (official,
// community PR, or AI-written) and host targeting, to the targeted pass and
// the optional full-corpus sweep. The timestamps make the race measurable:
// poc_at → template_at → started_at → finished_at.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// PocdayRun is the pipeline state for one CVE.
type PocdayRun struct {
	CVEID          string `json:"cve_id"`
	Status         string `json:"status"`          // queued | resolving | targeting | running | done | no_template | no_hosts | suspicious | skipped | error
	TemplateSource string `json:"template_source"` // pdcp | pdcp-pr | github | github-pr | ai | ""
	TemplateID     string `json:"template_id"`
	TemplatePath   string `json:"template_path"`
	Keywords       string `json:"keywords"` // comma list used to pick hosts
	Hosts          int    `json:"hosts"`    // hosts the targeted pass ran against
	HostsMatched   int    `json:"hosts_matched"`
	Hits           int    `json:"hits"`
	ScanID         string `json:"scan_id"`       // targeted pass
	SweepScanID    string `json:"sweep_scan_id"` // full-corpus sweep (official templates only)
	SweepPending   bool   `json:"sweep_pending"`
	Note           string `json:"note"`
	Attempts       int    `json:"attempts"`
	AITried        int    `json:"ai_tried"`    // AI template attempts (errors may retry once)
	AIDeclined     bool   `json:"ai_declined"` // the model said "not auto-detectable"; no more AI calls unless forced
	PoCAt          int64  `json:"poc_at"`
	QueuedAt       int64  `json:"queued_at"`
	TemplateAt     int64  `json:"template_at"`
	StartedAt      int64  `json:"started_at"`
	FinishedAt     int64  `json:"finished_at"`
	UpdatedAt      int64  `json:"updated_at"`
}

var pocdaySchema = []string{
	`CREATE TABLE IF NOT EXISTS pocday_runs (
		cve_id TEXT PRIMARY KEY,
		status TEXT NOT NULL DEFAULT 'queued',
		template_source TEXT NOT NULL DEFAULT '',
		template_id TEXT NOT NULL DEFAULT '',
		template_path TEXT NOT NULL DEFAULT '',
		keywords TEXT NOT NULL DEFAULT '',
		hosts INTEGER NOT NULL DEFAULT 0,
		hosts_matched INTEGER NOT NULL DEFAULT 0,
		hits INTEGER NOT NULL DEFAULT 0,
		scan_id TEXT NOT NULL DEFAULT '',
		sweep_scan_id TEXT NOT NULL DEFAULT '',
		sweep_pending INTEGER NOT NULL DEFAULT 0,
		note TEXT NOT NULL DEFAULT '',
		attempts INTEGER NOT NULL DEFAULT 0,
		ai_tried INTEGER NOT NULL DEFAULT 0,
		ai_declined INTEGER NOT NULL DEFAULT 0,
		poc_at BIGINT NOT NULL DEFAULT 0,
		queued_at BIGINT NOT NULL DEFAULT 0,
		template_at BIGINT NOT NULL DEFAULT 0,
		started_at BIGINT NOT NULL DEFAULT 0,
		finished_at BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_pocday_updated ON pocday_runs(updated_at)`,
	`CREATE INDEX IF NOT EXISTS idx_pocday_status ON pocday_runs(status)`,
}

var (
	pocdayMu      sync.Mutex
	pocdayReadyOn DB
)

func pocdayDB() (triageConn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	var c triageConn
	switch d := dbInstance.(type) {
	case *PostgresDB:
		c = pgTriage{p: d}
	case *SQLiteDB:
		c = sqliteTriage{s: d}
	default:
		return nil, errors.New("pocday: unsupported backend")
	}
	pocdayMu.Lock()
	defer pocdayMu.Unlock()
	if pocdayReadyOn != dbInstance {
		for _, q := range pocdaySchema {
			if err := c.exec(q); err != nil {
				return nil, fmt.Errorf("pocday schema: %w", err)
			}
		}
		// Tables from the first v4.21 builds predate the AI attempt columns;
		// CREATE IF NOT EXISTS does not add them ("duplicate column" on
		// SQLite / "already exists" on Postgres = already there).
		for _, col := range []string{"ai_tried", "ai_declined"} {
			if err := c.exec(`ALTER TABLE pocday_runs ADD COLUMN ` + col + ` INTEGER NOT NULL DEFAULT 0`); err != nil {
				low := strings.ToLower(err.Error())
				if !strings.Contains(low, "duplicate column") && !strings.Contains(low, "already exists") {
					return nil, fmt.Errorf("pocday migration (%s): %w", col, err)
				}
			}
		}
		pocdayReadyOn = dbInstance
	}
	return c, nil
}

const pocdayCols = `cve_id, status, template_source, template_id, template_path, keywords, hosts,
	hosts_matched, hits, scan_id, sweep_scan_id, sweep_pending, note, attempts, ai_tried, ai_declined, poc_at,
	queued_at, template_at, started_at, finished_at, updated_at`

func scanPocdayRun(r rowScanner) (*PocdayRun, error) {
	var x PocdayRun
	var sweepPending, aiDeclined int64
	err := r.Scan(&x.CVEID, &x.Status, &x.TemplateSource, &x.TemplateID, &x.TemplatePath, &x.Keywords,
		&x.Hosts, &x.HostsMatched, &x.Hits, &x.ScanID, &x.SweepScanID, &sweepPending, &x.Note, &x.Attempts,
		&x.AITried, &aiDeclined, &x.PoCAt, &x.QueuedAt, &x.TemplateAt, &x.StartedAt, &x.FinishedAt, &x.UpdatedAt)
	x.SweepPending, x.AIDeclined = sweepPending != 0, aiDeclined != 0
	return &x, err
}

// SavePocdayRun writes the whole row (insert or replace by cve_id).
func SavePocdayRun(x *PocdayRun) error {
	if x == nil || strings.TrimSpace(x.CVEID) == "" {
		return errors.New("pocday: cve_id required")
	}
	c, err := pocdayDB()
	if err != nil {
		return err
	}
	x.CVEID = strings.ToUpper(strings.TrimSpace(x.CVEID))
	x.UpdatedAt = time.Now().UTC().Unix()
	sweep, declined := 0, 0
	if x.SweepPending {
		sweep = 1
	}
	if x.AIDeclined {
		declined = 1
	}
	return c.exec(`INSERT INTO pocday_runs (`+pocdayCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (cve_id) DO UPDATE SET status = excluded.status, template_source = excluded.template_source,
			template_id = excluded.template_id, template_path = excluded.template_path, keywords = excluded.keywords,
			hosts = excluded.hosts, hosts_matched = excluded.hosts_matched, hits = excluded.hits,
			scan_id = excluded.scan_id, sweep_scan_id = excluded.sweep_scan_id, sweep_pending = excluded.sweep_pending,
			note = excluded.note, attempts = excluded.attempts, ai_tried = excluded.ai_tried, ai_declined = excluded.ai_declined,
			poc_at = excluded.poc_at, queued_at = excluded.queued_at,
			template_at = excluded.template_at, started_at = excluded.started_at, finished_at = excluded.finished_at,
			updated_at = excluded.updated_at`,
		x.CVEID, x.Status, x.TemplateSource, x.TemplateID, x.TemplatePath, x.Keywords, x.Hosts,
		x.HostsMatched, x.Hits, x.ScanID, x.SweepScanID, sweep, truncateRunes(x.Note, 1000), x.Attempts, x.AITried, declined,
		x.PoCAt, x.QueuedAt, x.TemplateAt, x.StartedAt, x.FinishedAt, x.UpdatedAt)
}

// GetPocdayRun loads one CVE's run; (nil, nil) when there is none.
func GetPocdayRun(cveID string) (*PocdayRun, error) {
	c, err := pocdayDB()
	if err != nil {
		return nil, err
	}
	var out *PocdayRun
	err = c.query(`SELECT `+pocdayCols+` FROM pocday_runs WHERE cve_id = ?`, func(r rowScanner) error {
		x, err := scanPocdayRun(r)
		if err == nil {
			out = x
		}
		return err
	}, strings.ToUpper(strings.TrimSpace(cveID)))
	return out, err
}

// ListPocdayRuns returns the most recently updated runs, optionally only
// those in one of statuses.
func ListPocdayRuns(limit int, statuses ...string) ([]*PocdayRun, error) {
	c, err := pocdayDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + pocdayCols + ` FROM pocday_runs`
	var args []any
	if len(statuses) > 0 {
		q += ` WHERE status IN (` + strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",") + `)`
		for _, s := range statuses {
			args = append(args, s)
		}
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	var out []*PocdayRun
	err = c.query(q, func(r rowScanner) error {
		x, err := scanPocdayRun(r)
		if err == nil {
			out = append(out, x)
		}
		return err
	}, args...)
	return out, err
}

// PocdayRunsFor loads the runs of the given CVEs keyed by id (the radar page
// joins them onto its rows).
func PocdayRunsFor(ids []string) (map[string]*PocdayRun, error) {
	out := map[string]*PocdayRun{}
	if len(ids) == 0 {
		return out, nil
	}
	c, err := pocdayDB()
	if err != nil {
		return nil, err
	}
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, strings.ToUpper(strings.TrimSpace(id)))
	}
	err = c.query(`SELECT `+pocdayCols+` FROM pocday_runs WHERE cve_id IN (`+
		strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)`, func(r rowScanner) error {
		x, err := scanPocdayRun(r)
		if err == nil {
			out[x.CVEID] = x
		}
		return err
	}, args...)
	return out, err
}

func truncateRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
