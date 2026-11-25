package db

// Agent validations: the AI agent's tool-backed verdict on one finding (the
// one-shot AI review lives in ai_triage; this is the deeper, evidence-backed
// check an operator asks for on selected findings).

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// FindingValidation is one finding's latest agent validation.
type FindingValidation struct {
	FindingID    int64  `json:"finding_id"`
	Status       string `json:"status"` // queued | running | done | error
	Verdict      string `json:"verdict"`
	Confidence   int    `json:"confidence"`
	Severity     string `json:"severity"`
	Reportable   bool   `json:"reportable"`
	Summary      string `json:"summary"`
	Evidence     string `json:"evidence"`
	Reproduction string `json:"reproduction"`
	NextSteps    string `json:"next_steps"`
	SessionID    string `json:"session_id"`
	Steps        int    `json:"steps"`
	Error        string `json:"error"`
	QueuedAt     int64  `json:"queued_at"`
	StartedAt    int64  `json:"started_at"`
	FinishedAt   int64  `json:"finished_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

var findingValidationSchema = []string{
	`CREATE TABLE IF NOT EXISTS finding_validations (
		finding_id BIGINT PRIMARY KEY,
		status TEXT NOT NULL DEFAULT 'queued',
		verdict TEXT NOT NULL DEFAULT '',
		confidence INTEGER NOT NULL DEFAULT 0,
		severity TEXT NOT NULL DEFAULT '',
		reportable INTEGER NOT NULL DEFAULT 0,
		summary TEXT NOT NULL DEFAULT '',
		evidence TEXT NOT NULL DEFAULT '',
		reproduction TEXT NOT NULL DEFAULT '',
		next_steps TEXT NOT NULL DEFAULT '',
		session_id TEXT NOT NULL DEFAULT '',
		steps INTEGER NOT NULL DEFAULT 0,
		error TEXT NOT NULL DEFAULT '',
		queued_at BIGINT NOT NULL DEFAULT 0,
		started_at BIGINT NOT NULL DEFAULT 0,
		finished_at BIGINT NOT NULL DEFAULT 0,
		updated_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_finding_validations_status ON finding_validations(status)`,
}

var (
	fvMu      sync.Mutex
	fvReadyOn DB
)

func findingValidationDB() (triageConn, error) {
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
		return nil, errors.New("finding validations: unsupported backend")
	}
	fvMu.Lock()
	defer fvMu.Unlock()
	if fvReadyOn != dbInstance {
		for _, q := range findingValidationSchema {
			if err := c.exec(q); err != nil {
				return nil, fmt.Errorf("finding validations schema: %w", err)
			}
		}
		fvReadyOn = dbInstance
	}
	return c, nil
}

const fvCols = `finding_id, status, verdict, confidence, severity, reportable, summary, evidence, reproduction,
	next_steps, session_id, steps, error, queued_at, started_at, finished_at, updated_at`

func scanFindingValidation(r rowScanner) (*FindingValidation, error) {
	var v FindingValidation
	var reportable int64
	err := r.Scan(&v.FindingID, &v.Status, &v.Verdict, &v.Confidence, &v.Severity, &reportable, &v.Summary,
		&v.Evidence, &v.Reproduction, &v.NextSteps, &v.SessionID, &v.Steps, &v.Error, &v.QueuedAt, &v.StartedAt,
		&v.FinishedAt, &v.UpdatedAt)
	v.Reportable = reportable != 0
	return &v, err
}

// SaveFindingValidation writes a finding's validation row (insert or replace).
func SaveFindingValidation(v *FindingValidation) error {
	if v == nil || v.FindingID <= 0 {
		return errors.New("finding validation: finding_id required")
	}
	c, err := findingValidationDB()
	if err != nil {
		return err
	}
	v.UpdatedAt = time.Now().UTC().Unix()
	rep := 0
	if v.Reportable {
		rep = 1
	}
	return c.exec(`INSERT INTO finding_validations (`+fvCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (finding_id) DO UPDATE SET status = excluded.status, verdict = excluded.verdict,
			confidence = excluded.confidence, severity = excluded.severity, reportable = excluded.reportable,
			summary = excluded.summary, evidence = excluded.evidence, reproduction = excluded.reproduction,
			next_steps = excluded.next_steps, session_id = excluded.session_id, steps = excluded.steps,
			error = excluded.error, queued_at = excluded.queued_at, started_at = excluded.started_at,
			finished_at = excluded.finished_at, updated_at = excluded.updated_at`,
		v.FindingID, v.Status, v.Verdict, v.Confidence, v.Severity, rep, truncateRunes(v.Summary, 4000),
		truncateRunes(v.Evidence, 12000), truncateRunes(v.Reproduction, 6000), truncateRunes(v.NextSteps, 3000),
		v.SessionID, v.Steps, truncateRunes(v.Error, 1000), v.QueuedAt, v.StartedAt, v.FinishedAt, v.UpdatedAt)
}

// GetFindingValidation loads one row; (nil, nil) when there is none.
func GetFindingValidation(findingID int64) (*FindingValidation, error) {
	c, err := findingValidationDB()
	if err != nil {
		return nil, err
	}
	var out *FindingValidation
	err = c.query(`SELECT `+fvCols+` FROM finding_validations WHERE finding_id = ?`, func(r rowScanner) error {
		v, err := scanFindingValidation(r)
		if err == nil {
			out = v
		}
		return err
	}, findingID)
	return out, err
}

// FindingValidationsFor loads the rows of the given findings keyed by id.
func FindingValidationsFor(ids []int64) (map[int64]*FindingValidation, error) {
	out := map[int64]*FindingValidation{}
	if len(ids) == 0 {
		return out, nil
	}
	c, err := findingValidationDB()
	if err != nil {
		return nil, err
	}
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	err = c.query(`SELECT `+fvCols+` FROM finding_validations WHERE finding_id IN (`+
		strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`)`, func(r rowScanner) error {
		v, err := scanFindingValidation(r)
		if err == nil {
			out[v.FindingID] = v
		}
		return err
	}, args...)
	return out, err
}

// ListFindingValidations returns rows in one of statuses (all when none),
// most recently updated first.
func ListFindingValidations(limit int, statuses ...string) ([]*FindingValidation, error) {
	c, err := findingValidationDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + fvCols + ` FROM finding_validations`
	var args []any
	if len(statuses) > 0 {
		q += ` WHERE status IN (` + strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",") + `)`
		for _, s := range statuses {
			args = append(args, s)
		}
	}
	q += ` ORDER BY updated_at DESC LIMIT ?`
	args = append(args, limit)
	var out []*FindingValidation
	err = c.query(q, func(r rowScanner) error {
		v, err := scanFindingValidation(r)
		if err == nil {
			out = append(out, v)
		}
		return err
	}, args...)
	return out, err
}
