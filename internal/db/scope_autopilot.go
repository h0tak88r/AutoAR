package db

// Scope autopilot state: the last asset list seen per program (so a scope
// update can be diffed into "which assets are new"), and one row per scan the
// autopilot planned for a new asset — from plan to launch to the AI review
// of its results.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ScopeAsset is one in-scope asset and its platform type.
type ScopeAsset struct {
	Asset string `json:"a"`
	Type  string `json:"t,omitempty"`
}

// AutopilotRun is one planned/launched scan for a newly in-scope asset.
type AutopilotRun struct {
	ID           int64  `json:"id"`
	EventID      string `json:"event_id"` // groups the scans planned for one asset of one scope update
	ProgramKey   string `json:"program_key"`
	Platform     string `json:"platform"`
	Handle       string `json:"handle"`
	ProgramName  string `json:"program_name"`
	ProgramURL   string `json:"program_url"`
	OffersBounty bool   `json:"offers_bounty"`
	Asset        string `json:"asset"`
	AssetType    string `json:"asset_type"`
	ScanType     string `json:"scan_type"`
	Target       string `json:"target"`
	Reason       string `json:"reason"`
	PlannedBy    string `json:"planned_by"` // ai | rules
	ScanID       string `json:"scan_id"`
	Status       string `json:"status"` // planned | launched | finished | reviewed | failed | skipped
	Findings     int    `json:"findings"`
	Insight      string `json:"insight"`
	Error        string `json:"error"`
	CreatedAt    int64  `json:"created_at"`
	LaunchedAt   int64  `json:"launched_at"`
	FinishedAt   int64  `json:"finished_at"`
	ReviewedAt   int64  `json:"reviewed_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

var (
	apMu      sync.Mutex
	apReadyOn DB
)

func autopilotDB() (triageConn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	var c triageConn
	idCol := "id INTEGER PRIMARY KEY AUTOINCREMENT"
	switch d := dbInstance.(type) {
	case *PostgresDB:
		c, idCol = pgTriage{p: d}, "id BIGSERIAL PRIMARY KEY"
	case *SQLiteDB:
		c = sqliteTriage{s: d}
	default:
		return nil, errors.New("scope autopilot: unsupported backend")
	}
	apMu.Lock()
	defer apMu.Unlock()
	if apReadyOn == dbInstance {
		return c, nil
	}
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS program_asset_snapshots (
			program_key TEXT PRIMARY KEY,
			assets TEXT NOT NULL DEFAULT '[]',
			digest TEXT NOT NULL DEFAULT '',
			updated_at BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS scope_autopilot_runs (
			` + idCol + `,
			event_id TEXT NOT NULL DEFAULT '',
			program_key TEXT NOT NULL DEFAULT '',
			platform TEXT NOT NULL DEFAULT '',
			handle TEXT NOT NULL DEFAULT '',
			program_name TEXT NOT NULL DEFAULT '',
			program_url TEXT NOT NULL DEFAULT '',
			offers_bounty INTEGER NOT NULL DEFAULT 0,
			asset TEXT NOT NULL DEFAULT '',
			asset_type TEXT NOT NULL DEFAULT '',
			scan_type TEXT NOT NULL DEFAULT '',
			target TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			planned_by TEXT NOT NULL DEFAULT '',
			scan_id TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'planned',
			findings INTEGER NOT NULL DEFAULT 0,
			insight TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_at BIGINT NOT NULL DEFAULT 0,
			launched_at BIGINT NOT NULL DEFAULT 0,
			finished_at BIGINT NOT NULL DEFAULT 0,
			reviewed_at BIGINT NOT NULL DEFAULT 0,
			updated_at BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_autopilot_status ON scope_autopilot_runs(status)`,
		`CREATE INDEX IF NOT EXISTS idx_autopilot_event ON scope_autopilot_runs(event_id)`,
	} {
		if err := c.exec(q); err != nil {
			return nil, fmt.Errorf("scope autopilot schema: %w", err)
		}
	}
	apReadyOn = dbInstance
	return c, nil
}

// GetAssetSnapshot returns the stored asset list of a program (ok=false when
// none was stored yet).
func GetAssetSnapshot(programKey string) ([]ScopeAsset, string, bool, error) {
	c, err := autopilotDB()
	if err != nil {
		return nil, "", false, err
	}
	var raw, digest string
	found := false
	err = c.query(`SELECT assets, digest FROM program_asset_snapshots WHERE program_key = ?`, func(r rowScanner) error {
		found = true
		return r.Scan(&raw, &digest)
	}, programKey)
	if err != nil || !found {
		return nil, "", found, err
	}
	var out []ScopeAsset
	_ = json.Unmarshal([]byte(raw), &out)
	return out, digest, true, nil
}

// SaveAssetSnapshot stores a program's current asset list.
func SaveAssetSnapshot(programKey, digest string, assets []ScopeAsset) error {
	c, err := autopilotDB()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(assets)
	now := time.Now().UTC().Unix()
	return c.exec(`INSERT INTO program_asset_snapshots (program_key, assets, digest, updated_at) VALUES (?,?,?,?)
		ON CONFLICT (program_key) DO UPDATE SET assets = excluded.assets, digest = excluded.digest, updated_at = excluded.updated_at`,
		programKey, string(b), digest, now)
}

// CountAssetSnapshots reports how many programs have a stored asset list.
func CountAssetSnapshots() (int, error) {
	c, err := autopilotDB()
	if err != nil {
		return 0, err
	}
	n := 0
	err = c.query(`SELECT COUNT(*) FROM program_asset_snapshots`, func(r rowScanner) error { return r.Scan(&n) })
	return n, err
}

const apCols = `id, event_id, program_key, platform, handle, program_name, program_url, offers_bounty, asset, asset_type,
	scan_type, target, reason, planned_by, scan_id, status, findings, insight, error, created_at, launched_at, finished_at,
	reviewed_at, updated_at`

func scanAutopilotRun(r rowScanner) (*AutopilotRun, error) {
	var x AutopilotRun
	var bounty int64
	err := r.Scan(&x.ID, &x.EventID, &x.ProgramKey, &x.Platform, &x.Handle, &x.ProgramName, &x.ProgramURL, &bounty,
		&x.Asset, &x.AssetType, &x.ScanType, &x.Target, &x.Reason, &x.PlannedBy, &x.ScanID, &x.Status, &x.Findings,
		&x.Insight, &x.Error, &x.CreatedAt, &x.LaunchedAt, &x.FinishedAt, &x.ReviewedAt, &x.UpdatedAt)
	x.OffersBounty = bounty != 0
	return &x, err
}

// InsertAutopilotRun stores a new run and sets its ID.
func InsertAutopilotRun(x *AutopilotRun) error {
	c, err := autopilotDB()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	if x.CreatedAt == 0 {
		x.CreatedAt = now
	}
	x.UpdatedAt = now
	if x.Status == "" {
		x.Status = "planned"
	}
	bounty := 0
	if x.OffersBounty {
		bounty = 1
	}
	return c.query(`INSERT INTO scope_autopilot_runs (event_id, program_key, platform, handle, program_name, program_url,
		offers_bounty, asset, asset_type, scan_type, target, reason, planned_by, scan_id, status, findings, insight, error,
		created_at, launched_at, finished_at, reviewed_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`, func(r rowScanner) error {
		return r.Scan(&x.ID)
	}, x.EventID, x.ProgramKey, x.Platform, x.Handle, truncateRunes(x.ProgramName, 200), x.ProgramURL, bounty,
		truncateRunes(x.Asset, 500), x.AssetType, x.ScanType, truncateRunes(x.Target, 500), truncateRunes(x.Reason, 500),
		x.PlannedBy, x.ScanID, x.Status, x.Findings, truncateRunes(x.Insight, 6000), truncateRunes(x.Error, 1000),
		x.CreatedAt, x.LaunchedAt, x.FinishedAt, x.ReviewedAt, x.UpdatedAt)
}

// UpdateAutopilotRun saves the mutable fields of a run.
func UpdateAutopilotRun(x *AutopilotRun) error {
	c, err := autopilotDB()
	if err != nil {
		return err
	}
	x.UpdatedAt = time.Now().UTC().Unix()
	return c.exec(`UPDATE scope_autopilot_runs SET scan_id = ?, status = ?, findings = ?, insight = ?, error = ?,
		launched_at = ?, finished_at = ?, reviewed_at = ?, updated_at = ? WHERE id = ?`,
		x.ScanID, x.Status, x.Findings, truncateRunes(x.Insight, 6000), truncateRunes(x.Error, 1000),
		x.LaunchedAt, x.FinishedAt, x.ReviewedAt, x.UpdatedAt, x.ID)
}

// ListAutopilotRuns returns runs (optionally only in statuses), newest first.
func ListAutopilotRuns(limit int, statuses ...string) ([]*AutopilotRun, error) {
	c, err := autopilotDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + apCols + ` FROM scope_autopilot_runs`
	var args []any
	if len(statuses) > 0 {
		q += ` WHERE status IN (` + strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",") + `)`
		for _, s := range statuses {
			args = append(args, s)
		}
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	var out []*AutopilotRun
	err = c.query(q, func(r rowScanner) error {
		x, err := scanAutopilotRun(r)
		if err == nil {
			out = append(out, x)
		}
		return err
	}, args...)
	return out, err
}

// AutopilotRunsForEvent returns every run of one event.
func AutopilotRunsForEvent(eventID string) ([]*AutopilotRun, error) {
	c, err := autopilotDB()
	if err != nil {
		return nil, err
	}
	var out []*AutopilotRun
	err = c.query(`SELECT `+apCols+` FROM scope_autopilot_runs WHERE event_id = ? ORDER BY id`, func(r rowScanner) error {
		x, err := scanAutopilotRun(r)
		if err == nil {
			out = append(out, x)
		}
		return err
	}, eventID)
	return out, err
}

// CountAutopilotLaunchedSince counts runs launched at or after ts (daily cap).
func CountAutopilotLaunchedSince(ts int64) (int, error) {
	c, err := autopilotDB()
	if err != nil {
		return 0, err
	}
	n := 0
	err = c.query(`SELECT COUNT(*) FROM scope_autopilot_runs WHERE launched_at >= ?`, func(r rowScanner) error {
		return r.Scan(&n)
	}, ts)
	return n, err
}
