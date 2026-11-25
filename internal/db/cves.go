package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// CVERecord is one tracked CVE on the radar page. Rows come from the CVE
// radar's NVD polling (descriptive fields), its PoC search (poc fields) and
// the nuclei template watcher / PoC→Scan bridge (template + scan fields).
type CVERecord struct {
	CVEID          string  `json:"cve_id"`
	Description    string  `json:"description"`
	CVSSScore      float64 `json:"cvss_score"`
	CVSSVector     string  `json:"cvss_vector"`
	AttackVector   string  `json:"attack_vector"` // Network | Adjacent | Local | Physical | ""
	Severity       string  `json:"severity"`      // critical | high | medium | low | ""
	CWE            string  `json:"cwe"`
	PublishedAt    string  `json:"published_at"` // RFC3339 or ""
	FirstSeenAt    int64   `json:"first_seen_at"`
	LastSeenAt     int64   `json:"last_seen_at"`
	PoCPublished   bool    `json:"poc_published"`
	FirstPoCAt     int64   `json:"first_poc_at"`
	PoCLinks       string  `json:"poc_links"`       // JSON [{source,link,seen_at}]
	TemplateStatus string  `json:"template_status"` // none | pr | merged
	Label          string  `json:"label"`           // operator label: done | skip | in-progress | ...
	Scanned        bool    `json:"scanned"`
	ScanID         string  `json:"scan_id"`
	UpdatedAt      int64   `json:"updated_at"`
	RunState       string  `json:"run_state,omitempty"` // never | active | tried | ran (set by the API, not a column)
}

// CVEPoCLink is one entry of CVERecord.PoCLinks.
type CVEPoCLink struct {
	Source string `json:"source"`
	Link   string `json:"link"`
	SeenAt int64  `json:"seen_at"`
}

// CVEFilter narrows ListCVEs. Zero values are "no filter".
type CVEFilter struct {
	PoCOnly   bool
	NoPoCOnly bool
	Scanned   *bool
	AV        string // attack vector exact match, case-insensitive
	MinScore  float64
	Q         string // substring over cve id + description
	RunState  string // never | active | tried | ran — see CVERunState
	Limit     int
	Offset    int
}

const cveCols = `cve_id, description, cvss_score, cvss_vector, attack_vector, severity, cwe,
	published_at, first_seen_at, last_seen_at, poc_published, first_poc_at, poc_links,
	template_status, label, scanned, scan_id, updated_at`

var cveSchema = []string{
	`CREATE TABLE IF NOT EXISTS cves (
		cve_id TEXT PRIMARY KEY,
		description TEXT NOT NULL DEFAULT '',
		cvss_score REAL NOT NULL DEFAULT 0,
		cvss_vector TEXT NOT NULL DEFAULT '',
		attack_vector TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		cwe TEXT NOT NULL DEFAULT '',
		published_at TEXT NOT NULL DEFAULT '',
		first_seen_at BIGINT NOT NULL DEFAULT 0,
		last_seen_at BIGINT NOT NULL DEFAULT 0,
		poc_published INTEGER NOT NULL DEFAULT 0,
		first_poc_at BIGINT NOT NULL DEFAULT 0,
		poc_links TEXT NOT NULL DEFAULT '[]',
		template_status TEXT NOT NULL DEFAULT 'none',
		label TEXT NOT NULL DEFAULT '',
		scanned INTEGER NOT NULL DEFAULT 0,
		scan_id TEXT NOT NULL DEFAULT '',
		updated_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_cves_last_seen ON cves(last_seen_at)`,
	`CREATE INDEX IF NOT EXISTS idx_cves_poc ON cves(poc_published)`,
}

var (
	cveReadyOn   DB
	cveReadyOnce bool
)

func cveDB() (triageConn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if !cveReadyOnce || cveReadyOn != dbInstance {
		var c triageConn
		switch d := dbInstance.(type) {
		case *PostgresDB:
			c = pgTriage{p: d}
		case *SQLiteDB:
			c = sqliteTriage{s: d}
		default:
			return nil, errors.New("cves: unsupported backend")
		}
		for _, q := range cveSchema {
			if err := c.exec(q); err != nil {
				return nil, fmt.Errorf("cves schema: %w", err)
			}
		}
		// CREATE IF NOT EXISTS does not extend a pre-existing table; duplicate
		// errors on new installs are expected. SQLite says "duplicate column",
		// Postgres says "already exists" — both wordings mean the column is
		// there, so neither may fail the boot.
		if err := c.exec(`ALTER TABLE cves ADD COLUMN label TEXT NOT NULL DEFAULT ''`); err != nil {
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "duplicate column") && !strings.Contains(low, "already exists") {
				return nil, errors.New("cves label migration: " + err.Error())
			}
		}
		cveReadyOn, cveReadyOnce = dbInstance, true
	}
	switch d := dbInstance.(type) {
	case *PostgresDB:
		return pgTriage{p: d}, nil
	case *SQLiteDB:
		return sqliteTriage{s: d}, nil
	}
	return nil, errors.New("cves: unsupported backend")
}

// UpsertCVE refreshes a row from radar data. Descriptive fields overwrite;
// poc/template/scan progress fields are NEVER clobbered by this call (they
// advance only via MarkCVEPoC / MarkCVEScanState) so a late NVD re-score
// can't reset the tracking state.
func UpsertCVE(r CVERecord) error {
	c, err := cveDB()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	if r.LastSeenAt == 0 {
		r.LastSeenAt = now
	}
	if r.UpdatedAt == 0 {
		r.UpdatedAt = now
	}
	if r.Severity == "" && r.CVSSScore > 0 {
		r.Severity = cveSeverity(r.CVSSScore)
	}
	if r.AttackVector == "" {
		r.AttackVector = AttackVectorFromCVSS(r.CVSSVector)
	}
	if r.TemplateStatus == "" {
		r.TemplateStatus = "none"
	}
	return c.exec(`INSERT INTO cves (`+cveCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (cve_id) DO UPDATE SET
			description = CASE WHEN excluded.description <> '' THEN excluded.description ELSE cves.description END,
			cvss_score = CASE WHEN excluded.cvss_score > 0 THEN excluded.cvss_score ELSE cves.cvss_score END,
			cvss_vector = CASE WHEN excluded.cvss_vector <> '' THEN excluded.cvss_vector ELSE cves.cvss_vector END,
			attack_vector = CASE WHEN excluded.attack_vector <> '' THEN excluded.attack_vector ELSE cves.attack_vector END,
			severity = CASE WHEN excluded.severity <> '' THEN excluded.severity ELSE cves.severity END,
			cwe = CASE WHEN excluded.cwe <> '' THEN excluded.cwe ELSE cves.cwe END,
			published_at = CASE WHEN excluded.published_at <> '' THEN excluded.published_at ELSE cves.published_at END,
			first_seen_at = CASE WHEN cves.first_seen_at = 0 THEN excluded.first_seen_at ELSE cves.first_seen_at END,
			last_seen_at = excluded.last_seen_at,
			updated_at = excluded.updated_at`,
		r.CVEID, r.Description, r.CVSSScore, r.CVSSVector, r.AttackVector, r.Severity, r.CWE,
		r.PublishedAt, r.FirstSeenAt, r.LastSeenAt, boolInt(r.PoCPublished), r.FirstPoCAt,
		nonEmptyJSON(r.PoCLinks), r.TemplateStatus, r.Label, boolInt(r.Scanned), r.ScanID, r.UpdatedAt)
}

func nonEmptyJSON(s string) string {
	if strings.TrimSpace(s) == "" {
		return "[]"
	}
	return s
}

// MarkCVEPoC records a confirmed public PoC link, creating a stub row when
// the radar confirmed a PoC before the descriptive upsert ran.
func MarkCVEPoC(cveID string, cvss float64, source, link string, seenAt int64) error {
	c, err := cveDB()
	if err != nil {
		return err
	}
	// Read-merge-write the link list (small array, low contention).
	var links []CVEPoCLink
	existing, err := GetCVE(cveID)
	if err == nil && existing != nil {
		_ = json.Unmarshal([]byte(existing.PoCLinks), &links)
	}
	dup := false
	for _, l := range links {
		if l.Link == link {
			dup = true
			break
		}
	}
	if !dup {
		links = append(links, CVEPoCLink{Source: source, Link: link, SeenAt: seenAt})
	}
	b, _ := json.Marshal(links)
	now := time.Now().UTC().Unix()
	if existing != nil {
		return c.exec(`UPDATE cves SET poc_published = 1,
			first_poc_at = CASE WHEN first_poc_at = 0 THEN ? ELSE first_poc_at END,
			poc_links = ?, last_seen_at = ?, updated_at = ? WHERE cve_id = ?`,
			seenAt, string(b), now, now, cveID)
	}
	return c.exec(`INSERT INTO cves (cve_id, cvss_score, severity, poc_published, first_poc_at, poc_links, last_seen_at, updated_at)
		VALUES (?,?,?,1,?,?,?,?)`,
		cveID, cvss, cveSeverity(cvss), seenAt, string(b), now, now)
}

// MarkCVEScanState records template/sweep progress for a CVE.
func MarkCVEScanState(cveID, templateStatus, scanID string) error {
	c, err := cveDB()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	if templateStatus == "" {
		templateStatus = "none"
	}
	scanned := 0
	if scanID != "" {
		scanned = 1
	}
	return c.exec(`INSERT INTO cves (cve_id, template_status, scanned, scan_id, last_seen_at, updated_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT (cve_id) DO UPDATE SET
			template_status = excluded.template_status,
			scanned = CASE WHEN excluded.scanned = 1 THEN 1 ELSE cves.scanned END,
			scan_id = CASE WHEN excluded.scan_id <> '' THEN excluded.scan_id ELSE cves.scan_id END,
			updated_at = excluded.updated_at`,
		cveID, templateStatus, scanned, scanID, now, now)
}

// ErrCVENotFound is returned by GetCVE for an unknown id.
var ErrCVENotFound = errors.New("cve record not found")

// GetCVE loads one row.
func GetCVE(cveID string) (*CVERecord, error) {
	c, err := cveDB()
	if err != nil {
		return nil, err
	}
	var out *CVERecord
	err = c.query(`SELECT `+cveCols+` FROM cves WHERE cve_id = ? LIMIT 1`, func(r rowScanner) error {
		rec, err := scanCVE(r)
		out = rec
		return err
	}, cveID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCVENotFound
		}
		return nil, err
	}
	if out == nil {
		return nil, ErrCVENotFound
	}
	return out, nil
}

// ListCVEs returns filtered rows, newest activity first, plus the total
// matching count (ignoring limit/offset) for pagination.
func ListCVEs(f CVEFilter) ([]*CVERecord, int, error) {
	c, err := cveDB()
	if err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where := []string{"1=1"}
	var args []any
	if f.PoCOnly {
		where = append(where, "poc_published = 1")
	}
	if f.NoPoCOnly {
		where = append(where, "poc_published = 0")
	}
	if f.Scanned != nil {
		where = append(where, "scanned = ?")
		args = append(args, boolInt(*f.Scanned))
	}
	if f.AV != "" {
		where = append(where, "LOWER(attack_vector) = ?")
		args = append(args, strings.ToLower(f.AV))
	}
	if f.MinScore > 0 {
		where = append(where, "cvss_score >= ?")
		args = append(args, f.MinScore)
	}
	if f.Q != "" {
		where = append(where, "(LOWER(cve_id) LIKE ? OR LOWER(description) LIKE ?)")
		like := "%" + strings.ToLower(f.Q) + "%"
		args = append(args, like, like)
	}
	if f.RunState != "" {
		clause, ok := cveRunStateWhere[f.RunState]
		if !ok {
			return nil, 0, fmt.Errorf("unknown run state %q (never, active, tried, ran)", f.RunState)
		}
		if _, err := pocdayDB(); err != nil { // the clause reads pocday_runs
			return nil, 0, err
		}
		where = append(where, clause)
	}
	wsql := strings.Join(where, " AND ")

	total := 0
	if err := c.query(`SELECT COUNT(*) FROM cves WHERE `+wsql, func(r rowScanner) error {
		return r.Scan(&total)
	}, args...); err != nil {
		return nil, 0, err
	}

	var out []*CVERecord
	q := `SELECT ` + cveCols + ` FROM cves WHERE ` + wsql + ` ORDER BY last_seen_at DESC LIMIT ? OFFSET ?`
	err = c.query(q, func(r rowScanner) error {
		rec, err := scanCVE(r)
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

func scanCVE(r rowScanner) (*CVERecord, error) {
	var rec CVERecord
	var poc, scanned int
	if err := r.Scan(&rec.CVEID, &rec.Description, &rec.CVSSScore, &rec.CVSSVector, &rec.AttackVector,
		&rec.Severity, &rec.CWE, &rec.PublishedAt, &rec.FirstSeenAt, &rec.LastSeenAt,
		&poc, &rec.FirstPoCAt, &rec.PoCLinks, &rec.TemplateStatus, &rec.Label, &scanned, &rec.ScanID, &rec.UpdatedAt); err != nil {
		return nil, err
	}
	rec.PoCPublished = poc != 0
	rec.Scanned = scanned != 0
	if rec.TemplateStatus == "" {
		rec.TemplateStatus = "none"
	}
	if strings.TrimSpace(rec.PoCLinks) == "" {
		rec.PoCLinks = "[]"
	}
	return &rec, nil
}

// cveSeverity buckets a CVSS base score. NVD's own boundaries.
func cveSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}

// AttackVectorFromCVSS extracts AV:N|A|L|P from a CVSS 2/3/x vector string
// into the human labels the radar page shows. "" when unknown.
func AttackVectorFromCVSS(vector string) string {
	v := strings.ToUpper(vector)
	for _, p := range []struct{ prefix, label string }{
		{"AV:N", "Network"}, {"AV:A", "Adjacent"}, {"AV:L", "Local"}, {"AV:P", "Physical"},
	} {
		if strings.Contains(v, p.prefix) {
			return p.label
		}
	}
	return ""
}

// DiscoveredSubdomain is one row of the newly-discovered assets feed.
type DiscoveredSubdomain struct {
	Subdomain string `json:"subdomain"`
	Domain    string `json:"domain"` // root the asset belongs to
	IsLive    bool   `json:"is_live"`
	HTTPSURL  string `json:"https_url,omitempty"`
	HTTPURL   string `json:"http_url,omitempty"`
	CreatedAt int64  `json:"created_at"` // unix seconds
}

// ListRecentlyDiscoveredSubdomains returns the newest subdomains (by
// first-seen created_at) within the last `hours`, newest first.
func ListRecentlyDiscoveredSubdomains(limit, hours int) ([]*DiscoveredSubdomain, error) {
	c, err := cveDB() // shared dual-backend conn; only needs exec/query
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	var out []*DiscoveredSubdomain
	scanRow := func(r rowScanner) error {
		var a DiscoveredSubdomain
		var live int
		var created string
		if err := r.Scan(&a.Subdomain, &a.Domain, &live, &a.HTTPSURL, &a.HTTPURL, &created); err != nil {
			return err
		}
		a.IsLive = live != 0
		if t, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(created[:19])); err == nil {
			a.CreatedAt = t.Unix()
		}
		out = append(out, &a)
		return nil
	}
	// Dialect split: SQLite and Postgres spell "created in the last N hours"
	// differently; everything else is portable.
	if _, isPG := dbInstance.(*PostgresDB); isPG {
		err = c.query(`SELECT s.subdomain, COALESCE(d.domain, ''), COALESCE(s.is_live, false),
			COALESCE(s.https_url, ''), COALESCE(s.http_url, ''), to_char(s.created_at, 'YYYY-MM-DD HH24:MI:SS')
			FROM subdomains s LEFT JOIN domains d ON s.domain_id = d.id
			WHERE s.created_at > now() - make_interval(hours => ?)
			ORDER BY s.created_at DESC LIMIT ?`, scanRow, hours, limit)
	} else {
		err = c.query(`SELECT s.subdomain, COALESCE(d.domain, ''), COALESCE(s.is_live, 0),
			COALESCE(s.https_url, ''), COALESCE(s.http_url, ''), strftime('%Y-%m-%d %H:%M:%S', s.created_at)
			FROM subdomains s LEFT JOIN domains d ON s.domain_id = d.id
			WHERE s.created_at > datetime('now', ?)
			ORDER BY s.created_at DESC LIMIT ?`, scanRow, fmt.Sprintf("-%d hours", hours), limit)
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FilterLiveHosts returns live-host URLs whose tech fingerprint, page title,
// server header or URL matches a substring (case-insensitive) — the
// PoC-runner's target selector: only hosts that look like the affected product
// get the PoC.
func FilterLiveHosts(pattern string, limit int) ([]map[string]string, int, error) {
	c, pg, err := fingerprintDB()
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return nil, 0, fmt.Errorf("pattern is required (tech, title or url substring, e.g. joomla, splunk, /com_os_cck)")
	}
	like := "%" + pattern + "%"
	where := liveCond(pg) + ` AND (LOWER(COALESCE(techs,'')) LIKE ? OR LOWER(fp_title) LIKE ? OR LOWER(fp_server) LIKE ?
		OR LOWER(COALESCE(https_url,'')) LIKE ? OR LOWER(COALESCE(http_url,'')) LIKE ?)`
	args := []any{like, like, like, like, like}
	total := 0
	if err := c.query(`SELECT COUNT(*) FROM subdomains WHERE `+where, func(r rowScanner) error {
		return r.Scan(&total)
	}, args...); err != nil {
		return nil, 0, err
	}
	var out []map[string]string
	err = c.query(`SELECT COALESCE(https_url,''), COALESCE(http_url,''), COALESCE(techs,''), fp_title, fp_server, subdomain
		FROM subdomains WHERE `+where+` LIMIT ?`,
		func(r rowScanner) error {
			var httpsURL, httpURL, techs, title, server, host string
			if err := r.Scan(&httpsURL, &httpURL, &techs, &title, &server, &host); err != nil {
				return err
			}
			out = append(out, map[string]string{"url": httpsURL, "http_url": httpURL, "techs": techs,
				"title": title, "server": server, "host": host})
			return nil
		}, append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ActionableCVEs returns PoC-confirmed, web-reachable CVEs that have no
// nuclei template and were never swept — the PoC-runner worklist.
func ActionableCVEs(limit int) ([]*CVERecord, error) {
	// cveDB() (not findingDB) so the cves table schema is ensured too.
	c, err := cveDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var out []*CVERecord
	err = c.query(`SELECT `+cveCols+` FROM cves
		WHERE poc_published = 1 AND template_status = 'none' AND scanned = 0
		AND (attack_vector = '' OR LOWER(attack_vector) = 'network')
		ORDER BY first_poc_at DESC LIMIT ?`, func(r rowScanner) error {
		rec, err := scanCVE(r)
		if err != nil {
			return err
		}
		out = append(out, rec)
		return nil
	}, limit)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Run states of a tracked CVE — has anything run against it yet?
//
//	never  — no PoC-day run and never swept
//	active — a PoC-day run is queued or in progress
//	tried  — PoC-day picked it up but nothing ran against hosts (no template,
//	         no matching hosts, gated, fake PoC, error)
//	ran    — a targeted pass or a full sweep ran
const (
	CVERunNever  = "never"
	CVERunActive = "active"
	CVERunTried  = "tried"
	CVERunRan    = "ran"
)

const pocdayActiveStatuses = `'queued','resolving','targeting','running'`

// cveRunStateWhere mirrors CVERunState in SQL over the cves table.
var cveRunStateWhere = map[string]string{
	CVERunNever:  `scanned = 0 AND cve_id NOT IN (SELECT cve_id FROM pocday_runs)`,
	CVERunActive: `cve_id IN (SELECT cve_id FROM pocday_runs WHERE status IN (` + pocdayActiveStatuses + `))`,
	CVERunTried: `scanned = 0 AND cve_id IN (SELECT cve_id FROM pocday_runs WHERE status NOT IN ('done',` +
		pocdayActiveStatuses + `) AND sweep_scan_id = '')`,
	CVERunRan: `cve_id NOT IN (SELECT cve_id FROM pocday_runs WHERE status IN (` + pocdayActiveStatuses + `))
		AND (scanned = 1 OR cve_id IN (SELECT cve_id FROM pocday_runs WHERE status = 'done' OR sweep_scan_id <> ''))`,
}

// CVERunState classifies one CVE from its row and PoC-day run (nil = none).
func CVERunState(rec *CVERecord, run *PocdayRun) string {
	if run != nil {
		switch run.Status {
		case "queued", "resolving", "targeting", "running":
			return CVERunActive
		}
	}
	switch {
	case rec != nil && rec.Scanned, run != nil && (run.Status == "done" || run.SweepScanID != ""):
		return CVERunRan
	case run != nil:
		return CVERunTried
	}
	return CVERunNever
}

// unracedPoCWhere selects PoC-published CVEs nothing has run against yet that
// PoC-day would accept: network-reachable (or unknown vector), not labeled
// skip/done/ignore, CVSS unknown or at least the floor.
const unracedPoCWhere = `poc_published = 1 AND scanned = 0
	AND cve_id NOT IN (SELECT cve_id FROM pocday_runs)
	AND LOWER(label) NOT IN ('skip','done','ignore')
	AND (attack_vector = '' OR LOWER(attack_vector) = 'network')
	AND (cvss_score = 0 OR cvss_score >= ?)`

// ListUnracedPoCCVEs returns up to limit never-run PoC CVEs, newest PoC
// first, and how many there are in total — the auto-race worklist.
func ListUnracedPoCCVEs(limit int, minCVSS float64) ([]*CVERecord, int, error) {
	c, err := cveDB()
	if err != nil {
		return nil, 0, err
	}
	if _, err := pocdayDB(); err != nil {
		return nil, 0, err
	}
	if limit < 0 || limit > 500 {
		limit = 20
	}
	total := 0
	if err := c.query(`SELECT COUNT(*) FROM cves WHERE `+unracedPoCWhere, func(r rowScanner) error {
		return r.Scan(&total)
	}, minCVSS); err != nil {
		return nil, 0, err
	}
	var out []*CVERecord
	if limit == 0 {
		return out, total, nil
	}
	err = c.query(`SELECT `+cveCols+` FROM cves WHERE `+unracedPoCWhere+`
		ORDER BY first_poc_at DESC, cvss_score DESC, cve_id LIMIT ?`, func(r rowScanner) error {
		rec, err := scanCVE(r)
		if err == nil {
			out = append(out, rec)
		}
		return err
	}, minCVSS, limit)
	return out, total, err
}

// CountPoCCVEsByRunState counts PoC-published CVEs per run state.
func CountPoCCVEsByRunState() (map[string]int, error) {
	c, err := cveDB()
	if err != nil {
		return nil, err
	}
	if _, err := pocdayDB(); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, st := range []string{CVERunNever, CVERunActive, CVERunTried, CVERunRan} {
		n := 0
		if err := c.query(`SELECT COUNT(*) FROM cves WHERE poc_published = 1 AND `+cveRunStateWhere[st], func(r rowScanner) error {
			return r.Scan(&n)
		}); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, nil
}

// SetCVELabel stores an operator label on a tracked CVE.
func SetCVELabel(cveID, label string) error {
	c, err := cveDB()
	if err != nil {
		return err
	}
	return c.exec(`INSERT INTO cves (cve_id, label, updated_at) VALUES (?,?,?)
		ON CONFLICT (cve_id) DO UPDATE SET label = excluded.label, updated_at = excluded.updated_at`,
		cveID, label, time.Now().UTC().Unix())
}
