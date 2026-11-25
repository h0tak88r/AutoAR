package db

// Host fingerprints for targeting: what product a live host runs. techs
// (httpx/wappalyzer) existed before but only ~3% of live hosts ever had a tech
// scan; the backfill fills fp_title / fp_server / techs for every live host
// and stamps fp_at so a host is probed once (empty techs is a valid answer).
// PoC-day targeting and corpus_filter match keywords against all three.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	fpMu      sync.Mutex
	fpReadyOn DB
)

// fingerprintDB returns the shared conn with the fingerprint columns ensured.
// ALTER TABLE ... ADD COLUMN with a constant default is metadata-only on
// Postgres 11+, so this is cheap even on the ~1M-row prod table; the backlog
// index is built CONCURRENTLY so live-host writes are never blocked.
func fingerprintDB() (triageConn, bool, error) {
	if err := Init(); err != nil {
		return nil, false, err
	}
	var c triageConn
	pg := false
	switch d := dbInstance.(type) {
	case *PostgresDB:
		c, pg = pgTriage{p: d}, true
	case *SQLiteDB:
		c = sqliteTriage{s: d}
	default:
		return nil, false, errors.New("fingerprints: unsupported backend")
	}
	fpMu.Lock()
	defer fpMu.Unlock()
	if fpReadyOn == dbInstance {
		return c, pg, nil
	}
	cols := []string{"fp_title TEXT NOT NULL DEFAULT ''", "fp_server TEXT NOT NULL DEFAULT ''", "fp_at BIGINT NOT NULL DEFAULT 0"}
	for _, col := range cols {
		q := `ALTER TABLE subdomains ADD COLUMN ` + col
		if pg {
			// A waiting ALTER queues every later query on the table behind its
			// lock request; give up after 5s instead (the next call retries).
			q = `DO $$ BEGIN SET LOCAL lock_timeout = '5s'; ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ` + col + `; END $$`
		}
		if err := c.exec(q); err != nil {
			low := strings.ToLower(err.Error())
			if !strings.Contains(low, "duplicate column") && !strings.Contains(low, "already exists") {
				return nil, pg, fmt.Errorf("fingerprint column: %w", err)
			}
		}
	}
	idx := `CREATE INDEX IF NOT EXISTS idx_subdomains_fp_backlog ON subdomains (id) WHERE fp_at = 0 AND is_live = 1`
	if pg {
		idx = `CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_subdomains_fp_backlog ON subdomains (id) WHERE fp_at = 0 AND is_live = true`
	}
	if err := c.exec(idx); err != nil {
		return nil, pg, fmt.Errorf("fingerprint index: %w", err)
	}
	fpReadyOn = dbInstance
	return c, pg, nil
}

// bestURLExpr mirrors SubdomainStatus.BestURL in SQL: the scheme that
// answered, else any stored URL, else https://host.
const bestURLExpr = `CASE WHEN COALESCE(https_status,0) > 0 AND COALESCE(https_url,'') <> '' THEN https_url
	WHEN COALESCE(http_status,0) > 0 AND COALESCE(http_url,'') <> '' THEN http_url
	WHEN COALESCE(https_url,'') <> '' THEN https_url
	WHEN COALESCE(http_url,'') <> '' THEN http_url
	ELSE 'https://' || subdomain END`

func liveCond(pg bool) string {
	if pg {
		return "is_live = true"
	}
	return "is_live = 1"
}

// FingerprintTarget is one live host still waiting for a fingerprint.
type FingerprintTarget struct {
	ID        int64
	Subdomain string
	URL       string // best known URL (as SubdomainStatus.BestURL)
}

// FingerprintBacklog returns up to limit live hosts never fingerprinted,
// oldest rows first.
func FingerprintBacklog(limit int) ([]FingerprintTarget, error) {
	c, pg, err := fingerprintDB()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	var out []FingerprintTarget
	err = c.query(`SELECT id, subdomain, `+bestURLExpr+`
		FROM subdomains WHERE fp_at = 0 AND `+liveCond(pg)+` ORDER BY id LIMIT ?`, func(r rowScanner) error {
		var t FingerprintTarget
		if err := r.Scan(&t.ID, &t.Subdomain, &t.URL); err != nil {
			return err
		}
		out = append(out, t)
		return nil
	}, limit)
	return out, err
}

// FingerprintResult is what one probe learned about a host. Empty Techs keeps
// whatever a tech scan stored before.
type FingerprintResult struct {
	ID     int64
	Techs  string
	Title  string
	Server string
	At     int64
}

// SaveFingerprints stores a batch of probe results.
func SaveFingerprints(rs []FingerprintResult) error {
	c, _, err := fingerprintDB()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	for _, r := range rs {
		at := r.At
		if at == 0 {
			at = now
		}
		techs := truncateRunes(strings.TrimSpace(r.Techs), 1000)
		if err := c.exec(`UPDATE subdomains SET techs = CASE WHEN ? <> '' THEN ? ELSE COALESCE(techs,'') END,
			fp_title = ?, fp_server = ?, fp_at = ? WHERE id = ?`,
			techs, techs, truncateRunes(strings.TrimSpace(r.Title), 300), truncateRunes(strings.TrimSpace(r.Server), 120), at, r.ID); err != nil {
			return err
		}
	}
	return nil
}

// FingerprintCoverageStats summarises how much of the live corpus can be
// targeted by product.
type FingerprintCoverageStats struct {
	Live          int64 `json:"live"`
	Fingerprinted int64 `json:"fingerprinted"`
	WithTech      int64 `json:"with_tech"`
}

// FingerprintCoverage counts live hosts, probed hosts, and hosts with techs.
func FingerprintCoverage() (FingerprintCoverageStats, error) {
	var s FingerprintCoverageStats
	c, pg, err := fingerprintDB()
	if err != nil {
		return s, err
	}
	err = c.query(`SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN fp_at > 0 THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN COALESCE(techs,'') NOT IN ('', '[]', 'null') THEN 1 ELSE 0 END), 0)
		FROM subdomains WHERE `+liveCond(pg), func(r rowScanner) error {
		return r.Scan(&s.Live, &s.Fingerprinted, &s.WithTech)
	})
	return s, err
}

// FingerprintHost is one live host matched by product keyword.
type FingerprintHost struct {
	Subdomain string `json:"host"`
	URL       string `json:"url"`
	Techs     string `json:"techs"`
	Title     string `json:"title"`
	Server    string `json:"server"`
	Via       string `json:"via"` // "techs:<kw>" | "title:<kw>" | "server:<kw>"
}

// cleanFPKeyword lowercases a keyword and drops LIKE wildcards; keywords
// shorter than 3 characters match too much to be useful.
func cleanFPKeyword(kw string) string {
	kw = strings.ToLower(strings.TrimSpace(kw))
	kw = strings.NewReplacer("%", "", "_", "", "\\", "").Replace(kw)
	if len(kw) < 3 || len(kw) > 64 {
		return ""
	}
	return kw
}

// MatchHostsByFingerprint returns live hosts whose techs, title or server
// header contains one of keywords: tech-stack matches first (the strongest
// signal), then title/server matches, up to limit. total is the full match
// count (above limit when the result was capped).
func MatchHostsByFingerprint(keywords []string, limit int) ([]FingerprintHost, int, error) {
	c, pg, err := fingerprintDB()
	if err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 20000 {
		limit = 2000
	}
	var kws []string
	seen := map[string]bool{}
	for _, k := range keywords {
		if k = cleanFPKeyword(k); k != "" && !seen[k] {
			seen[k] = true
			kws = append(kws, k)
		}
	}
	if len(kws) == 0 {
		return nil, 0, nil
	}
	clause := func(fields ...string) (string, []any) {
		var parts []string
		var args []any
		for _, k := range kws {
			for _, f := range fields {
				parts = append(parts, "LOWER(COALESCE("+f+",'')) LIKE ?")
				args = append(args, "%"+k+"%")
			}
		}
		return "(" + strings.Join(parts, " OR ") + ")", args
	}
	anyField, anyArgs := clause("techs", "fp_title", "fp_server")
	total := 0
	if err := c.query(`SELECT COUNT(*) FROM subdomains WHERE `+liveCond(pg)+` AND `+anyField, func(r rowScanner) error {
		return r.Scan(&total)
	}, anyArgs...); err != nil {
		return nil, 0, err
	}
	var out []FingerprintHost
	got := map[string]bool{}
	collect := func(where string, args []any, max int) error {
		return c.query(`SELECT subdomain, `+bestURLExpr+`,
			COALESCE(techs,''), fp_title, fp_server FROM subdomains WHERE `+liveCond(pg)+` AND `+where+` ORDER BY id LIMIT ?`,
			func(r rowScanner) error {
				var h FingerprintHost
				if err := r.Scan(&h.Subdomain, &h.URL, &h.Techs, &h.Title, &h.Server); err != nil {
					return err
				}
				if got[h.Subdomain] {
					return nil
				}
				got[h.Subdomain] = true
				h.Via = fingerprintVia(h, kws)
				out = append(out, h)
				return nil
			}, append(args, max)...)
	}
	techWhere, techArgs := clause("techs")
	if err := collect(techWhere, techArgs, limit); err != nil {
		return nil, total, err
	}
	if len(out) < limit {
		restWhere, restArgs := clause("fp_title", "fp_server")
		// Hosts already taken by the techs pass are skipped, so ask for a
		// full page again and trim after.
		if err := collect(restWhere, restArgs, limit); err != nil {
			return nil, total, err
		}
		if len(out) > limit {
			out = out[:limit]
		}
	}
	return out, total, nil
}

// fingerprintVia names the field and keyword that matched a host.
func fingerprintVia(h FingerprintHost, kws []string) string {
	for _, f := range []struct{ name, val string }{{"techs", h.Techs}, {"title", h.Title}, {"server", h.Server}} {
		low := strings.ToLower(f.val)
		for _, k := range kws {
			if strings.Contains(low, k) {
				return f.name + ":" + k
			}
		}
	}
	return ""
}
