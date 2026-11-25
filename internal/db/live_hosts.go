package db

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Fleet-wide live-host helpers for the global nuclei sweep and the race pass.
// Kept in their own file (type switch on the two backends) so they stay
// additive: no DB-interface change, identical semantics on SQLite and Postgres.

// ListLiveSubdomainsAfter returns up to limit live subdomains whose row id is
// greater than afterID, ordered by id, plus the id to pass as the next cursor
// (0 when the page is empty). Keyset pagination: unlike OFFSET pages it never
// re-COUNTs, stays an index range scan at any depth, and rows inserted during
// a multi-hour dump land after the cursor instead of shifting every later
// page (which skipped or duplicated hosts).
func ListLiveSubdomainsAfter(afterID int64, limit int) ([]GlobalSubdomain, int64, error) {
	return listLiveSubdomainsAfter(afterID, limit, false)
}

// ListLivePHPSubdomainsAfter is ListLiveSubdomainsAfter restricted to hosts
// whose tech fingerprint mentions PHP — the fast path for the php2shell sweep,
// which otherwise probes every live host (hundreds of times more requests).
func ListLivePHPSubdomainsAfter(afterID int64, limit int) ([]GlobalSubdomain, int64, error) {
	return listLiveSubdomainsAfter(afterID, limit, true)
}

func listLiveSubdomainsAfter(afterID int64, limit int, phpOnly bool) ([]GlobalSubdomain, int64, error) {
	if err := Init(); err != nil {
		return nil, 0, err
	}
	if limit <= 0 {
		limit = 1000
	}
	const cols = `s.id, d.domain, s.subdomain,
		       COALESCE(s.http_url, ''), COALESCE(s.https_url, ''),
		       COALESCE(s.http_status, 0), COALESCE(s.https_status, 0),
		       COALESCE(s.techs, ''), COALESCE(s.cnames, '')
		FROM subdomains s
		JOIN domains d ON s.domain_id = d.id`
	type rowScanner interface {
		Next() bool
		Scan(dest ...any) error
		Err() error
	}
	collect := func(rows rowScanner) ([]GlobalSubdomain, int64, error) {
		var (
			out  []GlobalSubdomain
			last int64
		)
		for rows.Next() {
			var g GlobalSubdomain
			if err := rows.Scan(&last, &g.Domain, &g.Subdomain, &g.HTTPURL, &g.HTTPSURL,
				&g.HTTPStatus, &g.HTTPSStatus, &g.Techs, &g.CNAMEs); err != nil {
				return nil, 0, fmt.Errorf("scan live subdomain: %w", err)
			}
			g.IsLive = true
			out = append(out, g)
		}
		if err := rows.Err(); err != nil {
			return nil, 0, fmt.Errorf("iterate live subdomains: %w", err)
		}
		return out, last, nil
	}

	switch d := dbInstance.(type) {
	case *PostgresDB:
		ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
		defer cancel()
		php := ""
		if phpOnly {
			php = " AND s.techs ILIKE '%php%'"
		}
		rows, err := d.pool.Query(ctx, `SELECT `+cols+`
		WHERE s.id > $1 AND s.is_live = true`+php+`
		ORDER BY s.id
		LIMIT $2`, afterID, limit)
		if err != nil {
			return nil, 0, fmt.Errorf("list live subdomains: %w", err)
		}
		defer rows.Close()
		return collect(rows)
	case *SQLiteDB:
		php := ""
		if phpOnly {
			php = " AND LOWER(COALESCE(s.techs, '')) LIKE '%php%'"
		}
		rows, err := d.db.Query(`SELECT `+cols+`
		WHERE s.id > ? AND COALESCE(s.is_live, 0) = 1`+php+`
		ORDER BY s.id
		LIMIT ?`, afterID, limit)
		if err != nil {
			return nil, 0, fmt.Errorf("list live subdomains: %w", err)
		}
		defer rows.Close()
		return collect(rows)
	default:
		return nil, 0, fmt.Errorf("list live subdomains: unsupported DB backend %T", dbInstance)
	}
}

// FilterLiveSubdomains returns the subset of hosts (bare hostnames; lowercased
// like stored subdomains, so the unique subdomain index serves the lookup)
// that still exist as LIVE subdomains in the DB. Used to
// drop historical hosts whose domain was deleted (ended program) or that went
// dark, so nothing outside the current asset base is ever re-scanned.
func FilterLiveSubdomains(hosts []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(hosts) == 0 {
		return out, nil
	}
	if err := Init(); err != nil {
		return nil, err
	}
	norm := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			norm = append(norm, h)
		}
	}
	const chunk = 500
	for start := 0; start < len(norm); start += chunk {
		part := norm[start:min(start+chunk, len(norm))]
		switch d := dbInstance.(type) {
		case *PostgresDB:
			ctx, cancel := context.WithTimeout(d.ctx, 30*time.Second)
			rows, err := d.pool.Query(ctx,
				`SELECT subdomain FROM subdomains WHERE is_live = true AND subdomain = ANY($1)`, part)
			if err != nil {
				cancel()
				return nil, fmt.Errorf("filter live subdomains: %w", err)
			}
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err == nil {
					out[strings.ToLower(s)] = true
				}
			}
			err = rows.Err()
			rows.Close()
			cancel()
			if err != nil {
				return nil, fmt.Errorf("filter live subdomains: %w", err)
			}
		case *SQLiteDB:
			args := make([]any, len(part))
			for i, h := range part {
				args[i] = h
			}
			q := `SELECT subdomain FROM subdomains WHERE COALESCE(is_live, 0) = 1 AND subdomain IN (?` +
				strings.Repeat(",?", len(part)-1) + `)`
			rows, err := d.db.Query(q, args...)
			if err != nil {
				return nil, fmt.Errorf("filter live subdomains: %w", err)
			}
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err == nil {
					out[strings.ToLower(s)] = true
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return nil, fmt.Errorf("filter live subdomains: %w", err)
			}
		default:
			return nil, fmt.Errorf("filter live subdomains: unsupported DB backend %T", dbInstance)
		}
	}
	return out, nil
}
