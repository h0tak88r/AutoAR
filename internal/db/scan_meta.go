package db

import (
	"errors"
	"strings"
)

// Scan display metadata: an operator title (scans.name) and free-text notes
// (scans.description). Both are optional; nil leaves a field unchanged.

// UpdateScanMeta sets name and/or description on scanID. found=false means no
// row exists yet (a tracked scan's row is written just after launch), so the
// caller can hold the values until it is created.
func UpdateScanMeta(scanID string, name, description *string) (found bool, err error) {
	if err := Init(); err != nil {
		return false, err
	}
	if name == nil && description == nil {
		return false, errors.New("nothing to update")
	}
	var c triageConn
	switch d := dbInstance.(type) {
	case *PostgresDB:
		c = pgTriage{p: d}
	case *SQLiteDB:
		c = sqliteTriage{s: d}
	default:
		return false, errors.New("scan meta: unsupported backend")
	}
	var sets []string
	var args []any
	if name != nil {
		sets, args = append(sets, "name = ?"), append(args, *name)
	}
	if description != nil {
		sets, args = append(sets, "description = ?"), append(args, *description)
	}
	args = append(args, scanID)
	// RETURNING reports whether the row exists on both Postgres and SQLite.
	err = c.query(`UPDATE scans SET `+strings.Join(sets, ", ")+` WHERE scan_id = ? RETURNING scan_id`,
		func(r rowScanner) error {
			var id string
			found = true
			return r.Scan(&id)
		}, args...)
	return found, err
}
