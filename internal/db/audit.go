package db

// Package-level wrappers for the admin audit log.

// InsertAuditEvent records one activity-log entry.
func InsertAuditEvent(e AuditEvent) error {
	if err := Init(); err != nil {
		return err
	}
	return dbInstance.InsertAuditEvent(e)
}

// ListAuditEvents returns recent audit events, newest first, optionally filtered
// by actor and/or action. limit defaults to 200 (max 1000).
func ListAuditEvents(limit int, actor, action string) ([]AuditEvent, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	return dbInstance.ListAuditEvents(limit, actor, action)
}
