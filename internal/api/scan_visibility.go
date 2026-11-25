package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// Scan visibility (owner directive 2026-10-12): a non-admin dashboard user
// sees ONLY the scans they started; an admin sees everything, including
// system-initiated scans (watcher, bridge, scheduled sweeps). Unknown scans
// fail closed as 404 — existence of another user's scan is not revealed.

// scanVisible reports whether the requesting user may see one scan record.
// Admin: always. Otherwise the record must carry their username in CreatedBy
// (system/empty-owner rows are invisible to viewers).
func scanVisible(c *gin.Context, rec *db.ScanRecord) bool {
	if requestIsAdmin(c) {
		return true
	}
	u := currentUsername(c)
	return u != "" && rec != nil && rec.CreatedBy == u
}

// ownScanOnly wraps a /scans/:id read handler with the visibility gate.
func ownScanOnly(h gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			h(c)
			return
		}
		if requestIsAdmin(c) {
			h(c)
			return
		}
		u := currentUsername(c)
		rec, err := db.GetScan(id)
		if err != nil || rec == nil || u == "" || rec.CreatedBy != u {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		h(c)
	}
}

// filterScansToOwner drops rows a non-admin may not see (in place, returns the
// kept slice). Admins get the input unchanged.
func filterScansToOwner(c *gin.Context, scans []*db.ScanRecord) []*db.ScanRecord {
	if requestIsAdmin(c) {
		return scans
	}
	kept := make([]*db.ScanRecord, 0, len(scans))
	for _, s := range scans {
		if scanVisible(c, s) {
			kept = append(kept, s)
		}
	}
	return kept
}
