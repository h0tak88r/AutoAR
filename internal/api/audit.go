package api

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// audit records an activity-log entry attributed to the request's user (falling
// back to "system"), best-effort — a logging failure must never break the action.
func audit(c *gin.Context, action, target, detail string) {
	actor := currentUsername(c)
	if actor == "" {
		actor = "system"
	}
	ip := ""
	if c != nil {
		ip = c.ClientIP()
	}
	if err := db.InsertAuditEvent(db.AuditEvent{Actor: actor, Action: action, Target: target, Detail: detail, IP: ip}); err != nil {
		log.Printf("[audit] insert failed (%s): %v", action, err)
	}
}

// auditActor records an activity-log entry for a non-request context (e.g. the
// scan runner, automated jobs). Empty actor becomes "system".
func auditActor(actor, action, target, detail string) {
	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	if err := db.InsertAuditEvent(db.AuditEvent{Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		log.Printf("[audit] insert failed (%s): %v", action, err)
	}
}

// GET /api/audit — admin-only activity log, newest first. Optional query params:
// limit (default 200, max 1000), actor, action.
func apiListAudit(c *gin.Context) {
	limit := 200
	if v := strings.TrimSpace(c.Query("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	events, err := db.ListAuditEvents(limit, strings.TrimSpace(c.Query("actor")), strings.TrimSpace(c.Query("action")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list audit events"})
		return
	}
	if events == nil {
		events = []db.AuditEvent{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}
