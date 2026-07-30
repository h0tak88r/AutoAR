package api

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/huntermonitor"
)

// ─────────────────────────────────────────────────────────────────────────────
// Hunter Monitor — tracks a HackerOne username's public reputation and
// resolved-report hacktivity, alerting on Discord when either changes.
// ─────────────────────────────────────────────────────────────────────────────

func parseHunterMonitorID(c *gin.Context) (int64, bool) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid hunter monitor id"})
		return 0, false
	}
	return id, true
}

// GET /api/monitor/hunter-targets — list hunter monitor targets
func apiHunterMonitorTargets(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	targets, err := db.ListHunterMonitorTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"targets": targets, "total": len(targets)})
}

// POST /api/monitor/hunter-targets — add (or update the interval of) a hunter monitor target;
// optionally mark running and start the hunter monitor daemon.
func apiPostHunterMonitorTarget(c *gin.Context) {
	_ = db.Init()
	_ = db.EnsureSchema()

	var body struct {
		Username        string `json:"username"`
		IntervalSeconds int    `json:"interval_seconds"`
		Start           *bool  `json:"start"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body"})
		return
	}

	username := strings.TrimSpace(body.Username)
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	interval := body.IntervalSeconds
	if interval <= 0 {
		interval = 3600
	}

	id, err := db.AddHunterMonitorTarget(username, interval)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	start := true
	if body.Start != nil {
		start = *body.Start
	}
	if start {
		if err := db.SetHunterMonitorRunningStatus(id, true); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if !huntermonitor.IsDaemonRunning() {
			if err := huntermonitor.StartDaemon(); err != nil {
				log.Printf("[WARN] hunter monitor daemon: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"id":               id,
		"username":         username,
		"interval_seconds": interval,
		"started":          start,
	})
}

// DELETE /api/monitor/hunter-targets/:id — remove hunter monitor target.
func apiDeleteHunterMonitorTarget(c *gin.Context) {
	id, ok := parseHunterMonitorID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetHunterMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.RemoveHunterMonitorTarget(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/monitor/hunter-targets/:id/pause
func apiPauseHunterMonitorTarget(c *gin.Context) {
	id, ok := parseHunterMonitorID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetHunterMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.SetHunterMonitorRunningStatus(id, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "running": false})
}

// POST /api/monitor/hunter-targets/:id/resume
func apiResumeHunterMonitorTarget(c *gin.Context) {
	id, ok := parseHunterMonitorID(c)
	if !ok {
		return
	}
	_ = db.Init()
	_ = db.EnsureSchema()
	if _, err := db.GetHunterMonitorTargetByID(id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if err := db.SetHunterMonitorRunningStatus(id, true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !huntermonitor.IsDaemonRunning() {
		if err := huntermonitor.StartDaemon(); err != nil {
			log.Printf("[WARN] hunter monitor daemon: %v", err)
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "running": true})
}
