package api

import (
	"net/http"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/jsmonitor"
	"github.com/gin-gonic/gin"
)

// POST /api/jsmonitor/targets — enroll a root domain in the JS-file monitor.
// Body: {"domain": "example.com", "interval_seconds": 21600, "threads": 30}
func apiPostJSMonitorTarget(c *gin.Context) {
	var body struct {
		Domain          string `json:"domain"`
		IntervalSeconds int    `json:"interval_seconds"`
		Threads         int    `json:"threads"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain is required"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(body.Domain))
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")
	domain = strings.TrimSuffix(domain, "/")
	if body.IntervalSeconds < 600 {
		body.IntervalSeconds = 21600 // floor: no tighter than 10-minute sweeps
	}
	if body.Threads <= 0 {
		body.Threads = 30
	}
	id, err := db.AddJSMonitorTarget(domain, body.IntervalSeconds, body.Threads)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !jsmonitor.IsDaemonRunning() {
		jsmonitor.StartDaemon()
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "id": id, "domain": domain, "message": "JS monitor target added — first sweep starting now"})
}

// GET /api/jsmonitor/targets — list enrolled domains with file counts.
func apiGetJSMonitorTargets(c *gin.Context) {
	targets, err := db.ListJSMonitorTargets()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"targets": targets, "daemon_running": jsmonitor.IsDaemonRunning()})
}

// DELETE /api/jsmonitor/targets/:id — remove a domain and its inventory.
func apiDeleteJSMonitorTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	if err := db.DeleteJSMonitorTarget(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// POST /api/jsmonitor/targets/:id/run — trigger an immediate sweep.
func apiRunJSMonitorTarget(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	targets, terr := db.ListJSMonitorTargets()
	if terr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": terr.Error()})
		return
	}
	for _, t := range targets {
		if t.ID == id {
			go jsmonitor.MonitorDomain(t.Domain)
			c.JSON(http.StatusOK, gin.H{"ok": true, "message": "sweep started"})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "target not found"})
}

// GET /api/jsmonitor/targets/:id/files — inventory for one domain.
func apiGetJSMonitorFiles(c *gin.Context) {
	id, ok := parseMonitorTargetID(c)
	if !ok {
		return
	}
	files, ferr := db.ListJSMonitorFiles(id)
	if ferr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": ferr.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"files": files})
}
