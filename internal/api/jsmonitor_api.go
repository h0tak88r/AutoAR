package api

import (
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/scanner/jsmonitor"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// maxJSMonitorThreads bounds a JS-monitor target's threads (they size the URL
// collector run on every sweep).
const maxJSMonitorThreads = 50

// jsMonitorManualRuns tracks domains with a manual (API-triggered) sweep in
// flight: repeated POSTs used to start overlapping sweeps of the same domain —
// duplicate alerts and racing writes to its js-urls.txt. (The jsmonitor
// package exposes no in-flight hook, so the daemon's own sweeps aren't covered.)
var (
	jsMonitorManualMu   sync.Mutex
	jsMonitorManualRuns = map[string]struct{}{}
)

// claimJSMonitorRun marks key as having a manual sweep in flight; false if one
// already is.
func claimJSMonitorRun(key string) bool {
	jsMonitorManualMu.Lock()
	defer jsMonitorManualMu.Unlock()
	if _, busy := jsMonitorManualRuns[key]; busy {
		return false
	}
	jsMonitorManualRuns[key] = struct{}{}
	return true
}

func releaseJSMonitorRun(key string) {
	jsMonitorManualMu.Lock()
	delete(jsMonitorManualRuns, key)
	jsMonitorManualMu.Unlock()
}

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
	if body.Threads > maxJSMonitorThreads {
		body.Threads = maxJSMonitorThreads
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
			key := strings.ToLower(strings.TrimSpace(t.Domain))
			if !claimJSMonitorRun(key) {
				c.JSON(http.StatusConflict, gin.H{"error": "a sweep of this domain is already running"})
				return
			}
			domain := t.Domain
			utils.SafeGo("js-monitor:manual-sweep", func() {
				defer releaseJSMonitorRun(key)
				if err := jsmonitor.MonitorDomain(domain); err != nil {
					log.Printf("[JS-MONITOR] manual sweep of %s: %v", domain, err)
				}
			})
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
