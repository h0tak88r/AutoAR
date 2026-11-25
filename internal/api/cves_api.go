package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// CVE radar page endpoints. Read-only; visible to every authenticated user
// (radar intel carries no per-user data).

// apiListCVEs serves GET /api/cves with the page's filters.
func apiListCVEs(c *gin.Context) {
	_ = db.Init()
	f := db.CVEFilter{Q: strings.TrimSpace(c.Query("q"))}
	if c.Query("poc") == "1" {
		f.PoCOnly = true
	}
	if c.Query("poc") == "0" {
		f.NoPoCOnly = true
	}
	switch v := c.DefaultQuery("scanned", ""); v {
	case "1":
		t := true
		f.Scanned = &t
	case "0":
		t := false
		f.Scanned = &t
	}
	if v := c.Query("av"); v != "" {
		f.AV = v
	}
	switch v := strings.ToLower(strings.TrimSpace(c.Query("run"))); v {
	case "", "any":
	case db.CVERunNever, db.CVERunActive, db.CVERunTried, db.CVERunRan:
		f.RunState = v
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "run must be never, active, tried or ran"})
		return
	}
	if v, err := strconv.ParseFloat(c.Query("min_score"), 64); err == nil && v > 0 {
		f.MinScore = v
	}
	if v, err := strconv.Atoi(c.DefaultQuery("limit", "100")); err == nil {
		f.Limit = v
	}
	if v, err := strconv.Atoi(c.DefaultQuery("offset", "0")); err == nil {
		f.Offset = v
	}
	rows, total, err := db.ListCVEs(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []*db.CVERecord{}
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.CVEID)
	}
	runs, err := db.PocdayRunsFor(ids)
	if err != nil || runs == nil {
		runs = map[string]*db.PocdayRun{}
	}
	for _, r := range rows {
		r.RunState = db.CVERunState(r, runs[r.CVEID])
	}
	c.JSON(http.StatusOK, gin.H{"cves": rows, "total": total, "limit": f.Limit, "offset": f.Offset, "pocday": runs})
}

// apiGetCVE serves GET /api/cves/:id.
func apiGetCVE(c *gin.Context) {
	_ = db.Init()
	rec, err := db.GetCVE(strings.TrimSpace(c.Param("id")))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "cve not found"})
		return
	}
	c.JSON(http.StatusOK, rec)
}

// apiSetCVELabel (PATCH /api/cves/:id/label) — operator labeling on the radar page.
func apiSetCVELabel(c *gin.Context) {
	_ = db.Init()
	var req struct {
		Label string `json:"label"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "label required"})
		return
	}
	if err := db.SetCVELabel(strings.ToUpper(strings.TrimSpace(c.Param("id"))), req.Label); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "labeled", "label": req.Label})
}
