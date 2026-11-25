package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Findings pipeline endpoints + the weekly bounty digest.

// apiListFindings (GET /api/findings) — the merged Findings list: every
// finding with its AI review joined. Filters: status, platform, program
// (handle, or "__none__"), report (1 = has a link, 0 = none), closed (0 =
// leave out rejected / dup / wontfix unless status asks), ai, severity,
// module, scan_id, q, min_age_hours; facets=1 adds per-label/status/program
// counts.
func apiListFindings(c *gin.Context) {
	_ = db.Init()
	q := func(k string) string { return strings.TrimSpace(c.Query(k)) }
	f := db.FindingFilter{Status: q("status"), Platform: q("platform"), AI: q("ai"), Severity: q("severity"),
		Module: q("module"), ScanID: q("scan_id"), Q: q("q"), FKey: q("fkey"), Program: q("program"), Report: q("report"),
		HideClosed: q("closed") == "0"}
	if q("remind") == "due" {
		f.RemindDueBefore = time.Now().UTC().Unix()
	}
	if v, err := strconv.Atoi(c.Query("min_age_hours")); err == nil && v > 0 {
		f.MinAgeH = v
	}
	if v, err := strconv.Atoi(c.DefaultQuery("limit", "100")); err == nil {
		f.Limit = v
	}
	if v, err := strconv.Atoi(c.DefaultQuery("offset", "0")); err == nil && v >= 0 {
		f.Offset = v
	}
	rows, total, err := db.ListFindings(f)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.HasPrefix(err.Error(), "unknown AI filter") {
			code = http.StatusBadRequest
		}
		c.JSON(code, gin.H{"error": err.Error()})
		return
	}
	if rows == nil {
		rows = []*db.Finding{}
	}
	attachValidations(rows...)
	attachProgramURLs(rows...)
	resp := gin.H{"findings": rows, "total": total}
	if c.Query("facets") == "1" {
		if facets, err := db.GetFindingFacetsOpts(f.ScanID, f.HideClosed && f.Status == ""); err == nil {
			resp["facets"] = facets
		}
	}
	c.JSON(http.StatusOK, resp)
}

func apiCreateFinding(c *gin.Context) {
	_ = db.Init()
	var f db.Finding
	if err := c.ShouldBindJSON(&f); err != nil || strings.TrimSpace(f.Title) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "title is required"})
		return
	}
	f.Title = strings.TrimSpace(f.Title)
	if err := db.CreateFinding(&f); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "created", "finding": f})
}

func apiUpdateFinding(c *gin.Context) {
	_ = db.Init()
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	// Any subset of the editable fields; nil = unchanged. The old status form
	// ({status, report_ref, notes}) keeps working: empty report_ref / notes
	// there meant "keep", so they are dropped rather than clearing.
	var req db.FindingEdit
	if err := c.ShouldBindJSON(&req); err != nil || req.Empty() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "send at least one field to change"})
		return
	}
	if req.Status != nil {
		if req.ReportRef != nil && *req.ReportRef == "" {
			req.ReportRef = nil
		}
		if req.Notes != nil && *req.Notes == "" {
			req.Notes = nil
		}
	}
	if err := db.UpdateFindingFields(id, req); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, db.ErrFindingNotFound) {
			code = http.StatusNotFound
		}
		c.JSON(code, gin.H{"error": err.Error()})
		return
	}
	audit(c, "finding.update", strconv.FormatInt(id, 10), "")
	rec, _ := db.GetFinding(id)
	c.JSON(http.StatusOK, gin.H{"status": "updated", "finding": rec})
}

// ─────────────────────────────────────────────────────────────────────────────
// Weekly bounty digest
// ─────────────────────────────────────────────────────────────────────────────

const digestLastSentKey = "bounty_digest_last_sent"

// digestSection renders one block of the digest.
type digestSection struct {
	Title string
	Lines []string
}

// buildBountyDigest assembles the weekly digest from the findings pipeline,
// scan activity and the discovered-assets feed.
func buildBountyDigest() string {
	var secs []digestSection

	// 1. Decisions waiting on the operator — validated/drafted findings.
	for _, st := range []string{"validated", "drafted"} {
		rows, _, err := db.ListFindings(db.FindingFilter{Status: st, Limit: 25})
		if err != nil || len(rows) == 0 {
			continue
		}
		var lines []string
		for _, f := range rows {
			age := time.Since(time.Unix(f.UpdatedAt, 0)).Round(time.Hour)
			ref := ""
			if f.ReportRef != "" {
				ref = " · `" + f.ReportRef + "`"
			}
			lines = append(lines, fmt.Sprintf("• **%s** — %s `%s`%s · waiting **%s**",
				f.Title, f.Platform, f.Severity, ref, age))
		}
		secs = append(secs, digestSection{Title: "⏳ " + map[string]string{"validated": "Validated, needs your submit/drop call", "drafted": "Drafted reports ready"}[st], Lines: lines})
	}

	// 2. In flight.
	if rows, _, err := db.ListFindings(db.FindingFilter{Status: "submitted", Limit: 10}); err == nil && len(rows) > 0 {
		var lines []string
		for _, f := range rows {
			lines = append(lines, fmt.Sprintf("• **%s** → %s `%s` · submitted %s ago",
				f.Title, f.Platform, f.ReportRef, time.Since(time.Unix(f.UpdatedAt, 0)).Round(time.Hour)))
		}
		secs = append(secs, digestSection{Title: "📤 Submitted, awaiting triage", Lines: lines})
	}

	// 3. Fresh findings not yet triaged.
	if rows, _, err := db.ListFindings(db.FindingFilter{Status: "discovered", Limit: 10}); err == nil && len(rows) > 0 {
		var lines []string
		for _, f := range rows {
			lines = append(lines, fmt.Sprintf("• **%s** — %s `%s` · %s", f.Title, f.Platform, f.Severity, time.Since(time.Unix(f.UpdatedAt, 0)).Round(time.Hour)))
		}
		secs = append(secs, digestSection{Title: "🆕 Discovered, not yet validated", Lines: lines})
	}

	// 4. New assets this week.
	if assets, err := db.ListRecentlyDiscoveredSubdomains(3, 24*7); err == nil && len(assets) > 0 {
		secs = append(secs, digestSection{Title: "🛰️ Asset growth",
			Lines: []string{fmt.Sprintf("• **%d** new asset(s) discovered in the last 7 days (showing newest):", len(assets))}})
		for _, a := range assets {
			secs[len(secs)-1].Lines = append(secs[len(secs)-1].Lines, "  · `"+a.Subdomain+"`")
		}
	}

	var b strings.Builder
	b.WriteString("📅 **Weekly bounty digest**\n")
	if len(secs) == 0 {
		b.WriteString("Nothing waiting: no open findings, nothing submitted, no new assets. Quiet week.\n")
	}
	for _, s := range secs {
		b.WriteString("\n**" + s.Title + "**\n" + strings.Join(s.Lines, "\n") + "\n")
	}
	return b.String()
}

// apiDigestPreview serves the digest text (dashboard preview).
func apiDigestPreview(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"digest": buildBountyDigest()})
}

// apiDigestSend forces the weekly digest out now (admin).
func apiDigestSend(c *gin.Context) {
	msg := buildBountyDigest()
	utils.SendMonitorWebhook(msg)
	_ = db.SetSetting(digestLastSentKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
	c.JSON(http.StatusOK, gin.H{"status": "sent"})
}

// StartBountyDigest sends the digest weekly (first run ~1h after boot, then
// every 7 days; SEND now endpoint resets the timer).
func StartBountyDigest() {
	utils.SafeGo("bounty-digest", func() {
		time.Sleep(1 * time.Hour)
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			last := int64(db.GetSettingInt(digestLastSentKey, 0))
			if time.Since(time.Unix(last, 0)) < 7*24*time.Hour {
				continue
			}
			_ = db.SetSetting(digestLastSentKey, strconv.FormatInt(time.Now().UTC().Unix(), 10))
			utils.SendMonitorWebhook(buildBountyDigest())
		}
	})
}
