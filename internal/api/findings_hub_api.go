package api

// Merged Findings actions: one finding, its AI review, the operator's
// verdict, Discord delivery, importing a scan, and cleanup. The AI review is
// the triage engine's record under the finding's fkey.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/triage"
)

func findingFromParam(c *gin.Context) (*db.Finding, bool) {
	_ = db.Init()
	id, err := parseID64(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return nil, false
	}
	f, err := db.GetFinding(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return nil, false
	}
	return f, true
}

// GET /api/findings/:id — one finding with evidence, the AI draft and the
// agent validation.
func apiGetFinding(c *gin.Context) {
	if f, ok := findingFromParam(c); ok {
		attachValidations(f)
		attachProgramURLs(f)
		c.JSON(http.StatusOK, gin.H{"finding": f})
	}
}

// POST /api/findings/:id/ai-review {force} — run the AI on one finding now
// (any severity; the daily budget applies).
func apiFindingAIReview(c *gin.Context) {
	f, ok := findingFromParam(c)
	if !ok {
		return
	}
	if !brain.Available() {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "no AI provider key configured — add one in Settings ▸ AI Providers"})
		return
	}
	var body struct {
		Force *bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&body)
	force := body.Force == nil || *body.Force // a click means "review it now"
	tf, err := findingForReview(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Minute)
	defer cancel()
	rec, err := triageEngine.ReviewOne(ctx, loadTriageConfig(), tf, force)
	switch {
	case errors.Is(err, triage.ErrBudget):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
		return
	case err != nil:
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	audit(c, "finding.ai_review", f.Title, rec.Verdict)
	out, _ := db.GetFinding(f.ID)
	c.JSON(http.StatusOK, gin.H{"finding": out})
}

var findingVerdicts = map[string]bool{"": true, "true_positive": true, "likely": true, "needs_manual_review": true, "false_positive": true}

// POST /api/findings/:id/verdict {verdict} — the operator's label; "" clears it.
func apiFindingVerdict(c *gin.Context) {
	f, ok := findingFromParam(c)
	if !ok {
		return
	}
	var body struct {
		Verdict string `json:"verdict"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || !findingVerdicts[body.Verdict] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verdict must be true_positive, likely, needs_manual_review, false_positive or empty"})
		return
	}
	if f.FKey == "" {
		if _, err := findingForReview(f); err != nil { // gives manual findings a key
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if err := db.SetFindingVerdict(f, body.Verdict); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	audit(c, "finding.verdict", f.Title, body.Verdict)
	out, _ := db.GetFinding(f.ID)
	c.JSON(http.StatusOK, gin.H{"finding": out})
}

// POST /api/findings/:id/notify — send the finding to the Discord findings
// channel with its report (the stored report, else the AI draft).
func apiFindingNotify(c *gin.Context) {
	f, ok := findingFromParam(c)
	if !ok {
		return
	}
	now, err := notifyFindingDiscord(c.Request.Context(), f, currentUsername(c))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	audit(c, "finding.notify", f.Title, f.Host)
	c.JSON(http.StatusOK, gin.H{"ok": true, "notified_at": now})
}

// notifyFindingDiscord posts a finding (dashboard and MCP share it).
func notifyFindingDiscord(ctx context.Context, f *db.Finding, actor string) (int64, error) {
	rec := &db.TriageRecord{ID: f.FKey, ScanID: f.ScanID, TemplateID: f.TemplateID, Title: f.Title, Host: f.Host,
		MatchedAt: f.MatchedAt, Severity: f.Severity}
	if f.AI != nil {
		rec.Verdict, rec.Confidence, rec.Reason, rec.AISeverity = f.AI.Verdict, f.AI.Confidence, f.AI.Reason, f.AI.Severity
		rec.Scope, rec.ScopeProgram, rec.Reportable = f.AI.Scope, f.AI.ScopeProgram, f.AI.Reportable
		rec.ReportMD = f.AI.ReportMD
	}
	if strings.TrimSpace(f.ReportMD) != "" {
		rec.ReportMD = f.ReportMD
	}
	if strings.TrimSpace(rec.ReportMD) == "" {
		rec.ReportMD = "## Title\n" + f.Title + "\n\n## Summary\n" + rec.Reason + "\n\n## Steps to Reproduce\n1. " + firstNonEmptyStr(f.MatchedAt, f.Host) + "\n"
	}
	if err := triage.NotifyDiscord(ctx, rec, loadTriageConfig()); err != nil {
		return 0, err
	}
	now := time.Now().Unix()
	if f.FKey != "" && f.AI != nil {
		_ = db.SetTriageNotified(f.FKey, now, "sent to Discord by "+firstNonEmptyStr(actor, "dashboard"))
	}
	return now, nil
}

// POST /api/findings/import-scan {scan_id, include_info, ai} — pull a scan's
// hits into Findings (queued; ai=true also reviews medium+ hits).
func apiFindingsImportScan(c *gin.Context) {
	var body struct {
		ScanID      string `json:"scan_id"`
		IncludeInfo bool   `json:"include_info"`
		AI          *bool  `json:"ai"`
		Force       bool   `json:"force"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || strings.TrimSpace(body.ScanID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id required"})
		return
	}
	id := strings.TrimSpace(body.ScanID)
	if rec, err := db.GetScan(id); err != nil || rec == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
		return
	}
	withAI := (body.AI == nil || *body.AI) && brain.Available()
	enqueueTriage(triageJob{ScanID: id, Force: body.Force, Reason: "import", AI: withAI, IncludeInfo: body.IncludeInfo}, true)
	audit(c, "findings.import", id, "")
	c.JSON(http.StatusAccepted, gin.H{"queued": true, "scan_id": id, "ai": withAI})
}

// POST /api/findings/bulk-delete {ids:[...]}
func apiFindingsBulkDelete(c *gin.Context) {
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || len(body.IDs) == 0 || len(body.IDs) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ids required (max 1000)"})
		return
	}
	n, err := db.DeleteFindings(body.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	audit(c, "findings.delete", "", fmt.Sprintf("%d deleted", n))
	c.JSON(http.StatusOK, gin.H{"deleted": n})
}
