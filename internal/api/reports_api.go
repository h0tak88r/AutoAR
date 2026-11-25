package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// Report writer for the findings pipeline: AI-assisted drafts in the owner's
// report format, editable in the UI, saved on the finding row.

// reportSpecSystem is the owner's format spec (standing rules): ONLY these
// sections, honest CVSS, no invented facts.
const reportSpecSystem = `You write bug-bounty vulnerability reports from EVIDENCE the platform provides.
Absolute rules:
- Use ONLY facts present in the evidence. If a fact is missing, write exactly [NOT PROVIDED] in its place. NEVER invent endpoints, versions, responses, parameters, counts or impact.
- Sections, in this exact order, each as a "## <name>" heading: Title, Severity, CVSS 3.1, Asset, OWASP Reference, Vulnerable Endpoint, Description, Steps to Reproduce, Remediation, POC.
- Description = one deep-technical paragraph + one business-impact paragraph. NO request snippets in Description (raw requests/responses go in POC only).
- Steps to Reproduce = numbered steps.
- Remediation = bullet points.
- Severity must match the evidence's severity; if none, use the CVSS band.
- CVSS 3.1 = a real vector string ONLY if the evidence contains one; otherwise [NOT PROVIDED].
- No dates, no report IDs, no cross-references to other reports.
- Output ONLY the report markdown, nothing else.`

// reportScaffold is the no-AI fallback: the format with placeholders.
func reportScaffold(f *db.Finding, evidence string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Title\n%s\n\n", nonEmptyStr(f.Title, "[NOT PROVIDED]"))
	fmt.Fprintf(&b, "## Severity\n%s\n\n", strings.ToUpper(nonEmptyStr(f.Severity, "[NOT PROVIDED]")))
	fmt.Fprintf(&b, "## CVSS 3.1\n[NOT PROVIDED]\n\n")
	fmt.Fprintf(&b, "## Asset\n%s\n\n", nonEmptyStr(f.Host, "[NOT PROVIDED]"))
	fmt.Fprintf(&b, "## OWASP Reference\n[NOT PROVIDED]\n\n")
	fmt.Fprintf(&b, "## Vulnerable Endpoint\n[NOT PROVIDED]\n\n")
	fmt.Fprintf(&b, "## Description\n[NOT PROVIDED]\n\n")
	fmt.Fprintf(&b, "## Steps to Reproduce\n1. [NOT PROVIDED]\n\n")
	fmt.Fprintf(&b, "## Remediation\n- [NOT PROVIDED]\n\n")
	fmt.Fprintf(&b, "## POC\n[NOT PROVIDED]\n")
	if evidence != "" {
		fmt.Fprintf(&b, "\n<!-- evidence pack:\n%s\n-->\n", evidence)
	}
	return b.String()
}

// apiGenerateFindingReport (POST /api/findings/:id/report) writes an
// AI-assisted draft from the finding's evidence pack and stores it.
func apiGenerateFindingReport(c *gin.Context) {
	_ = db.Init()
	id, err := parseID64(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	f, err := db.GetFinding(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
	var body struct {
		Regenerate bool `json:"regenerate"` // ignore the stored report and the AI review's draft
	}
	_ = c.ShouldBindJSON(&body)
	evidence := buildEvidencePack(f)
	report, provider := f.ReportMD, "existing"
	if body.Regenerate {
		report = ""
	}

	if strings.TrimSpace(report) == "" {
		// Prefer this finding's own AI-review draft (exact link by key); the
		// host match is only for older manual findings with no link.
		draft := ""
		if !body.Regenerate {
			if f.AI != nil && strings.TrimSpace(f.AI.ReportMD) != "" {
				draft = f.AI.ReportMD
			} else if f.FKey == "" {
				draft = triageReportForHost(f.Host)
			}
		}
		if draft != "" {
			report, provider = draft, "triage-record"
		} else {
			reply, cerr := brain.Complete(context.Background(), reportSpecSystem, evidence,
				brain.Options{MaxTokens: 4096, Timeout: 3 * time.Minute, Feature: "report"})
			if cerr == nil && strings.TrimSpace(reply) != "" {
				report, provider = strings.TrimSpace(reply), "ai"
			} else {
				report, provider = reportScaffold(f, ""), "scaffold"
			}
		}
		if err := db.UpdateFindingReport(id, report); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"report_md": report, "source": provider, "evidence": evidence})
}

// apiSaveFindingReport (PATCH /api/findings/:id/report) stores edited markdown;
// with bump=true the finding moves to drafted.
func apiSaveFindingReport(c *gin.Context) {
	_ = db.Init()
	id, err := parseID64(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req struct {
		ReportMD string `json:"report_md"`
		Bump     bool   `json:"bump_status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.ReportMD) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "report_md is required"})
		return
	}
	if err := db.UpdateFindingReport(id, req.ReportMD); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if req.Bump {
		_ = db.UpdateFindingStatus(id, "drafted", "", "")
	}
	c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

// buildEvidencePack assembles everything the writer may use — finding fields,
// the tracked CVE record and the scan row when the source references one.
func buildEvidencePack(f *db.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "FINDING:\n%s\n", mcpJSON(f))
	if f.CVE != "" {
		if rec, err := db.GetCVE(strings.ToUpper(f.CVE)); err == nil && rec != nil {
			fmt.Fprintf(&b, "\nTRACKED CVE RECORD:\n%s\n", mcpJSON(rec))
		}
	}
	scanID := f.ScanID
	if scanID == "" && f.Source != "" && !strings.Contains(f.Source, " ") {
		scanID = strings.TrimPrefix(f.Source, "scan:")
	}
	if scanID != "" {
		if rec, err := db.GetScan(scanID); err == nil && rec != nil {
			fmt.Fprintf(&b, "\nSOURCE SCAN:\n%s\n", mcpJSON(rec))
		}
	}
	fmt.Fprintf(&b, "\nSCOPE: %s\n", mcpJSON(triageScopeFor(f.Host)))
	return b.String()
}

// triageReportForHost finds the newest AI-triage report for a host.
func triageReportForHost(host string) string {
	if strings.TrimSpace(host) == "" {
		return ""
	}
	rows, err := db.ListTriage(db.TriageFilter{Host: host, Limit: 5})
	if err != nil {
		return ""
	}
	for _, r := range rows {
		if strings.TrimSpace(r.ReportMD) != "" {
			return r.ReportMD
		}
	}
	return ""
}

func parseID64(s string) (int64, error) {
	var id int64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &id)
	return id, err
}

// brainComplete is a thin seam so tests can stub the provider call.
var brainComplete = func(system, user string) (string, error) {
	return brain.Complete(context.Background(), system, user, brain.Options{MaxTokens: 4096, Timeout: 3 * time.Minute, Feature: "report"})
}
