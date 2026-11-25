package api

// One-click report submission from a finding.
//
//   - HackerOne: real API submit (POST /v1/hackers/reports with the account's
//     username + API token). Returns the report URL.
//   - YesWeHack / Bugcrowd: assisted — the preview returns the submission page
//     and the report body to paste (YWH's API needs structured fields a finding
//     doesn't carry; Bugcrowd has no submission API at all).
//
// Submitting is irreversible, so the flow is two steps: the UI reads the
// preview (GET, no side effects), shows a confirm dialog with the program, the
// account it will file from, and the report, and only then POSTs to submit.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Seams for tests: the HackerOne API base and the HTTP client.
var (
	h1APIBase  = "https://api.hackerone.com"
	submitHTTP = &http.Client{Timeout: 30 * time.Second}
)

// submitPreview is what the UI shows before filing, and what the submit
// endpoint re-derives server-side (never trusting the client's copy).
type submitPreview struct {
	FindingID int64    `json:"finding_id"`
	Platform  string   `json:"platform"`          // h1 | bc | ywh | it | ...
	Program   string   `json:"program"`           // handle
	Via       string   `json:"via"`               // api | manual
	Account   string   `json:"account,omitempty"` // label it will submit from
	Options   []string `json:"account_options,omitempty"`
	Title     string   `json:"title"`
	Severity  string   `json:"severity,omitempty"`
	Body      string   `json:"body"`          // the report markdown to file
	URL       string   `json:"url,omitempty"` // manual: the submission page
	CanSubmit bool     `json:"can_submit"`    // an API submit is possible now
	Blocker   string   `json:"blocker,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// submitReportBody is the finding's report: its own markdown, else the AI draft.
func submitReportBody(f *db.Finding) string {
	if s := strings.TrimSpace(f.ReportMD); s != "" {
		return s
	}
	if f.AI != nil {
		return strings.TrimSpace(f.AI.ReportMD)
	}
	return ""
}

// h1Severity maps a finding severity to a HackerOne severity_rating, or "".
func h1Severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low":
		return strings.ToLower(s)
	case "info", "informational", "none":
		return "none"
	}
	return ""
}

// pickSubmitAccount chooses which account files the report: the one explicitly
// chosen, else the single account that can see the program, else (when the
// program's visibility is unknown, e.g. public) the single configured account.
// A non-empty options slice means the operator must choose.
func pickSubmitAccount(platform string, visible []string, chosen string) (acct accounts.Account, options []string, err error) {
	accts := accounts.For(platform)
	byLabel := map[string]accounts.Account{}
	labels := make([]string, 0, len(accts))
	for _, a := range accts {
		byLabel[a.Label] = a
		labels = append(labels, a.Label)
	}
	if len(accts) == 0 {
		return accounts.Account{}, nil, fmt.Errorf("no %s account configured — add one in Settings", platform)
	}
	if chosen != "" {
		if a, ok := byLabel[chosen]; ok {
			return a, nil, nil
		}
		return accounts.Account{}, nil, fmt.Errorf("no %s account labelled %q", platform, chosen)
	}
	var canSee []string
	for _, l := range visible {
		if _, ok := byLabel[l]; ok {
			canSee = append(canSee, l)
		}
	}
	switch {
	case len(canSee) == 1:
		return byLabel[canSee[0]], nil, nil
	case len(canSee) > 1:
		return accounts.Account{}, canSee, nil
	case len(accts) == 1:
		return accts[0], nil, nil
	default:
		return accounts.Account{}, labels, nil
	}
}

// buildSubmitPreview assembles the preview for a finding (no side effects).
func buildSubmitPreview(f *db.Finding, chosen string) submitPreview {
	p := submitPreview{
		FindingID: f.ID, Platform: f.Platform, Program: f.Program,
		Title: f.Title, Severity: f.Severity, Body: submitReportBody(f),
	}
	if p.Platform == "" && f.AI != nil && f.AI.ScopeProgram != "" {
		p.Platform, p.Program = db.ProgramOf(f.AI.ScopeProgram)
	}
	if p.Program == "" {
		p.Blocker = "no program on this finding — set one first"
		return p
	}
	if p.Body == "" {
		p.Blocker = "no report yet — draft the report first"
		return p
	}
	switch strings.ToLower(f.Status) {
	case "submitted", "resolved", "dup":
		p.Warnings = append(p.Warnings, "this finding is already marked "+f.Status)
	}
	// Account that can see it (fills program_url + program_accounts).
	attachProgramURLs(f)
	p.URL = f.ProgramURL
	if accounts.Canonical(p.Platform) == "h1" {
		p.Via = "api"
		acct, opts, err := pickSubmitAccount("h1", f.ProgramAccounts, chosen)
		switch {
		case err != nil:
			p.Blocker = err.Error()
		case len(opts) > 0:
			p.Options = opts
			p.Warnings = append(p.Warnings, "several accounts can see this program — choose one")
		default:
			p.Account = acct.Label
			p.CanSubmit = true
		}
		return p
	}
	// YWH / Bugcrowd / Intigriti: no one-click API submit here.
	p.Via = "manual"
	p.Warnings = append(p.Warnings, "no API submission for "+p.Platform+" — open the submission page and paste the report")
	return p
}

// submitToHackerOne files the report via the HackerOne hacker API and returns
// the new report URL.
func submitToHackerOne(a accounts.Account, program, title, body, severity string) (string, error) {
	if strings.TrimSpace(a.Username) == "" || strings.TrimSpace(a.Token) == "" {
		return "", errors.New("the HackerOne account has no username/API token")
	}
	attrs := map[string]any{"team_handle": program, "title": title, "vulnerability_information": body}
	if sr := h1Severity(severity); sr != "" {
		attrs["severity_rating"] = sr
	}
	payload := map[string]any{"data": map[string]any{"type": "report", "attributes": attrs}}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", h1APIBase+"/v1/hackers/reports", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(a.Username, a.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := submitHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HackerOne rejected the report (%d): %s", resp.StatusCode, h1ErrorMessage(b))
	}
	var out struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				URL string `json:"url"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Data.ID == "" {
		return "", fmt.Errorf("HackerOne returned no report id: %s", clipText(string(b), 300))
	}
	if out.Data.Attributes.URL != "" {
		return out.Data.Attributes.URL, nil
	}
	return "https://hackerone.com/reports/" + out.Data.ID, nil
}

// h1ErrorMessage pulls the detail out of a HackerOne JSON:API error body.
func h1ErrorMessage(b []byte) string {
	var e struct {
		Errors []struct {
			Title  string `json:"title"`
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if json.Unmarshal(b, &e) == nil && len(e.Errors) > 0 {
		msg := e.Errors[0].Detail
		if msg == "" {
			msg = e.Errors[0].Title
		}
		if msg != "" {
			return clipText(msg, 300)
		}
	}
	return clipText(string(b), 300)
}

// GET /api/findings/:id/submit — the submission preview (no side effects).
func apiFindingSubmitPreview(c *gin.Context) {
	f, ok := findingFromParam(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, buildSubmitPreview(f, strings.TrimSpace(c.Query("account"))))
}

// POST /api/findings/:id/submit {account_label} — file the report. Admin only;
// only the API platforms (HackerOne) submit here.
func apiFindingSubmit(c *gin.Context) {
	f, ok := findingFromParam(c)
	if !ok {
		return
	}
	var body struct {
		AccountLabel string `json:"account_label"`
	}
	_ = c.ShouldBindJSON(&body)
	p := buildSubmitPreview(f, strings.TrimSpace(body.AccountLabel))
	if p.Blocker != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": p.Blocker})
		return
	}
	if len(p.Options) > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "choose an account", "account_options": p.Options})
		return
	}
	if p.Via != "api" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no API submission for " + p.Platform + " — use the submission page", "url": p.URL, "via": "manual"})
		return
	}
	acct, _, err := pickSubmitAccount("h1", f.ProgramAccounts, strings.TrimSpace(body.AccountLabel))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	url, err := submitToHackerOne(acct, p.Program, p.Title, p.Body, p.Severity)
	if err != nil {
		audit(c, "finding.submit", fmt.Sprintf("#%d %s/%s", f.ID, p.Platform, p.Program), "failed: "+err.Error())
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	if err := db.UpdateFindingStatus(f.ID, "submitted", url, ""); err != nil {
		// The report WAS filed — report the URL even if the status save failed.
		logger.GetLogger().Infof("[SUBMIT] finding %d filed to %s but status save failed: %v", f.ID, url, err)
	}
	audit(c, "finding.submit", fmt.Sprintf("#%d %s/%s as %s", f.ID, p.Platform, p.Program, acct.Label), url)
	utils.SendMonitorWebhook(fmt.Sprintf("📤 **Report submitted** — #%d %s on `%s` filed to %s as `%s`\n%s",
		f.ID, utils.DiscordEscapeTrunc(f.Title, 120), utils.DiscordEscapeTrunc(p.Program, 80), strings.ToUpper(p.Platform), utils.DiscordEscapeTrunc(acct.Label, 40), url))
	c.JSON(http.StatusOK, gin.H{"submitted": true, "url": url, "status": "submitted", "account": acct.Label})
}
