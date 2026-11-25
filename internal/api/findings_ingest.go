package api

// Scan → Findings ingestion. When a scan finishes, its vulnerability hits
// become findings (one per hit across scans, keyed like the AI review), then
// the triage engine reviews the ones at or above the configured severity.
//
// Only confirmed-vulnerability modules feed Findings: nuclei, zerodays,
// misconfig, DNS takeover/dangling, secrets/exposure, dalfox/sqlmap,
// dependency confusion, backups, AEM, exposed MCP servers, open buckets and
// Firebase. Candidate lists (GF patterns, kxss/reflection, client-side sinks,
// ffuf) are URLs to test, not vulnerabilities, and stay on the scan page.

import (
	"encoding/json"
	"log"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/triage"
)

const maxNewFindingsPerScan = 2000

// ingestableVulnFile reports whether a non-nuclei result file holds
// confirmed findings (as opposed to candidates to test).
func ingestableVulnFile(name string) bool {
	n := strings.ToLower(filepath.Base(name))
	for _, skip := range []string{"nuclei", "gf-", "kxss", "reflection", "js-clientside", "ffuf", "fuzz"} {
		if strings.Contains(n, skip) {
			return false
		}
	}
	for _, ok := range []string{"zeroday", "misconfig", "takeover", "dangling", "dnsreap", "cf1016", "cf-1016",
		"exposure", "secret", "dalfox", "sqlmap", "depconf", "confusion", "backup", "aem", "mcp-server",
		"mcp_discovery", "aws-", "azure-", "gcp-", "bucket", "s3-", "firebase"} {
		if strings.Contains(n, ok) {
			return true
		}
	}
	return false
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(s string, max int) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > max {
		s = strings.Trim(s[:max], "-")
	}
	return s
}

// moduleOf names the module a result file came from.
func moduleOf(file, module string) string {
	n := strings.ToLower(filepath.Base(file))
	switch {
	case strings.Contains(n, "zeroday"):
		return "zerodays"
	case strings.Contains(n, "misconfig"):
		return "misconfig"
	case strings.Contains(n, "takeover"), strings.Contains(n, "dangling"), strings.Contains(n, "dnsreap"),
		strings.Contains(n, "cf1016"), strings.Contains(n, "cf-1016"):
		return "dns-takeover"
	case strings.Contains(n, "secret"), strings.Contains(n, "exposure"):
		return "exposure"
	case strings.Contains(n, "dalfox"):
		return "dalfox"
	case strings.Contains(n, "sqlmap"):
		return "sqlmap"
	case strings.Contains(n, "depconf"), strings.Contains(n, "confusion"):
		return "depconf"
	case strings.Contains(n, "mcp"):
		return "mcp-server"
	case strings.Contains(n, "bucket"), strings.Contains(n, "s3-"), strings.Contains(n, "aws-"),
		strings.Contains(n, "azure-"), strings.Contains(n, "gcp-"):
		return "buckets"
	case strings.Contains(n, "firebase"):
		return "firebase"
	case strings.Contains(n, "backup"):
		return "backup"
	case strings.Contains(n, "aem"):
		return "aem"
	}
	if m := strings.TrimSpace(module); m != "" && m != "autoar" {
		return m
	}
	return strings.TrimSuffix(n, filepath.Ext(n))
}

// findingFromRow turns one parsed (non-nuclei) result row into a triage
// finding. ok is false for rows with nothing to identify.
func findingFromRow(scanID string, r parsedFinding) (triage.Finding, bool) {
	title := strings.TrimSpace(firstNonEmptyStr(r.Finding, r.CategoryName))
	target := strings.TrimSpace(firstNonEmptyStr(r.Target, r.Path))
	if title == "" && target == "" {
		return triage.Finding{}, false
	}
	module := moduleOf(r.File, r.Module)
	if title == "" {
		title = module + " finding"
	}
	sev := triage.NormalizeSeverity(r.Severity)
	if sev == "unknown" || sev == "" {
		// Confirmed-vuln modules rarely grade themselves; medium puts them in
		// front of the AI, which assigns its own severity.
		sev = "medium"
	}
	f := triage.Finding{
		ScanID: scanID, TemplateID: module + ":" + slugify(title, 80), Name: clipStr(title, 200),
		Severity: sev, Host: db.HostOf(target), MatchedAt: target, Type: module,
		Description: clipStr(strings.TrimSpace(r.Context), 2000), Matcher: clipStr(r.MatcherValue, 300),
	}
	if v := strings.TrimSpace(r.Value); v != "" {
		f.Extracted = []string{clipStr(v, 500)}
	}
	if len(r.Raw) > 0 {
		if b, err := json.Marshal(r.Raw); err == nil {
			f.Response = clipStr(string(b), 6000) // the module's own record, shown to the AI as evidence
		}
	}
	if cve := db.FirstCVE(title, r.Context, r.Value); cve != "" {
		f.CVE = []string{cve}
	}
	return f, true
}

// ingestScanFindings records a finished scan's vulnerability hits as
// findings and returns them (for the AI review). includeInfo also takes
// info-level nuclei detections, which are skipped by default.
func ingestScanFindings(scanID string, includeInfo bool) ([]triage.Finding, int, error) {
	minSev := "low"
	if includeInfo {
		minSev = "info"
	}
	var all []triage.Finding
	seen := map[string]bool{}
	add := func(f triage.Finding) {
		if k := f.Key(); !seen[k] {
			seen[k] = true
			all = append(all, f)
		}
	}
	nucleiHits, err := collectScanFindings(scanID, minSev)
	if err != nil {
		log.Printf("[findings] %s: nuclei results: %v", scanID, err)
	}
	for _, f := range nucleiHits {
		add(f)
	}
	rows, err := collectParsedRows(scanID, "vulnerability", 20000)
	if err != nil {
		log.Printf("[findings] %s: parsed results: %v", scanID, err)
	}
	for _, r := range rows {
		if !ingestableVulnFile(r.File) {
			continue
		}
		if f, ok := findingFromRow(scanID, r); ok && triage.SeverityRank(f.Severity) >= triage.SeverityRank(minSev) {
			add(f)
		}
	}

	created := 0
	var kept []triage.Finding
	for _, f := range all {
		if created >= maxNewFindingsPerScan {
			break
		}
		host := db.HostOf(firstNonEmptyStr(f.Host, f.MatchedAt))
		hp := resolveHostProgramCached(host)
		module := f.Type
		if module == "" || module == "http" || module == "dns" || module == "network" || module == "ssl" {
			module = "nuclei"
		}
		ev, _ := json.Marshal(f)
		rec := &db.Finding{
			Title: clipStr(f.Title(), 300), CVE: db.FirstCVE(strings.Join(f.CVE, " "), f.TemplateID, f.Name),
			Host: host, Program: hp.Program, Platform: hp.Platform, ProgramMatch: hp.Match, Severity: f.Severity,
			Source: "scan:" + scanID, Status: "discovered",
			FKey: f.Key(), ScanID: scanID, Module: module, TemplateID: f.TemplateID, MatchedAt: f.MatchedAt,
			Evidence: string(ev),
		}
		isNew, err := db.RecordScanFinding(rec)
		if err != nil {
			log.Printf("[findings] %s: record %s: %v", scanID, f.TemplateID, err)
			continue
		}
		if isNew {
			created++
		}
		kept = append(kept, f)
	}
	return kept, created, nil
}

// findingForReview rebuilds the triage finding behind a stored finding. Scan
// findings carry it as evidence JSON; manual ones get a synthetic identity
// (and are linked to it) so their review joins like any other.
func findingForReview(f *db.Finding) (triage.Finding, error) {
	var tf triage.Finding
	if strings.TrimSpace(f.Evidence) != "" && json.Unmarshal([]byte(f.Evidence), &tf) == nil && tf.TemplateID != "" {
		if f.FKey == "" {
			f.FKey = tf.Key()
			if err := db.SetFindingFKey(f.ID, f.FKey); err != nil {
				return tf, err
			}
		}
		return tf, nil
	}
	tf = triage.Finding{
		ScanID: f.ScanID, TemplateID: "manual:" + strconv.FormatInt(f.ID, 10),
		Name: f.Title, Severity: triage.NormalizeSeverity(f.Severity), Host: f.Host,
		MatchedAt: firstNonEmptyStr(f.MatchedAt, f.Host), Description: clipStr(f.Notes, 4000), Type: "manual",
	}
	if tf.Severity == "unknown" || tf.Severity == "" {
		tf.Severity = "medium"
	}
	if f.CVE != "" {
		tf.CVE = []string{f.CVE}
	}
	if f.FKey == "" {
		f.FKey = tf.Key()
		if err := db.SetFindingFKey(f.ID, f.FKey); err != nil {
			return tf, err
		}
	}
	return tf, nil
}

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func clipStr(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
