package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

type mcpFinding struct {
	Severity    string
	Target      string
	Finding     string
	SeverityVal int
}

type mcpResult struct {
	ScanID   string
	Target   string
	Finding  string
	Severity string
}

func (s *Server) registerTools() {
	s.registerTool(Tool{
		Name:        "list_scans",
		Description: "List recent scans. Returns scan_id, type, target, status, findings count, and timestamps.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]property{
				"limit":  {Type: "number", Description: "Max scans to return (default 20)"},
				"status": {Type: "string", Description: "Filter by status: running, completed, failed, cancelled"},
			},
		},
	}, s.listScans)

	s.registerTool(Tool{
		Name:        "get_scan",
		Description: "Get full details for a specific scan by ID.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]property{
				"scan_id": {Type: "string", Description: "The scan ID to look up (required)"},
			},
			Required: []string{"scan_id"},
		},
	}, s.getScan)

	s.registerTool(Tool{
		Name:        "list_scan_files",
		Description: "List all result files for a scan. Returns file names, sizes, module, and category.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]property{
				"scan_id": {Type: "string", Description: "The scan ID (required)"},
			},
			Required: []string{"scan_id"},
		},
	}, s.listScanFiles)

	s.registerTool(Tool{
		Name:        "get_file_content",
		Description: "Read the content of a result file from a scan. Supports text and JSON files with pagination.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]property{
				"scan_id":   {Type: "string", Description: "The scan ID (required)"},
				"file_name": {Type: "string", Description: "Name of the file to read (required)"},
				"page":      {Type: "number", Description: "Page number for pagination (default 1)"},
				"per_page":  {Type: "number", Description: "Items per page (default 50, max 500)"},
			},
			Required: []string{"scan_id", "file_name"},
		},
	}, s.getFileContent)

	s.registerTool(Tool{
		Name:        "list_findings",
		Description: "Get parsed findings for a scan. Extracts vulnerabilities, URLs, secrets and other results from all result files.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]property{
				"scan_id":  {Type: "string", Description: "The scan ID (required)"},
				"limit":    {Type: "number", Description: "Max findings to return (default 200, max 1000)"},
				"severity": {Type: "string", Description: "Filter by severity: critical, high, medium, low, info"},
			},
			Required: []string{"scan_id"},
		},
	}, s.listFindings)

	s.registerTool(Tool{
		Name:        "search_findings",
		Description: "Search across all scans for findings matching a query.",
		InputSchema: inputSchema{
			Type: "object",
			Properties: map[string]property{
				"query": {Type: "string", Description: "Search term (required)"},
				"limit": {Type: "number", Description: "Max results (default 50)"},
			},
			Required: []string{"query"},
		},
	}, s.searchFindings)
}

// ---- helpers ----

func scanTypeLabel(t string) string {
	m := map[string]string{
		"domain_run":             "Domain Recon",
		"subdomain_run":          "Subdomain Recon",
		"nuclei":                 "Nuclei",
		"nuclei-full":            "Nuclei Full",
		"nuclei-cves":            "Nuclei CVEs",
		"nuclei-panels":          "Nuclei Panels",
		"nuclei-vulnerabilities": "Nuclei Vulnerabilities",
		"nuclei-default-logins":  "Nuclei Default Logins",
		"dns_cf1016":             "CF1016 Dangling",
		"dns-cf1016":             "CF1016 Dangling",
		"dns-takeover":           "DNS Takeover",
		"misconfig":              "Misconfig",
		"s3":                     "S3 Scan",
		"github":                 "GitHub Scan",
		"reflection":             "Reflection",
		"gf":                     "GF Patterns",
		"ffuf":                   "FFUF Fuzzing",
		"sqlmap":                 "SQLMap",
		"backup":                 "Backup Detection",
		"zerodays":               "ZeroDays",
		"mcp-discovery":          "MCP Discovery",
	}
	if l, ok := m[strings.ToLower(t)]; ok {
		return l
	}
	return t
}

func isScanFindingType(scanType string) bool {
	for _, ft := range []string{"dns_cf1016", "dns-cf1016", "dns", "dns-takeover", "dns-dangling-ip",
		"nuclei", "nuclei-full", "nuclei-cves", "nuclei-panels", "nuclei-vulnerabilities",
		"nuclei-default-logins", "misconfig", "s3", "github", "reflection",
		"zerodays", "jwt", "gf", "ffuf", "sqlmap", "backup", "mcp-discovery"} {
		if strings.EqualFold(scanType, ft) {
			return true
		}
	}
	return false
}

func findingIcon(scanType string) string {
	if isScanFindingType(scanType) {
		return "\U0001f3af"
	}
	return "\U0001f4c1"
}

func getStr(args map[string]interface{}, key string) string {
	v, ok := args[key]
	if !ok {
		return ""
	}
	switch s := v.(type) {
	case string:
		return strings.TrimSpace(s)
	default:
		return strings.TrimSpace(fmt.Sprint(s))
	}
}

func getNum(args map[string]interface{}, key string, def int) int {
	v, ok := args[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return def
}

func fmtBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
	}
}

// ---- Tool handlers ----

func (s *Server) listScans(args map[string]interface{}) (string, error) {
	limit := getNum(args, "limit", 20)
	if limit < 1 || limit > 100 {
		limit = 20
	}

	scans, err := db.ListRecentScans(limit)
	if err != nil {
		return "", fmt.Errorf("failed to list scans: %w", err)
	}
	if len(scans) == 0 {
		return "No scans found.", nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d scan(s):\n\n", len(scans))
	for _, sc := range scans {
		if sc == nil {
			continue
		}
		icon := findingIcon(sc.ScanType)
		label := scanTypeLabel(sc.ScanType)
		fl := "findings"
		if !isScanFindingType(sc.ScanType) {
			fl = "files"
		}
		fmt.Fprintf(&b, "  %s %s (%s)\n", icon, sc.ScanID, label)
		fmt.Fprintf(&b, "     Target: %s | Status: %s | %d %s | Started: %s\n",
			sc.Target, sc.Status, sc.FilesUploaded, fl,
			sc.StartedAt.Format("2006-01-02 15:04"))
		if sc.CompletedAt != nil && !sc.CompletedAt.IsZero() {
			d := sc.CompletedAt.Sub(sc.StartedAt).Round(time.Second)
			fmt.Fprintf(&b, "     Duration: %s\n", d)
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func (s *Server) getScan(args map[string]interface{}) (string, error) {
	scanID := getStr(args, "scan_id")
	if scanID == "" {
		return "", fmt.Errorf("scan_id is required")
	}

	rec, err := db.GetScan(scanID)
	if err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	artifacts, _ := db.ListScanArtifacts(scanID)
	var totalSize int64
	for _, a := range artifacts {
		if a != nil {
			totalSize += a.SizeBytes
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s Scan: %s\n", findingIcon(rec.ScanType), rec.ScanID)
	fmt.Fprintf(&b, "  Type:       %s\n", scanTypeLabel(rec.ScanType))
	fmt.Fprintf(&b, "  Target:     %s\n", rec.Target)
	fmt.Fprintf(&b, "  Status:     %s\n", rec.Status)
	fmt.Fprintf(&b, "  Started:    %s\n", rec.StartedAt.Format("2006-01-02 15:04:05 MST"))
	if rec.CompletedAt != nil && !rec.CompletedAt.IsZero() {
		d := rec.CompletedAt.Sub(rec.StartedAt).Round(time.Second)
		fmt.Fprintf(&b, "  Completed:  %s (duration: %s)\n", rec.CompletedAt.Format("2006-01-02 15:04:05 MST"), d)
	}
	fmt.Fprintf(&b, "  Phase:      %d/%d %s\n", rec.CurrentPhase, rec.TotalPhases, rec.PhaseName)
	fmt.Fprintf(&b, "  Findings:   %d\n", rec.FilesUploaded)
	fmt.Fprintf(&b, "  Errors:     %d\n", rec.ErrorCount)
	fmt.Fprintf(&b, "  Artifacts:  %d files (%s)\n", len(artifacts), fmtBytes(totalSize))
	if rec.Command != "" {
		fmt.Fprintf(&b, "  Command:    %s\n", rec.Command)
	}
	if len(rec.CompletedPhases) > 0 {
		fmt.Fprintf(&b, "  Phases done: %s\n", strings.Join(rec.CompletedPhases, ", "))
	}
	if len(rec.FailedPhases) > 0 {
		fmt.Fprintf(&b, "  Phases failed: %s\n", strings.Join(rec.FailedPhases, ", "))
	}
	return b.String(), nil
}

func (s *Server) listScanFiles(args map[string]interface{}) (string, error) {
	scanID := getStr(args, "scan_id")
	if scanID == "" {
		return "", fmt.Errorf("scan_id is required")
	}
	if _, err := db.GetScan(scanID); err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	artifacts, err := db.ListScanArtifacts(scanID)
	if err != nil {
		return "", fmt.Errorf("failed to list artifacts: %w", err)
	}

	localFiles := listLocalResultFiles(scanID)

	type fi struct {
		Name     string
		Size     int64
		Module   string
		Category string
		Source   string
	}
	merged := make(map[string]fi)
	for _, f := range localFiles {
		merged[f.Name] = fi{
			Name: f.Name, Size: f.Size,
			Module:   inferModuleFromName(f.Name),
			Category: inferCategoryFromName(f.Name),
			Source:   "local",
		}
	}
	for _, a := range artifacts {
		if a == nil {
			continue
		}
		base := filepath.Base(a.FileName)
		src := "db"
		if a.PublicURL != "" {
			src = "r2"
		}
		merged[base] = fi{
			Name: base, Size: a.SizeBytes,
			Module: a.Module, Source: src,
		}
	}

	if len(merged) == 0 {
		return "No result files found.", nil
	}

	byModule := make(map[string][]fi)
	for _, f := range merged {
		mod := f.Module
		if mod == "" {
			mod = "other"
		}
		byModule[mod] = append(byModule[mod], f)
	}
	mods := make([]string, 0, len(byModule))
	for m := range byModule {
		mods = append(mods, m)
	}
	sort.Strings(mods)

	var b strings.Builder
	fmt.Fprintf(&b, "%d file(s):\n\n", len(merged))
	for _, mod := range mods {
		entries := byModule[mod]
		fmt.Fprintf(&b, "  [%s] (%d files)\n", mod, len(entries))
		for _, e := range entries {
			fmt.Fprintf(&b, "    %-40s %-8s  %s\n", e.Name, fmtBytes(e.Size), e.Source)
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func (s *Server) getFileContent(args map[string]interface{}) (string, error) {
	scanID := getStr(args, "scan_id")
	fileName := getStr(args, "file_name")
	if scanID == "" || fileName == "" {
		return "", fmt.Errorf("scan_id and file_name are required")
	}
	page := getNum(args, "page", 1)
	perPage := getNum(args, "per_page", 50)
	if perPage > 500 {
		perPage = 500
	}
	if page < 1 {
		page = 1
	}

	if _, err := db.GetScan(scanID); err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	scanDir := utils.GetScanResultsDir(scanID)
	fileName = filepath.Base(fileName)
	filePath := filepath.Join(scanDir, fileName)

	raw, err := os.ReadFile(filePath)
	if err != nil {
		artifacts, _ := db.ListScanArtifacts(scanID)
		for _, a := range artifacts {
			if a == nil {
				continue
			}
			if filepath.Base(a.FileName) == fileName && a.PublicURL != "" {
				return fmt.Sprintf("File available in R2:\n%s", a.PublicURL), nil
			}
		}
		return "", fmt.Errorf("file not found: %s", fileName)
	}

	if len(raw) == 0 {
		return "(empty file)", nil
	}
	if len(raw) > 5*1024*1024 {
		return fmt.Sprintf("File too large: %.1f MB. Download from the web UI.", float64(len(raw))/1024/1024), nil
	}

	if json.Valid(raw) && (raw[0] == '{' || raw[0] == '[') {
		return formatJSONContent(raw, page, perPage)
	}

	lines := strings.Split(string(raw), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	total := len(lines)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	var b strings.Builder
	fmt.Fprintf(&b, "File: %s (%d lines, %s)\n", fileName, total, fmtBytes(int64(len(raw))))
	if page > 1 || end < total {
		fmt.Fprintf(&b, "Showing lines %d-%d of %d\n", start+1, end, total)
	}
	for _, line := range lines[start:end] {
		b.WriteString(line + "\n")
	}
	if end < total {
		fmt.Fprintf(&b, "\n... %d more lines (use page=%d)\n", total-end, page+1)
	}
	return b.String(), nil
}

func (s *Server) listFindings(args map[string]interface{}) (string, error) {
	scanID := getStr(args, "scan_id")
	if scanID == "" {
		return "", fmt.Errorf("scan_id is required")
	}
	limit := getNum(args, "limit", 200)
	if limit > 1000 {
		limit = 1000
	}
	sevFilter := strings.ToLower(getStr(args, "severity"))

	if _, err := db.GetScan(scanID); err != nil {
		return "", fmt.Errorf("scan not found: %w", err)
	}

	scanDir := utils.GetScanResultsDir(scanID)
	var findings []mcpFinding

	entries, err := os.ReadDir(scanDir)
	if err != nil {
		return "", fmt.Errorf("no results directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || len(findings) >= limit {
			continue
		}
		name := entry.Name()
		low := strings.ToLower(name)

		// JSON files
		if strings.HasSuffix(low, ".json") {
			data, err := os.ReadFile(filepath.Join(scanDir, name))
			if err != nil || len(data) == 0 || len(data) > 5*1024*1024 {
				continue
			}
			findings = append(findings, parseFindings(data, name, limit)...)
			if len(findings) >= limit {
				findings = findings[:limit]
				break
			}
			continue
		}

		// TXT files — line-by-line
		if strings.HasSuffix(low, ".txt") {
			data, err := os.ReadFile(filepath.Join(scanDir, name))
			if err != nil || len(data) == 0 {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if sevFilter != "" && sevFilter != "info" && sevFilter != "all" {
					continue
				}
				findings = append(findings, mcpFinding{
					Severity: "info", Target: line, Finding: inferModuleFromName(name), SeverityVal: 4,
				})
				if len(findings) >= limit {
					break
				}
			}
		}
	}

	if sevFilter != "" {
		var filtered []mcpFinding
		for _, f := range findings {
			if strings.EqualFold(f.Severity, sevFilter) {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	if len(findings) == 0 {
		return "No findings found.", nil
	}

	sevOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "—": 5}
	sort.Slice(findings, func(i, j int) bool {
		si := sevOrder[strings.ToLower(findings[i].Severity)]
		sj := sevOrder[strings.ToLower(findings[j].Severity)]
		if si != sj {
			return si < sj
		}
		return findings[i].Target < findings[j].Target
	})

	var b strings.Builder
	fmt.Fprintf(&b, "%d finding(s):\n\n", len(findings))
	curSev := ""
	for _, f := range findings {
		sev := strings.ToUpper(f.Severity)
		if sev == "" || sev == "—" || sev == "<NIL>" {
			sev = "INFO"
		}
		if sev != curSev {
			fmt.Fprintf(&b, "  [%s]\n", sev)
			curSev = sev
		}
		t := f.Target
		if len(t) > 90 {
			t = t[:90] + "..."
		}
		fmt.Fprintf(&b, "    %s\n", t)
		if f.Finding != "" && f.Finding != "autoar" {
			fd := f.Finding
			if len(fd) > 70 {
				fd = fd[:70] + "..."
			}
			fmt.Fprintf(&b, "      %s\n", fd)
		}
	}
	return b.String(), nil
}

func (s *Server) searchFindings(args map[string]interface{}) (string, error) {
	query := strings.ToLower(getStr(args, "query"))
	if query == "" {
		return "", fmt.Errorf("query is required")
	}
	limit := getNum(args, "limit", 50)
	if limit > 200 {
		limit = 200
	}

	scans, err := db.ListRecentScans(100)
	if err != nil {
		return "", fmt.Errorf("failed to list scans: %w", err)
	}

	var results []mcpResult

	for _, sc := range scans {
		if sc == nil || len(results) >= limit {
			continue
		}
		scanDir := utils.GetScanResultsDir(sc.ScanID)
		entries, err := os.ReadDir(scanDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || len(results) >= limit {
				break
			}
			data, err := os.ReadFile(filepath.Join(scanDir, entry.Name()))
			if err != nil || len(data) == 0 || len(data) > 1024*1024 {
				continue
			}
			if !strings.Contains(strings.ToLower(string(data)), query) {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				if len(results) >= limit {
					break
				}
				if strings.Contains(strings.ToLower(line), query) {
					trunc := strings.TrimSpace(line)
					if len(trunc) > 150 {
						trunc = trunc[:150] + "..."
					}
					results = append(results, mcpResult{
						ScanID: sc.ScanID, Target: sc.Target, Finding: trunc, Severity: "info",
					})
				}
			}
		}
	}

	if len(results) == 0 {
		return fmt.Sprintf("No results matching %q.", query), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d result(s) matching %q:\n\n", len(results), query)
	for _, r := range results {
		fmt.Fprintf(&b, "  Scan: %s (%s)\n  %s\n\n", r.ScanID, r.Target, r.Finding)
	}
	return b.String(), nil
}

// ---- JSON/file helpers ----

func formatJSONContent(raw []byte, page, perPage int) (string, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 50
	}
	var top interface{}
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Sprintf("(invalid JSON: %s)\n\n%s", err, truncStr(string(raw), 2000)), nil
	}

	switch v := top.(type) {
	case []interface{}:
		total := len(v)
		start := (page - 1) * perPage
		if start > total {
			start = total
		}
		end := start + perPage
		if end > total {
			end = total
		}
		var b strings.Builder
		fmt.Fprintf(&b, "JSON Array — %d items (showing %d-%d):\n", total, start+1, end)
		for i, item := range v[start:end] {
			j, _ := json.MarshalIndent(item, "", "  ")
			fmt.Fprintf(&b, "[%d] %s\n\n", start+i+1, string(j))
		}
		if end < total {
			fmt.Fprintf(&b, "... %d more items\n", total-end)
		}
		return b.String(), nil

	case map[string]interface{}:
		for _, key := range []string{"results", "findings", "matches", "issues", "vulnerabilities", "data", "items", "React2ShellVulns", "MongoDBVulns"} {
			if arr, ok := v[key].([]interface{}); ok && len(arr) > 0 {
				total := len(arr)
				start := (page - 1) * perPage
				if start > total {
					start = total
				}
				end := start + perPage
				if end > total {
					end = total
				}
				var b strings.Builder
				fmt.Fprintf(&b, "Key %q — %d items (showing %d-%d):\n", key, total, start+1, end)
				for i, item := range arr[start:end] {
					j, _ := json.MarshalIndent(item, "", "  ")
					fmt.Fprintf(&b, "[%d] %s\n\n", start+i+1, string(j))
				}
				if end < total {
					fmt.Fprintf(&b, "... %d more items\n", total-end)
				}
				return b.String(), nil
			}
		}
		j, _ := json.MarshalIndent(v, "", "  ")
		return fmt.Sprintf("JSON Object:\n%s", string(j)), nil

	default:
		return fmt.Sprintf("JSON: %v", string(raw)), nil
	}
}

func parseFindings(data []byte, fileName string, maxResults int) []mcpFinding {
	var results []mcpFinding

	add := func(sev, target, finding string) {
		if len(results) >= maxResults {
			return
		}
		sv := 5
		switch strings.ToLower(sev) {
		case "critical":
			sv = 0
		case "high":
			sv = 1
		case "medium":
			sv = 2
		case "low":
			sv = 3
		case "info":
			sv = 4
		}
		results = append(results, mcpFinding{Severity: sev, Target: target, Finding: finding, SeverityVal: sv})
	}

	// JSONL (one JSON object per line)
	if strings.HasSuffix(strings.ToLower(fileName), ".jsonl") {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || (!strings.HasPrefix(line, "{") && !strings.HasPrefix(line, "[")) {
				continue
			}
			var obj map[string]interface{}
			if json.Unmarshal([]byte(line), &obj) == nil {
				sev, t, f := extractFinding(obj, "")
				add(sev, t, f)
				if len(results) >= maxResults {
					break
				}
			}
		}
		return results
	}

	var top interface{}
	if json.Unmarshal(data, &top) != nil {
		return results
	}

	var walk func(interface{})
	walk = func(x interface{}) {
		if len(results) >= maxResults {
			return
		}
		switch t := x.(type) {
		case map[string]interface{}:
			if tv, ok := t["TotalVulnerable"]; ok {
				if n, ok := tv.(float64); ok && n == 0 {
					return
				}
			}
			for _, key := range []string{"findings", "React2ShellVulns", "MongoDBVulns", "results", "matches", "issues", "vulnerabilities", "data", "items"} {
				if arr, ok := t[key].([]interface{}); ok && len(arr) > 0 {
					for _, it := range arr {
						walk(it)
						if len(results) >= maxResults {
							return
						}
					}
					return
				}
			}
			sev, tgt, fnd := extractFinding(t, "")
			add(sev, tgt, fnd)
		case []interface{}:
			for _, it := range t {
				walk(it)
				if len(results) >= maxResults {
					return
				}
			}
		}
	}
	walk(top)
	return results
}

func extractFinding(v map[string]interface{}, _ string) (severity, target, finding string) {
	// TruffleHog / GitHub secrets
	if v["DetectorName"] != nil || v["SourceMetadata"] != nil {
		d := firstOf(fmt.Sprint(v["DetectorName"]), fmt.Sprint(v["detector_name"]), "GitHub Secret")
		verified := fmt.Sprint(v["Verified"]) == "true" || fmt.Sprint(v["verified"]) == "true"
		sev := "medium"
		if verified {
			sev = "high"
		}
		if s := firstOf(fmt.Sprint(v["severity"]), fmt.Sprint(v["Severity"])); s != "" && s != "<nil>" {
			sev = s
		}
		t := firstOf(fmt.Sprint(v["Target"]), fmt.Sprint(v["target"]), "-")
		return sev, t, d
	}

	// CF1016 dangling
	if _, ok := v["cloudflare_ips"]; ok {
		t := firstOf(fmt.Sprint(v["target"]), fmt.Sprint(v["subdomain"]), "-")
		sev := firstOf(fmt.Sprint(v["severity"]), "high")
		return sev, t, "Dangling Record (CF-1016)"
	}

	// DNS takeover
	if t, ok := v["type"].(string); ok && v["target"] != nil {
		tgt := strings.TrimSpace(fmt.Sprint(v["target"]))
		status := strings.TrimSpace(fmt.Sprint(v["status"]))
		label := map[string]string{
			"dangling-ip": "Dangling IP", "azure-takeover": "Azure Takeover",
			"aws-takeover": "AWS Takeover", "ns-takeover": "NS Takeover",
			"cloudflare-tunnel": "Cloudflare Tunnel Error", "dns-takeover": "DNS Takeover",
		}[strings.ToLower(t)]
		if label == "" {
			label = t
		}
		if status != "" && status != "<nil>" {
			label += " [" + status + "]"
		}
		sev := "-"
		if strings.Contains(strings.ToLower(t), "takeover") || strings.Contains(strings.ToLower(t), "vulnerable") {
			sev = "medium"
		}
		return sev, tgt, label
	}

	// FFUF
	if strings.EqualFold(fmt.Sprint(v["module"]), "ffuf-fuzzing") {
		u := firstOf(fmt.Sprint(v["url"]), fmt.Sprint(v["matched-at"]), fmt.Sprint(v["matched_at"]))
		w := firstOf(fmt.Sprint(v["word"]), fmt.Sprint(v["path"]), "-")
		return "info", u, "ffuf: " + w
	}

	// JS Secrets
	if t, ok := v["type"].(string); ok && v["secret"] != nil && v["file"] != nil {
		sev := firstOf(fmt.Sprint(v["severity"]), "high")
		return sev, fmt.Sprint(v["file"]), fmt.Sprintf("[%s]: %s", t, v["secret"])
	}

	// Subdomain discovered
	if v["subdomain"] != nil {
		sub := strings.TrimSpace(fmt.Sprint(v["subdomain"]))
		if sub != "" && sub != "<nil>" {
			return firstOf(fmt.Sprint(v["severity"]), "info"), sub, "Subdomain discovered"
		}
	}

	// Generic object
	target = firstOf(
		fmt.Sprint(v["matched-at"]), fmt.Sprint(v["matched_at"]),
		fmt.Sprint(v["url"]), fmt.Sprint(v["host"]),
		fmt.Sprint(v["subdomain"]), fmt.Sprint(v["domain"]),
		fmt.Sprint(v["target"]), fmt.Sprint(v["ip"]),
	)
	if target == "<nil>" || target == "" {
		target = "-"
	}

	finding = firstOf(
		fmt.Sprint(v["finding"]), fmt.Sprint(v["template-id"]),
		fmt.Sprint(v["name"]), fmt.Sprint(v["severity"]),
	)
	if finding == "<nil>" || finding == "" {
		finding = "-"
	}

	severity = firstOf(fmt.Sprint(v["severity"]), fmt.Sprint(v["Severity"]), fmt.Sprint(v["level"]))
	if severity == "<nil>" || severity == "" {
		severity = "-"
	}

	if info, ok := v["info"].(map[string]interface{}); ok {
		if s := firstOf(fmt.Sprint(info["severity"])); s != "" && s != "<nil>" {
			severity = s
		}
		if f := firstOf(fmt.Sprint(info["name"]), fmt.Sprint(info["description"])); f != "" && f != "<nil>" && (finding == "-") {
			finding = f
		}
	}

	return severity, target, finding
}

func listLocalResultFiles(scanID string) []struct {
	Name string
	Size int64
} {
	scanDir := utils.GetScanResultsDir(scanID)
	entries, err := os.ReadDir(scanDir)
	if err != nil {
		return nil
	}
	var out []struct {
		Name string
		Size int64
	}
	for _, e := range entries {
		if !e.IsDir() {
			info, _ := e.Info()
			sz := int64(0)
			if info != nil {
				sz = info.Size()
			}
			out = append(out, struct {
				Name string
				Size int64
			}{Name: e.Name(), Size: sz})
		}
	}
	return out
}

func inferModuleFromName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(n, "cf1016") || strings.Contains(n, "cf-1016"):
		return "cf1016"
	case strings.Contains(n, "nuclei"):
		return "nuclei"
	case strings.Contains(n, "subdomain") || strings.Contains(n, "all-subs") || strings.Contains(n, "live-subs"):
		return "subdomain-enum"
	case strings.Contains(n, "httpx") || strings.Contains(n, "live-host"):
		return "httpx"
	case strings.Contains(n, "katana"):
		return "katana"
	case strings.Contains(n, "js-endpoint"):
		return "js-endpoints"
	// github scan before js-analysis (which also matches "secret")
	case strings.Contains(n, "github") || strings.Contains(n, "trufflehog") || strings.Contains(n, "secrets_table"):
		return "github-scan"
	case strings.Contains(n, "js-secret") || strings.Contains(n, "js-exposure") || (strings.Contains(n, "secret") && strings.HasSuffix(n, ".json")):
		return "js-analysis"
	case strings.HasPrefix(n, "gf-") || strings.Contains(n, "gf-"):
		return "gf-patterns"
	case strings.Contains(n, "misconfig"):
		return "misconfig"
	case strings.Contains(n, "zeroday") || strings.Contains(n, "cve"):
		return "zerodays"
	case strings.Contains(n, "ffuf") || strings.Contains(n, "fuzz"):
		return "ffuf-fuzzing"
	case strings.Contains(n, "bucket") || strings.Contains(n, "s3-"):
		return "s3-scan"
	case strings.Contains(n, "dns") || strings.Contains(n, "takeover") || strings.Contains(n, "dangling"):
		return "dns-takeover"
	case strings.Contains(n, "tech"):
		return "tech-detect"
	case strings.Contains(n, "port-scan") || strings.Contains(n, "ports") || strings.Contains(n, "nmap"):
		return "port-scan"
	case strings.Contains(n, "aem"):
		return "aem"
	case strings.Contains(n, "mcp-server") || strings.Contains(n, "mcp_discovery") || strings.Contains(n, "backup") || strings.Contains(n, "fuzzuli"):
		return "backup-detection"
	// dalfox before reflection (which matches "xss")
	case strings.Contains(n, "dalfox"):
		return "xss-detection"
	case strings.Contains(n, "reflection") || strings.Contains(n, "kxss") || strings.Contains(n, "xss"):
		return "reflection"
	case strings.Contains(n, "confusion"):
		return "dependency-confusion"
	case strings.Contains(n, "urls.txt") || strings.Contains(n, "urls.json") || strings.Contains(n, "all-url") || strings.Contains(n, "wayback") ||
		strings.Contains(n, "js-url") || strings.Contains(n, "jsurl"):
		return "url-collection"
	default:
		return "autoar"
	}
}

func inferCategoryFromName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if strings.Contains(n, "nuclei") || strings.HasPrefix(n, "gf-") || strings.Contains(n, "gf-") ||
		strings.Contains(n, "cf1016") || strings.Contains(n, "cf-1016") ||
		strings.Contains(n, "misconfig") || strings.Contains(n, "zeroday") ||
		strings.Contains(n, "dalfox") || strings.Contains(n, "ffuf") || strings.Contains(n, "sqlmap") || strings.Contains(n, "vuln") ||
		strings.Contains(n, "xss") || strings.Contains(n, "kxss") || strings.Contains(n, "reflection") ||
		strings.Contains(n, "secret") || strings.Contains(n, "exposure") || strings.Contains(n, "js-secret") ||
		strings.Contains(n, "takeover") || strings.Contains(n, "dangling") ||
		strings.Contains(n, "confusion") || strings.Contains(n, "aem") {
		return "vulnerability"
	}
	return "recon"
}

func firstOf(vals ...string) string {
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v != "" && v != "<nil>" {
			return v
		}
	}
	return ""
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
