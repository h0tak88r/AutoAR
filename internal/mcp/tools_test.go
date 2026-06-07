package mcp

import (
	"testing"
)

func TestExtractFinding_Trufflehog(t *testing.T) {
	v := map[string]interface{}{
		"DetectorName": "AWS Key",
		"Verified":     "true",
		"Target":       "github.com/org/repo",
		"severity":     "critical",
	}
	sev, target, finding := extractFinding(v, "")
	if sev != "critical" {
		t.Errorf("expected critical, got %s", sev)
	}
	if target != "github.com/org/repo" {
		t.Errorf("expected github.com/org/repo, got %s", target)
	}
	if finding != "AWS Key" {
		t.Errorf("expected AWS Key, got %s", finding)
	}
}

func TestExtractFinding_CF1016(t *testing.T) {
	v := map[string]interface{}{
		"target":        "sub.example.com",
		"cloudflare_ips": []interface{}{"1.1.1.1", "2.2.2.2"},
		"severity":      "high",
	}
	sev, target, finding := extractFinding(v, "")
	if sev != "high" {
		t.Errorf("expected high, got %s", sev)
	}
	if target != "sub.example.com" {
		t.Errorf("expected sub.example.com, got %s", target)
	}
	if finding != "Dangling Record (CF-1016)" {
		t.Errorf("expected Dangling Record, got %s", finding)
	}
}

func TestExtractFinding_DNSTakeover(t *testing.T) {
	v := map[string]interface{}{
		"type":   "aws-takeover",
		"target": "vuln.example.com",
		"status": "vulnerable",
	}
	sev, target, finding := extractFinding(v, "")
	if sev != "medium" {
		t.Errorf("expected medium, got %s", sev)
	}
	if target != "vuln.example.com" {
		t.Errorf("expected vuln.example.com, got %s", target)
	}
	if finding != "AWS Takeover [vulnerable]" {
		t.Errorf("expected AWS Takeover [vulnerable], got %s", finding)
	}
}

func TestExtractFinding_FFUF(t *testing.T) {
	v := map[string]interface{}{
		"module":      "ffuf-fuzzing",
		"url":         "https://example.com/FUZZ",
		"word":        "admin",
		"status_code": float64(200),
	}
	sev, target, finding := extractFinding(v, "")
	if sev != "info" {
		t.Errorf("expected info, got %s", sev)
	}
	if target != "https://example.com/FUZZ" {
		t.Errorf("expected https://example.com/FUZZ, got %s", target)
	}
	expected := "ffuf: admin"
	if finding != expected {
		t.Errorf("expected %q, got %s", expected, finding)
	}
}

func TestExtractFinding_JSSecret(t *testing.T) {
	v := map[string]interface{}{
		"type":     "api-key",
		"secret":   "sk-1234",
		"file":     "/js/app.js",
		"severity": "high",
	}
	sev, target, finding := extractFinding(v, "")
	if sev != "high" {
		t.Errorf("expected high, got %s", sev)
	}
	if target != "/js/app.js" {
		t.Errorf("expected /js/app.js, got %s", target)
	}
	if finding != "[api-key]: sk-1234" {
		t.Errorf("expected [api-key]: sk-1234, got %s", finding)
	}
}

func TestExtractFinding_Subdomain(t *testing.T) {
	v := map[string]interface{}{
		"subdomain": "admin.example.com",
	}
	sev, target, _ := extractFinding(v, "")
	if sev != "info" {
		t.Errorf("expected info, got %s", sev)
	}
	if target != "admin.example.com" {
		t.Errorf("expected admin.example.com, got %s", target)
	}
}

func TestExtractFinding_Generic(t *testing.T) {
	v := map[string]interface{}{
		"matched-at": "https://example.com/admin",
		"severity":   "medium",
		"finding":    "Admin panel detected",
	}
	sev, target, finding := extractFinding(v, "")
	if sev != "medium" {
		t.Errorf("expected medium, got %s", sev)
	}
	if target != "https://example.com/admin" {
		t.Errorf("expected https://example.com/admin, got %s", target)
	}
	if finding != "Admin panel detected" {
		t.Errorf("expected Admin panel detected, got %s", finding)
	}
}

func TestInferModuleFromName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"nuclei-results.json", "nuclei"},
		{"cf1016-vulnerabilities.json", "cf1016"},
		{"all-subs.txt", "subdomain-enum"},
		{"httpx-live.txt", "httpx"},
		{"gf-ssrf.json", "gf-patterns"},
		{"ffuf-results.json", "ffuf-fuzzing"},
		{"reflection-findings.json", "reflection"},
		{"js-endpoints.json", "js-endpoints"},
		{"js-secrets.json", "js-analysis"},
		{"backup-files.txt", "backup-detection"},
		{"urls.json", "url-collection"},
		{"tech-detect.json", "tech-detect"},
		{"port-scan.json", "port-scan"},
		{"bucket-scan.json", "s3-scan"},
		{"unknown-file.txt", "autoar"},
		{"trufflehog-secrets.json", "github-scan"},
		{"zeroday-cve.json", "zerodays"},
		{"takeover-dns.json", "dns-takeover"},
		{"confusion-test.json", "dependency-confusion"},
		{"dalfox-xss.json", "xss-detection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferModuleFromName(tt.name)
			if got != tt.expected {
				t.Errorf("inferModuleFromName(%q) = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

func TestInferCategoryFromName(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"nuclei-results.json", "vulnerability"},
		{"cf1016-vulnerabilities.json", "vulnerability"},
		{"gf-ssrf.json", "vulnerability"},
		{"all-subs.txt", "recon"},
		{"httpx-live.txt", "recon"},
		{"urls.json", "recon"},
		{"tech-detect.json", "recon"},
		{"ffuf-results.json", "vulnerability"},
		{"reflection.json", "vulnerability"},
		{"secret-findings.json", "vulnerability"},
		{"port-scan.txt", "recon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferCategoryFromName(tt.name)
			if got != tt.expected {
				t.Errorf("inferCategoryFromName(%q) = %q, want %q", tt.name, got, tt.expected)
			}
		})
	}
}

func TestFormatJSONContent_Array(t *testing.T) {
	data := []byte(`[{"id":1,"name":"test"},{"id":2,"name":"test2"}]`)
	result, err := formatJSONContent(data, 1, 1)
	if err != nil {
		t.Fatalf("formatJSONContent failed: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestFormatJSONContent_ObjectWithArray(t *testing.T) {
	data := []byte(`{"findings":[{"severity":"high","target":"test.com"}]}`)
	result, err := formatJSONContent(data, 1, 10)
	if err != nil {
		t.Fatalf("formatJSONContent failed: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestFormatJSONContent_Invalid(t *testing.T) {
	data := []byte(`{bad json`)
	result, err := formatJSONContent(data, 1, 10)
	if err != nil {
		t.Fatalf("formatJSONContent failed: %v", err)
	}
	if result == "" {
		t.Error("expected non-empty result")
	}
}

func TestParseFindings_JSONArray(t *testing.T) {
	data := []byte(`[{"severity":"high","target":"test.com","finding":"XSS found"}]`)
	results := parseFindings(data, "nuclei-results.json", 100)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Severity != "high" {
		t.Errorf("expected high, got %s", results[0].Severity)
	}
	if results[0].Target != "test.com" {
		t.Errorf("expected test.com, got %s", results[0].Target)
	}
}

func TestParseFindings_JSONL(t *testing.T) {
	data := []byte("{\"severity\":\"high\",\"target\":\"test.com\",\"finding\":\"XSS found\"}\n{\"severity\":\"low\",\"target\":\"test2.com\",\"finding\":\"Info leak\"}")
	results := parseFindings(data, "nuclei.jsonl", 100)
	if len(results) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(results), results)
	}
}

func TestParseFindings_ObjectWithArray(t *testing.T) {
	data := []byte(`{"findings":[{"severity":"critical","target":"vuln.com","finding":"RCE"}]}`)
	results := parseFindings(data, "test.json", 100)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Severity != "critical" {
		t.Errorf("expected critical, got %s", results[0].Severity)
	}
	if results[0].Target != "vuln.com" {
		t.Errorf("expected vuln.com, got %s", results[0].Target)
	}
	if results[0].Finding != "RCE" {
		t.Errorf("expected RCE, got %s", results[0].Finding)
	}
}

func TestParseFindings_CF1016(t *testing.T) {
	data := []byte(`[{"target":"sub.example.com","cloudflare_ips":["1.1.1.1"],"severity":"high"}]`)
	results := parseFindings(data, "cf1016-vulnerabilities.json", 100)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
	if results[0].Severity != "high" {
		t.Errorf("expected high, got %s", results[0].Severity)
	}
	if results[0].Target != "sub.example.com" {
		t.Errorf("expected sub.example.com, got %s", results[0].Target)
	}
}

func TestParseFindings_EmptyZeroDays(t *testing.T) {
	data := []byte(`{"TotalVulnerable":0}`)
	results := parseFindings(data, "zerodays.json", 100)
	if len(results) != 0 {
		t.Errorf("expected 0 findings for empty ZeroDays, got %d", len(results))
	}
}

func TestParseFindings_ZeroDaysWithResults(t *testing.T) {
	data := []byte(`{"TotalVulnerable":1,"React2ShellVulns":[{"severity":"critical","target":"test.com","finding":"RCE"}]}`)
	results := parseFindings(data, "zerodays.json", 100)
	if len(results) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(results))
	}
}

func TestFirstOf(t *testing.T) {
	tests := []struct {
		vals []string
		want string
	}{
		{[]string{"", "hello", "world"}, "hello"},
		{[]string{"<nil>", "", "real"}, "real"},
		{[]string{"", "", ""}, ""},
		{[]string{"first", "second"}, "first"},
		{[]string{"<nil>", "second"}, "second"},
	}
	for _, tt := range tests {
		got := firstOf(tt.vals...)
		if got != tt.want {
			t.Errorf("firstOf(%v) = %q, want %q", tt.vals, got, tt.want)
		}
	}
}

func TestTruncStr(t *testing.T) {
	if s := truncStr("hello", 10); s != "hello" {
		t.Errorf("expected hello, got %s", s)
	}
	if s := truncStr("hello world", 5); s != "hello..." {
		t.Errorf("expected hello..., got %s", s)
	}
}

func TestScanTypeLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nuclei", "Nuclei"},
		{"dns_cf1016", "CF1016 Dangling"},
		{"reflection", "Reflection"},
		{"unknown-type", "unknown-type"},
		{"", ""},
	}
	for _, tt := range tests {
		got := scanTypeLabel(tt.input)
		if got != tt.want {
			t.Errorf("scanTypeLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsScanFindingType(t *testing.T) {
	if !isScanFindingType("nuclei") {
		t.Error("expected nuclei to be finding type")
	}
	if !isScanFindingType("dns_cf1016") {
		t.Error("expected dns_cf1016 to be finding type")
	}
	if isScanFindingType("subdomain_run") {
		t.Error("expected subdomain_run NOT to be finding type")
	}
	if isScanFindingType("") {
		t.Error("expected empty NOT to be finding type")
	}
}

func TestGetStr(t *testing.T) {
	args := map[string]interface{}{
		"name":  "test",
		"empty": "",
		"num":   42,
	}
	if got := getStr(args, "name"); got != "test" {
		t.Errorf("expected test, got %s", got)
	}
	if got := getStr(args, "empty"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
	if got := getStr(args, "missing"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
	if got := getStr(args, "num"); got != "42" {
		t.Errorf("expected 42, got %s", got)
	}
}

func TestGetNum(t *testing.T) {
	args := map[string]interface{}{
		"int":   float64(42),
		"str":   "100",
		"zero":  0,
		"empty": "",
	}
	if got := getNum(args, "int", 10); got != 42 {
		t.Errorf("expected 42, got %d", got)
	}
	if got := getNum(args, "str", 10); got != 100 {
		t.Errorf("expected 100, got %d", got)
	}
	if got := getNum(args, "missing", 10); got != 10 {
		t.Errorf("expected 10 (default), got %d", got)
	}
}

func TestFmtBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
	}
	for _, tt := range tests {
		got := fmtBytes(tt.n)
		if got != tt.want {
			t.Errorf("fmtBytes(%d) = %s, want %s", tt.n, got, tt.want)
		}
	}
}
