package api

import (
	"testing"
)

func TestScanResultSizeBytesNil(t *testing.T) {
	if got := scanResultSizeBytes(nil); got != 0 {
		t.Errorf("scanResultSizeBytes(nil) = %d, want 0", got)
	}
}

func TestScanResultSizeBytesEmpty(t *testing.T) {
	r := &ScanResult{}
	if got := scanResultSizeBytes(r); got != 0 {
		t.Errorf("scanResultSizeBytes({}) = %d, want 0", got)
	}
}

func TestScanResultSizeBytesNonEmpty(t *testing.T) {
	r := &ScanResult{
		ScanID:   "abc-123",
		ScanType: "domain_run",
		Status:   "completed",
		Output:   "output data",
		Error:    "some error",
	}
	expected := int64(len(r.Output) + len(r.Error) + len(r.ScanID) + len(r.ScanType) + len(r.Status))
	if got := scanResultSizeBytes(r); got != expected {
		t.Errorf("scanResultSizeBytes() = %d, want %d", got, expected)
	}
}

func TestExtractScanTargetFromCommandEmpty(t *testing.T) {
	if got := extractScanTargetFromCommand(nil, "domain_run"); got != "" {
		t.Errorf("extractScanTargetFromCommand(nil) = %q, want empty", got)
	}
	if got := extractScanTargetFromCommand([]string{}, "domain_run"); got != "" {
		t.Errorf("extractScanTargetFromCommand([]) = %q, want empty", got)
	}
}

func TestExtractScanTargetFromCommandDomainShort(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-d", "example.com"}, "domain_run")
	if got != "example.com" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "example.com")
	}
}

func TestExtractScanTargetFromCommandDomainLong(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "--domain", "example.com"}, "domain_run")
	if got != "example.com" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "example.com")
	}
}

func TestExtractScanTargetFromCommandSubdomainShort(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-s", "sub.example.com"}, "subdomain_run")
	if got != "sub.example.com" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "sub.example.com")
	}
}

func TestExtractScanTargetFromCommandSubdomainLong(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "--subdomain", "sub.example.com"}, "subdomain_run")
	if got != "sub.example.com" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "sub.example.com")
	}
}

func TestExtractScanTargetFromCommandURL(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-u", "https://example.com"}, "url_scan")
	if got != "https://example.com" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "https://example.com")
	}
}

func TestExtractScanTargetFromCommandURNilValue(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-u", ""}, "url_scan")
	if got != "" {
		t.Errorf("extractScanTargetFromCommand() = %q, want empty", got)
	}
}

func TestExtractScanTargetFromCommandURLFirstArgOnly(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"-u"}, "url_scan")
	if got != "" {
		t.Errorf("extractScanTargetFromCommand() = %q, want empty", got)
	}
}

func TestExtractScanTargetFromCommandBucket(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-b", "my-bucket"}, "s3")
	if got != "my-bucket" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "my-bucket")
	}
}

func TestExtractScanTargetFromCommandRepo(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-r", "owner/repo"}, "github")
	if got != "owner/repo" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "owner/repo")
	}
}

func TestExtractScanTargetFromCommandOrg(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-o", "my-org"}, "github_org")
	if got != "my-org" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, "my-org")
	}
}

func TestExtractScanTargetFromCommandZerodays(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-f", "/data/zerodays.txt"}, "zerodays")
	want := "file:zerodays.txt"
	if got != want {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q", got, want)
	}
}

func TestExtractScanTargetFromCommandNoMatch(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "--verbose"}, "domain_run")
	if got != "" {
		t.Errorf("extractScanTargetFromCommand() = %q, want empty", got)
	}
}

func TestExtractScanTargetFromCommandDomainPriorityOverURL(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-d", "example.com", "-u", "https://other.com"}, "domain_run")
	if got != "example.com" {
		t.Errorf("extractScanTargetFromCommand() = %q, want %q (domain before url)", got, "example.com")
	}
}

func TestExtractScanTargetFromCommandBucketWrongScanType(t *testing.T) {
	got := extractScanTargetFromCommand([]string{"./autorecon", "-b", "my-bucket"}, "domain_run")
	if got != "" {
		t.Errorf("extractScanTargetFromCommand() = %q, want empty (bucket only valid for s3)", got)
	}
}

func TestTargetHostForR2PrefixesSimple(t *testing.T) {
	got := targetHostForR2Prefixes("example.com")
	if got != "example.com" {
		t.Errorf("targetHostForR2Prefixes() = %q, want %q", got, "example.com")
	}
}

func TestTargetHostForR2PrefixesWithHTTP(t *testing.T) {
	got := targetHostForR2Prefixes("http://example.com")
	if got != "example.com" {
		t.Errorf("targetHostForR2Prefixes() = %q, want %q", got, "example.com")
	}
}

func TestTargetHostForR2PrefixesWithHTTPS(t *testing.T) {
	got := targetHostForR2Prefixes("https://example.com")
	if got != "example.com" {
		t.Errorf("targetHostForR2Prefixes() = %q, want %q", got, "example.com")
	}
}

func TestTargetHostForR2PrefixesWithWWW(t *testing.T) {
	got := targetHostForR2Prefixes("www.example.com")
	if got != "example.com" {
		t.Errorf("targetHostForR2Prefixes() = %q, want %q", got, "example.com")
	}
}

func TestTargetHostForR2PrefixesWithPath(t *testing.T) {
	got := targetHostForR2Prefixes("https://www.example.com/path/to/page")
	if got != "example.com" {
		t.Errorf("targetHostForR2Prefixes() = %q, want %q", got, "example.com")
	}
}

func TestTargetHostForR2PrefixesCase(t *testing.T) {
	got := targetHostForR2Prefixes("WWW.EXAMPLE.COM")
	if got != "example.com" {
		t.Errorf("targetHostForR2Prefixes() = %q, want %q", got, "example.com")
	}
}

func TestTargetHostForR2PrefixesEmpty(t *testing.T) {
	got := targetHostForR2Prefixes("")
	if got != "" {
		t.Errorf("targetHostForR2Prefixes() = %q, want empty", got)
	}
}

func TestWorkflowScanR2Prefixes(t *testing.T) {
	got := workflowScanR2Prefixes("example.com")
	if len(got) != 4 {
		t.Errorf("workflowScanR2Prefixes() len = %d, want 4: %v", len(got), got)
	}
	expectedPrefixes := []string{
		"new-results/example.com/",
		"results/example.com/",
		"new-results/misconfig/example.com/",
		"misconfig/example.com/",
	}
	for _, want := range expectedPrefixes {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("workflowScanR2Prefixes() missing %q in %v", want, got)
		}
	}
}

func TestWorkflowScanR2PrefixesWithWWW(t *testing.T) {
	got := workflowScanR2Prefixes("www.example.com")
	// should normalize to example.com
	if len(got) < 1 || got[0] != "new-results/example.com/" {
		t.Errorf("workflowScanR2Prefixes() = %v, should use normalized host", got)
	}
}

func TestWorkflowScanR2PrefixesEmpty(t *testing.T) {
	got := workflowScanR2Prefixes("")
	if got != nil {
		t.Errorf("workflowScanR2Prefixes() = %v, want nil", got)
	}
}

func TestIsR2KeyIndexableArtifactSpecialFiles(t *testing.T) {
	if isR2KeyIndexableArtifact("scan-manifest.json") {
		t.Error("scan-manifest.json should not be indexable")
	}
	if isR2KeyIndexableArtifact("cache_info.json") {
		t.Error("cache_info.json should not be indexable")
	}
	if isR2KeyIndexableArtifact("report-table.json") {
		t.Error("report-table.json should not be indexable")
	}
}

func TestIsR2KeyIndexableArtifactLiteUploadsPrefix(t *testing.T) {
	if isR2KeyIndexableArtifact(".lite-uploads-somehash") {
		t.Error(".lite-uploads-* should not be indexable")
	}
}

func TestIsR2KeyIndexableArtifactTempPrefixes(t *testing.T) {
	if isR2KeyIndexableArtifact("temp-something.txt") {
		t.Error("temp-* should not be indexable")
	}
	if isR2KeyIndexableArtifact("dangling-ip-temp.json") {
		t.Error("dangling-ip-temp* should not be indexable")
	}
}

func TestIsR2KeyIndexableArtifactTempURL(t *testing.T) {
	if isR2KeyIndexableArtifact("temp-url.txt") {
		t.Error("temp-url.txt should not be indexable")
	}
	if isR2KeyIndexableArtifact("Temp-URL.txt") {
		t.Error("Temp-URL.txt should not be indexable (case-insensitive)")
	}
}

func TestIsR2KeyIndexableArtifactValidExtensions(t *testing.T) {
	validExts := []string{".txt", ".json", ".log", ".csv", ".html", ".md", ".bin", ".xml"}
	for _, ext := range validExts {
		t.Run(ext, func(t *testing.T) {
			if !isR2KeyIndexableArtifact("results/output" + ext) {
				t.Errorf("isR2KeyIndexableArtifact(output%s) should be true", ext)
			}
		})
	}
}

func TestIsR2KeyIndexableArtifactInvalidExtension(t *testing.T) {
	if isR2KeyIndexableArtifact("results/image.png") {
		t.Error("image.png should not be indexable")
	}
	if isR2KeyIndexableArtifact("results/video.mp4") {
		t.Error("video.mp4 should not be indexable")
	}
}

func TestIsR2KeyIndexableArtifactExtensionCaseInsensitive(t *testing.T) {
	if !isR2KeyIndexableArtifact("results/output.TXT") {
		t.Error("output.TXT should be indexable (case-insensitive extension)")
	}
	if !isR2KeyIndexableArtifact("results/output.JSON") {
		t.Error("output.JSON should be indexable (case-insensitive extension)")
	}
}

func TestShouldSkipArtifactManifestFiles(t *testing.T) {
	if !shouldSkipArtifact("scan-manifest.json") {
		t.Error("scan-manifest.json should be skipped")
	}
	if !shouldSkipArtifact("cache_info.json") {
		t.Error("cache_info.json should be skipped")
	}
	if !shouldSkipArtifact("report-table.json") {
		t.Error("report-table.json should be skipped")
	}
}

func TestShouldSkipArtifactByName(t *testing.T) {
	skipFiles := []string{
		"misconfig-scan-results.txt",
		"ffuf-results.txt",
		"kxss-results.txt",
		"exposure-findings.txt",
		"wp-confusion-results.txt",
		"js-secrets.txt",
		"nuclei-summary.txt",
		"all-subs.txt",
		"live-subs.txt",
		"live-hosts.txt",
		"all-urls.txt",
		"subdomains.txt",
		"enumerated-subs.txt",
		"urls.json",
		"js-urls.json",
		"subdomains.json",
		"ports.json",
		"livehosts.json",
		"cname-records.json",
	}
	for _, f := range skipFiles {
		t.Run(f, func(t *testing.T) {
			if !shouldSkipArtifact(f) {
				t.Errorf("shouldSkipArtifact(%q) should be true", f)
			}
		})
	}
}

func TestShouldSkipArtifactByNameCaseInsensitive(t *testing.T) {
	if !shouldSkipArtifact("NUCLEI-SUMMARY.TXT") {
		t.Error("shouldSkipArtifact should be case-insensitive")
	}
	if !shouldSkipArtifact("Js-Urls.json") {
		t.Error("shouldSkipArtifact should be case-insensitive")
	}
}

func TestShouldSkipArtifactAllowedFile(t *testing.T) {
	if shouldSkipArtifact("my-custom-results.txt") {
		t.Error("custom results file should not be skipped")
	}
	if shouldSkipArtifact("unique-output.json") {
		t.Error("unique output file should not be skipped")
	}
}
