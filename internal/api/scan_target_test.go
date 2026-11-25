package api

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateScanTarget(t *testing.T) {
	for _, ok := range []string{"example.com", "sub.example.com", "https://example.com/FUZZ", "owner/repo", "my-bucket_1", "example.com:8443"} {
		if err := validateScanTarget(ok); err != nil {
			t.Errorf("validateScanTarget(%q) = %v, want ok", ok, err)
		}
	}
	for _, bad := range []string{"", "../../../../app", "..", "a/../b", "/etc", `a\b`, "a\x00b", "a b", "x.com\n", strings.Repeat("a", maxScanTargetLen+1)} {
		if err := validateScanTarget(bad); err == nil {
			t.Errorf("validateScanTarget(%q) = nil, want an error", bad)
		}
	}
}

// TestArtifactIndexRootsStayInResults guards the indexer traversal: whatever
// the target, every root it walks must stay inside the results dir.
func TestArtifactIndexRootsStayInResults(t *testing.T) {
	results := filepath.Join(t.TempDir(), "new-results")
	types := []string{"subdomains", "domain_run", "misconfig", "s3", "github", "github_org", "dns-takeover", "dns_cf1016", "zerodays"}
	for _, target := range []string{"../../../../app", "../../../../..", "..", "/etc", `..\..\x`, "a/../../b"} {
		for _, st := range types {
			for _, root := range artifactIndexRoots(results, st, target) {
				if !pathWithin(results, root) || root == filepath.Clean(results) {
					t.Errorf("artifactIndexRoots(%q, %q) walks %q — outside (or all of) %q", st, target, root, results)
				}
			}
		}
	}
}

func TestArtifactIndexRootsMatchScannerLayout(t *testing.T) {
	results := "/r"
	cases := []struct {
		scanType, target, want string
	}{
		// githubscan writes github/repos/<SanitizeTargetSegment(owner/repo)>.
		{"github", "owner/repo", "/r/github/repos/owner-repo"},
		{"subdomains", "https://Example.com/", "/r/Example.com"},
		{"dns_cf1016", "example.com", "/r/example.com/vulnerabilities/cf1016"},
	}
	for _, tc := range cases {
		roots := artifactIndexRoots(results, tc.scanType, tc.target)
		found := false
		for _, r := range roots {
			if r == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("artifactIndexRoots(%q, %q) = %v, want it to include %q", tc.scanType, tc.target, roots, tc.want)
		}
	}
	// The root pipeline indexes its own output file; walking its shared label
	// tree re-indexed every earlier run's nuclei JSON.
	if roots := artifactIndexRoots(results, "pipeline", "root-pipeline"); len(roots) != 0 {
		t.Errorf("pipeline scans must not walk a shared tree, got %v", roots)
	}
}
