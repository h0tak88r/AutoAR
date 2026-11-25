package api

import (
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func TestIsPurgeableTargetHost(t *testing.T) {
	for _, h := range []string{"example.com", "sub.example.com", "example.com:8443"} {
		if !isPurgeableTargetHost(h) {
			t.Errorf("isPurgeableTargetHost(%q) = false, want true", h)
		}
	}
	// Shared trees hold every watcher / race-pass / pipeline JSONL — never purge.
	for _, h := range []string{"", "global-subdomains", "root-pipeline", "race-pass", "nuclei-templates-watch", "misconfig", "localhost", "a..b"} {
		if isPurgeableTargetHost(h) {
			t.Errorf("isPurgeableTargetHost(%q) = true, want false", h)
		}
	}
	if scanOwnsTargetR2Tree("nuclei") || scanOwnsTargetR2Tree("pipeline") || !scanOwnsTargetR2Tree("domain_run") || !scanOwnsTargetR2Tree("subdomain_run") {
		t.Error("only domain_run / subdomain_run scans own a per-host R2 tree")
	}
}

// TestCountOtherScansForHostNormalizes guards the scan-delete purge: scans are
// counted on the normalized host the R2 prefixes are built from, so deleting
// the only www.example.com scan keeps example.com's tree while example.com
// scans exist.
func TestCountOtherScansForHostNormalizes(t *testing.T) {
	withTestSQLite(t)
	now := time.Now()
	for id, target := range map[string]string{
		"del-www":   "www.example.com",
		"keep-apex": "https://Example.com/",
		"other-sub": "sub.example.com",
		"other-sfx": "notexample.com",
	} {
		if err := db.CreateScan(&db.ScanRecord{ScanID: id, ScanType: "domain_run", Target: target, Status: "completed", StartedAt: now, LastUpdate: now}); err != nil {
			t.Fatalf("CreateScan(%s): %v", id, err)
		}
	}
	host := targetHostForR2Prefixes("www.example.com")
	n, err := countOtherScansForHost("del-www", host)
	if err != nil {
		t.Fatalf("countOtherScansForHost: %v", err)
	}
	if n != 1 {
		t.Fatalf("other scans sharing %q = %d, want 1 (the https://Example.com/ scan)", host, n)
	}
	if n, _ := countOtherScansForHost("other-sub", "sub.example.com"); n != 0 {
		t.Fatalf("sub.example.com shares its tree with %d other scans, want 0", n)
	}
}
