package api

import "testing"

func TestClaimJSMonitorRunIsPerDomainExclusive(t *testing.T) {
	if !claimJSMonitorRun("example.com") {
		t.Fatal("first manual sweep must be allowed")
	}
	if claimJSMonitorRun("example.com") {
		t.Fatal("overlapping manual sweep of the same domain must be refused")
	}
	if !claimJSMonitorRun("other.com") {
		t.Fatal("another domain must not be blocked")
	}
	releaseJSMonitorRun("example.com")
	releaseJSMonitorRun("other.com")
	if !claimJSMonitorRun("example.com") {
		t.Fatal("sweep must be allowed again after release")
	}
	releaseJSMonitorRun("example.com")
}
