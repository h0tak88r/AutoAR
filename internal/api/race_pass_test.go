package api

import (
	"fmt"
	"testing"
	"time"
)

func TestRacePassEligible(t *testing.T) {
	mk := func(sev, raw string, cves ...string) pdcpTemplate {
		tt := pdcpTemplate{Severity: sev, Raw: raw, IsGithub: true} // merged
		tt.Class.CVEs = cves
		return tt
	}
	// Owner directive 2026-10-14: draft-stage templates ARE auto-run (same
	// static-safety gates) — the race pass includes them too.
	draft := mk("critical", "id: x", "CVE-2026-1")
	draft.IsGithub = false
	draft.IsDraft = true
	if !racePassEligible(draft) {
		t.Error("draft-stage safe template -> eligible under the run-everything directive")
	}
	draft = mk("critical", "id: x", "CVE-2026-1")
	draft.TemplateID = "CVE-2026-1-draft"
	if !racePassEligible(draft) {
		t.Error("-draft template_id safe template -> eligible under the run-everything directive")
	}
	if racePassEligible(mk("critical", "id: x\ncode:\n  - engine: [sh]\n    source: id\n", "CVE-2026-1")) {
		t.Error("code-protocol template -> not eligible")
	}
	if racePassEligible(mk("critical", "id: x")) {
		t.Error("no CVE id -> not eligible")
	}
	if racePassEligible(mk("info", "id: x", "CVE-2026-1")) {
		t.Error("info severity -> not eligible")
	}
	if racePassEligible(mk("high", "", "CVE-2026-1")) {
		t.Error("no raw body -> not eligible (nothing to run)")
	}
	if !racePassEligible(mk("critical", "id: x", "CVE-2026-1")) {
		t.Error("critical + CVE + raw -> eligible")
	}
	if !racePassEligible(mk("high", "id: x", "CVE-2026-1")) {
		t.Error("high + CVE + raw -> eligible")
	}
}

func TestRaceTechKeywordsDropsClassNoise(t *testing.T) {
	tt := pdcpTemplate{Tags: []string{"cve", "rce", "gitlab", "tech", "panel", "default-login", "workhorse", "2026"}}
	kws := raceTechKeywords(tt)
	want := map[string]bool{"gitlab": true, "workhorse": true, "2026": true}
	if len(kws) != len(want) {
		t.Fatalf("keywords = %v, want exactly %v", kws, want)
	}
	for _, k := range kws {
		if !want[k] {
			t.Errorf("unexpected keyword %q in %v", k, kws)
		}
	}
}

func TestRaceIndexKeywordsFor(t *testing.T) {
	kws := raceIndexKeywordsFor("CVE-2026-85706-gitlab-file-read")
	joined := map[string]bool{}
	for _, k := range kws {
		joined[k] = true
	}
	if !joined["gitlab"] {
		t.Errorf("gitlab token missing from %v", kws)
	}
	if joined["cve"] || joined["read"] {
		t.Errorf("generic token leaked into %v", kws)
	}
}

func TestRaceHostOf(t *testing.T) {
	cases := map[string]string{
		"https://gitlab.erc.monash.edu/api/v4/projects/1/x?file=y": "gitlab.erc.monash.edu",
		"http://host.example.com:8080/path":                        "host.example.com",
		"plain.host.com":                                           "plain.host.com",
	}
	for in, want := range cases {
		if got := raceHostOf(in); got != want {
			t.Errorf("raceHostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRaceProgramsForHostNoCatalog(t *testing.T) {
	// Without a catalog in the test DB this returns nothing, but must not
	// error or panic on multi-label hosts.
	if got := raceProgramsForHost("gitlab.erc.monash.edu"); len(got) != 0 {
		t.Errorf("expected no matches in test env, got %+v", got)
	}
}

// TestRacePassEnqueueQueuesSequentiallyAndDedupes: eligible templates are
// queued (not fired as parallel goroutines that silently lose the
// single-flight race), the per-cycle cap is enforced, and a deferred batch
// re-discovered next tick does not queue the same revision again.
func TestRacePassEnqueueQueuesSequentiallyAndDedupes(t *testing.T) {
	racePassQueueMu.Lock()
	savedQueue, savedOn, savedSeen := racePassQueue, racePassWorkerOn, racePassQueued
	racePassQueue, racePassQueued = nil, map[string]time.Time{}
	racePassWorkerOn = true // pretend a worker runs: nothing executes in this test
	racePassQueueMu.Unlock()
	t.Cleanup(func() {
		racePassQueueMu.Lock()
		racePassQueue, racePassWorkerOn, racePassQueued = savedQueue, savedOn, savedSeen
		racePassQueueMu.Unlock()
	})

	var batch []pdcpTemplate
	for i := 1; i <= 3; i++ {
		tt := pdcpTemplate{ID: fmt.Sprintf("CVE-2026-100%d", i), Severity: "critical", IsGithub: true,
			Raw: fmt.Sprintf("id: CVE-2026-100%d\n", i), Tags: []string{"gitlab"}}
		batch = append(batch, tt)
	}
	racePassEnqueue(batch)
	racePassQueueMu.Lock()
	n := len(racePassQueue)
	racePassQueueMu.Unlock()
	if n != racePassMaxScansPerCycle {
		t.Fatalf("queued %d, want the per-cycle cap %d", n, racePassMaxScansPerCycle)
	}
	racePassEnqueue(batch) // same batch re-discovered (deferred behind a global sweep)
	racePassQueueMu.Lock()
	n = len(racePassQueue)
	racePassQueueMu.Unlock()
	if n != racePassMaxScansPerCycle+1 {
		t.Fatalf("after re-discovery queued %d, want %d (only the previously capped one is new)", n, racePassMaxScansPerCycle+1)
	}
}
