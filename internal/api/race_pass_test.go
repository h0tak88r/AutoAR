package api

import (
	"testing"
)

func TestRacePassEligible(t *testing.T) {
	mk := func(sev, raw string, cves ...string) pdcpTemplate {
		tt := pdcpTemplate{Severity: sev, Raw: raw}
		tt.Class.CVEs = cves
		return tt
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
