package api

import "testing"

func TestClassifyWatch(t *testing.T) {
	live := ProgramSummary{Platform: "h1", Handle: "finnair_bbp", SubmissionState: "open",
		LatestTarget: "www.finnair.com", ScopeTargets: 14}

	cases := []struct {
		name            string
		p               ProgramSummary
		prevFP          string
		seen            bool
		want            watchVerdict
		wantFPUnchanged bool // returned fp equals prevFP (skip verdicts)
	}{
		{"closed program always skips", ProgramSummary{Platform: "h1", Handle: "x", SubmissionState: "closed",
			LatestTarget: "a.com", ScopeTargets: 3}, "anything", true, watchSkip, true},
		{"zero substance skips", ProgramSummary{Platform: "ywh", Handle: "y", SubmissionState: "open"}, "", false, watchSkip, true},
		{"paused program skips", ProgramSummary{Platform: "h1", Handle: "p", SubmissionState: "paused",
			LatestTarget: "a.com", ScopeTargets: 3}, "anything", true, watchSkip, true},
		{"disabled program skips", ProgramSummary{Platform: "h1", Handle: "d", SubmissionState: "disabled",
			LatestTarget: "a.com", ScopeTargets: 3}, "anything", true, watchSkip, true},
		{"first sighting = new scope", live, "", false, watchNewScope, false},
		{"fingerprint changed = new scope", live, programWatchFingerprint(ProgramSummary{Platform: "h1",
			Handle: "finnair_bbp", LatestTarget: "new.finnair.com", ScopeTargets: 15}), true, watchNewScope, false},
		{"same fingerprint = asset touched", live, programWatchFingerprint(live), true, watchAssetTouched, false},
	}
	for _, tc := range cases {
		got, fp := classifyWatch(tc.p, tc.prevFP, tc.seen)
		if got != tc.want {
			t.Errorf("%s: verdict = %v, want %v", tc.name, got, tc.want)
		}
		if tc.wantFPUnchanged && fp != tc.prevFP {
			t.Errorf("%s: skip verdict must not rewrite the fingerprint", tc.name)
		}
	}
}

// The Finnair case: an already-in-scope asset is edited — LatestTarget and
// ScopeTargets are identical, only the timestamp moved. Old gate: suppressed.
// New classification: watchAssetTouched (✏️ notice), never 🆕.
func TestClassifyWatchFinnairAssetEdit(t *testing.T) {
	before := ProgramSummary{Platform: "h1", Handle: "finnair_bbp", SubmissionState: "open",
		LatestTarget: "www.finnair.com", ScopeTargets: 14, LatestTargetUpdatedAt: "2026-09-10T10:27:47Z"}
	after := before
	after.LatestTargetUpdatedAt = "2026-10-05T10:45:00Z"

	v, _ := classifyWatch(after, programWatchFingerprint(before), true)
	if v != watchAssetTouched {
		t.Fatalf("edited existing asset = %v, want watchAssetTouched", v)
	}
	// Sanity: the same program with no stored fingerprint is still a plain
	// first-sighting new-scope (the 🆕 path's precondition).
	if v2, _ := classifyWatch(after, "", false); v2 != watchNewScope {
		t.Fatalf("first sighting = %v, want watchNewScope", v2)
	}
}

func TestAssetTouchKillSwitch(t *testing.T) {
	t.Setenv("PROGRAM_WATCH_ASSET_TOUCH", "off")
	if programWatchAssetTouchEnabled() {
		t.Fatal("off must disable asset-touch notices")
	}
	t.Setenv("PROGRAM_WATCH_ASSET_TOUCH", "")
	if !programWatchAssetTouchEnabled() {
		t.Fatal("default must be enabled")
	}
}

// The fingerprint compares the SORTED asset set: order and case never count
// as a change, a different set always does.
func TestWatchFingerprintAssetSet(t *testing.T) {
	a := ProgramSummary{Platform: "h1", Handle: "x", SubmissionState: "open", ScopeTargets: 2,
		Assets: []string{"B.example.com", "a.example.com"}}
	b := a
	b.Assets = []string{"a.example.com", "b.example.com"}
	if v, _ := classifyWatch(b, programWatchFingerprint(a), true); v != watchAssetTouched {
		t.Fatalf("reordered set = %v, want watchAssetTouched", v)
	}
	c := a
	c.Assets = []string{"a.example.com", "c.example.com"}
	if v, _ := classifyWatch(c, programWatchFingerprint(a), true); v != watchNewScope {
		t.Fatalf("swapped asset (same count) = %v, want watchNewScope", v)
	}
	// Legacy (pre-v2) fingerprints still compare once.
	if v, _ := classifyWatch(a, legacyWatchFingerprint(a), true); v != watchAssetTouched {
		t.Fatalf("legacy fingerprint = %v, want watchAssetTouched", v)
	}
}
