package api

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// setupWatchTestDB points the DB layer at a throwaway SQLite file and swaps
// the Discord sender for a recorder.
func setupWatchTestDB(t *testing.T) *[]string {
	t.Helper()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "watch_test.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	t.Setenv("MONITOR_WEBHOOK_URL", "http://127.0.0.1:9/unused")
	t.Setenv("PROGRAM_MONITOR", "")
	t.Setenv("PROGRAM_MONITOR_PLATFORMS", "")
	t.Setenv("PROGRAM_WATCH_ASSET_TOUCH", "")
	db.SetDB(nil)
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("db.InitSchema: %v", err)
	}
	var sent []string
	prevSend, prevIntro := programWatchSend, programWatchIntroSent
	programWatchSend = func(msg string) error { sent = append(sent, msg); return nil }
	programWatchIntroSent = true // keep the boot intro out of the assertions
	programPauseStatesInvalidate()
	t.Cleanup(func() {
		programWatchSend, programWatchIntroSent = prevSend, prevIntro
		programPauseStatesInvalidate()
		db.SetDB(nil)
	})
	return &sent
}

func isoAgo(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

func countPrefix(msgs []string, prefix string) int {
	n := 0
	for _, m := range msgs {
		if strings.HasPrefix(m, prefix) {
			n++
		}
	}
	return n
}

// C1: the fast loop's fresh HA/YWH timestamps used to push ONE global
// watermark to ~now, so the warmer's later H1 scope addition (older timestamp)
// was never alerted. State is per program now.
func TestProgramWatchPerProgramWatermark(t *testing.T) {
	sent := setupWatchTestDB(t)
	h1 := ProgramSummary{Platform: "h1", Handle: "acme", Name: "Acme", SubmissionState: "open",
		ScopeTargets: 1, LatestTarget: "a.acme.com", Assets: []string{"a.acme.com"}, LatestTargetUpdatedAt: isoAgo(48 * time.Hour)}
	ha := ProgramSummary{Platform: "ha", Handle: "42", Name: "Ext", SubmissionState: "open",
		ScopeTargets: 3, LatestTargetUpdatedAt: isoAgo(48 * time.Hour)}

	programWatchScope([]ProgramSummary{h1, ha}, time.Now()) // first run: silent baseline
	if len(*sent) != 0 {
		t.Fatalf("baseline must be silent, sent %v", *sent)
	}

	// Fast loop: HA moves to "now" (count changed → 🆕 for HA).
	ha.LatestTargetUpdatedAt, ha.ScopeTargets = isoAgo(time.Minute), 4
	programWatchScope([]ProgramSummary{ha}, time.Now())
	if countPrefix(*sent, "🆕 **Scope updated** — Ext") != 1 {
		t.Fatalf("HA update not alerted: %v", *sent)
	}

	// Warmer, later: H1 got a new asset 30 minutes ago — older than HA's time.
	h1.LatestTargetUpdatedAt = isoAgo(30 * time.Minute)
	h1.Assets, h1.ScopeTargets, h1.LatestTarget = []string{"a.acme.com", "new.acme.com"}, 2, "new.acme.com"
	programWatchScope([]ProgramSummary{h1, ha}, time.Now())
	if countPrefix(*sent, "🆕 **Scope updated** — Acme") != 1 {
		t.Fatalf("H1 scope addition behind a fresher HA timestamp was not alerted: %v", *sent)
	}

	// Re-running the same snapshot never re-alerts.
	n := len(*sent)
	programWatchScope([]ProgramSummary{h1, ha}, time.Now())
	if len(*sent) != n {
		t.Fatalf("same snapshot re-alerted: %v", (*sent)[n:])
	}
}

// C5: all updates are classified before the cap; churn never eats the cap and
// capped real changes stay pending instead of being skipped forever.
func TestProgramWatchClassifyBeforeCap(t *testing.T) {
	sent := setupWatchTestDB(t)
	var progs []ProgramSummary
	for i := 0; i < 10; i++ { // YWH churn: program-level timestamps, same asset set
		progs = append(progs, ProgramSummary{Platform: "ywh", Handle: fmt.Sprintf("y%d", i), SubmissionState: "open",
			ScopeTargets: 1, Assets: []string{"y.example.com"}, LatestTargetUpdatedAt: isoAgo(72 * time.Hour)})
	}
	for i := 0; i < 15; i++ { // real H1 programs
		progs = append(progs, ProgramSummary{Platform: "h1", Handle: fmt.Sprintf("h%d", i), Name: fmt.Sprintf("H%d", i), SubmissionState: "open",
			ScopeTargets: 1, Assets: []string{"old.example.com"}, LatestTargetUpdatedAt: isoAgo(72 * time.Hour)})
	}
	programWatchScope(progs, time.Now()) // baseline

	for i := range progs {
		if progs[i].Platform == "ywh" {
			progs[i].LatestTargetUpdatedAt = isoAgo(time.Minute) // freshest, but churn
		} else {
			progs[i].LatestTargetUpdatedAt = isoAgo(time.Hour)
			progs[i].Assets = append(progs[i].Assets, "new.example.com")
			progs[i].ScopeTargets = 2
		}
	}
	programWatchScope(progs, time.Now())
	if got := countPrefix(*sent, "🆕"); got != programWatchMaxAlertsCyc {
		t.Fatalf("first cycle sent %d 🆕, want %d (churn must not use the cap): %v", got, programWatchMaxAlertsCyc, *sent)
	}
	programWatchScope(progs, time.Now())
	if got := countPrefix(*sent, "🆕"); got != 15 {
		t.Fatalf("capped changes must be sent next cycle: total 🆕 = %d, want 15", got)
	}
	if strings.Contains(strings.Join(*sent, "\n"), "y0") {
		t.Fatalf("YWH same-asset churn must stay silent: %v", *sent)
	}
}

// C6: the YWH fast loop (count only) and warmer (asset list) agree — a
// same-count bump is deferred to the warmer, which decides on the sorted set.
func TestProgramWatchYWHLoopsAgree(t *testing.T) {
	sent := setupWatchTestDB(t)
	warm := ProgramSummary{Platform: "ywh", Handle: "acme", Name: "Acme", SubmissionState: "open",
		ScopeTargets: 2, LatestTarget: "b.acme.com", Assets: []string{"b.acme.com", "a.acme.com"}, LatestTargetUpdatedAt: isoAgo(72 * time.Hour)}
	programWatchScope([]ProgramSummary{warm}, time.Now()) // baseline with assets

	fast := warm
	fast.Assets, fast.LatestTarget = nil, ""
	fast.LatestTargetUpdatedAt = isoAgo(time.Hour) // program edited, count unchanged
	programWatchScope([]ProgramSummary{fast}, time.Now())
	programWatchScope([]ProgramSummary{fast}, time.Now())
	if len(*sent) != 0 {
		t.Fatalf("fast loop can't judge a same-count YWH bump, sent %v", *sent)
	}

	// Warmer: same set in another order → silent (no ✏️ for program-level timestamps).
	same := warm
	same.Assets, same.LatestTarget = []string{"a.acme.com", "b.acme.com"}, "a.acme.com"
	same.LatestTargetUpdatedAt = fast.LatestTargetUpdatedAt
	programWatchScope([]ProgramSummary{same}, time.Now())
	if len(*sent) != 0 {
		t.Fatalf("unchanged YWH asset set must stay silent, sent %v", *sent)
	}

	// Next edit swaps an asset (same count): warmer must say 🆕.
	fast.LatestTargetUpdatedAt = isoAgo(30 * time.Minute)
	programWatchScope([]ProgramSummary{fast}, time.Now())
	swapped := same
	swapped.Assets = []string{"a.acme.com", "c.acme.com"}
	swapped.LatestTargetUpdatedAt = fast.LatestTargetUpdatedAt
	programWatchScope([]ProgramSummary{swapped}, time.Now())
	if countPrefix(*sent, "🆕 **Scope updated** — Acme") != 1 {
		t.Fatalf("YWH asset swap not alerted: %v", *sent)
	}
}

// ProgramWatchCheckProgram (force refresh of one program) must only advance
// that program.
func TestProgramWatchCheckProgramIsolated(t *testing.T) {
	sent := setupWatchTestDB(t)
	a := ProgramSummary{Platform: "h1", Handle: "a", Name: "A", SubmissionState: "open", ScopeTargets: 1,
		Assets: []string{"a.com"}, LatestTargetUpdatedAt: isoAgo(72 * time.Hour)}
	b := ProgramSummary{Platform: "h1", Handle: "b", Name: "B", SubmissionState: "open", ScopeTargets: 1,
		Assets: []string{"b.com"}, LatestTargetUpdatedAt: isoAgo(72 * time.Hour)}
	programWatchScope([]ProgramSummary{a, b}, time.Now())

	a.LatestTargetUpdatedAt, a.Assets, a.ScopeTargets = isoAgo(time.Minute), []string{"a.com", "x.a.com"}, 2
	ProgramWatchCheckProgram(a)
	b.LatestTargetUpdatedAt, b.Assets, b.ScopeTargets = isoAgo(time.Hour), []string{"b.com", "x.b.com"}, 2
	programWatchScope([]ProgramSummary{a, b}, time.Now())
	if countPrefix(*sent, "🆕 **Scope updated** — A") != 1 || countPrefix(*sent, "🆕 **Scope updated** — B") != 1 {
		t.Fatalf("want one alert each for A (force) and B (older, warmer): %v", *sent)
	}
}

// C4 + C15: the pause/new-program map baselines each platform AND each newly
// added account silently, defers over-cap alerts instead of dropping them,
// honors PROGRAM_MONITOR_PLATFORMS and prunes long-absent programs.
func TestProgramWatchPauseDiffBaselines(t *testing.T) {
	sent := setupWatchTestDB(t)
	now := time.Now()
	mk := func(platform, handle, state string, labels ...string) ProgramSummary {
		return ProgramSummary{Platform: platform, Handle: handle, Name: handle, SubmissionState: state, Sources: labels}
	}
	programWatchPauseDiff([]ProgramSummary{mk("h1", "p1", "open", "a"), mk("h1", "p2", "open", "a")}, now)
	if len(*sent) != 0 {
		t.Fatalf("first fetch must baseline silently: %v", *sent)
	}

	// New program via the known account → 🆕; a new account's whole list and
	// a platform's first successful fetch → silent.
	programWatchPauseDiff([]ProgramSummary{
		mk("h1", "p1", "open", "a"), mk("h1", "p2", "open", "a"), mk("h1", "p3", "open", "a"),
		mk("h1", "priv1", "open", "b"), mk("h1", "priv2", "open", "b"),
		mk("bc", "c1", "open", "x"),
	}, now)
	if len(*sent) != 1 || !strings.Contains((*sent)[0], "New program") || !strings.Contains((*sent)[0], "p3") {
		t.Fatalf("want exactly the p3 announcement, got %v", *sent)
	}

	// 13 brand-new programs: 12 now, the 13th next cycle (not baselined silently).
	*sent = nil
	var batch []ProgramSummary
	for i := 0; i < 13; i++ {
		batch = append(batch, mk("h1", fmt.Sprintf("n%02d", i), "open", "a"))
	}
	programWatchPauseDiff(batch, now)
	if len(*sent) != programWatchPauseAlert {
		t.Fatalf("cycle 1 sent %d, want %d", len(*sent), programWatchPauseAlert)
	}
	programWatchPauseDiff(batch, now)
	if len(*sent) != 13 {
		t.Fatalf("over-cap program must be announced next cycle: total %d, want 13", len(*sent))
	}

	// Platform filter applies to the pause diff too.
	*sent = nil
	t.Setenv("PROGRAM_MONITOR_PLATFORMS", "bc")
	programWatchPauseDiff([]ProgramSummary{mk("h1", "p1", "paused", "a"), mk("bc", "c1", "paused", "x")}, now)
	if len(*sent) != 1 || !strings.Contains((*sent)[0], "c1") {
		t.Fatalf("only the bc pause should alert: %v", *sent)
	}
	t.Setenv("PROGRAM_MONITOR_PLATFORMS", "")

	// Pruning: a program absent for > 30 days is forgotten.
	programWatchPauseDiff([]ProgramSummary{mk("h1", "p1", "open", "a")}, now.Add(31*24*time.Hour))
	st := loadPauseStore(now)
	if _, ok := st.Programs["h1|p2"]; ok {
		t.Fatal("long-absent program must be pruned")
	}
	if _, ok := st.Programs["h1|p1"]; !ok {
		t.Fatal("live program must be kept")
	}
	if got := programPauseStates()["h1|p1"]; got != "open" {
		t.Fatalf("programPauseStates = %q, want open", got)
	}
}

func TestProgramWatchPlatformAllowedTokens(t *testing.T) {
	t.Setenv("PROGRAM_MONITOR_PLATFORMS", "h1, YesWeHack")
	for platform, want := range map[string]bool{"h1": true, "ywh": true, "bc": false, "it": false, "ha": false} {
		if got := programWatchPlatformAllowed(platform); got != want {
			t.Errorf("allowed(%q) = %v, want %v", platform, got, want)
		}
	}
	t.Setenv("PROGRAM_MONITOR_PLATFORMS", "hackadvisor")
	if !programWatchPlatformAllowed("ha") || programWatchPlatformAllowed("h1") {
		t.Error("full platform names must map to codes")
	}
}

// C14: untrusted platform/aggregator text can't inject mentions, masked links
// or javascript: URLs into Discord messages.
func TestProgramWatchDiscordEscaping(t *testing.T) {
	sent := setupWatchTestDB(t)
	sendProgramUpdateDiscord(ProgramSummary{Platform: "ha", Handle: "1`x", Name: "@everyone [click](https://evil.example)",
		LatestTarget: "a`b\nc", LatestTargetBrief: "<@123> **x**", URL: "javascript:alert(1)", LatestTargetUpdatedAt: isoAgo(time.Hour)})
	msg := (*sent)[0]
	for _, bad := range []string{"@everyone", "[click](", "<@123>", "javascript:", "1`x", "a`b"} {
		if strings.Contains(msg, bad) {
			t.Errorf("message contains %q unescaped:\n%s", bad, msg)
		}
	}
	if discordSafeURL("https://hackerone.com/finnair_bbp") == "" {
		t.Error("plain program URLs must be kept")
	}
	for _, u := range []string{"javascript:alert(1)", "https://x.com/[a](b)", "https://x.com/@everyone", "ftp://x.com"} {
		if discordSafeURL(u) != "" {
			t.Errorf("discordSafeURL(%q) must be rejected", u)
		}
	}
}

func TestValidProgramHandle(t *testing.T) {
	for _, ok := range []string{"finnair_bbp", "acme-x", "a.b", "12345", "4f1e-uuid"} {
		if !validProgramHandle(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "../me/reports#", "a/b", "%25zz", "a b", "x?y", "a#"} {
		if validProgramHandle(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if !validBCBriefPath("/engagements/acme") || validBCBriefPath("/engagements/../../user") || validBCBriefPath("/engagements/a?x=1") {
		t.Error("validBCBriefPath")
	}
	if !validHAHandle("123") || validHAHandle("../me") {
		t.Error("validHAHandle")
	}
}
