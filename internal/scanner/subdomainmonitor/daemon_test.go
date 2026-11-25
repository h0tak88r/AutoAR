package subdomainmonitor

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// TestNextBaselines: a feature is baselined only by a run whose step succeeded,
// stays baselined across later failures, and is forgotten when disabled.
func TestNextBaselines(t *testing.T) {
	none := map[string]bool{}
	// Existing target re-saved with monitor_js/check_new: no markers yet, so the
	// run is a (silent) baseline; a failed step leaves it pending.
	if got := nextBaselines(none, true, true, false, false); len(got) != 0 {
		t.Fatalf("failed baseline steps marked: %v", got)
	}
	got := nextBaselines(none, true, true, true, false)
	if !got[featureReenum] || got[featureJS] {
		t.Fatalf("only the successful step should be baselined: %v", got)
	}
	got = nextBaselines(got, true, true, false, true)
	if !got[featureReenum] || !got[featureJS] {
		t.Fatalf("baseline must persist across a later failure: %v", got)
	}
	got = nextBaselines(got, true, false, true, false)
	if got[featureJS] {
		t.Fatalf("disabling monitor_js must forget its baseline: %v", got)
	}
	if !sameFeatures(map[string]bool{"a": true}, map[string]bool{"a": true}) || sameFeatures(map[string]bool{"a": true}, none) {
		t.Fatal("sameFeatures")
	}
}

// TestBaselineStoreRoundTrip exercises the settings-backed marker store on a
// throwaway SQLite DB.
func TestBaselineStoreRoundTrip(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "submon.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	if err := db.Init(); err != nil {
		t.Skipf("sqlite unavailable: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Skipf("schema: %v", err)
	}
	if got := loadBaselines(7); len(got) != 0 {
		t.Fatalf("fresh target has baselines: %v", got)
	}
	if err := saveBaselines(7, map[string]bool{featureJS: true}); err != nil {
		t.Fatal(err)
	}
	if err := saveBaselines(8, map[string]bool{featureReenum: true}); err != nil {
		t.Fatal(err)
	}
	if got := loadBaselines(7); !got[featureJS] || got[featureReenum] {
		t.Fatalf("target 7 baselines = %v", got)
	}
	if err := saveBaselines(7, nil); err != nil {
		t.Fatal(err)
	}
	if got := loadBaselines(7); len(got) != 0 {
		t.Fatalf("cleared target still has baselines: %v", got)
	}
	if got := loadBaselines(8); !got[featureReenum] {
		t.Fatalf("other target's markers clobbered: %v", got)
	}
}

func TestSubdomainMonitorIntervalAndBackoff(t *testing.T) {
	if effectiveInterval(1) != minCheckInterval {
		t.Fatal("interval floor not applied")
	}
	if failureBackoff(1, time.Hour) != 5*time.Minute || failureBackoff(3, time.Hour) != 20*time.Minute || failureBackoff(9, time.Hour) != time.Hour {
		t.Fatal("unexpected backoff schedule")
	}
	const id = 919191
	now := time.Now()
	recordAttempt(id, false, time.Hour, now)
	if retryDue(id, now.Add(time.Minute)) {
		t.Fatal("failing target re-run on the next tick")
	}
	recordAttempt(id, true, time.Hour, now)
	if !retryDue(id, now) {
		t.Fatal("success should clear the backoff")
	}
}

// TestSubdomainLoopSurvivesPanickingTick: one panicking tick must not kill the
// loop, and the running flag is cleared when the loop exits.
func TestSubdomainLoopSurvivesPanickingTick(t *testing.T) {
	oldInterval, oldFn := tickInterval, tickFn
	defer func() { tickInterval, tickFn = oldInterval, oldFn }()
	var ticks int32
	tickInterval = 5 * time.Millisecond
	tickFn = func() {
		atomic.AddInt32(&ticks, 1)
		panic("boom")
	}
	daemonMutex.Lock()
	daemonRunning = true
	daemonMutex.Unlock()
	stop := make(chan struct{})
	daemonWg.Add(1)
	go superviseLoop(stop)
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&ticks) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&ticks); n < 3 {
		t.Fatalf("loop died after a panicking tick (ticks=%d)", n)
	}
	close(stop)
	daemonWg.Wait()
	if IsDaemonRunning() {
		t.Fatal("daemonRunning not cleared after the loop exited")
	}
}

// TestChangeSection covers the pure alert-list renderer: empty input yields no
// section, and the per-category cap (maxAlertItemsPerCategory) truncates with an
// "…and N more" line rather than dumping an unbounded list into a Discord message.
func TestChangeSection(t *testing.T) {
	if got := changeSection("**%d** changed", nil); got != "" {
		t.Errorf("empty changes should render nothing, got %q", got)
	}

	one := []SubdomainChange{{Subdomain: "a.example.com", Message: "became live"}}
	got := changeSection("**%d** became **live**", one)
	if !strings.Contains(got, "a.example.com") || !strings.Contains(got, "became live") {
		t.Errorf("section missing subdomain/message: %q", got)
	}
	if !strings.Contains(got, "1") {
		t.Errorf("section header should include the count: %q", got)
	}

	// One over the cap: exactly maxAlertItemsPerCategory bullets, then a summary.
	n := maxAlertItemsPerCategory + 5
	many := make([]SubdomainChange, n)
	for i := range many {
		many[i] = SubdomainChange{Subdomain: "h", Message: "m"}
	}
	got = changeSection("**%d** status change(s)", many)
	if bullets := strings.Count(got, "•"); bullets != maxAlertItemsPerCategory {
		t.Errorf("expected %d bullets at cap, got %d", maxAlertItemsPerCategory, bullets)
	}
	if !strings.Contains(got, "…and 5 more") {
		t.Errorf("expected overflow summary '…and 5 more', got %q", got)
	}
}

// TestFormatChangeAlert covers the top-level alert assembler: it names the domain,
// includes only the non-empty categories, and renders new JS endpoints.
func TestFormatChangeAlert(t *testing.T) {
	r := &MonitorResult{
		Domain:        "example.com",
		NewSubdomains: []SubdomainChange{{Subdomain: "new.example.com", Message: "new"}},
		NewEndpoints:  []EndpointChange{{Endpoint: "/api/secret"}},
	}
	got := formatChangeAlert("example.com", r)
	if !strings.Contains(got, "example.com") {
		t.Errorf("alert should name the domain: %q", got)
	}
	if !strings.Contains(got, "new.example.com") {
		t.Errorf("alert should list the new subdomain: %q", got)
	}
	if !strings.Contains(got, "/api/secret") {
		t.Errorf("alert should list the new JS endpoint: %q", got)
	}
	// Categories with no changes must not appear.
	if strings.Contains(got, "became **dead**") {
		t.Errorf("empty category should be omitted: %q", got)
	}
}
