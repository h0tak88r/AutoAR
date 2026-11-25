package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNucleiTemplateWatchToggles(t *testing.T) {
	// Defaults: watcher on (when a key exists), autorun on, 30-minute interval.
	t.Setenv("PDCP_API_KEY", "test-key")
	t.Setenv("CHAOS_API_KEY", "")
	t.Setenv("NUCLEI_TEMPLATE_WATCH", "")
	t.Setenv("NUCLEI_TEMPLATE_AUTORUN", "")
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "")
	if !nucleiTemplateWatchEnabled() {
		t.Error("watch should default to enabled when a PDCP key is set")
	}
	if !nucleiTemplateAutoRunEnabled() {
		t.Error("autorun should default to enabled")
	}
	if got := nucleiTemplateWatchInterval(); got != 30*time.Minute {
		t.Errorf("default interval = %s, want 30m", got)
	}

	t.Setenv("NUCLEI_TEMPLATE_WATCH", "off")
	if nucleiTemplateWatchEnabled() {
		t.Error("NUCLEI_TEMPLATE_WATCH=off should disable the watch")
	}
	t.Setenv("NUCLEI_TEMPLATE_WATCH", "")
	t.Setenv("NUCLEI_TEMPLATE_AUTORUN", "off")
	if nucleiTemplateAutoRunEnabled() {
		t.Error("NUCLEI_TEMPLATE_AUTORUN=off should disable autorun")
	}

	// Interval: valid override, plus the floor at 5 minutes.
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "60")
	if got := nucleiTemplateWatchInterval(); got != time.Hour {
		t.Errorf("interval override = %s, want 1h", got)
	}
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "1")
	if got := nucleiTemplateWatchInterval(); got != 30*time.Minute {
		t.Errorf("below-floor interval = %s, want fallback 30m", got)
	}
	t.Setenv("NUCLEI_TEMPLATE_WATCH_INTERVAL_MINUTES", "not-a-number")
	if got := nucleiTemplateWatchInterval(); got != 30*time.Minute {
		t.Errorf("garbage interval = %s, want fallback 30m", got)
	}
}

func TestNucleiTemplateAPIKeyFallback(t *testing.T) {
	// PDCP_API_KEY wins; CHAOS_API_KEY (the same PDCP key) is the fallback.
	t.Setenv("PDCP_API_KEY", "pdcp-key")
	t.Setenv("CHAOS_API_KEY", "chaos-key")
	if got := nucleiTemplateAPIKey(); got != "pdcp-key" {
		t.Errorf("nucleiTemplateAPIKey() = %q, want PDCP_API_KEY", got)
	}

	t.Setenv("PDCP_API_KEY", "")
	if got := nucleiTemplateAPIKey(); got != "chaos-key" {
		t.Errorf("nucleiTemplateAPIKey() = %q, want CHAOS_API_KEY fallback", got)
	}

	// No key at all: watch stays off even without an explicit =off.
	t.Setenv("CHAOS_API_KEY", "")
	t.Setenv("NUCLEI_TEMPLATE_WATCH", "")
	if nucleiTemplateWatchEnabled() {
		t.Error("watch should be disabled when no PDCP/CHAOS key is set")
	}
}

func TestNucleiWatchRunnable(t *testing.T) {
	cases := []struct {
		severity string
		want     bool
	}{
		{"info", false},
		{"INFO", false},
		{" info ", false},
		{"low", true},
		{"medium", true},
		{"high", true},
		{"critical", true},
		{"unknown", true}, // fail-open
		{"", true},        // fail-open
	}
	for _, tc := range cases {
		if got := nucleiWatchRunnable(pdcpTemplate{Severity: tc.severity}); got != tc.want {
			t.Errorf("nucleiWatchRunnable(severity=%q) = %v, want %v", tc.severity, got, tc.want)
		}
	}
}

func TestNucleiTemplateBlocked(t *testing.T) {
	t.Setenv("NUCLEI_TEMPLATE_IGNORE", "CVE-2026-32475, cve-2026-73570 ,")
	cases := []struct {
		id   string
		want bool
	}{
		{"CVE-2026-32475", true},
		{"cve-2026-32475", true},  // case-insensitive
		{"CVE-2026-73570", true},  // whitespace-trimmed entry
		{"CVE-2026-77806", false}, // not listed
		{"", false},
	}
	for _, tc := range cases {
		if got := nucleiTemplateBlocked(tc.id); got != tc.want {
			t.Errorf("nucleiTemplateBlocked(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
	if !nucleiWatchRunnable(pdcpTemplate{ID: "CVE-2026-77806", Severity: "critical"}) {
		t.Error("non-blocklisted template must be runnable")
	}
	if nucleiWatchRunnable(pdcpTemplate{ID: "CVE-2026-32475", Severity: "critical"}) {
		t.Error("blocklisted template must not be runnable")
	}
	t.Setenv("NUCLEI_TEMPLATE_IGNORE", "")
	if nucleiTemplateBlocked("CVE-2026-32475") {
		t.Error("empty blocklist must not block anything")
	}
}

const safeHTTPTemplate = `id: CVE-2026-1111
info:
  name: test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
`

func TestNucleiWatchAutoRunBlock(t *testing.T) {
	merged := pdcpTemplate{ID: "CVE-2026-1111", IsGithub: true, Raw: safeHTTPTemplate}
	if why := nucleiWatchAutoRunBlock(merged); why != "" {
		t.Fatalf("merged plain-http template blocked: %q", why)
	}
	// Owner directive 2026-10-14: EVERY statically-safe template auto-runs —
	// PR/draft stage no longer disqualifies. Draft markers must NOT block.
	for name, tt := range map[string]pdcpTemplate{
		"is_draft":         {ID: "x", IsDraft: true, Raw: safeHTTPTemplate},
		"-draft template":  {ID: "x", TemplateID: "x-draft", Raw: safeHTTPTemplate},
		"-draft id suffix": {ID: "x-draft", Raw: safeHTTPTemplate},
		"is_early preview": {ID: "x", IsEarly: true, Raw: safeHTTPTemplate},
	} {
		if why := nucleiWatchAutoRunBlock(tt); why != "" {
			t.Errorf("%s: draft-stage template blocked (%q) — owner directive: run everything safe", name, why)
		}
	}
	unsafe := map[string]string{
		"code":           "id: a\ncode:\n  - engine: [sh]\n    source: id\n",
		"javascript":     "id: a\njavascript:\n  - code: 'x'\n",
		"headless":       "id: a\nheadless:\n  - steps: []\n",
		"file":           "id: a\nfile:\n  - extensions: [all]\n",
		"workflows":      "id: a\nworkflows:\n  - template: x.yaml\n",
		"self-contained": "id: a\nself-contained: true\nhttp:\n  - path: ['{{BaseURL}}']\n",
		"@Host":          "id: a\nhttp:\n  - raw:\n      - |\n        @Host: https://169.254.169.254\n        GET / HTTP/1.1\n",
		"fixed path":     "id: a\nhttp:\n  - method: GET\n    path:\n      - https://attacker.example/x\n",
		"fixed tcp host": "id: a\ntcp:\n  - host:\n      - 127.0.0.1:6379\n",
		"bad yaml":       "id: [unterminated\n",
	}
	for name, raw := range unsafe {
		if why := nucleiTemplateUnsafeReason(raw); why == "" {
			t.Errorf("%s: unsafe template passed the auto-run screen", name)
		}
	}
	if why := nucleiTemplateUnsafeReason("id: a\ntcp:\n  - host:\n      - '{{Hostname}}:6379'\n"); why != "" {
		t.Errorf("target-derived tcp host blocked: %q", why)
	}
}

func TestNucleiWatchFreshPrefersMergedAndParsesTimes(t *testing.T) {
	wm := "2026-10-07T12:00:00Z"
	templates := []pdcpTemplate{
		// Same ID twice: the draft first, the merged revision second.
		{ID: "CVE-2026-2", TemplateID: "CVE-2026-2-draft", CreatedAt: "2026-10-07T12:30:00Z", Raw: "draft"},
		{ID: "CVE-2026-2", IsGithub: true, CreatedAt: "2026-10-07T12:30:00Z", Raw: "merged"},
		// Fractional seconds: later than the watermark although "…00.5Z" < "…00Z" as strings.
		{ID: "CVE-2026-3", IsGithub: true, CreatedAt: "2026-10-07T12:00:00.5Z"},
		// At the watermark and already seen -> not fresh; older -> not fresh.
		{ID: "CVE-2026-4", IsGithub: true, CreatedAt: wm},
		{ID: "CVE-2026-5", IsGithub: true, CreatedAt: "2026-10-07T11:59:59Z"},
		// At the watermark, merged revision of a template only seen as a draft -> fresh.
		{ID: "CVE-2026-6", IsGithub: true, CreatedAt: wm},
	}
	seen := map[string]bool{"CVE-2026-4": true, "CVE-2026-6#draft": true}
	fresh := nucleiWatchFresh(templates, wm, seen)
	got := map[string]pdcpTemplate{}
	for _, f := range fresh {
		got[f.ID] = f
	}
	if len(fresh) != 3 {
		t.Fatalf("fresh = %+v, want CVE-2026-2, -3, -6", fresh)
	}
	if got["CVE-2026-2"].Raw != "merged" {
		t.Errorf("dedupe kept the %q revision, want the merged one", got["CVE-2026-2"].Raw)
	}
	if _, ok := got["CVE-2026-3"]; !ok {
		t.Error("fractional-second created_at after the watermark was missed")
	}
	if _, ok := got["CVE-2026-6"]; !ok {
		t.Error("merged revision suppressed because its draft was seen")
	}
	if pdcpCompare("2026-10-07T12:00:00.5Z", "2026-10-07T12:00:00Z") <= 0 {
		t.Error("pdcpCompare must order by time, not string")
	}
}

func TestNucleiWatchStageNameNoTraversal(t *testing.T) {
	used := map[string]bool{}
	for _, tt := range []pdcpTemplate{
		{ID: "../../etc/cron.d/x"},
		{ID: "..", URI: ""},
		{ID: "a b/c", URI: "/"},
		{ID: "ok", URI: "http/cves/2026/CVE-2026-1.yaml"},
		{ID: "dup", URI: "other/CVE-2026-1.yaml"},
	} {
		name := nucleiWatchStageName(tt, used)
		if strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".yaml") {
			t.Errorf("stage name for %+v = %q — must be a plain .yaml file name", tt, name)
		}
	}
	if len(used) != 5 {
		t.Errorf("names collided: %v", used)
	}

	t.Setenv("AUTOAR_RESULTS_DIR", t.TempDir())
	dir, staged, cleanup, err := nucleiWatchStage("scan-x", []pdcpTemplate{
		{ID: "../../../../tmp/evil", IsGithub: true, Raw: safeHTTPTemplate},
		{ID: "draft", IsDraft: true, Raw: safeHTTPTemplate}, // unmerged: never staged
	}, false)
	defer cleanup()
	if err != nil || len(staged) != 1 {
		t.Fatalf("staged = %v, err = %v; want only the merged template", staged, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("template dir holds %d files, want 1", len(entries))
	}
}

func TestNucleiWatchStageBridgeAllowsUnmerged(t *testing.T) {
	t.Setenv("AUTOAR_RESULTS_DIR", t.TempDir())
	// Watcher mode: the unmerged PR is refused.
	dir, staged, cleanup, err := nucleiWatchStage("scan-watch", []pdcpTemplate{
		{ID: "pr-1", IsDraft: true, Raw: safeHTTPTemplate},
	}, false)
	defer cleanup()
	if err != nil || len(staged) != 0 {
		t.Fatalf("watcher mode staged unmerged %v (err=%v); want 0", staged, err)
	}
	// Bridge mode: the same template stages.
	dir, staged, cleanup2, err := nucleiWatchStage("scan-bridge", []pdcpTemplate{
		{ID: "pr-1", Raw: safeHTTPTemplate},
	}, true)
	defer cleanup2()
	if err != nil || len(staged) != 1 {
		t.Fatalf("bridge mode staged = %v (err=%v); want the unmerged template", staged, err)
	}
	if _, rerr := os.Stat(filepath.Join(dir, "pr-1.yaml")); rerr != nil {
		t.Fatalf("bridge-mode template file missing: %v", rerr)
	}
	// Bridge mode still refuses statically unsafe YAML.
	_, staged, cleanup3, err := nucleiWatchStage("scan-bridge-unsafe", []pdcpTemplate{
		{ID: "pr-evil", Raw: "id: x\njavascript:\n  - code: alert(1)\n"},
	}, true)
	defer cleanup3()
	if err != nil || len(staged) != 0 {
		t.Fatalf("bridge mode staged unsafe template %v (err=%v); want 0", staged, err)
	}
}

func TestNucleiWatchSearchSincePages(t *testing.T) {
	var offsets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		offsets = append(offsets, r.URL.Query().Get("offset"))
		// 60 templates, one per minute, newest first; page size 25.
		var res []map[string]any
		for i := off; i < 60 && i < off+nucleiWatchPageSize; i++ {
			res = append(res, map[string]any{
				"id":         fmt.Sprintf("T-%02d", i),
				"created_at": time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Minute).Format(time.RFC3339),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": res})
	}))
	defer srv.Close()
	saved := nucleiWatchSearchEndpoint
	nucleiWatchSearchEndpoint = srv.URL
	t.Cleanup(func() { nucleiWatchSearchEndpoint = saved })

	// Watermark 40 minutes back: pages 1 and 2 (50 results) reach past it.
	wm := time.Date(2026, 10, 7, 11, 20, 0, 0, time.UTC).Format(time.RFC3339)
	got, err := nucleiWatchSearchSince(wm, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 50 || len(offsets) != 2 {
		t.Fatalf("got %d templates over %d request(s) %v, want 50 over 2", len(got), len(offsets), offsets)
	}
	// 40 newer than the watermark + the unseen one exactly at it.
	if fresh := nucleiWatchFresh(got, wm, nil); len(fresh) != 41 {
		t.Fatalf("fresh = %d, want 41 (everything at or after the watermark)", len(fresh))
	}
}

func TestDiscordCode(t *testing.T) {
	if got := discordCode("a`b\nc", 10); got != "`a'b c`" {
		t.Errorf("discordCode = %q", got)
	}
	if got := discordCode(strings.Repeat("x", 20), 5); got != "`xxxxx…`" {
		t.Errorf("discordCode truncation = %q", got)
	}
}

// TestAcquireGlobalSweepQueues: a second fleet-wide sweep waits for the first
// instead of running alongside it, and a cancelled waiter gives up cleanly.
func TestAcquireGlobalSweepQueues(t *testing.T) {
	release, err := acquireGlobalSweep("sweep-a")
	if err != nil {
		t.Fatal(err)
	}
	if busy := globalNucleiSweepBusy(); !strings.Contains(busy, "global sweep") {
		t.Fatalf("busy = %q while a sweep holds the slot", busy)
	}
	got := make(chan error, 1)
	go func() {
		r2, err := acquireGlobalSweep("sweep-b")
		if err == nil {
			r2()
		}
		got <- err
	}()
	select {
	case <-got:
		t.Fatal("second sweep acquired the slot while the first still held it")
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if err := <-got; err != nil {
		t.Fatalf("queued sweep failed after release: %v", err)
	}

	// Cancelled while queued.
	release, _ = acquireGlobalSweep("sweep-c")
	ctx, cancel := context.WithCancel(context.Background())
	ScansMutex.Lock()
	ActiveScans["sweep-d"] = &ScanInfo{ScanID: "sweep-d", Ctx: ctx}
	ScansMutex.Unlock()
	t.Cleanup(func() {
		ScansMutex.Lock()
		delete(ActiveScans, "sweep-d")
		ScansMutex.Unlock()
	})
	go func() { _, err := acquireGlobalSweep("sweep-d"); got <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-got; err == nil {
		t.Fatal("cancelled queued sweep acquired the slot")
	}
	release()
	if n := globalSweepActive.Load(); n != 0 {
		t.Fatalf("globalSweepActive = %d after all sweeps ended", n)
	}
}
