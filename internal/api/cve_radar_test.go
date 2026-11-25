package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCVERadarPasses(t *testing.T) {
	re := cveRadarKeywordRE()
	if re == nil {
		t.Fatal("keyword matcher failed to compile")
	}
	cases := []struct {
		name  string
		desc  string
		score float64
		want  bool
	}{
		{"critical any product", "some obscure library heap overflow", 9.8, true},
		{"at threshold any product", "some obscure library heap overflow", 9.0, true},
		{"high on watched product", "GitLab CE/EE arbitrary file read via workhorse", 7.5, true},
		{"high on unknown product", "some obscure library heap overflow", 7.5, false},
		{"below bar", "some obscure library reflected xss", 6.9, false},
		{"medium on watched product", "wordpress plugin stored xss", 5.5, false},
		{"keyword case-insensitive", "AFFECTED: GitLab.com deployments", 7.0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cveRadarPasses(tc.desc, tc.score, re); got != tc.want {
				t.Fatalf("cveRadarPasses(%q, %.1f) = %v, want %v", tc.desc, tc.score, got, tc.want)
			}
		})
	}
}

func TestCVERadarToggles(t *testing.T) {
	// Defaults: radar on, 5-minute interval (also the floor).
	t.Setenv("CVE_RADAR", "")
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "")
	if !cveRadarEnabled() {
		t.Error("radar should default to enabled")
	}
	if got := cveRadarInterval(); got != 5*time.Minute {
		t.Errorf("default interval = %s, want 5m", got)
	}
	t.Setenv("CVE_RADAR", "off")
	if cveRadarEnabled() {
		t.Error("CVE_RADAR=off should disable the radar")
	}
	t.Setenv("CVE_RADAR", "")
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "20")
	if got := cveRadarInterval(); got != 20*time.Minute {
		t.Errorf("override interval = %s, want 20m", got)
	}
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "2")
	if got := cveRadarInterval(); got != 5*time.Minute {
		t.Errorf("below-floor interval = %s, want 5m", got)
	}
	t.Setenv("CVE_RADAR_INTERVAL_MINUTES", "not-a-number")
	if got := cveRadarInterval(); got != 5*time.Minute {
		t.Errorf("garbage interval = %s, want fallback 5m", got)
	}
}

func TestCVERadarScoreThresholds(t *testing.T) {
	t.Setenv("CVE_RADAR_CRITICAL_MIN", "")
	t.Setenv("CVE_RADAR_HIGH_MIN", "")
	if got := cveRadarCriticalMin(); got != 9.0 {
		t.Errorf("critical min = %.1f, want 9.0", got)
	}
	if got := cveRadarHighMin(); got != 7.0 {
		t.Errorf("high min = %.1f, want 7.0", got)
	}
	t.Setenv("CVE_RADAR_CRITICAL_MIN", "8.5")
	t.Setenv("CVE_RADAR_HIGH_MIN", "6.5")
	if got := cveRadarCriticalMin(); got != 8.5 {
		t.Errorf("critical override = %.1f, want 8.5", got)
	}
	if got := cveRadarHighMin(); got != 6.5 {
		t.Errorf("high override = %.1f, want 6.5", got)
	}
}

func TestCVERadarNVDScoreExtraction(t *testing.T) {
	raw := `{
      "id": "CVE-2026-0001",
      "vulnStatus": "Analyzed",
      "descriptions": [{"lang":"en","value":"GitLab workhorse path traversal"}],
      "metrics": {
        "cvssMetricV31": [{"cvssData":{"baseScore":10.0}}],
        "cvssMetricV2":  [{"cvssData":{"baseScore":7.5}}]
      }
    }`
	var c nvdCVEEntry
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := c.cveRadarScore(); got != 10.0 {
		t.Fatalf("score = %v, want 10.0 (highest across metric versions)", got)
	}
	if got := c.cveRadarDesc(); !strings.Contains(got, "GitLab") {
		t.Fatalf("desc = %q", got)
	}
}

func TestCVERadarPoCGate(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	repo := func(name string, stars int, age time.Duration, fork bool) cveRadarGHRepo {
		r := cveRadarGHRepo{FullName: name, HTMLURL: "https://github.com/" + name, Stars: stars, Fork: fork, CreatedAt: now.Add(-age)}
		r.Owner.Login = strings.SplitN(name, "/", 2)[0]
		return r
	}
	// Same-day zero-star repos and forks (the fake-PoC malware pattern) are not PoCs.
	display, _, err := cveRadarPoCFromRepos([]cveRadarGHRepo{
		repo("fresh/CVE-2026-1-poc", 0, time.Hour, false),
		repo("forker/CVE-2026-1", 50, 30*24*time.Hour, true),
	}, now)
	if err != nil || len(display) != 0 {
		t.Fatalf("display = %v, want none (fresh zero-star + fork)", display)
	}
	display, links, _ := cveRadarPoCFromRepos([]cveRadarGHRepo{
		repo("someone/CVE-2026-1", 3, time.Hour, false),        // starred
		repo("projectdiscovery/nuclei-templates", 0, 0, false), // trusted, sorts first
	}, now)
	if len(display) != 2 || len(links) != 2 {
		t.Fatalf("display = %v", display)
	}
	if !strings.Contains(display[0], "trusted source") || !strings.Contains(display[1], "unverified PoC — review before running") {
		t.Errorf("labels = %v", display)
	}
	// Untrusted description text is escaped (no masked links / mentions).
	evil := repo("old/CVE-2026-1", 0, 72*time.Hour, false)
	evil.Description = "[nvd.nist.gov](https://evil.example) @everyone"
	display, _, _ = cveRadarPoCFromRepos([]cveRadarGHRepo{evil}, now)
	if len(display) != 1 || strings.Contains(display[0], "](") || strings.Contains(display[0], "@everyone") {
		t.Errorf("description not escaped: %v", display)
	}
}

func TestCVERadarCapPendingKeepsWorstAndNewest(t *testing.T) {
	var items []cveRadarPendingItem
	for i := 0; i < 10; i++ {
		items = append(items, cveRadarPendingItem{ID: fmt.Sprintf("CVE-%d", i), CVSS: 7.0, FirstSeen: int64(i)})
	}
	items = append(items, cveRadarPendingItem{ID: "CVE-crit", CVSS: 9.8, FirstSeen: 0})
	items = append(items, cveRadarPendingItem{ID: "CVE-undelivered", CVSS: 7.0, FirstSeen: 0, Proof: "x"})
	got := cveRadarCapPending(items, 4)
	ids := map[string]bool{}
	for _, p := range got {
		ids[p.ID] = true
	}
	if len(got) != 4 || !ids["CVE-undelivered"] || !ids["CVE-crit"] || !ids["CVE-9"] || !ids["CVE-8"] {
		t.Fatalf("capped = %+v, want undelivered, crit, then the newest", got)
	}
}

func TestCVERadarGitHubRateLimit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	h := http.Header{}
	h.Set("X-RateLimit-Remaining", "0")
	h.Set("X-RateLimit-Reset", "1800000300")
	if until, ok := cveRadarGitHubRateLimit(http.StatusForbidden, h, now); !ok || until.Unix() != 1800000300 {
		t.Errorf("primary rate limit: until=%v ok=%v", until, ok)
	}
	plain := http.Header{}
	plain.Set("X-RateLimit-Remaining", "25")
	if _, ok := cveRadarGitHubRateLimit(http.StatusForbidden, plain, now); ok {
		t.Error("a 403 with quota left is not a rate limit")
	}
	sec := http.Header{}
	sec.Set("Retry-After", "30")
	if until, ok := cveRadarGitHubRateLimit(http.StatusForbidden, sec, now); !ok || until.Sub(now) != 30*time.Second {
		t.Errorf("secondary rate limit: until=%v ok=%v", until, ok)
	}
	if _, ok := cveRadarGitHubRateLimit(http.StatusUnauthorized, h, now); ok {
		t.Error("401 is a dead token, not a rate limit")
	}
}

func TestCVERadarNVDFetchPages(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("lastModStartDate") == "" {
			t.Errorf("query missing lastModStartDate: %s", r.URL.RawQuery)
		}
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		var vulns []map[string]any
		for i := start; i < 450 && i < start+nvdPageLimit; i++ {
			vulns = append(vulns, map[string]any{"cve": map[string]any{"id": fmt.Sprintf("CVE-2026-%05d", i)}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 450, "resultsPerPage": len(vulns), "vulnerabilities": vulns})
	}))
	defer srv.Close()
	savedURL, savedSleep := nvdBaseURL, nvdSleep
	nvdBaseURL, nvdSleep = srv.URL+"/", func(time.Duration) {}
	t.Cleanup(func() { nvdBaseURL, nvdSleep = savedURL, savedSleep })

	got, err := cveRadarNVDFetch("lastMod", "2026-10-07T00:00:00.000Z", "2026-10-07T01:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 450 || calls != 3 {
		t.Fatalf("got %d CVEs in %d request(s), want all 450 in 3 pages", len(got), calls)
	}
}

func TestCVERadarAlertTextEscapes(t *testing.T) {
	msg := cveRadarAlertText([]cveRadarItem{{
		ID: "CVE-2026-1", CVSS: 9.8, Link: "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
		Desc: "RCE in **thing** see [nvd](https://evil.example) @here",
	}}, 0)
	if strings.Contains(msg, "[nvd](") || strings.Contains(msg, "@here") || strings.Contains(msg, "**thing**") {
		t.Fatalf("description not escaped:\n%s", msg)
	}
	if !strings.Contains(msg, "<https://nvd.nist.gov/vuln/detail/CVE-2026-1>") {
		t.Fatalf("NVD link missing/mangled:\n%s", msg)
	}
}

func TestCVERadarGHSAFetchFollowsCursorStopsAtFloor(t *testing.T) {
	withTestSQLite(t)
	now := time.Now().UTC()
	adv := func(id string, age time.Duration) map[string]any {
		return map[string]any{
			"cve_id":       id,
			"summary":      id + " summary",
			"severity":     "critical",
			"published_at": now.Add(-age).Format(time.RFC3339),
			"html_url":     "https://github.com/advisories/" + id,
		}
	}
	calls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("after") == "" {
			w.Header().Set("Link", `<`+srv.URL+`/?after=cursor1>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]map[string]any{adv("CVE-2026-NEW", time.Hour), adv("CVE-2026-LATE", 40*time.Hour)})
			return
		}
		// Page 2 dips below the 72h floor — the fetch must stop after it.
		_ = json.NewEncoder(w).Encode([]map[string]any{adv("CVE-2026-P2", 50*time.Hour), adv("CVE-2026-OLD", 100*time.Hour)})
	}))
	defer srv.Close()

	savedURL, savedBackoff := cveRadarGHSAURL, cveRadarGHBackoffUntil.Swap(0)
	cveRadarGHSAURL = srv.URL
	t.Cleanup(func() { cveRadarGHSAURL = savedURL; cveRadarGHBackoffUntil.Store(savedBackoff) })

	got, ok := cveRadarGHSAFetch(now.Add(-cveRadarGHSALookback))
	if !ok {
		t.Fatal("fetch reported failure on a healthy first page")
	}
	if len(got) != 4 || calls != 2 {
		t.Fatalf("got %d advisories in %d request(s), want 4 in 2 pages", len(got), calls)
	}
	if got[0].CVEID != "CVE-2026-NEW" || got[3].CVEID != "CVE-2026-OLD" {
		t.Fatalf("unexpected advisory order: %s .. %s", got[0].CVEID, got[3].CVEID)
	}
}

func TestCVERadarGHSAFetchFirstPageFailure(t *testing.T) {
	withTestSQLite(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	savedURL, savedBackoff := cveRadarGHSAURL, cveRadarGHBackoffUntil.Swap(0)
	cveRadarGHSAURL = srv.URL
	t.Cleanup(func() { cveRadarGHSAURL = savedURL; cveRadarGHBackoffUntil.Store(savedBackoff) })

	got, ok := cveRadarGHSAFetch(time.Now().UTC().Add(-cveRadarGHSALookback))
	if ok || got != nil {
		t.Fatalf("want not-ok on first-page failure, got ok=%v advisories=%d", ok, len(got))
	}
}

// TestCVERadarPollPicksUpLateVisibleGHSAAdvisory is the CVE-2026-107806
// regression: the advisory carried published_at 2026-10-09 20:45Z but only
// became list-visible days later, by which time the cycle watermark had
// advanced past its stamp and it was permanently excluded. The 72h lookback
// must admit it with a watermark only 15 minutes old.
func TestCVERadarPollPicksUpLateVisibleGHSAAdvisory(t *testing.T) {
	withTestSQLite(t)
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"totalResults": 0, "vulnerabilities": []any{}})
	}))
	defer nvd.Close()
	pub := time.Now().UTC().Add(-40 * time.Hour).Format(time.RFC3339)
	ghsa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]any{{
			"cve_id":       "CVE-2026-107806",
			"summary":      "nginx-ui RCE via config test command",
			"severity":     "critical",
			"published_at": pub,
			"html_url":     "https://github.com/advisories/GHSA-test",
		}})
	}))
	defer ghsa.Close()

	savedURL, savedSleep := nvdBaseURL, nvdSleep
	nvdBaseURL, nvdSleep = nvd.URL+"/", func(time.Duration) {}
	savedGHSA, savedBackoff := cveRadarGHSAURL, cveRadarGHBackoffUntil.Swap(0)
	cveRadarGHSAURL = ghsa.URL
	t.Cleanup(func() {
		nvdBaseURL, nvdSleep = savedURL, savedSleep
		cveRadarGHSAURL = savedGHSA
		cveRadarGHBackoffUntil.Store(savedBackoff)
	})

	items, err := cveRadarPoll(time.Now().UTC().Add(-15*time.Minute), cveRadarKeywordRE())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("want the 40h-old late-visible advisory as an item, got %d", len(items))
	}
	if items[0].ID != "CVE-2026-107806" || items[0].CVSS != 9.5 {
		t.Fatalf("got %+v, want CVE-2026-107806 at the critical severity floor 9.5", items[0])
	}
}
