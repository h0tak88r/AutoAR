package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPocdayAndFingerprintsSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "pocday.db"))
	pocdayFingerprintContract(t)
}

// Prod runs Postgres: the partial index (CREATE INDEX CONCURRENTLY), the
// boolean is_live, the CASE/|| URL expression and the upsert must hold there.
func TestPocdayAndFingerprintsPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	pocdayFingerprintContract(t)
	if c, _, err := fingerprintDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS pocday_runs`)
		_ = c.exec(`DELETE FROM subdomains`)
		_ = c.exec(`DELETE FROM domains`)
	}
}

func pocdayFingerprintContract(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if err := InitSchema(); err != nil {
		t.Fatal(err)
	}
	fpReadyOn, pocdayReadyOn = nil, nil
	if c, _, err := fingerprintDB(); err == nil {
		_ = c.exec(`DELETE FROM subdomains`)
	} else {
		t.Fatal(err)
	}

	// ── fingerprints ──
	for _, h := range []struct {
		sub       string
		live      bool
		httpsCode int
		httpURL   string
		httpCode  int
	}{
		{"git.acme.com", true, 200, "", 0},
		{"jira.acme.com", true, 200, "", 0},
		{"plain.acme.com", true, 0, "http://plain.acme.com", 200}, // only http answered
		{"dead.acme.com", false, 0, "", 0},
	} {
		if err := InsertSubdomain("acme.com", h.sub, h.live, h.httpURL, "https://"+h.sub, h.httpCode, h.httpsCode); err != nil {
			t.Fatalf("insert %s: %v", h.sub, err)
		}
	}
	backlog, err := FingerprintBacklog(10)
	if err != nil || len(backlog) != 3 {
		t.Fatalf("backlog: %d %v (want the 3 live hosts)", len(backlog), err)
	}
	urls := map[string]string{}
	ids := map[string]int64{}
	for _, b := range backlog {
		urls[b.Subdomain], ids[b.Subdomain] = b.URL, b.ID
	}
	if urls["plain.acme.com"] != "http://plain.acme.com" || urls["git.acme.com"] != "https://git.acme.com" {
		t.Fatalf("best URLs: %v", urls)
	}
	if err := SaveFingerprints([]FingerprintResult{
		{ID: ids["git.acme.com"], Techs: "GitLab,Nginx", Title: "Sign in · GitLab", Server: "nginx"},
		{ID: ids["jira.acme.com"], Title: "System Dashboard - Acme JIRA", Server: "Apache-Coyote"},
		{ID: ids["plain.acme.com"]}, // did not answer: stamped, nothing learned
	}); err != nil {
		t.Fatal(err)
	}
	if b, _ := FingerprintBacklog(10); len(b) != 0 {
		t.Fatalf("every probed host must leave the backlog, %d left", len(b))
	}
	cov, err := FingerprintCoverage()
	if err != nil || cov.Live != 3 || cov.Fingerprinted != 3 || cov.WithTech != 1 {
		t.Fatalf("coverage: %+v %v", cov, err)
	}
	hosts, total, err := MatchHostsByFingerprint([]string{"gitlab"}, 10)
	if err != nil || total != 1 || len(hosts) != 1 || hosts[0].Subdomain != "git.acme.com" || hosts[0].Via != "techs:gitlab" {
		t.Fatalf("techs match: %+v total=%d %v", hosts, total, err)
	}
	hosts, total, _ = MatchHostsByFingerprint([]string{"jira", "gitlab"}, 10)
	if total != 2 || len(hosts) != 2 || hosts[0].Subdomain != "git.acme.com" || hosts[1].Via != "title:jira" {
		t.Fatalf("tech matches first, then title: %+v", hosts)
	}
	if hosts, total, _ = MatchHostsByFingerprint([]string{"jira", "gitlab"}, 1); len(hosts) != 1 || total != 2 {
		t.Fatalf("cap: %+v total=%d", hosts, total)
	}
	if hosts, _, _ := MatchHostsByFingerprint([]string{"%", "a_"}, 10); len(hosts) != 0 {
		t.Fatalf("wildcards/short keywords must not match everything: %+v", hosts)
	}
	rows, n, err := FilterLiveHosts("acme jira", 10)
	if err != nil || n != 1 || rows[0]["host"] != "jira.acme.com" || rows[0]["title"] == "" {
		t.Fatalf("corpus_filter must match titles too: %v n=%d %v", rows, n, err)
	}

	// ── pocday runs ──
	r := &PocdayRun{CVEID: "cve-2026-1111", Status: "running", TemplateSource: "ai", Hosts: 2, SweepPending: true, PoCAt: 100, QueuedAt: 110}
	if err := SavePocdayRun(r); err != nil {
		t.Fatal(err)
	}
	r.Status, r.Hits, r.FinishedAt = "done", 1, 200
	if err := SavePocdayRun(r); err != nil {
		t.Fatal(err)
	}
	got, err := GetPocdayRun("CVE-2026-1111")
	if err != nil || got == nil || got.Status != "done" || got.Hits != 1 || !got.SweepPending || got.TemplateSource != "ai" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if none, err := GetPocdayRun("CVE-2026-9999"); err != nil || none != nil {
		t.Fatalf("missing run should be (nil, nil): %+v %v", none, err)
	}
	_ = SavePocdayRun(&PocdayRun{CVEID: "CVE-2026-2222", Status: "no_template"})
	if list, _ := ListPocdayRuns(10, "no_template"); len(list) != 1 || list[0].CVEID != "CVE-2026-2222" {
		t.Fatalf("status filter: %+v", list)
	}
	byID, err := PocdayRunsFor([]string{"CVE-2026-1111", "CVE-2026-2222", "CVE-2026-3333"})
	if err != nil || len(byID) != 2 || byID["CVE-2026-1111"] == nil {
		t.Fatalf("runs for ids: %+v %v", byID, err)
	}
}

func TestFindingValidationsSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "fv.db"))
	findingValidationContract(t)
}

func TestFindingValidationsPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingValidationContract(t)
	if c, err := findingValidationDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS finding_validations`)
	}
}

func findingValidationContract(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	fvReadyOn = nil
	if err := SaveFindingValidation(&FindingValidation{FindingID: 7, Status: "queued", QueuedAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := SaveFindingValidation(&FindingValidation{FindingID: 7, Status: "done", Verdict: "true_positive", Confidence: 90,
		Reportable: true, Evidence: "curl …", SessionID: "validate-f7-1", Steps: 4, QueuedAt: 1, FinishedAt: 9}); err != nil {
		t.Fatal(err)
	}
	_ = SaveFindingValidation(&FindingValidation{FindingID: 8, Status: "running"})
	v, err := GetFindingValidation(7)
	if err != nil || v == nil || v.Status != "done" || !v.Reportable || v.Steps != 4 || v.SessionID != "validate-f7-1" {
		t.Fatalf("round trip: %+v %v", v, err)
	}
	if none, err := GetFindingValidation(99); err != nil || none != nil {
		t.Fatalf("missing: %+v %v", none, err)
	}
	m, err := FindingValidationsFor([]int64{7, 8, 9})
	if err != nil || len(m) != 2 || m[8].Status != "running" {
		t.Fatalf("for ids: %+v %v", m, err)
	}
	if busy, _ := ListFindingValidations(10, "queued", "running"); len(busy) != 1 || busy[0].FindingID != 8 {
		t.Fatalf("busy list: %+v", busy)
	}
}

func TestScopeAutopilotStoreSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "ap.db"))
	autopilotStoreContract(t)
}

func TestScopeAutopilotStorePostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	autopilotStoreContract(t)
	if c, err := autopilotDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS scope_autopilot_runs`)
		_ = c.exec(`DROP TABLE IF EXISTS program_asset_snapshots`)
	}
}

func autopilotStoreContract(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	apReadyOn = nil
	if _, _, ok, err := GetAssetSnapshot("h1|acme"); err != nil || ok {
		t.Fatalf("empty snapshot: ok=%v err=%v", ok, err)
	}
	assets := []ScopeAsset{{Asset: "*.acme.com", Type: "WILDCARD"}, {Asset: "api.acme.com"}}
	if err := SaveAssetSnapshot("h1|acme", "d1", assets); err != nil {
		t.Fatal(err)
	}
	_ = SaveAssetSnapshot("h1|acme", "d2", append(assets, ScopeAsset{Asset: "pay.acme.com"}))
	got, digest, ok, err := GetAssetSnapshot("h1|acme")
	if err != nil || !ok || digest != "d2" || len(got) != 3 || got[0].Type != "WILDCARD" {
		t.Fatalf("snapshot: %+v %s %v %v", got, digest, ok, err)
	}
	if n, _ := CountAssetSnapshots(); n != 1 {
		t.Fatalf("count: %d", n)
	}
	a := &AutopilotRun{EventID: "e1", ProgramKey: "h1|acme", Platform: "h1", Handle: "acme", Asset: "pay.acme.com",
		ScanType: "subdomain_run", Target: "pay.acme.com", PlannedBy: "ai", OffersBounty: true}
	b := &AutopilotRun{EventID: "e1", ProgramKey: "h1|acme", Asset: "pay.acme.com", ScanType: "nuclei_target:cves", Target: "pay.acme.com"}
	if err := InsertAutopilotRun(a); err != nil || a.ID == 0 {
		t.Fatalf("insert a: id=%d %v", a.ID, err)
	}
	if err := InsertAutopilotRun(b); err != nil || b.ID <= a.ID {
		t.Fatalf("insert b: id=%d %v", b.ID, err)
	}
	a.Status, a.ScanID, a.LaunchedAt = "launched", "scan-1", time.Now().Unix()
	if err := UpdateAutopilotRun(a); err != nil {
		t.Fatal(err)
	}
	if n, _ := CountAutopilotLaunchedSince(time.Now().Add(-time.Hour).Unix()); n != 1 {
		t.Fatalf("launched since: %d", n)
	}
	if rs, _ := ListAutopilotRuns(10, "planned"); len(rs) != 1 || rs[0].ID != b.ID {
		t.Fatalf("planned: %+v", rs)
	}
	if rs, _ := AutopilotRunsForEvent("e1"); len(rs) != 2 || rs[0].ID != a.ID || !rs[0].OffersBounty || rs[0].ScanID != "scan-1" {
		t.Fatalf("event runs: %+v", rs)
	}
}
