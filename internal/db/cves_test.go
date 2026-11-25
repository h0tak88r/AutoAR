package db

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cveTestDB(t *testing.T) {
	t.Helper()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "cves.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	dbInstance = s
}

func TestCVEUpsertAndTrackState(t *testing.T) {
	cveTestDB(t)

	// Radar upsert with full NVD data.
	if err := UpsertCVE(CVERecord{
		CVEID: "CVE-2026-1234", Description: "RCE in thing", CVSSScore: 9.8,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CWE: "CWE-78",
		PublishedAt: "2026-10-12T00:00:00Z", FirstSeenAt: 100,
	}); err != nil {
		t.Fatalf("UpsertCVE: %v", err)
	}
	rec, err := GetCVE("CVE-2026-1234")
	if err != nil {
		t.Fatalf("GetCVE: %v", err)
	}
	if rec.AttackVector != "Network" || rec.Severity != "critical" || rec.CWE != "CWE-78" {
		t.Errorf("derived fields wrong: AV=%q sev=%q cwe=%q", rec.AttackVector, rec.Severity, rec.CWE)
	}

	// A later, poorer upsert (e.g. GHSA-only data) must not clobber good data
	// or reset tracking state.
	if err := MarkCVEPoC("CVE-2026-1234", 9.8, "github", "https://github.com/x/y", 555); err != nil {
		t.Fatalf("MarkCVEPoC: %v", err)
	}
	if err := UpsertCVE(CVERecord{CVEID: "CVE-2026-1234", CVSSScore: 8.0}); err != nil {
		t.Fatalf("re-UpsertCVE: %v", err)
	}
	rec, _ = GetCVE("CVE-2026-1234")
	if rec.CVSSScore != 8.0 {
		t.Errorf("score should refresh to 8.0, got %.1f", rec.CVSSScore)
	}
	if rec.CWE != "CWE-78" || rec.AttackVector != "Network" {
		t.Errorf("enrichment clobbered by poor upsert: cwe=%q av=%q", rec.CWE, rec.AttackVector)
	}
	if !rec.PoCPublished || rec.FirstPoCAt != 555 {
		t.Errorf("poc state lost: published=%v first=%d", rec.PoCPublished, rec.FirstPoCAt)
	}
	var links []CVEPoCLink
	if err := json.Unmarshal([]byte(rec.PoCLinks), &links); err != nil || len(links) != 1 || links[0].Link != "https://github.com/x/y" {
		t.Errorf("poc links = %s", rec.PoCLinks)
	}

	// Scan-state marking and its no-regress rule.
	if err := MarkCVEScanState("CVE-2026-1234", "pr", "poc-scan-1"); err != nil {
		t.Fatalf("MarkCVEScanState: %v", err)
	}
	if err := MarkCVEScanState("CVE-2026-1234", "merged", ""); err != nil {
		t.Fatalf("MarkCVEScanState 2: %v", err)
	}
	rec, _ = GetCVE("CVE-2026-1234")
	if rec.TemplateStatus != "merged" || !rec.Scanned || rec.ScanID != "poc-scan-1" {
		t.Errorf("scan state wrong: tpl=%q scanned=%v scan=%q", rec.TemplateStatus, rec.Scanned, rec.ScanID)
	}

	// PoC-only stub row (radar confirmed before NVD enriched it).
	if err := MarkCVEPoC("CVE-2026-9999", 7.5, "feed", "https://feed/x", 777); err != nil {
		t.Fatalf("stub MarkCVEPoC: %v", err)
	}
	rec, err = GetCVE("CVE-2026-9999")
	if err != nil || !rec.PoCPublished || rec.Severity != "high" {
		t.Errorf("stub row wrong: %+v err=%v", rec, err)
	}
}

func TestListCVEsFilters(t *testing.T) {
	cveTestDB(t)
	seed := []CVERecord{
		{CVEID: "CVE-2026-A", CVSSScore: 9.8, AttackVector: "Network"},
		{CVEID: "CVE-2026-B", CVSSScore: 7.0, AttackVector: "Local"},
		{CVEID: "CVE-2026-C", CVSSScore: 5.0, AttackVector: "Physical", Description: "wordpress plugin"},
	}
	for _, r := range seed {
		if err := UpsertCVE(r); err != nil {
			t.Fatalf("seed %s: %v", r.CVEID, err)
		}
	}
	_ = MarkCVEPoC("CVE-2026-A", 9.8, "github", "https://x/a", 1)
	_ = MarkCVEScanState("CVE-2026-B", "merged", "scan-b")

	f := CVEFilter{PoCOnly: true}
	rows, total, err := ListCVEs(f)
	if err != nil || total != 1 || len(rows) != 1 || rows[0].CVEID != "CVE-2026-A" {
		t.Errorf("poc filter: total=%d rows=%d err=%v", total, len(rows), err)
	}
	scanned := true
	rows, total, _ = ListCVEs(CVEFilter{Scanned: &scanned})
	if total != 1 || rows[0].CVEID != "CVE-2026-B" {
		t.Errorf("scanned filter: total=%d", total)
	}
	rows, total, _ = ListCVEs(CVEFilter{AV: "physical"})
	if total != 1 || rows[0].CVEID != "CVE-2026-C" {
		t.Errorf("av filter: total=%d", total)
	}
	rows, total, _ = ListCVEs(CVEFilter{MinScore: 7.0})
	if total != 2 {
		t.Errorf("min_score filter: total=%d", total)
	}
	rows, total, _ = ListCVEs(CVEFilter{Q: "wordpress"})
	if total != 1 || rows[0].CVEID != "CVE-2026-C" {
		t.Errorf("q filter: total=%d", total)
	}
}

func TestAttackVectorFromCVSS(t *testing.T) {
	cases := map[string]string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": "Network",
		"CVSS:3.1/AV:A/AC:L":                           "Adjacent",
		"CVSS:3.1/AV:L/AC:L":                           "Local",
		"CVSS:3.1/AV:P/AC:L":                           "Physical",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P":                   "Network", // CVSS v2
		"":                                             "",
		"CVSS:3.1/AC:L":                                "",
	}
	for vec, want := range cases {
		if got := AttackVectorFromCVSS(vec); got != want {
			t.Errorf("AttackVectorFromCVSS(%q) = %q, want %q", vec, got, want)
		}
	}
}

func TestCVERunStatesSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "runstate.db"))
	cveRunStateContract(t)
}

func TestCVERunStatesPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	cveRunStateContract(t)
	if c, err := cveDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS cves`)
		_ = c.exec(`DROP TABLE IF EXISTS pocday_runs`)
	}
}

// Run states ("has anything run against this CVE?") and the auto-race
// worklist — the same SQL on both backends.
func cveRunStateContract(t *testing.T) {
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
	c, _ := cveDB()
	_ = c.exec(`DELETE FROM cves`)
	if p, err := pocdayDB(); err == nil {
		_ = p.exec(`DELETE FROM pocday_runs`)
	}
	base := time.Now().Add(-10 * time.Hour).Unix()
	track := func(id, av string, cvss float64, pocHoursAgo int) {
		t.Helper()
		if err := UpsertCVE(CVERecord{CVEID: id, Description: "d " + id, CVSSScore: cvss, AttackVector: av, FirstSeenAt: base}); err != nil {
			t.Fatal(err)
		}
		if pocHoursAgo > 0 {
			if err := MarkCVEPoC(id, cvss, "cve-daily-brief", "https://github.com/x/"+id, time.Now().Add(-time.Duration(pocHoursAgo)*time.Hour).Unix()); err != nil {
				t.Fatal(err)
			}
		}
	}
	track("CVE-2026-7001", "Network", 9.0, 1) // never, eligible (newest PoC)
	track("CVE-2026-7002", "", 0, 2)          // never, eligible (unknown vector + score)
	track("CVE-2026-7009", "Network", 9.0, 3) // never, eligible
	track("CVE-2026-7010", "Network", 9.0, 4) // never, eligible (oldest)
	track("CVE-2026-7003", "Local", 9.8, 1)   // never, not reachable
	track("CVE-2026-7004", "Network", 5.0, 1) // never, below the CVSS floor
	track("CVE-2026-7005", "Network", 9.0, 1) // never, labeled skip
	_ = SetCVELabel("CVE-2026-7005", "Skip")
	track("CVE-2026-7006", "Network", 9.0, 1) // tried: no template
	_ = SavePocdayRun(&PocdayRun{CVEID: "CVE-2026-7006", Status: "no_template"})
	track("CVE-2026-7007", "Network", 9.0, 0) // never, no PoC
	track("CVE-2026-7008", "Network", 8.0, 1) // ran: swept
	_ = MarkCVEScanState("CVE-2026-7008", "merged", "sweep-1")
	track("CVE-2026-7011", "Network", 9.0, 1) // active
	_ = SavePocdayRun(&PocdayRun{CVEID: "CVE-2026-7011", Status: "resolving"})
	track("CVE-2026-7012", "Network", 9.0, 1) // ran: PoC-day done
	_ = SavePocdayRun(&PocdayRun{CVEID: "CVE-2026-7012", Status: "done", ScanID: "race-cve-2026-7012-1"})
	_ = MarkCVEScanState("CVE-2026-7012", "ai", "race-cve-2026-7012-1")

	recs, total, err := ListUnracedPoCCVEs(3, 7.0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range recs {
		got = append(got, r.CVEID)
	}
	if total != 4 || strings.Join(got, ",") != "CVE-2026-7001,CVE-2026-7002,CVE-2026-7009" {
		t.Fatalf("worklist: total=%d %v", total, got)
	}
	if _, n, _ := ListUnracedPoCCVEs(0, 7.0); n != 4 {
		t.Fatalf("count-only: %d", n)
	}

	counts, err := CountPoCCVEsByRunState()
	if err != nil {
		t.Fatal(err)
	}
	if counts[CVERunNever] != 7 || counts[CVERunTried] != 1 || counts[CVERunActive] != 1 || counts[CVERunRan] != 2 {
		t.Fatalf("counts (PoC CVEs only): %v", counts)
	}
	want := map[string]string{CVERunNever: "8", CVERunTried: "CVE-2026-7006", CVERunActive: "CVE-2026-7011", CVERunRan: "CVE-2026-7008,CVE-2026-7012"}
	for st, exp := range want {
		rows, n, err := ListCVEs(CVEFilter{RunState: st, Limit: 100})
		if err != nil {
			t.Fatalf("%s: %v", st, err)
		}
		var ids []string
		for _, r := range rows {
			ids = append(ids, r.CVEID)
		}
		sort.Strings(ids)
		if st == CVERunNever {
			if strconv.Itoa(n) != exp {
				t.Fatalf("never: %d %v", n, ids)
			}
			continue
		}
		if strings.Join(ids, ",") != exp {
			t.Fatalf("%s: %v", st, ids)
		}
	}
	if _, _, err := ListCVEs(CVEFilter{RunState: "bogus"}); err == nil {
		t.Fatal("unknown run state accepted")
	}
	// The Go classifier agrees with the SQL.
	for id, st := range map[string]string{"CVE-2026-7001": CVERunNever, "CVE-2026-7006": CVERunTried,
		"CVE-2026-7011": CVERunActive, "CVE-2026-7008": CVERunRan, "CVE-2026-7012": CVERunRan} {
		rec, _ := GetCVE(id)
		run, _ := GetPocdayRun(id)
		if got := CVERunState(rec, run); got != st {
			t.Errorf("%s: %s, want %s", id, got, st)
		}
	}
}

// A pocday_runs table from the first v4.21 builds (no AI attempt columns)
// is migrated in place.
func TestPocdayRunsMigratesOldTable(t *testing.T) {
	cveTestDB(t)
	s := dbInstance.(*SQLiteDB)
	if _, err := s.db.Exec(`CREATE TABLE pocday_runs (cve_id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'queued',
		template_source TEXT NOT NULL DEFAULT '', template_id TEXT NOT NULL DEFAULT '', template_path TEXT NOT NULL DEFAULT '',
		keywords TEXT NOT NULL DEFAULT '', hosts INTEGER NOT NULL DEFAULT 0, hosts_matched INTEGER NOT NULL DEFAULT 0,
		hits INTEGER NOT NULL DEFAULT 0, scan_id TEXT NOT NULL DEFAULT '', sweep_scan_id TEXT NOT NULL DEFAULT '',
		sweep_pending INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0,
		poc_at BIGINT NOT NULL DEFAULT 0, queued_at BIGINT NOT NULL DEFAULT 0, template_at BIGINT NOT NULL DEFAULT 0,
		started_at BIGINT NOT NULL DEFAULT 0, finished_at BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	pocdayMu.Lock()
	pocdayReadyOn = nil
	pocdayMu.Unlock()
	if err := SavePocdayRun(&PocdayRun{CVEID: "CVE-2026-1", Status: "no_template", AITried: 2, AIDeclined: true}); err != nil {
		t.Fatal(err)
	}
	run, err := GetPocdayRun("CVE-2026-1")
	if err != nil || run == nil || run.AITried != 2 || !run.AIDeclined {
		t.Fatalf("migrated row: %+v %v", run, err)
	}
	pocdayMu.Lock()
	pocdayReadyOn = nil
	pocdayMu.Unlock()
	if _, err := GetPocdayRun("CVE-2026-1"); err != nil {
		t.Fatalf("second migration pass: %v", err)
	}
}
