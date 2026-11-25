package db

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFindingsMergeSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "merge.db"))
	findingsMergeContract(t)
}

// Prod runs Postgres: the joined list, facet SUMs and the partial unique
// index must hold there too.
func TestFindingsMergePostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingsMergeContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
	_ = SetSetting(findingsMergedKey, "")
}

func findingsMergeContract(t *testing.T) {
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
	c, _, err := findingDB()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.exec(`DELETE FROM findings`)
	_ = c.exec(`DELETE FROM ai_triage`)
	_ = SetSetting(findingsMergedKey, "")

	// Two AI verdicts; the first was already promoted by hand from the old page.
	for _, r := range []*TriageRecord{
		{ID: "k1", ScanID: "s1", TemplateID: "CVE-2026-21589", Title: "Atlassian file read", Host: "https://jira.acme.com",
			MatchedAt: "https://jira.acme.com/x", Severity: "critical", AISeverity: "high", Verdict: "true_positive", Confidence: 90,
			Reportable: true, Scope: "in", ScopeProgram: "bc acme", Status: "done", ReportMD: "## draft", CreatedAt: 100, UpdatedAt: 200},
		{ID: "k2", ScanID: "s1", TemplateID: "tech-detect", Title: "nginx", Host: "acme.com", MatchedAt: "https://acme.com/",
			Severity: "info", Verdict: "false_positive", Confidence: 97, Status: "done", CreatedAt: 100, UpdatedAt: 150},
	} {
		if err := UpsertTriage(r); err != nil {
			t.Fatal(err)
		}
	}
	promoted := &Finding{Title: "Atlassian file read", Host: "jira.acme.com", Source: "triage:k1", Status: "validated"}
	if err := CreateFinding(promoted); err != nil {
		t.Fatal(err)
	}

	created, linked, err := MergeTriageIntoFindings()
	if err != nil || created != 1 || linked != 1 {
		t.Fatalf("merge: created=%d linked=%d err=%v", created, linked, err)
	}
	if c2, l2, _ := MergeTriageIntoFindings(); c2 != 0 || l2 != 0 {
		t.Fatalf("merge must run once: %d %d", c2, l2)
	}

	all, total, err := ListFindings(FindingFilter{})
	if err != nil || total != 2 {
		t.Fatalf("list: %d %v", total, err)
	}
	byKey := map[string]*Finding{}
	for _, f := range all {
		byKey[f.FKey] = f
	}
	p := byKey["k1"]
	if p == nil || p.ID != promoted.ID || p.Status != "validated" || p.AI == nil || !p.AI.Reportable || !p.AI.HasReport {
		t.Fatalf("promoted finding must be linked, not duplicated: %+v %+v", p, p.AI)
	}
	n := byKey["k2"]
	if n == nil || n.Severity != "info" || n.Module != "nuclei" || n.Host != "acme.com" || n.AI == nil || n.AI.Verdict != "false_positive" {
		t.Fatalf("migrated finding: %+v", n)
	}

	check := func(f FindingFilter, want int) {
		t.Helper()
		_, n, err := ListFindings(f)
		if err != nil || n != want {
			t.Fatalf("%+v: got %d (%v), want %d", f, n, err, want)
		}
	}
	check(FindingFilter{AI: "reportable"}, 1)
	check(FindingFilter{AI: "false_positive"}, 1)
	check(FindingFilter{AI: "unreviewed"}, 0)
	check(FindingFilter{Severity: "high"}, 1) // the model's severity wins over the template's "critical"
	check(FindingFilter{Q: "JIRA"}, 1)
	check(FindingFilter{ScanID: "s1"}, 1) // the promoted row predates scan provenance

	// The unique key keeps one finding per hit.
	if _, err := RecordScanFinding(&Finding{Title: "nginx", FKey: "k2", ScanID: "s2"}); err != nil {
		t.Fatal(err)
	}
	check(FindingFilter{}, 2)
	if f, _ := GetFinding(n.ID); f.ScanID != "s2" || f.LastSeen == 0 {
		t.Fatalf("re-seen hit should refresh scan/last_seen: %+v", f)
	}

	facets, err := GetFindingFacets("")
	if err != nil || facets.Total != 2 || facets.AI["reportable"] != 1 || facets.Status["validated"] != 1 {
		t.Fatalf("facets: %+v %v", facets, err)
	}
	if got, _ := GetFinding(promoted.ID); got.AI == nil || got.AI.ReportMD != "## draft" {
		t.Fatalf("detail should carry the AI draft: %+v", got.AI)
	}
}

// Prod already has a findings table in the old shape; the new columns and the
// partial unique index must be added in place without losing rows.
func TestFindingsLegacyTableSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "legacy.db"))
	findingsLegacyContract(t)
}

func TestFindingsLegacyTablePostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingsLegacyContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
	}
}

func findingsLegacyContract(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	var raw triageConn
	idCol := "id INTEGER PRIMARY KEY AUTOINCREMENT"
	switch d := dbInstance.(type) {
	case *PostgresDB:
		raw, idCol = pgTriage{p: d}, "id BIGSERIAL PRIMARY KEY"
	case *SQLiteDB:
		raw = sqliteTriage{s: d}
	}
	_ = raw.exec(`DROP TABLE IF EXISTS findings`)
	if err := raw.exec(`CREATE TABLE findings (` + idCol + `, title TEXT NOT NULL, cve TEXT NOT NULL DEFAULT '',
		host TEXT NOT NULL DEFAULT '', program TEXT NOT NULL DEFAULT '', platform TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '', cvss REAL NOT NULL DEFAULT 0, source TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'discovered', report_ref TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
		report_md TEXT NOT NULL DEFAULT '', first_seen BIGINT NOT NULL DEFAULT 0, updated_at BIGINT NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if err := raw.exec(`INSERT INTO findings (title, host, status, updated_at) VALUES ('legacy row', 'old.acme.com', 'submitted', 5)`); err != nil {
		t.Fatal(err)
	}
	findingReadyOn, findingReadyOnce = nil, false // force the migration on this instance

	rows, total, err := ListFindings(FindingFilter{})
	if err != nil || total != 1 || rows[0].Title != "legacy row" || rows[0].FKey != "" || rows[0].AI != nil {
		t.Fatalf("legacy row after migration: %d %v %+v", total, err, rows)
	}
	// Two manual rows may both have an empty fkey (partial index) …
	if err := CreateFinding(&Finding{Title: "manual 2"}); err != nil {
		t.Fatalf("second empty-fkey row: %v", err)
	}
	// … but a scan key is unique.
	if _, err := RecordScanFinding(&Finding{Title: "hit", FKey: "kx", ScanID: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := CreateFinding(&Finding{Title: "dup hit", FKey: "kx"}); err == nil {
		t.Fatal("duplicate fkey must be rejected by the unique index")
	}
}

// The verdict filters follow the operator first. Mirrors prod on 2026-10-18:
// 11 validated/drafted/submitted/resolved findings without an AI review sat
// under "Not reviewed", an approved one under "Needs review", and "True
// positive" / "Reportable" showed 0.
func TestFindingVerdictFollowsWorkflowSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "wf.db"))
	findingWorkflowContract(t)
}

func TestFindingVerdictFollowsWorkflowPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingWorkflowContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
}

func findingWorkflowContract(t *testing.T) {
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
	c, _, err := findingDB()
	if err != nil {
		t.Fatal(err)
	}
	_ = c.exec(`DELETE FROM findings`)
	_ = c.exec(`DELETE FROM ai_triage`)
	mk := func(title, status, fkey string) {
		t.Helper()
		if err := CreateFinding(&Finding{Title: title, Status: status, FKey: fkey}); err != nil {
			t.Fatal(err)
		}
	}
	for _, st := range []string{"validated", "validated", "drafted", "submitted", "resolved"} {
		mk(st+" by hand", st, "")
	}
	mk("approved, AI unsure", "approved", "k-approved")
	mk("AI false positive", "discovered", "k-fp")
	mk("AI reportable", "discovered", "k-rep")
	mk("untouched", "discovered", "")
	mk("rejected by program", "rejected", "")
	mk("AI said TP, you said FP", "validated", "k-override")
	for _, r := range []*TriageRecord{
		{ID: "k-approved", Title: "x", Verdict: "needs_manual_review", Status: "done", CreatedAt: 1, UpdatedAt: 1},
		{ID: "k-fp", Title: "x", Verdict: "false_positive", Status: "done", CreatedAt: 1, UpdatedAt: 1},
		{ID: "k-rep", Title: "x", Verdict: "true_positive", Reportable: true, Status: "done", CreatedAt: 1, UpdatedAt: 1},
		{ID: "k-override", Title: "x", Verdict: "true_positive", HumanVerdict: "false_positive", Status: "done", CreatedAt: 1, UpdatedAt: 1},
	} {
		if err := UpsertTriage(r); err != nil {
			t.Fatal(err)
		}
	}
	f, err := GetFindingFacets("")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"reportable":          4, // 2 validated + drafted + approved (AI-reportable untouched one adds 1 below)
		"true_positive":       7, // validated×2, drafted, submitted, resolved, approved, AI-TP untouched
		"needs_manual_review": 0, // the approved one is yours now
		"false_positive":      3, // AI FP, rejected, your override
		"unreviewed":          1, // the untouched one
	}
	want["reportable"]++ // the untouched AI-reportable finding
	for k, n := range want {
		if f.AI[k] != n {
			t.Errorf("%s = %d, want %d (facets %+v)", k, f.AI[k], n, f.AI)
		}
	}
	// The filters agree with the counts.
	for k, n := range want {
		if _, total, err := ListFindings(FindingFilter{AI: k}); err != nil || total != n {
			t.Errorf("filter %s: %d (%v), want %d", k, total, err, n)
		}
	}
}

func TestUpdateFindingFieldsSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "edit.db"))
	findingEditContract(t)
}

func TestUpdateFindingFieldsPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingEditContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
}

func findingEditContract(t *testing.T) {
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
	f := &Finding{Title: "XSS", Host: "a.acme.com", Severity: "medium", Status: "discovered", Notes: "n1"}
	if err := CreateFinding(f); err != nil {
		t.Fatal(err)
	}
	str := func(s string) *string { return &s }
	cvss := 7.4
	if err := UpdateFindingFields(f.ID, FindingEdit{Title: str("Stored XSS"), Severity: str("HIGH"), CVSS: &cvss,
		CVE: str("cve-2026-9"), Notes: str(""), Status: str("validated"), ReportMD: str("## r")}); err != nil {
		t.Fatal(err)
	}
	got, err := GetFinding(f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Title != "Stored XSS" || got.Severity != "high" || got.CVSS != 7.4 || got.CVE != "CVE-2026-9" ||
		got.Notes != "" || got.Status != "validated" || got.ReportMD != "## r" || got.Host != "a.acme.com" {
		t.Fatalf("edited: %+v", got)
	}
	bad := 10.5
	for name, e := range map[string]FindingEdit{
		"severity": {Severity: str("extreme")}, "status": {Status: str("pwned")}, "cvss": {CVSS: &bad},
		"title": {Title: str(" ")}, "empty": {},
	} {
		if err := UpdateFindingFields(f.ID, e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := UpdateFindingFields(987654, FindingEdit{Title: str("x")}); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestFindingProgramMatchSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "prog.db"))
	findingProgramContract(t)
}

func TestFindingProgramMatchPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingProgramContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
}

// Findings carry how their program was found; a hit seen again fills a
// missing program but never replaces one; the backfill helpers only touch
// findings without a program.
func findingProgramContract(t *testing.T) {
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
	a := &Finding{Title: "a", Host: "888kiss.aliexpress.com", FKey: "fk-a", ScanID: "s1", Platform: "h1", Program: "alibaba", ProgramMatch: "related"}
	if _, err := RecordScanFinding(a); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetFinding(a.ID); got.ProgramMatch != "related" || got.Program != "alibaba" {
		t.Fatalf("stored: %+v", got)
	}
	// Seen again with no program: the existing one stays.
	if _, err := RecordScanFinding(&Finding{Title: "a", FKey: "fk-a", ScanID: "s2"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetFinding(a.ID); got.Program != "alibaba" || got.ProgramMatch != "related" || got.ScanID != "s2" {
		t.Fatalf("re-sighting cleared the program: %+v", got)
	}
	b := &Finding{Title: "b", Host: "x.acme.com", FKey: "fk-b", ScanID: "s1"}
	_, _ = RecordScanFinding(b)
	// Seen again once the catalog knows the host: the program is filled in.
	_, _ = RecordScanFinding(&Finding{Title: "b", FKey: "fk-b", ScanID: "s3", Platform: "bc", Program: "acme", ProgramMatch: "in"})
	if got, _ := GetFinding(b.ID); got.Program != "acme" || got.Platform != "bc" || got.ProgramMatch != "in" {
		t.Fatalf("missing program not filled: %+v", got)
	}
	c := &Finding{Title: "c", Host: "y.acme.com", FKey: "fk-c"}
	d := &Finding{Title: "d", Host: "z.acme.com", FKey: "fk-d"}
	_, _ = RecordScanFinding(c)
	_, _ = RecordScanFinding(d)
	gaps, err := FindingsMissingProgram(0, 10)
	if err != nil || len(gaps) != 2 || gaps[0].ID != c.ID || gaps[1].Host != "z.acme.com" {
		t.Fatalf("gaps: %+v %v", gaps, err)
	}
	if gaps, _ := FindingsMissingProgram(c.ID, 10); len(gaps) != 1 || gaps[0].ID != d.ID {
		t.Fatalf("paging: %+v", gaps)
	}
	if err := SetFindingProgram(c.ID, "ywh", "acme-bbp", "guess"); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetFinding(c.ID); got.Program != "acme-bbp" || got.ProgramMatch != "guess" {
		t.Fatalf("set: %+v", got)
	}
	// Never over a program that is already set.
	_ = SetFindingProgram(c.ID, "h1", "other", "in")
	if got, _ := GetFinding(c.ID); got.Program != "acme-bbp" {
		t.Fatalf("overwrote: %+v", got)
	}
	// A hand edit clears the match label.
	prog := "acme-private"
	if err := UpdateFindingFields(c.ID, FindingEdit{Program: &prog}); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetFinding(c.ID); got.Program != "acme-private" || got.ProgramMatch != "" {
		t.Fatalf("hand edit: %+v", got)
	}
	rows, _, err := ListFindings(FindingFilter{Q: "aliexpress"})
	if err != nil || len(rows) != 1 || rows[0].ProgramMatch != "related" {
		t.Fatalf("list carries program_match: %+v %v", rows, err)
	}
	// Program links come from the catalog, matched case-insensitively.
	for _, p := range []CatalogProgram{
		{Source: "h1", Handle: "Alibaba", URL: "https://hackerone.com/alibaba"},
		{Source: "as93", Handle: "alibaba", URL: "https://security.alibaba.com/"},
		{Source: "bc", Handle: "acme", URL: "https://bugcrowd.com/engagements/acme"},
	} {
		if _, err := UpsertCatalogProgram(p); err != nil {
			t.Fatal(err)
		}
	}
	byHandle, err := CatalogProgramsByHandle([]string{"ALIBABA", " alibaba ", "", "nope"})
	if err != nil || len(byHandle) != 1 || len(byHandle["alibaba"]) != 2 || byHandle["alibaba"][0].URL != "https://hackerone.com/alibaba" {
		t.Fatalf("by handle: %+v %v", byHandle, err)
	}
	if m, err := CatalogProgramsByHandle(nil); err != nil || len(m) != 0 {
		t.Fatalf("no handles: %v %v", m, err)
	}
	// The program filter ignores case.
	if rows, total, _ := ListFindings(FindingFilter{Program: "ALIBABA"}); total != 1 || rows[0].ID != a.ID {
		t.Fatalf("case-insensitive program filter: %d", total)
	}
}

func TestFindingProgramFiltersSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "pf.db"))
	findingProgramFilterContract(t)
}

func TestFindingProgramFiltersPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingProgramFilterContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
}

// Program / platform / report-link filters and their facets.
func findingProgramFilterContract(t *testing.T) {
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
	for i, f := range []*Finding{
		{Title: "a1", Platform: "h1", Program: "alibaba", ReportRef: "https://hackerone.com/reports/1"},
		{Title: "a2", Platform: "h1", Program: "alibaba"},
		{Title: "a3", Platform: "h1", Program: "alibaba"},
		{Title: "c1", Platform: "bc", Program: "cat"},
		{Title: "n1"},
		{Title: "n2", ReportRef: "H1#9"},
	} {
		f.FKey = "pf" + strconv.Itoa(i)
		if err := CreateFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	count := func(f FindingFilter) int {
		t.Helper()
		_, n, err := ListFindings(f)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(FindingFilter{Program: "alibaba"}); n != 3 {
		t.Errorf("program=alibaba: %d", n)
	}
	if n := count(FindingFilter{Program: "alibaba", Platform: "bc"}); n != 0 {
		t.Errorf("program+platform must both match: %d", n)
	}
	if n := count(FindingFilter{Program: NoProgram}); n != 2 {
		t.Errorf("no program: %d", n)
	}
	if n := count(FindingFilter{Report: "1"}); n != 2 {
		t.Errorf("has report link: %d", n)
	}
	if n := count(FindingFilter{Report: "0", Program: "alibaba"}); n != 2 {
		t.Errorf("alibaba without a link: %d", n)
	}
	fc, err := GetFindingFacets("")
	if err != nil {
		t.Fatal(err)
	}
	if fc.NoProgram != 2 || fc.Reported != 2 || fc.Platforms["h1"] != 3 || fc.Platforms["bc"] != 1 || len(fc.Programs) != 2 ||
		fc.Programs[0].Program != "alibaba" || fc.Programs[0].Count != 3 || fc.Programs[0].Platform != "h1" {
		t.Fatalf("facets: %+v", fc)
	}
}

func TestValidReportRef(t *testing.T) {
	for ref, ok := range map[string]bool{
		"": true, "H1#2401337": true, "YWH-PGM1234-56": true, "https://hackerone.com/reports/1": true, "http://x.example/r": true,
		"javascript:alert(1)": false, " JavaScript:alert(1)": false, "data:text/html,x": false, "vbscript:x": false,
		"file:///etc/passwd": false, "ftp://x.example/r": false, "hackerone:123": true,
	} {
		if err := ValidReportRef(ref); (err == nil) != ok {
			t.Errorf("ValidReportRef(%q) = %v, want ok=%v", ref, err, ok)
		}
	}
}

func TestFindingHideClosedSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "closed.db"))
	findingHideClosedContract(t)
}

func TestFindingHideClosedPostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	findingHideClosedContract(t)
	if c, _, err := findingDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS findings`)
		_ = c.exec(`DROP TABLE IF EXISTS ai_triage`)
	}
}

// Rejected / dup / wontfix findings drop out of the default view (list and
// counts) but stay stored; asking for the status shows them.
func findingHideClosedContract(t *testing.T) {
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
	for i, st := range []string{"discovered", "discovered", "validated", "rejected", "rejected", "rejected", "dup", "wontfix", "submitted"} {
		if err := CreateFinding(&Finding{Title: "f" + strconv.Itoa(i), Status: st, FKey: "hc" + strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(f FindingFilter) int {
		t.Helper()
		_, n, err := ListFindings(f)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(FindingFilter{}); n != 9 {
		t.Errorf("default API view keeps everything: %d", n)
	}
	if n := count(FindingFilter{HideClosed: true}); n != 4 {
		t.Errorf("closed hidden: %d", n)
	}
	if n := count(FindingFilter{HideClosed: true, Status: "rejected"}); n != 3 {
		t.Errorf("an explicit status shows closed ones: %d", n)
	}
	fc, err := GetFindingFacetsOpts("", true)
	if err != nil {
		t.Fatal(err)
	}
	if fc.Total != 4 || fc.Closed != 5 || fc.Status["rejected"] != 0 || fc.Status["discovered"] != 2 || fc.AI["false_positive"] != 0 {
		t.Fatalf("hidden facets: %+v", fc)
	}
	all, _ := GetFindingFacetsOpts("", false)
	if all.Total != 9 || all.Closed != 5 || all.Status["rejected"] != 3 {
		t.Fatalf("all facets: %+v", all)
	}
}
