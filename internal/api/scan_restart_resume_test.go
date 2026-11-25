package api

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// fakeLiveHosts serves live hosts with row ids 1..n, page by page; ids in
// blank have no name or URL (skipped by the dump).
func fakeLiveHosts(t *testing.T, n int, blank map[int64]bool) *int {
	t.Helper()
	calls := 0
	old := listLiveHostsAfter
	listLiveHostsAfter = func(cursor int64, limit int) ([]db.GlobalSubdomain, int64, error) {
		calls++
		var out []db.GlobalSubdomain
		next := cursor
		for id := cursor + 1; id <= int64(n) && len(out) < limit; id++ {
			g := db.GlobalSubdomain{}
			if !blank[id] {
				g.Subdomain = fmt.Sprintf("h%d.example.com", id)
				g.HTTPSURL = "https://" + g.Subdomain
			}
			out = append(out, g)
			next = id
		}
		return out, next, nil
	}
	t.Cleanup(func() { listLiveHostsAfter = old })
	return &calls
}

func batchLines(t *testing.T, b *hostBatches) [][]string {
	t.Helper()
	var out [][]string
	for _, f := range b.files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, strings.Fields(string(raw)))
	}
	return out
}

func TestDumpLiveHostBatchesEndOnPages(t *testing.T) {
	fakeLiveHosts(t, 23, map[int64]bool{7: true})
	b, err := dumpLiveHostBatches("s1", 0, 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer b.remove()
	// Pages 1-5, 6-10 | 11-15, 16-20 | 21-23: a batch never splits a page.
	if fmt.Sprint(b.ends) != "[10 20 23]" || fmt.Sprint(b.hosts) != "[9 10 3]" || b.total != 22 {
		t.Fatalf("ends %v hosts %v total %d", b.ends, b.hosts, b.total)
	}
	lines := batchLines(t, b)
	if lines[0][0] != "https://h1.example.com" || lines[1][0] != "https://h11.example.com" || len(lines[2]) != 3 {
		t.Fatalf("batches: %v", lines)
	}
	// Resuming after the first batch dumps only the hosts after its last id.
	r, err := dumpLiveHostBatches("s1", b.ends[0], 10, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer r.remove()
	if fmt.Sprint(r.ends) != "[20 23]" || r.total != 13 || batchLines(t, r)[0][0] != "https://h11.example.com" {
		t.Fatalf("resumed: ends %v total %d", r.ends, r.total)
	}
	// Nothing left after the last batch: one empty batch, no hosts.
	e, err := dumpLiveHostBatches("s1", 23, 10, 5)
	if err != nil || e.total != 0 {
		t.Fatalf("empty: %+v %v", e, err)
	}
	e.remove()
}

func TestDumpLiveHostBatchesFailsOnDBError(t *testing.T) {
	old, oldPause := listLiveHostsAfter, dumpRetryPause
	t.Cleanup(func() { listLiveHostsAfter, dumpRetryPause = old, oldPause })
	dumpRetryPause = 0
	listLiveHostsAfter = func(int64, int) ([]db.GlobalSubdomain, int64, error) { return nil, 0, errors.New("timeout") }
	if b, err := dumpLiveHostBatches("s1", 0, 10, 5); err == nil || b != nil {
		t.Fatal("a DB error must fail the dump, not sweep a partial list")
	}
}

func TestSweepCheckpointAndOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AUTOAR_RESULTS_DIR", dir)
	if _, ok := loadSweepCheckpoint("scan-x"); ok {
		t.Fatal("no checkpoint yet")
	}
	want := sweepCheckpoint{LastID: 25000, Total: 60000, Batches: 1, Scanned: 24990, OutBytes: 4}
	saveSweepCheckpoint("scan-x", want)
	if got, ok := loadSweepCheckpoint("scan-x"); !ok || got != want {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
	if !strings.HasPrefix(filepath.Base(sweepCheckpointPath("scan-x")), ".") {
		t.Fatal("the checkpoint must be a dotfile so it isn't indexed as an artifact")
	}
	clearSweepCheckpoint("scan-x")
	if _, ok := loadSweepCheckpoint("scan-x"); ok {
		t.Fatal("cleared")
	}

	out := filepath.Join(dir, "nuclei-scan-x.json")
	// Two hits before the checkpoint, one from the batch that was cut off.
	os.WriteFile(out, []byte("{a}\n{b}\n{c}\n"), 0o644)
	if n := prepareSweepOutput("scan-x", out, sweepCheckpoint{Total: 1, OutBytes: 8}, true); n != 2 {
		t.Fatalf("resumed hits: %d", n)
	}
	if raw, _ := os.ReadFile(out); string(raw) != "{a}\n{b}\n" {
		t.Fatalf("output after trim: %q", raw)
	}
	// Restarted without a checkpoint: fresh file, the old one kept beside it.
	if n := prepareSweepOutput("scan-x", out, sweepCheckpoint{}, false); n != 0 || fileSize(out) != 0 {
		t.Fatalf("fresh start: %d", n)
	}
	aside, _ := filepath.Glob(out + ".interrupted-*")
	if len(aside) != 1 {
		t.Fatalf("old output not kept: %v", aside)
	}
}

func TestInterruptedScanResumeRules(t *testing.T) {
	dir := t.TempDir()
	tpl := filepath.Join(dir, "scan-1.yaml")
	os.WriteFile(tpl, []byte("id: x\n"), 0o600)
	watchDir := filepath.Join(dir, "nuclei-watch-1")
	os.MkdirAll(watchDir, 0o755)
	rec := func(typ, target, status, cmd string) *db.ScanRecord {
		return &db.ScanRecord{ScanID: "id-" + typ, ScanType: typ, Target: target, Status: status, Command: cmd}
	}
	for _, c := range []struct {
		r    *db.ScanRecord
		want string // "" = resumable, else part of the reason
	}{
		{rec("domain_run", "dflow.net", "running", "inprocess:domain_run target=dflow.net"), ""},
		{rec("subdomain_run", "a.dflow.net", "starting", "inprocess:subdomain_run target=a.dflow.net skip_ffuf=true"), ""},
		{rec("nuclei", "global-subdomains", "running", "inprocess:nuclei target=global-subdomains template="+tpl), ""},
		{rec("nuclei", "global-subdomains", "running", "inprocess:nuclei target=global-subdomains template=http/cves/2026/CVE-2026-1.yaml"), ""},
		{rec("nuclei", watcherSweepTarget, "running", "inprocess:nuclei target=global-subdomains template="+watchDir), ""},
		{rec("domain_run", "dflow.net", "paused", "inprocess:domain_run target=dflow.net"), "it was paused"},
		{rec("nuclei", "race-pass", "running", "inprocess:nuclei target=race-pass template="+tpl), "race pass"},
		{rec("nuclei", "global-subdomains", "running", "inprocess:nuclei target=global-subdomains template="+filepath.Join(dir, "gone.yaml")), "template is gone"},
		{rec("nuclei", "global-subdomains", "running", "inprocess:nuclei target=global-subdomains"), "isn't recorded"},
		{rec("js", "app.acme.com", "running", "inprocess:js target=app.acme.com"), "no resume support for js"},
	} {
		fn, why := interruptedScanResume(c.r)
		if c.want == "" && fn == nil {
			t.Errorf("%s %s %s: not resumed (%s)", c.r.ScanType, c.r.Target, c.r.Status, why)
		}
		if c.want != "" && (fn != nil || !strings.Contains(why, c.want)) {
			t.Errorf("%s %s %s: %q, want refusal %q", c.r.ScanType, c.r.Target, c.r.Status, why, c.want)
		}
	}
}

func TestStagedTemplateRevs(t *testing.T) {
	dir := t.TempDir()
	a := "id: CVE-2026-1111\ninfo:\n  name: a\n"
	os.WriteFile(filepath.Join(dir, "CVE-2026-1111.yaml"), []byte(a), 0o600)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte("id: 'acme-panel'\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("id: nope\n"), 0o600)
	revs := stagedTemplateRevs(dir)
	if len(revs) != 2 || revs["CVE-2026-1111"] != nucleiTemplateRevKey("CVE-2026-1111", a) || revs["acme-panel"] == "" {
		t.Fatalf("revs: %v", revs)
	}
}

// A scan a restart cut off: the startup reconcile marks it failed, the
// resume flips it back to running under the same id and it completes.
func TestResumeAfterRestart(t *testing.T) {
	withTestSQLite(t)
	now := time.Now()
	for _, r := range []*db.ScanRecord{
		{ScanID: "rs-old", ScanType: "domain_run", Target: "dflow.net", Status: "running", StartedAt: now.Add(-2 * time.Hour), LastUpdate: now, Command: "inprocess:domain_run target=dflow.net"},
		{ScanID: "rs-js", ScanType: "js", Target: "a.acme.com", Status: "running", StartedAt: now.Add(-time.Hour), LastUpdate: now, Command: "inprocess:js target=a.acme.com"},
		{ScanID: "rs-paused", ScanType: "domain_run", Target: "b.net", Status: "paused", StartedAt: now, LastUpdate: now, Command: "inprocess:domain_run target=b.net"},
	} {
		if err := db.CreateScan(r); err != nil {
			t.Fatal(err)
		}
	}
	// What app.reconcileStaleScansOnStartup does.
	interrupted, _ := db.ListActiveScans()
	if _, err := db.FailStaleActiveScans(); err != nil {
		t.Fatal(err)
	}
	ran := make(chan string, 4)
	oldStagger := resumeStagger
	resumeStagger = 0
	t.Cleanup(func() { resumeStagger = oldStagger })
	old := resumeFuncFor
	resumeFuncFor = func(rec *db.ScanRecord) (func() error, string) {
		fn, why := interruptedScanResume(rec)
		if fn == nil {
			return nil, why
		}
		id := rec.ScanID
		return func() error { ran <- id; return nil }, ""
	}
	t.Cleanup(func() { resumeFuncFor = old })

	resumed, failed := resumeInterruptedScansNow(interrupted)
	if len(resumed) != 1 || !strings.Contains(resumed[0], "rs-old") || len(failed) != 2 {
		t.Fatalf("resumed %v failed %v", resumed, failed)
	}
	select {
	case id := <-ran:
		if id != "rs-old" {
			t.Fatalf("ran %s", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("resumed scan never ran")
	}
	waitFor(t, "resumed scan completes", func() bool { return scanStatus("rs-old") == "completed" })
	if st := scanStatus("rs-js"); st != "failed" {
		t.Fatalf("js scan: %s", st)
	}
	if st := scanStatus("rs-paused"); st != "failed" {
		t.Fatalf("paused scan: %s", st)
	}
}
