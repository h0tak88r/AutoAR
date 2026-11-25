package api

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// withTestSQLite points the db package at a throwaway SQLite file and runs the
// test from a temp dir (results land under ./new-results there).
func withTestSQLite(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(dir, "scans.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	t.Setenv("AUTOAR_RESULTS_DIR", "")
	s := &db.SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("sqlite Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("sqlite InitSchema: %v", err)
	}
	db.SetDB(s)
	t.Cleanup(func() {
		db.SetDB(nil)
		s.Close()
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func scanStatus(id string) string {
	rec, err := db.GetScan(id)
	if err != nil || rec == nil {
		return ""
	}
	return rec.Status
}

func TestClaimScanRunIsExclusive(t *testing.T) {
	const id = "claim-test"
	if !claimScanRun(id) {
		t.Fatal("first claim must succeed")
	}
	if claimScanRun(id) {
		t.Fatal("second claim of the same scan ID must fail")
	}
	if !scanRunInFlight(id) || !scanWorkerTracked(id) {
		t.Fatal("a claimed scan must be reported in flight / tracked")
	}
	releaseScanRun(id)
	if scanRunInFlight(id) {
		t.Fatal("released claim still reported in flight")
	}
	if !claimScanRun(id) {
		t.Fatal("claim after release must succeed")
	}
	releaseScanRun(id)
}

// TestResumeRefusedWhileWorkerWindsDown reproduces the double-run: a cancelled
// scan whose worker ignores the cancel is reconciled to "cancelled" (so
// ScanIsActiveInMemory says inactive) while fn is still running. Resume must be
// refused until that worker really exits, and must then work exactly once.
func TestResumeRefusedWhileWorkerWindsDown(t *testing.T) {
	withTestSQLite(t)
	old := scanStopAckWait
	scanStopAckWait = 50 * time.Millisecond
	t.Cleanup(func() { scanStopAckWait = old })

	const id = "resume-race-scan"
	release := make(chan struct{})
	go RunScanInProcess(id, "domain_run", "example.com", func() error {
		<-release // ignores the scan context, like an uninterruptible library call
		return nil
	})
	waitFor(t, "scan to start", func() bool { return ScanIsActiveInMemory(id) })

	if err := CancelScanByID(id); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitFor(t, "cancelled status", func() bool { return scanStatus(id) == "cancelled" })
	if ScanIsActiveInMemory(id) {
		t.Fatal("reconciled scan must not be reported active")
	}

	ran := make(chan struct{}, 2)
	resumeFn := func() error { ran <- struct{}{}; return nil }
	if err := startResumeScan(id, "domain_run", "example.com", "inprocess:domain_run target=example.com (resumed)", "tester", resumeFn); !errors.Is(err, errScanRunInFlight) {
		t.Fatalf("resume while the old worker is alive: err=%v, want errScanRunInFlight", err)
	}

	close(release) // old worker finally exits
	waitFor(t, "old worker to release its claim", func() bool { return !scanWorkerTracked(id) })

	if err := startResumeScan(id, "domain_run", "example.com", "inprocess:domain_run target=example.com (resumed)", "tester", resumeFn); err != nil {
		t.Fatalf("resume after the old worker exited: %v", err)
	}
	// A double click while the first resume is queued/running is refused.
	if err := startResumeScan(id, "domain_run", "example.com", "inprocess:domain_run target=example.com (resumed)", "tester", resumeFn); !errors.Is(err, errScanRunInFlight) {
		t.Fatalf("second resume: err=%v, want errScanRunInFlight", err)
	}
	waitFor(t, "resumed run to complete", func() bool { return scanStatus(id) == "completed" && !scanWorkerTracked(id) })
	if len(ran) != 1 {
		t.Fatalf("resumed fn ran %d times, want exactly 1", len(ran))
	}
}

func TestScanRowOrphaned(t *testing.T) {
	now := time.Now()
	idle := now.Add(-orphanGracePeriod - time.Minute)
	cases := []struct {
		name string
		rec  *db.ScanRecord
		want bool
	}{
		{"server row idle past grace", &db.ScanRecord{ScanID: "orph-1", ScanType: "domain_run", Command: "inprocess:domain_run target=x.com", StartedAt: idle, LastUpdate: idle}, true},
		{"server row recently updated", &db.ScanRecord{ScanID: "orph-2", ScanType: "domain_run", Command: "inprocess:x", StartedAt: idle, LastUpdate: now}, false},
		{"undatable row", &db.ScanRecord{ScanID: "orph-3", ScanType: "dns_cf1016", Command: "inprocess:x"}, false},
		{"CLI row inside the scan budget", &db.ScanRecord{ScanID: "orph-4", ScanType: "dns_cf1016", StartedAt: idle, LastUpdate: idle}, false},
		{"CLI row past budget + grace", &db.ScanRecord{ScanID: "orph-5", ScanType: "dns_cf1016", StartedAt: now.Add(-48 * time.Hour), LastUpdate: now.Add(-48 * time.Hour)}, true},
	}
	for _, tc := range cases {
		if got := scanRowOrphaned(tc.rec, now); got != tc.want {
			t.Errorf("%s: scanRowOrphaned = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A claimed (queued/running) scan is never orphaned, however stale its row.
	r := &db.ScanRecord{ScanID: "orph-claimed", ScanType: "domain_run", Command: "inprocess:x", StartedAt: idle, LastUpdate: idle}
	if !claimScanRun(r.ScanID) {
		t.Fatal("claim failed")
	}
	defer releaseScanRun(r.ScanID)
	if scanRowOrphaned(r, now) {
		t.Error("claimed scan reported orphaned")
	}
}

func TestLogBusRunGenerations(t *testing.T) {
	b := &logBus{subs: map[string][]chan string{}, logs: map[string][]string{}, runs: map[string]uint64{}}

	b.Logf("s1", "before open")
	if _, ok := b.logs["s1"]; ok {
		t.Fatal("Logf for a scan with no open run must not create history")
	}

	gen1 := b.Open("s1")
	b.Logf("s1", "run1 line")
	_, ch := b.Subscribe("s1")

	// A resume reopens the scan before run 1's delayed close fires.
	gen2 := b.Open("s1")
	b.Logf("s1", "run2 line")
	b.CloseRun("s1", gen1) // stale close: must not wipe run 2
	if len(b.logs["s1"]) != 2 || len(b.subs["s1"]) != 1 {
		t.Fatalf("stale CloseRun wiped the resumed run: logs=%v subs=%d", b.logs["s1"], len(b.subs["s1"]))
	}

	b.CloseRun("s1", gen2)
	if _, ok := <-drain(ch); ok {
		t.Fatal("subscriber channel must be closed by the current run's CloseRun")
	}
	if len(b.logs) != 0 || len(b.subs) != 0 || len(b.runs) != 0 {
		t.Fatalf("state left after close: logs=%d subs=%d runs=%d", len(b.logs), len(b.subs), len(b.runs))
	}
	b.Logf("s1", "after close")
	if _, ok := b.logs["s1"]; ok {
		t.Fatal("Logf after close recreated the scan's history")
	}

	// Subscribing to an unknown ID leaves no key behind once unsubscribed.
	_, ch2 := b.Subscribe("ghost")
	b.Unsubscribe("ghost", ch2)
	if _, ok := b.subs["ghost"]; ok {
		t.Fatal("Unsubscribe left an empty subscriber entry")
	}
}

// drain discards buffered lines and returns the channel for a final receive.
func drain(ch chan string) chan string {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				closed := make(chan string)
				close(closed)
				return closed
			}
		default:
			return ch
		}
	}
}
