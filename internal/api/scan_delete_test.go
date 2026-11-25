package api

import "testing"

// TestScanIsActiveInMemoryTerminalStatus guards the fix for the "timed-out scan
// undeletable" bug: when the runner reconciles a wedged scan's in-memory Status to
// a terminal value (timed_out/cancelled/failed/completed), ScanIsActiveInMemory
// must report it inactive so the delete endpoints stop refusing it — even while
// the entry still lingers in ActiveScans for the cooperative-stop signal.
func TestScanIsActiveInMemoryTerminalStatus(t *testing.T) {
	const id = "test-scan-terminal-status"
	ScansMutex.Lock()
	ActiveScans[id] = &ScanInfo{ScanID: id, Status: "running"}
	ScansMutex.Unlock()
	t.Cleanup(func() {
		ScansMutex.Lock()
		delete(ActiveScans, id)
		ScansMutex.Unlock()
	})

	if !ScanIsActiveInMemory(id) {
		t.Fatal("a running scan must be reported active")
	}
	for _, st := range []string{"timed_out", "cancelled", "failed", "completed", "stopped"} {
		ScansMutex.Lock()
		ActiveScans[id].Status = st
		ScansMutex.Unlock()
		if ScanIsActiveInMemory(id) {
			t.Errorf("scan with terminal status %q must NOT be reported active (blocks deletion)", st)
		}
	}
	// A still-live state keeps it active/undeletable, as intended.
	for _, st := range []string{"running", "starting", "paused", "cancelling"} {
		ScansMutex.Lock()
		ActiveScans[id].Status = st
		ScansMutex.Unlock()
		if !ScanIsActiveInMemory(id) {
			t.Errorf("scan with live status %q must be reported active", st)
		}
	}
}
