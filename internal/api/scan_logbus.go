package api

// scan_logbus.go — in-memory log broadcaster for in-process scans.
//
// When a scan runs in-process (via runScanInProcess), there is no child
// process whose stdout we can tail. This file provides a lightweight
// pub-sub log bus so the SSE /api/scans/:id/logs/stream endpoint can
// deliver live log lines to connected dashboard clients.
//
// Usage (inside scan module goroutines — optional):
//
//	scanlog.Logf(scanID, "phase: %s started", name)
//
// The SSE handler reads from the channel until the scan completes or
// the client disconnects.

import (
	"fmt"
	"sync"
)

const (
	logBusChanSize    = 256  // lines buffered per subscriber
	logBusMaxSubs     = 8    // max SSE clients per scan
	logBusMaxLogLines = 8192 // cap stored log lines per scan
)

type logBusEntry struct {
	scanID string
	line   string
}

type logBus struct {
	mu   sync.RWMutex
	subs map[string][]chan string // scanID → subscriber channels
	logs map[string][]string      // scanID → stored log lines (for late joiners)
	// runs holds the generation of each scan's currently open run (see Open).
	// Lines are only stored for an open run, and a run's delayed close only
	// tears down state if no newer run of the same scan ID has opened since.
	runs    map[string]uint64
	lastGen uint64
}

var globalLogBus = &logBus{
	subs: make(map[string][]chan string),
	logs: make(map[string][]string),
	runs: make(map[string]uint64),
}

// Open starts a run of scanID on the bus and returns its generation token, to be
// handed back to CloseRun. Reopening a scan ID (a resume) supersedes the earlier
// run: its pending CloseRun becomes a no-op instead of wiping the new run's
// history and SSE subscribers.
func (b *logBus) Open(scanID string) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.lastGen++
	b.runs[scanID] = b.lastGen
	return b.lastGen
}

// Logf appends a formatted log line to the in-process log bus for scanID.
// This is a fire-and-forget call — it never blocks. Lines for a scan with no
// open run (e.g. a wedged worker still logging after its run was closed) are
// dropped: storing them recreated the scan's history entry, which then leaked
// for the life of the process because nothing would ever close it again.
func (b *logBus) Logf(scanID, format string, args ...interface{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, open := b.runs[scanID]; !open {
		return
	}
	line := fmt.Sprintf(format, args...)

	// Store for late joiners, capped as a ring buffer keeping the NEWEST lines.
	// The old code stopped appending at the cap, keeping the oldest N — so a
	// late-joining UI replaying history on a long scan saw only the beginning and
	// missed the terminal [VULN]/completed/timed_out lines. Drop-oldest keeps the
	// end, which is what matters.
	stored := b.logs[scanID]
	if len(stored) >= logBusMaxLogLines {
		stored = stored[len(stored)-logBusMaxLogLines+1:]
	}
	b.logs[scanID] = append(stored, line)

	// Fan out to all current subscribers.
	for _, ch := range b.subs[scanID] {
		select {
		case ch <- line:
		default: // subscriber is slow — drop rather than block
		}
	}
}

// Subscribe returns a channel that receives log lines for scanID.
// The caller must call Unsubscribe when done.
// It also returns all previously stored lines so late joiners catch up.
func (b *logBus) Subscribe(scanID string) (history []string, ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Copy stored lines for replay.
	stored := b.logs[scanID]
	history = make([]string, len(stored))
	copy(history, stored)

	if len(b.subs[scanID]) >= logBusMaxSubs {
		// At the subscriber cap: hand back an already-closed channel so the SSE
		// loop receives ok=false and tears down cleanly, instead of an orphaned
		// open channel that Close() can never close (relying on client disconnect).
		ch = make(chan string)
		close(ch)
		return history, ch
	}
	ch = make(chan string, logBusChanSize)
	b.subs[scanID] = append(b.subs[scanID], ch)
	return history, ch
}

// Unsubscribe removes the channel from the subscriber list for scanID. The map
// key goes with the last subscriber, so SSE requests for arbitrary IDs (or for
// subprocess scans that never use the bus) don't leave empty entries behind.
func (b *logBus) Unsubscribe(scanID string, ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subs[scanID]
	for i, s := range subs {
		if s == ch {
			subs = append(subs[:i], subs[i+1:]...)
			break
		}
	}
	if len(subs) == 0 {
		delete(b.subs, scanID)
		return
	}
	b.subs[scanID] = subs
}

// CloseRun drains and removes all state for a finished run (prevents leaks).
// It does nothing when gen is no longer the scan's current run — a resumed run
// opened in the meantime owns the history and subscribers now.
func (b *logBus) CloseRun(scanID string, gen uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cur, open := b.runs[scanID]; !open || cur != gen {
		return
	}
	for _, ch := range b.subs[scanID] {
		close(ch)
	}
	delete(b.subs, scanID)
	delete(b.logs, scanID)
	delete(b.runs, scanID)
}

// ScanLogf is the public convenience function for logging a scan event to the bus.
func ScanLogf(scanID, format string, args ...interface{}) {
	globalLogBus.Logf(scanID, format, args...)
}
