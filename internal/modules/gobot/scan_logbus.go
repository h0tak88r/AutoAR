package gobot

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
	logBusChanSize    = 256 // lines buffered per subscriber
	logBusMaxSubs     = 8   // max SSE clients per scan
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
}

var globalLogBus = &logBus{
	subs: make(map[string][]chan string),
	logs: make(map[string][]string),
}

// Logf appends a formatted log line to the in-process log bus for scanID.
// This is a fire-and-forget call — it never blocks.
func (b *logBus) Logf(scanID, format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	b.mu.Lock()
	defer b.mu.Unlock()

	// Store for late joiners (capped).
	stored := b.logs[scanID]
	if len(stored) < logBusMaxLogLines {
		b.logs[scanID] = append(stored, line)
	}

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

	ch = make(chan string, logBusChanSize)
	if len(b.subs[scanID]) < logBusMaxSubs {
		b.subs[scanID] = append(b.subs[scanID], ch)
	}
	return history, ch
}

// Unsubscribe removes the channel from the subscriber list for scanID.
func (b *logBus) Unsubscribe(scanID string, ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subs[scanID]
	for i, s := range subs {
		if s == ch {
			b.subs[scanID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
}

// Close drains and removes all state for a finished scan (prevents leaks).
func (b *logBus) Close(scanID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs[scanID] {
		close(ch)
	}
	delete(b.subs, scanID)
	delete(b.logs, scanID)
}

// ScanLogf is the public convenience function for logging a scan event to the bus.
func ScanLogf(scanID, format string, args ...interface{}) {
	globalLogBus.Logf(scanID, format, args...)
}
