package utils

// scancontext.go — goroutine-safe scan ID registry for in-process scan execution.
//
// Problem: RunWorkflowPhase previously read AUTOAR_CURRENT_SCAN_ID from the
// environment because modules were always invoked in a child process where that
// variable was set. Now that modules run in-process, setting a process-wide env
// var is not goroutine-safe (concurrent scans would stomp each other's ID).
//
// Solution: a sync.Map keyed by goroutine ID (extracted cheaply via runtime.Stack).
// Each goroutine that runs a scan module calls SetGoroutineScanID before executing
// the module fn, and ClearGoroutineScanID in a defer after the fn returns.
// RunWorkflowPhase calls GetCurrentScanID(), which checks this map first, then
// falls back to the env var for subprocess compatibility.

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var goroutineScanIDs sync.Map // goroutine-id (int64) → scanID (string)

// goroutineID extracts the current goroutine's numeric ID from its stack header.
// This is not an official Go API but has been stable for 10+ years.
// Overhead: ~200ns per call — acceptable for per-phase granularity.
func goroutineID() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// Format: "goroutine 42 [running]:\n..."
	s := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	end := strings.IndexByte(s, ' ')
	if end < 0 {
		return -1
	}
	id, _ := strconv.ParseInt(s[:end], 10, 64)
	return id
}

// SetGoroutineScanID registers scanID for the calling goroutine.
// Call ClearGoroutineScanID (via defer) when the scan function returns.
func SetGoroutineScanID(scanID string) {
	goroutineScanIDs.Store(goroutineID(), scanID)
}

// ClearGoroutineScanID removes the scan ID for the calling goroutine.
func ClearGoroutineScanID() {
	goroutineScanIDs.Delete(goroutineID())
}

// GetCurrentScanID returns the scan ID for the current goroutine.
// Returns the env var AUTOAR_CURRENT_SCAN_ID as fallback (subprocess compat).
func GetCurrentScanID() string {
	if id, ok := goroutineScanIDs.Load(goroutineID()); ok {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return os.Getenv("AUTOAR_CURRENT_SCAN_ID")
}
