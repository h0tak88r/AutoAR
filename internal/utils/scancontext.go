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
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var goroutineScanIDs sync.Map // goroutine-id (int64) → scanID (string)
var goroutinePhaseKeys sync.Map // goroutine-id (int64) → phaseKey (string)

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

// SetGoroutinePhaseKey registers the current phase key for the calling goroutine.
// Call ClearGoroutinePhaseKey (via defer) when the phase function returns.
func SetGoroutinePhaseKey(phaseKey string) {
	goroutinePhaseKeys.Store(goroutineID(), phaseKey)
}

// ClearGoroutinePhaseKey removes the phase key for the calling goroutine.
func ClearGoroutinePhaseKey() {
	goroutinePhaseKeys.Delete(goroutineID())
}

// GetCurrentPhaseKey returns the phase key for the current goroutine.
func GetCurrentPhaseKey() string {
	if id, ok := goroutinePhaseKeys.Load(goroutineID()); ok {
		if s, ok := id.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// isCancelledFn is a hook registered by the api package to avoid a circular
// import. utils → api is not allowed; api → utils is fine.
var isCancelledFn func(scanID string) bool

// RegisterCancelChecker lets the api package inject its cancel-check function
// once at startup. Safe for concurrent reads after the initial registration.
func RegisterCancelChecker(fn func(scanID string) bool) {
	isCancelledFn = fn
}

// IsScanCancelled reports whether the scan with the given ID has been cancelled.
// Returns false if no cancel checker has been registered.
func IsScanCancelled(scanID string) bool {
	if isCancelledFn == nil || scanID == "" {
		return false
	}
	return isCancelledFn(scanID)
}

// scanContextFn is a hook registered by the api package (same circular-import
// avoidance as RegisterCancelChecker): it resolves a scan ID to the scan's
// lifetime context, which CancelScanByID and the scan timeout can cancel.
var scanContextFn func(scanID string) context.Context

// RegisterScanContextResolver lets the api package inject its scanID →
// context.Context lookup once at startup.
func RegisterScanContextResolver(fn func(scanID string) context.Context) {
	scanContextFn = fn
}

// CurrentScanContext returns the lifetime context of the scan running on this
// goroutine (see GetCurrentScanID), or context.Background() when no scan is
// active (CLI runs). Scanner engines must be built on this context — one built
// on context.Background() ignores UI cancels and the scan timeout, and keeps
// sweeping hosts + firing webhooks after the scan was marked done.
func CurrentScanContext() context.Context {
	id := GetCurrentScanID()
	if id == "" || scanContextFn == nil {
		return context.Background()
	}
	if ctx := scanContextFn(id); ctx != nil {
		return ctx
	}
	return context.Background()
}
