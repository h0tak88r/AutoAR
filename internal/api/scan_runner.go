package api

// scan_runner.go — generic in-process scan runner.
//
// runScanInProcess runs an arbitrary scan function directly in this process
// (no child "autoar ..." subprocess). It manages the full scan lifecycle:
// DB record, ActiveScans map, semaphore, notifications, artifact indexing.
//
// This avoids the double-memory fork that caused Docker OOM restarts when
// every scan called executeScan → exec.Command("autoar", ...).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ErrScanCancelled is returned by RunScanInProcess when the user requested a stop.
var ErrScanCancelled = errors.New("scan cancelled by user")

// ErrScanTimedOut marks a scan the runner killed at its own deadline. Kept
// distinct from ErrScanCancelled so the dashboard can tell "the operator
// stopped this" apart from "this outgrew its budget" — they need opposite fixes.
var ErrScanTimedOut = errors.New("scan exceeded its time budget")

// stdLog re-emits to both the global logger and the scan-local log bus.
func stdLog(scanID, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	ScanLogf(scanID, "%s", msg)
}

// scanTimeoutFor returns the wall-clock budget for a scan type.
//
// The 6h default is sized for a single-domain scan. Fleet-wide jobs (the root
// pipeline walks thousands of roots) legitimately run far longer, and sharing
// the single-domain budget meant the pipeline was killed mid-collection every
// time — a 3511-root run reached 1567 roots in 6h and never got as far as
// nuclei, so six hours of enumeration produced zero template results. These
// jobs still get a ceiling, just one matched to their scale.
//
// AUTOAR_SCAN_TIMEOUT overrides the default; AUTOAR_PIPELINE_TIMEOUT overrides
// the long-job budget.
func scanTimeoutFor(scanType string) time.Duration {
	def, long := 6*time.Hour, 24*time.Hour
	if d := os.Getenv("AUTOAR_SCAN_TIMEOUT"); d != "" {
		if p, err := time.ParseDuration(d); err == nil && p > 0 {
			def = p
		}
	}
	if d := os.Getenv("AUTOAR_PIPELINE_TIMEOUT"); d != "" {
		if p, err := time.ParseDuration(d); err == nil && p > 0 {
			long = p
		}
	}
	switch scanType {
	case "pipeline", "collect":
		return long
	default:
		return def
	}
}

// updateScanResultWithRetry writes a scan's terminal status, retrying a few
// times so a transient DB blip doesn't strand the row as permanently active.
func updateScanResultWithRetry(scanID, status string) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = db.UpdateScanResult(scanID, status, ""); err == nil {
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return err
}

// orphanGracePeriod is how long a DB row may claim to be active with no live
// worker before the reaper closes it. It must exceed the window between
// db.CreateScan and the ActiveScans registration in RunScanInProcess, or the
// reaper would kill scans a few milliseconds into their own startup.
const orphanGracePeriod = 15 * time.Minute

// StartOrphanedScanReaper closes scan rows whose worker no longer exists.
//
// Until now the only cleanup ran at startup, so a row that lost its worker
// mid-flight stayed "running" until the next restart — which is how 14 scans sat
// active for hours with no process behind them, making "wait for all scans" and
// the dashboard's active count both wrong. ActiveScans is the ground truth: this
// process knows every scan it is running, so an active row absent from that map
// (and past the grace period) has no worker and never will.
func StartOrphanedScanReaper() {
	go func() {
		defer utils.RecoverPanic("scan-reaper")
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// Per-tick barrier: a panic in one reap sweep must not kill the reaper
			// for the life of the process, or orphaned scans would pile up silently.
			func() {
				defer utils.RecoverPanic("scan-reaper:tick")
				reapOrphanedScans()
			}()
		}
	}()
}

func reapOrphanedScans() {
	rows, err := db.ListActiveScans()
	if err != nil {
		return
	}
	for _, r := range rows {
		if r == nil || time.Since(r.LastUpdate) < orphanGracePeriod {
			continue
		}
		ScansMutex.RLock()
		_, live := ActiveScans[r.ScanID]
		ScansMutex.RUnlock()
		if live {
			continue // a worker is genuinely running it
		}
		if dbErr := updateScanResultWithRetry(r.ScanID, "failed"); dbErr != nil {
			log.Printf("[reaper] could not close orphaned scan %s: %v", r.ScanID, dbErr)
			continue
		}
		log.Printf("[reaper] closed orphaned scan %s (%s): status %q with no running worker, idle %s",
			r.ScanID, r.ScanType, r.Status, time.Since(r.LastUpdate).Round(time.Minute))
	}
}

// runScanInProcess is the generic in-process scan runner. fn should call the
// module's Go API directly. target is used for display and notifications.
func RunScanInProcess(scanID, scanType, target string, fn func() error) {
	startedAt := time.Now()

	scanSemaphore <- struct{}{}
	defer func() { <-scanSemaphore }()

	dbRecord := &db.ScanRecord{
		ScanID:     scanID,
		ScanType:   scanType,
		Target:     target,
		Status:     "running",
		StartedAt:  startedAt,
		LastUpdate: startedAt,
		Command:    fmt.Sprintf("inprocess:%s target=%s", scanType, target),
	}
	if err := db.CreateScan(dbRecord); err != nil {
		// Without a DB record the scan would be invisible to the UI — abort rather
		// than run an orphaned scan whose results can never be retrieved.
		log.Printf("[runner] ABORT: failed to create DB record for %s (%s): %v", scanID, scanType, err)
		// The deferred release above already frees the acquired slot; releasing
		// again here would unbalance the semaphore (steal another scan's slot).
		return
	}

	// Create a cancel context with a configurable maximum duration so that a
	// hung scanner (e.g. waiting on an unreachable host) doesn't hold a
	// semaphore slot forever. Default: 6 hours. Override: AUTOAR_SCAN_TIMEOUT.
	maxDur := scanTimeoutFor(scanType)
	ctx, cancelCtx := context.WithTimeout(context.Background(), maxDur)
	defer cancelCtx() // always release resources

	ScansMutex.Lock()
	ActiveScans[scanID] = &ScanInfo{
		ScanID:     scanID,
		Status:     "running",
		ScanType:   scanType,
		Target:     target,
		StartedAt:  startedAt,
		Command:    fmt.Sprintf("inprocess:%s target=%s", scanType, target),
		CancelFunc: cancelCtx, // wired so CancelScanByID() can call it
	}
	ScansMutex.Unlock()

	utils.SendScanNotification("start", scanID, target, scanType, "running", 0)
	ScanLogf(scanID, "[%s] scan started for %s", scanType, target)

	// Run fn in a separate goroutine so we can watch the cancel context.
	// IMPORTANT: SetGoroutineScanID must be called inside this goroutine
	// because goroutine IDs are goroutine-local — the registry key is the
	// calling goroutine's ID. If we called it from the parent, fn() would
	// run with a different goroutine ID and GetCurrentScanID() would return "".
	done := make(chan error, 1)
	go func() {
		utils.SetGoroutineScanID(scanID)
		defer utils.ClearGoroutineScanID()
		// Recover from any panic inside a scanner module so a nil-pointer or
		// assertion failure doesn't crash the whole server process.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[runner] PANIC in scan %s (%s): %v", scanID, scanType, r)
				done <- fmt.Errorf("internal panic: %v", r)
			}
		}()
		done <- fn()
	}()

	var err error
	// fnDone tracks whether the work goroutine actually returned. On a deadline or
	// cancel it may still be running (a one-shot library call that ignores the
	// context); the concurrency slot must NOT be freed until it truly exits, or a
	// runaway keeps consuming CPU/memory while a new scan starts on top of it —
	// enough of those and live goroutines exceed the cap and OOM the container.
	fnDone := true
	timedOut := false
	select {
	case err = <-done:
		// fn finished normally (or with an error)
	case <-ctx.Done():
		// Either CancelScanByID was called or the budget expired.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			timedOut = true
			// Fire the cooperative-cancel signal so modules that poll
			// utils.IsScanCancelled (multi-phase scans, between phases) stop at the
			// deadline instead of running the full remaining workflow. The scan is
			// kept in ActiveScans until fn exits (below) so this signal stays live.
			ScansMutex.Lock()
			if si := ActiveScans[scanID]; si != nil {
				si.CancelRequested = true
			}
			ScansMutex.Unlock()
		}
		// Wait briefly for fn to acknowledge.
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			fnDone = false // still running; the slot is held until it exits (end of func)
		}
		if timedOut {
			err = fmt.Errorf("%w after %s", ErrScanTimedOut, maxDur)
		} else {
			err = ErrScanCancelled
		}
	}

	// Honour an explicit user cancel (CancelScanByID). Skip when WE timed out — the
	// CancelRequested flag the deadline path set for the cooperative stop must not
	// relabel a timeout as "cancelled by user".
	if !timedOut {
		ScansMutex.RLock()
		si, ok := ActiveScans[scanID]
		if ok && si != nil && si.CancelRequested {
			err = ErrScanCancelled
		}
		ScansMutex.RUnlock()
	}

	completedAt := time.Now()
	status := "completed"
	errMsg := ""
	if errors.Is(err, ErrScanTimedOut) {
		status = "timed_out"
		errMsg = err.Error()
		ScanLogf(scanID, "[%s] scan TIMED OUT: %v", scanType, err)
		log.Printf("[runner] scan %s (%s) timed out after %s", scanID, scanType, maxDur)
	} else if errors.Is(err, ErrScanCancelled) {
		status = "cancelled"
		errMsg = "cancelled by user"
		ScanLogf(scanID, "[%s] scan cancelled by user", scanType)
		log.Printf("[runner] scan %s (%s) cancelled", scanID, scanType)
	} else if err != nil {
		status = "failed"
		errMsg = err.Error()
		ScanLogf(scanID, "[%s] scan FAILED: %v", scanType, err)
		log.Printf("[runner] scan %s (%s) failed: %v", scanID, scanType, err)
	}

	// Do NOT discard this error. It is the only write that moves a scan out of
	// "running", so a silent failure strands the row as permanently active — the
	// worker is gone but the dashboard still shows it running, and "wait for all
	// scans to finish" never returns. Retry briefly, then at least say so.
	if dbErr := updateScanResultWithRetry(scanID, status); dbErr != nil {
		log.Printf("[runner] CRITICAL: scan %s (%s) finished as %q but the status write failed: %v — row left active, the reaper will clear it",
			scanID, scanType, status, dbErr)
	}

	// Ensure every in-process scan shows progress in the dashboard.
	// Without this, one-shot scans like global nuclei / subdomain_run
	// appear with 0 phases and no progress bar.
	record, _ := db.GetScan(scanID)
	if record != nil && record.TotalPhases == 0 {
		scanLabel := scanType
		phaseFailed := status == "failed"
		_ = db.AppendScanPhase(scanID, scanLabel+" scan", phaseFailed)
		_ = db.UpdateScanProgress(scanID, &db.ScanProgress{
			CurrentPhase:    1,
			TotalPhases:     1,
			PhaseName:       scanLabel + " scan",
			CompletedPhases: []string{scanLabel + " scan"},
			// Carry the finding count and error count the module already wrote via
			// UpdateScanStats. UpdateScanProgress overwrites files_uploaded/error_count
			// unconditionally, so leaving these at their zero value silently reset a
			// nuclei/pipeline run's match count to 0 in the DB — the scans list then
			// showed "0 findings" while the results file (and the detail view) held
			// the real hits. This is exactly why a confirmed CVE-2025-62138 match
			// looked like 0 in the scan list.
			FilesUploaded: record.FilesUploaded,
			ErrorCount:    record.ErrorCount,
		})
	}

	// Drop the ActiveScans entry now only if fn actually returned. If it is still
	// running (timed out / cancelled but uninterruptible), KEEP the entry so
	// IsScanCancelled keeps signalling a stop, and retire it after fn exits (below).
	if fnDone {
		ScansMutex.Lock()
		delete(ActiveScans, scanID)
		ScansMutex.Unlock()
	}

	apiScansMutex.Lock()
	sr := &ScanResult{
		ScanID:      scanID,
		Status:      status,
		ScanType:    scanType,
		StartedAt:   startedAt,
		CompletedAt: &completedAt,
		Error:       errMsg,
	}
	storeScanResultLocked(scanID, sr)
	apiScansMutex.Unlock()

	// Index artifacts written by the module.
	indexScanArtifacts(scanID, scanType, target)

	// findingsCount comes from the DB row's files_uploaded (set by the module via
	// db.UpdateScanStats, e.g. pipeline/global-nuclei match counts) -- NOT a
	// percent-complete flag. A prior version passed a 0/100 "progress" value here,
	// so every completed scan reported "100 findings" regardless of real matches.
	findingsCount := 0
	if record != nil {
		findingsCount = record.FilesUploaded
	}
	ScanLogf(scanID, "[%s] scan %s in %s", scanType, status, completedAt.Sub(startedAt).Round(time.Second))
	utils.SendScanNotification("complete", scanID, target, scanType, status, findingsCount)
	log.Printf("[runner] scan %s (%s/%s) %s in %s",
		scanID, scanType, target, status, completedAt.Sub(startedAt).Round(time.Second))

	// Give SSE clients a moment to drain, then close the bus for this scan.
	go func() {
		defer utils.RecoverPanic("scan-logbus-close")
		<-time.After(5 * time.Second)
		globalLogBus.Close(scanID)
	}()

	// If fn is still running (it ignored the deadline/cancel), keep holding the
	// concurrency slot — the deferred `<-scanSemaphore` fires only when this function
	// returns — until fn actually exits, so live goroutines never exceed the cap.
	// Bounded by a second budget: if it somehow never winds down (should not happen
	// once network calls all have timeouts), release the slot and log rather than
	// lose it permanently. Then retire the ActiveScans entry kept for the stop signal.
	if !fnDone {
		select {
		case <-done: // fn returned or panicked (done is buffered, one send guaranteed)
		case <-time.After(maxDur):
			log.Printf("[runner] CRITICAL: scan %s (%s) still running %s past its %s deadline — releasing the slot; goroutine leaked",
				scanID, scanType, maxDur, maxDur)
		}
		ScansMutex.Lock()
		delete(ActiveScans, scanID)
		ScansMutex.Unlock()
	}
}
