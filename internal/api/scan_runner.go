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

// stdLog re-emits to both the global logger and the scan-local log bus.
func stdLog(scanID, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	ScanLogf(scanID, "%s", msg)
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
	maxDur := 6 * time.Hour
	if d := os.Getenv("AUTOAR_SCAN_TIMEOUT"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			maxDur = parsed
		}
	}
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
	select {
	case err = <-done:
		// fn finished normally (or with an error)
	case <-ctx.Done():
		// CancelScanByID was called — wait briefly for fn to acknowledge, then proceed
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			// fn didn't return in time; treat as cancelled anyway
		}
		// Override any fn error with the cancellation sentinel
		err = ErrScanCancelled
	}

	// Also honour the CancelRequested flag (set by CancelScanByID before calling cancelCtx).
	ScansMutex.RLock()
	si, ok := ActiveScans[scanID]
	if ok && si != nil && si.CancelRequested {
		err = ErrScanCancelled
	}
	ScansMutex.RUnlock()

	completedAt := time.Now()
	status := "completed"
	errMsg := ""
	if errors.Is(err, ErrScanCancelled) {
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

	_ = db.UpdateScanResult(scanID, status, "")

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
		})
	}

	ScansMutex.Lock()
	delete(ActiveScans, scanID)
	ScansMutex.Unlock()

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

	progress := 0
	if status == "completed" {
		progress = 100
	}
	ScanLogf(scanID, "[%s] scan %s in %s", scanType, status, completedAt.Sub(startedAt).Round(time.Second))
	utils.SendScanNotification("complete", scanID, target, scanType, status, progress)
	log.Printf("[runner] scan %s (%s/%s) %s in %s",
		scanID, scanType, target, status, completedAt.Sub(startedAt).Round(time.Second))

	// Give SSE clients a moment to drain, then close the bus for this scan.
	go func() {
		select {
		case <-time.After(5 * time.Second):
			globalLogBus.Close(scanID)
		}
	}()
}
