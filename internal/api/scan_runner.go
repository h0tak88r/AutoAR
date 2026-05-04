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
		log.Printf("[runner] failed to create DB record for %s: %v", scanID, err)
	}

	// Create a cancel context so that CancelScanByID can interrupt this scan.
	ctx, cancelCtx := context.WithCancel(context.Background())
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

	// Register the scan ID in the goroutine-local registry so that
	// RunWorkflowPhase (called deep inside module fns) can look it up
	// without an env var, even in concurrent in-process execution.
	utils.SetGoroutineScanID(scanID)

	// Run fn in a separate goroutine so we can watch the cancel context.
	done := make(chan error, 1)
	go func() { done <- fn() }()

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

	utils.ClearGoroutineScanID()

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
		time.Sleep(5 * time.Second)
		globalLogBus.Close(scanID)
	}()
}
