package gobot

// scan_runner.go — generic in-process scan runner.
//
// runScanInProcess runs an arbitrary scan function directly in this process
// (no child "autoar ..." subprocess). It manages the full scan lifecycle:
// DB record, activeScans map, semaphore, notifications, artifact indexing.
//
// This avoids the double-memory fork that caused Docker OOM restarts when
// every scan called executeScan → exec.Command("autoar", ...).

import (
	"fmt"
	"log"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// runScanInProcess is the generic in-process scan runner. fn should call the
// module's Go API directly. target is used for display and notifications.
func runScanInProcess(scanID, scanType, target string, fn func() error) {
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

	scansMutex.Lock()
	activeScans[scanID] = &ScanInfo{
		ScanID:    scanID,
		Status:    "running",
		ScanType:  scanType,
		Target:    target,
		StartedAt: startedAt,
		Command:   fmt.Sprintf("inprocess:%s target=%s", scanType, target),
	}
	scansMutex.Unlock()

	utils.SendScanNotification("start", scanID, target, scanType, "running", 0)

	err := fn()

	completedAt := time.Now()
	status := "completed"
	errMsg := ""
	if err != nil {
		status = "failed"
		errMsg = err.Error()
		log.Printf("[runner] scan %s (%s) failed: %v", scanID, scanType, err)
	}

	_ = db.UpdateScanResult(scanID, status, "")

	scansMutex.Lock()
	delete(activeScans, scanID)
	scansMutex.Unlock()

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
	utils.SendScanNotification("complete", scanID, target, scanType, status, progress)
	log.Printf("[runner] scan %s (%s/%s) %s in %s",
		scanID, scanType, target, status, completedAt.Sub(startedAt).Round(time.Second))
}
