package utils

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
)

var (
	ErrTimeout = fmt.Errorf("timeout")
	// Global semaphore to limit concurrent heavy phases (e.g., 4 at a time)
	phaseSemaphore = make(chan struct{}, 4)
)

func SetMaxConcurrentPhases(n int) {
	if n > 0 {
		phaseSemaphore = make(chan struct{}, n)
	}
}

// RunWithTimeout executes a function with a given timeout
func RunWithTimeout(fn func() error, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrTimeout
	}
}

// RunWorkflowPhase is a shared helper to run a single workflow step with reporting
func RunWorkflowPhase(phaseKey string, step, total int, description, target string, timeoutSeconds int, fn func() error) error {
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	
	// Checkpoint: Skip if phase already completed successfully
	if scanID != "" && db.IsPhaseCompleted(scanID, description) {
		log.Printf("[SKIP] Step %d/%d: %s (already completed)", step, total, description)
		return nil
	}

	// Await occupancy in the worker pool
	phaseSemaphore <- struct{}{}
	defer func() { <-phaseSemaphore }()

	log.Printf("[INFO] Step %d/%d: %s", step, total, description)
	if scanID != "" {
		progress := &db.ScanProgress{
			CurrentPhase:   step,
			TotalPhases:    total,
			PhaseName:      description,
			PhaseStartTime: time.Now(),
		}
		_ = db.UpdateScanProgress(scanID, progress)
	}

	var err error
	if timeoutSeconds > 0 {
		err = RunWithTimeout(fn, time.Duration(timeoutSeconds)*time.Second)
	} else {
		err = fn()
	}

	if err != nil {
		if err == ErrTimeout {
			log.Printf("[WARN] %s timed out", description)
		} else {
			log.Printf("[ERROR] %s failed: %v", description, err)
		}
		
		if scanID != "" {
			_ = db.AppendScanPhase(scanID, description, true)
		}
		SendWebhookLogAsync(fmt.Sprintf("[ERROR] %s failed: %v", description, err))
		return err
	}

	log.Printf("[OK] %s completed", description)
	if scanID != "" {
		_ = db.AppendScanPhase(scanID, description, false)
	}

	// Real-time file reporting
	if phaseKey != "" {
		phaseFiles := GetPhaseFiles(phaseKey, target)
		if len(phaseFiles) > 0 {
			var existingFiles []string
			for _, f := range phaseFiles {
				if info, ferr := os.Stat(f); ferr == nil && info.Size() > 0 {
					existingFiles = append(existingFiles, f)
				}
			}
			if len(existingFiles) > 0 {
				_ = SendPhaseFiles(phaseKey, target, existingFiles)
			}
		}
	}

	return nil
}
