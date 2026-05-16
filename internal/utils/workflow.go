package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
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
	// GetCurrentScanID checks the goroutine-local registry first (in-process scans),
	// then falls back to AUTOAR_CURRENT_SCAN_ID env var (subprocess compat).
	scanID := GetCurrentScanID()

	// Register phase key and log capture immediately so EVERY log message emitted
	// by this phase (start, skip, cancel, complete, error, and anything logged by
	// the module function) lands in the per-phase log file.
	SetGoroutinePhaseKey(phaseKey)
	flushLogs := StartPhaseLogCapture(scanID, phaseKey)
	defer func() {
		ClearGoroutinePhaseKey()
		flushLogs()
	}()

	// Checkpoint: Skip if phase already completed successfully
	if scanID != "" && db.IsPhaseCompleted(scanID, description) {
		GetLogger().WithField("step", step).WithField("total", total).Infof("[SKIP] %s (already completed)", description)
		return nil
	}

	// Bail out early if the user cancelled this scan between phases.
	if IsScanCancelled(scanID) {
		GetLogger().Infof("[CANCEL] %s — scan %s was cancelled; skipping remaining phases", description, scanID)
		return fmt.Errorf("scan cancelled")
	}

	// Await occupancy in the worker pool
	phaseSemaphore <- struct{}{}

	GetLogger().WithField("step", step).WithField("total", total).Infof("[INFO] %s", description)
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
		done := make(chan error, 1)
		// The timeout goroutine also sets the phase key so logs from fn()
		// are captured under this phase's key.
		go func() {
			SetGoroutinePhaseKey(phaseKey)
			defer ClearGoroutinePhaseKey()
			done <- fn()
		}()
		select {
		case err = <-done:
			<-phaseSemaphore
		case <-time.After(time.Duration(timeoutSeconds) * time.Second):
			err = ErrTimeout
			// Keep slot occupied until underlying work truly exits to avoid runaway parallelism.
			go func() {
				<-done
				<-phaseSemaphore
			}()
		}
	} else {
		err = fn()
		<-phaseSemaphore
	}

	if err != nil {
		if err == ErrTimeout {
			GetLogger().Warnf("[WARN] %s timed out", description)
		} else {
			GetLogger().WithError(err).Errorf("[ERROR] %s failed", description)
		}

		if scanID != "" {
			_ = db.AppendScanPhase(scanID, description, true)
		}
		SendWebhookLogAsync(fmt.Sprintf("[ERROR] %s failed: %v", description, err))
		return err
	}

	GetLogger().Infof("[OK] %s completed", description)
	if scanID != "" {
		_ = db.AppendScanPhase(scanID, description, false)
	}

	// Log a per-phase summary with findings count for the log drawer.
	if phaseKey != "" {
		phaseFiles := GetPhaseFiles(phaseKey, target)
		var totalFindings int
		var foundFiles []string
		for _, f := range phaseFiles {
			if info, ferr := os.Stat(f); ferr == nil && info.Size() > 0 {
				count := countFindingsInFile(f)
				if count > 0 {
					totalFindings += count
					foundFiles = append(foundFiles, filepath.Base(f))
				}
			}
		}
		parts := []string{fmt.Sprintf("Phase: %s", description)}
		if totalFindings > 0 {
			parts = append(parts, fmt.Sprintf("Findings: %d across %d file(s)", totalFindings, len(foundFiles)))
			parts = append(parts, fmt.Sprintf("Files: %s", strings.Join(foundFiles, ", ")))
		} else {
			parts = append(parts, "Findings: 0 (no results)")
		}
		GetLogger().Infof("[SUMMARY] %s", strings.Join(parts, " | "))
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

// countFindingsInFile reads a result file and returns the number of findings it contains.
// For JSON arrays: counts array items.
// For structured JSON objects with known array keys (findings, results, etc.): counts those.
// For text files: counts non-empty, non-header lines.
func countFindingsInFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "" {
		return 0
	}

	ext := strings.ToLower(filepath.Ext(path))

	// ── JSON files ──
	if ext == ".json" {
		var top interface{}
		if json.Unmarshal(data, &top) != nil {
			return 0
		}
		switch v := top.(type) {
		case []interface{}:
			return len(v)
		case map[string]interface{}:
			// Look for known result-array keys.
			for _, key := range []string{"findings", "results", "matches", "issues", "vulnerabilities", "data", "items", "urls"} {
				if arr, ok := v[key].([]interface{}); ok {
					return len(arr)
				}
			}
			// For objects with string-array maps (like apkx results.json).
			total := 0
			for _, val := range v {
				if arr, ok := val.([]interface{}); ok {
					total += len(arr)
				}
			}
			return total
		}
		return 0
	}

	// ── Text / JSONL / mixed files ──
	// JSONL: count valid JSON objects per line.
	if ext == ".jsonl" || strings.HasPrefix(s, "{") {
		lines := strings.Split(s, "\n")
		count := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "{") {
				var obj map[string]interface{}
				if json.Unmarshal([]byte(line), &obj) == nil {
					count++
					continue
				}
			}
			// Non-JSON, non-empty content line.
			if !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
				count++
			}
		}
		return count
	}

	// ── Plain text ──
	lines := strings.Split(s, "\n")
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Skip summary/header lines in nuclei, gf, etc.
		if strings.HasPrefix(line, "Nuclei Scan Summary") ||
			strings.HasPrefix(line, "Target:") ||
			strings.HasPrefix(line, "Mode:") ||
			strings.HasPrefix(line, "=== ") ||
			strings.HasPrefix(line, "Tools Used:") {
			continue
		}
		count++
	}
	return count
}
