package api

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	ActiveScans = make(map[string]*ScanInfo)
	ScansMutex  sync.RWMutex
)

type ScanInfo struct {
	ScanID      string
	Type        string
	ScanType    string // For API compatibility
	Target      string
	Status      string
	StartTime   time.Time
	StartedAt   time.Time // For API compatibility
	CompletedAt *time.Time
	Command     string
	CancelFunc  context.CancelFunc // Function to cancel the scan (Discord / CommandContext runs)
	ExecCmd     *exec.Cmd          `json:"-"` // API executeScan: child process (kill / pause via signals)
	CancelRequested bool           `json:"-"` // API: user requested stop; Wait() will mark cancelled
	MessageID   string             // Discord message ID for updating messages
	ChannelID   string             // Discord channel ID for updating messages
	ThreadID    string             // Discord thread ID for sending updates (avoids token expiration)

	// Progress tracking
	CurrentPhase    int       // Current phase number (1-based)
	TotalPhases     int       // Total number of phases
	PhaseName       string    // Name of current phase
	PhaseStartTime  time.Time // When current phase started
	CompletedPhases []string  // List of completed phase names
	FailedPhases    []string  // List of failed phase names

	// Statistics
	FilesUploaded int       // Number of files uploaded
	ErrorCount    int       // Number of errors encountered
	LastUpdate    time.Time // Last progress update time
}

// CancelScanByID stops a running scan
func CancelScanByID(id string) error {
	ScansMutex.Lock()
	scan, ok := ActiveScans[id]
	if !ok {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s not found or not active", id)
	}
	scan.CancelRequested = true
	ScansMutex.Unlock()

	// If it's a child process, kill it
	if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
		log.Printf("[INFO] Killing child process for scan %s (pid %d)", id, scan.ExecCmd.Process.Pid)
		// Send SIGTERM first, then SIGKILL if it doesn't stop
		_ = scan.ExecCmd.Process.Signal(syscall.SIGTERM)
		go func() {
			time.Sleep(2 * time.Second)
			_ = scan.ExecCmd.Process.Kill()
		}()
	}

	// If it has a cancel function, call it
	if scan.CancelFunc != nil {
		scan.CancelFunc()
	}

	return nil
}

// PauseScanByID pauses a running scan child process
func PauseScanByID(id string) error {
	ScansMutex.RLock()
	scan, ok := ActiveScans[id]
	ScansMutex.RUnlock()
	if !ok {
		return fmt.Errorf("scan %s not found or not active", id)
	}
	if scan.ExecCmd == nil || scan.ExecCmd.Process == nil {
		return fmt.Errorf("scan %s has no active process to pause", id)
	}
	log.Printf("[INFO] Pausing scan %s (pid %d)", id, scan.ExecCmd.Process.Pid)
	return scan.ExecCmd.Process.Signal(syscall.SIGSTOP)
}

// ResumeScanByID resumes a paused scan child process
func ResumeScanByID(id string) error {
	ScansMutex.RLock()
	scan, ok := ActiveScans[id]
	ScansMutex.RUnlock()
	if !ok {
		return fmt.Errorf("scan %s not found or not active", id)
	}
	if scan.ExecCmd == nil || scan.ExecCmd.Process == nil {
		return fmt.Errorf("scan %s has no active process to resume", id)
	}
	log.Printf("[INFO] Resuming scan %s (pid %d)", id, scan.ExecCmd.Process.Pid)
	return scan.ExecCmd.Process.Signal(syscall.SIGCONT)
}

// ScanIsActiveInMemory checks if a scan ID is currently tracked as running/paused
func ScanIsActiveInMemory(id string) bool {
	ScansMutex.RLock()
	defer ScansMutex.RUnlock()
	scan, ok := ActiveScans[id]
	if !ok {
		return false
	}
	st := strings.ToLower(scan.Status)
	return st == "running" || st == "starting" || st == "paused" || st == "cancelling"
}
