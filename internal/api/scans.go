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

	"github.com/h0tak88r/AutoAR/internal/utils"
)

var (
	ActiveScans = make(map[string]*ScanInfo)
	ScansMutex  sync.RWMutex
)

func init() {
	// Register the cancel-check hook so utils.IsScanCancelled (called from
	// RunWorkflowPhase) can inspect the api-layer CancelRequested flag without
	// creating a circular import (utils → api is not allowed).
	utils.RegisterCancelChecker(func(scanID string) bool {
		ScansMutex.RLock()
		defer ScansMutex.RUnlock()
		si, ok := ActiveScans[scanID]
		return ok && si != nil && si.CancelRequested
	})
}

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

	// If it's a child process, kill the entire process group so that
	// sub-tools (nuclei, subfinder, etc.) are also terminated.
	if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
		pid := scan.ExecCmd.Process.Pid
		log.Printf("[INFO] Killing child process group for scan %s (pid %d)", id, pid)
		// Since we set Setpgid=true, the child leads its own process group.
		// Send SIGTERM to the group (negative pgid = group kill).
		pgid, pgidErr := syscall.Getpgid(pid)
		if pgidErr == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = scan.ExecCmd.Process.Signal(syscall.SIGTERM)
		}
		go func() {
			time.Sleep(2 * time.Second)
			if pgidErr == nil {
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			} else {
				_ = scan.ExecCmd.Process.Kill()
			}
		}()
	}

	// If it has a cancel function, call it
	if scan.CancelFunc != nil {
		scan.CancelFunc()
	}

	return nil
}

// PauseScanByID pauses a running scan child process and all its sub-tools
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
	pid := scan.ExecCmd.Process.Pid
	log.Printf("[INFO] Pausing scan %s (pid %d) process group", id, pid)
	pgid, pgidErr := syscall.Getpgid(pid)
	if pgidErr == nil {
		return syscall.Kill(-pgid, syscall.SIGSTOP)
	}
	return scan.ExecCmd.Process.Signal(syscall.SIGSTOP)
}

// ResumeScanByID resumes a paused scan child process and all its sub-tools
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
	pid := scan.ExecCmd.Process.Pid
	log.Printf("[INFO] Resuming scan %s (pid %d) process group", id, pid)
	pgid, pgidErr := syscall.Getpgid(pid)
	if pgidErr == nil {
		return syscall.Kill(-pgid, syscall.SIGCONT)
	}
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
