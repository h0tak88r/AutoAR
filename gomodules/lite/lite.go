package lite

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/gomodules/livehosts"
	"github.com/h0tak88r/AutoAR/gomodules/nuclei"
	"github.com/h0tak88r/AutoAR/gomodules/reflection"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
)

// Options holds lite scan options
type Options struct {
	Domain              string
	SkipJS              bool
	PhaseTimeoutDefault int // seconds
	Timeouts            map[string]int
}

// Result holds lite scan results
type Result struct {
	Domain string
	Steps  int
}

// RunLite runs the lite scan workflow
func RunLite(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if opts.PhaseTimeoutDefault == 0 {
		opts.PhaseTimeoutDefault = 3600 // 1 hour default
	}

	if opts.Timeouts == nil {
		opts.Timeouts = make(map[string]int)
	}

	// Set defaults for unset timeouts
	phases := []string{"livehosts", "reflection", "js", "nuclei"}
	for _, phase := range phases {
		if opts.Timeouts[phase] == 0 {
			opts.Timeouts[phase] = opts.PhaseTimeoutDefault
		}
	}

	totalSteps := 4
	if !opts.SkipJS {
		totalSteps = 5
	}

	log.Printf("[INFO] Starting Lite Scan for %s (%d steps)", opts.Domain, totalSteps)

	step := 1

	// Step 1: Live host filtering
	if err := runPhase("livehosts", step, totalSteps, "Live host filtering", opts.Domain, opts.Timeouts["livehosts"], func() error {
		_, err := livehosts.FilterLiveHosts(opts.Domain, 100, true)
		return err
	}); err != nil {
		log.Printf("[WARN] Live host filtering failed: %v", err)
	}
	step++

	// Step 2: Reflection scanning
	if err := runPhase("reflection", step, totalSteps, "Reflection scanning", opts.Domain, opts.Timeouts["reflection"], func() error {
		_, err := reflection.ScanReflection(opts.Domain)
		return err
	}); err != nil {
		log.Printf("[WARN] Reflection scanning failed: %v", err)
	}
	step++

	// Step 3: JavaScript scanning (skippable)
	if !opts.SkipJS {
		if err := runPhase("js", step, totalSteps, "JavaScript scanning", opts.Domain, opts.Timeouts["js"], func() error {
			// Call js_scan via autoar command
			cmd := exec.Command("autoar", "js", "scan", "-d", opts.Domain)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}); err != nil {
			log.Printf("[WARN] JavaScript scanning failed: %v", err)
		}
		step++
	}

	// Step 4: Nuclei vulnerability scan
	if err := runPhase("nuclei", step, totalSteps, "Nuclei vulnerability scan", opts.Domain, opts.Timeouts["nuclei"], func() error {
		_, err := nuclei.RunNuclei(nuclei.Options{Domain: opts.Domain, Mode: nuclei.ModeFull, Threads: 100})
		return err
	}); err != nil {
		log.Printf("[WARN] Nuclei scan failed: %v", err)
	}

	log.Printf("[OK] Lite Scan completed for %s", opts.Domain)
	return &Result{Domain: opts.Domain, Steps: totalSteps}, nil
}

func runPhase(phaseKey string, step, total int, description, domain string, timeoutSeconds int, fn func() error) error {
	timeoutLabel := ""
	if timeoutSeconds > 0 {
		timeoutLabel = fmt.Sprintf(" (timeout: %s)", formatTimeout(timeoutSeconds))
	}

	log.Printf("[INFO] Step %d/%d: %s", step, total, description)

	var err error
	if timeoutSeconds > 0 {
		err = runWithTimeout(fn, time.Duration(timeoutSeconds)*time.Second)
	} else {
		err = fn()
	}

	if err != nil {
		if err == ErrTimeout {
			log.Printf("[WARN] %s timed out after %s", description, formatTimeout(timeoutSeconds))
			return nil // Continue with next phase
		}
		return err
	}

	log.Printf("[OK] %s completed", description)
	return nil
}

var ErrTimeout = fmt.Errorf("timeout")

func runWithTimeout(fn func() error, timeout time.Duration) error {
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

func formatTimeout(seconds int) string {
	if seconds <= 0 {
		return "no limit"
	}
	hrs := seconds / 3600
	mins := (seconds % 3600) / 60
	secs := seconds % 60
	var parts []string
	if hrs > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hrs))
	}
	if mins > 0 {
		parts = append(parts, fmt.Sprintf("%dm", mins))
	}
	if hrs == 0 && mins == 0 {
		parts = append(parts, fmt.Sprintf("%ds", secs))
	}
	return strings.Join(parts, "")
}

// ParseTimeout parses timeout string like "30m", "2h", "3600" into seconds
func ParseTimeout(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "none" || s == "off" || s == "disable" || s == "disabled" || s == "0" {
		return 0, nil
	}

	// Try to parse as number with optional suffix
	if strings.HasSuffix(s, "s") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "s")); err == nil {
			return val, nil
		}
	}
	if strings.HasSuffix(s, "m") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "m")); err == nil {
			return val * 60, nil
		}
	}
	if strings.HasSuffix(s, "h") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "h")); err == nil {
			return val * 3600, nil
		}
	}
	if strings.HasSuffix(s, "d") {
		if val, err := strconv.Atoi(strings.TrimSuffix(s, "d")); err == nil {
			return val * 86400, nil
		}
	}

	// Try plain number
	if val, err := strconv.Atoi(s); err == nil {
		return val, nil
	}

	return 0, fmt.Errorf("invalid timeout format: %s", s)
}
