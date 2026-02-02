package monitor

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
)

// Options for monitor commands
type Options struct {
	URL      string
	ID       int
	Strategy string
	Pattern  string
	Action   string // "add", "remove", "list", "start", "stop"
	Interval int
	All      bool
}

// Run executes monitor command based on action
func Run(opts Options) error {
	if opts.Action == "" {
		return fmt.Errorf("action is required")
	}

	// Ensure DB is initialized
	if err := db.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema: %v", err)
	}

	switch opts.Action {
	case "list":
		return handleList()
	case "add":
		if opts.URL == "" {
			return fmt.Errorf("URL is required for add action")
		}
		if opts.Strategy == "" {
			opts.Strategy = "hash"
		}
		return handleAdd(opts.URL, opts.Strategy, opts.Pattern)
	case "remove":
		if opts.ID > 0 {
			target, err := db.GetMonitorTargetByID(opts.ID)
			if err != nil {
				return err
			}
			return handleRemove(target.URL)
		} else if opts.URL == "" {
			return fmt.Errorf("URL or ID is required for remove action")
		}
		return handleRemove(opts.URL)
	case "start":
		// Start monitoring is a placeholder - actual monitoring would run as a daemon
		return handleStart(opts)
	case "stop":
		// Stop monitoring is a placeholder
		return handleStop(opts)
	default:
		return fmt.Errorf("unknown action: %s", opts.Action)
	}
}

func handleList() error {
	targets, err := db.ListMonitorTargets()
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("No targets configured")
		return nil
	}

	for _, t := range targets {
		patternStr := "N/A"
		if t.Pattern != "" {
			patternStr = t.Pattern
		}
		status := "❌ Not Running"
		if t.IsRunning {
			status = "[ + ]Running"
		}
		fmt.Printf("ID: %d | URL: %s | Strategy: %s | Pattern: %s | Status: %s\n", t.ID, t.URL, t.Strategy, patternStr, status)
	}
	return nil
}

func handleAdd(url, strategy, pattern string) error {
	if err := db.AddMonitorTarget(url, strategy, pattern); err != nil {
		return err
	}
	fmt.Printf("[OK] Added monitoring target: %s (strategy: %s)\n", url, strategy)
	return nil
}

func handleRemove(url string) error {
	if err := db.RemoveMonitorTarget(url); err != nil {
		return err
	}
	fmt.Printf("[OK] Removed monitoring target: %s\n", url)
	return nil
}

func handleStart(opts Options) error {
	if opts.ID > 0 {
		target, err := db.GetMonitorTargetByID(opts.ID)
		if err != nil {
			return err
		}
		if err := db.SetMonitorRunningStatus(opts.ID, true); err != nil {
			return err
		}
		fmt.Printf("[OK] Started monitoring for ID %d: %s (strategy: %s)\n", target.ID, target.URL, target.Strategy)
		if opts.Interval > 0 {
			fmt.Printf("[INFO] Check interval: %d seconds\n", opts.Interval)
		}
	} else if opts.All {
		targets, err := db.ListMonitorTargets()
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("no targets configured")
		}
		for _, t := range targets {
			if err := db.SetMonitorRunningStatus(t.ID, true); err != nil {
				return err
			}
		}
		fmt.Printf("[OK] Started monitoring for %d target(s)\n", len(targets))
		if opts.Interval > 0 {
			fmt.Printf("[INFO] Check interval: %d seconds\n", opts.Interval)
		}
	} else if opts.URL != "" {
		// Find target by URL and start it
		targets, err := db.ListMonitorTargets()
		if err != nil {
			return err
		}
		found := false
		for _, t := range targets {
			if t.URL == opts.URL {
				if err := db.SetMonitorRunningStatus(t.ID, true); err != nil {
					return err
				}
				fmt.Printf("[OK] Started monitoring for: %s\n", opts.URL)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("target not found: %s", opts.URL)
		}
		if opts.Interval > 0 {
			fmt.Printf("[INFO] Check interval: %d seconds\n", opts.Interval)
		}
	} else {
		return fmt.Errorf("either --all, --id <id>, or -u <url> must be specified")
	}
	return nil
}

func handleStop(opts Options) error {
	if opts.ID > 0 {
		target, err := db.GetMonitorTargetByID(opts.ID)
		if err != nil {
			return err
		}
		if err := db.SetMonitorRunningStatus(opts.ID, false); err != nil {
			return err
		}
		fmt.Printf("[OK] Stopped monitor for ID %d: %s\n", target.ID, target.URL)
	} else if opts.All {
		targets, err := db.ListMonitorTargets()
		if err != nil {
			return err
		}
		for _, t := range targets {
			if err := db.SetMonitorRunningStatus(t.ID, false); err != nil {
				return err
			}
		}
		fmt.Printf("[OK] Stopped all monitors (%d target(s))\n", len(targets))
	} else if opts.URL != "" {
		targets, err := db.ListMonitorTargets()
		if err != nil {
			return err
		}
		found := false
		for _, t := range targets {
			if t.URL == opts.URL {
				if err := db.SetMonitorRunningStatus(t.ID, false); err != nil {
					return err
				}
				fmt.Printf("[OK] Stopped monitor for: %s\n", opts.URL)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("target not found: %s", opts.URL)
		}
	} else {
		return fmt.Errorf("either --all, --id <id>, or -u <url> must be specified")
	}
	return nil
}
