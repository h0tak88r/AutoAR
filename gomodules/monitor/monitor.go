package monitor

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/gomodules/db"
)

// Options for monitor commands
type Options struct {
	URL      string
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
		if opts.URL == "" {
			return fmt.Errorf("URL is required for remove action")
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
		fmt.Printf("ID: %d | URL: %s | Strategy: %s | Pattern: %s\n", t.ID, t.URL, t.Strategy, patternStr)
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
	if opts.All {
		targets, err := db.ListMonitorTargets()
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("no targets configured")
		}
		fmt.Printf("[INFO] Starting monitoring for %d target(s)\n", len(targets))
		for _, t := range targets {
			fmt.Printf("[INFO] Monitoring: %s (strategy: %s)\n", t.URL, t.Strategy)
		}
	} else if opts.URL != "" {
		fmt.Printf("[INFO] Starting monitoring for: %s\n", opts.URL)
	} else {
		return fmt.Errorf("either --all or -u <url> must be specified")
	}
	
	if opts.Interval > 0 {
		fmt.Printf("[INFO] Check interval: %d seconds\n", opts.Interval)
	}
	
	fmt.Println("[INFO] Monitoring daemon would start here (not implemented yet)")
	return nil
}

func handleStop(opts Options) error {
	if opts.All {
		fmt.Println("[INFO] Stopping all monitors")
	} else if opts.URL != "" {
		fmt.Printf("[INFO] Stopping monitor for: %s\n", opts.URL)
	} else {
		return fmt.Errorf("either --all or -u <url> must be specified")
	}
	fmt.Println("[INFO] Monitor daemon stop would execute here (not implemented yet)")
	return nil
}
