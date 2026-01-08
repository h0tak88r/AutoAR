package subdomainmonitor

import (
	"fmt"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
)

// ManagerOptions contains options for managing subdomain monitoring targets
type ManagerOptions struct {
	Action   string // "add", "remove", "list", "start", "stop"
	Domain   string
	ID       int
	Interval int
	Threads  int
	CheckNew bool
	All      bool
}

// ManageTargets manages subdomain monitoring targets
func ManageTargets(opts ManagerOptions) error {
	if opts.Action == "" {
		return fmt.Errorf("action is required")
	}

	// Ensure DB is initialized
	if err := db.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	if err := db.InitSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	switch opts.Action {
	case "list":
		return handleList()
	case "add":
		if opts.Domain == "" {
			return fmt.Errorf("domain is required for add action")
		}
		if opts.Interval <= 0 {
			opts.Interval = 3600 // Default 1 hour
		}
		if opts.Threads <= 0 {
			opts.Threads = 100
		}
		return handleAdd(opts.Domain, opts.Interval, opts.Threads, opts.CheckNew)
	case "remove":
		if opts.ID > 0 {
			target, err := db.GetSubdomainMonitorTargetByID(opts.ID)
			if err != nil {
				return err
			}
			return handleRemove(target.Domain)
		} else if opts.Domain == "" {
			return fmt.Errorf("domain or ID is required for remove action")
		}
		return handleRemove(opts.Domain)
	case "start":
		return handleStart(opts)
	case "stop":
		return handleStop(opts)
	default:
		return fmt.Errorf("unknown action: %s", opts.Action)
	}
}

func handleList() error {
	targets, err := db.ListSubdomainMonitorTargets()
	if err != nil {
		return err
	}

	if len(targets) == 0 {
		fmt.Println("No subdomain monitoring targets configured")
		return nil
	}

	for _, t := range targets {
		status := "❌ Not Running"
		if t.IsRunning {
			status = "[ + ]Running"
		}
		checkNewStr := "No"
		if t.CheckNew {
			checkNewStr = "Yes"
		}
		fmt.Printf("ID: %d | Domain: %s | Interval: %ds | Threads: %d | Check New: %s | Status: %s\n",
			t.ID, t.Domain, t.Interval, t.Threads, checkNewStr, status)
	}
	return nil
}

func handleAdd(domain string, interval int, threads int, checkNew bool) error {
	if err := db.AddSubdomainMonitorTarget(domain, interval, threads, checkNew); err != nil {
		return err
	}
	fmt.Printf("[OK] Added subdomain monitoring target: %s (interval: %ds, threads: %d, check_new: %v)\n",
		domain, interval, threads, checkNew)
	return nil
}

func handleRemove(domain string) error {
	if err := db.RemoveSubdomainMonitorTarget(domain); err != nil {
		return err
	}
	fmt.Printf("[OK] Removed subdomain monitoring target: %s\n", domain)
	return nil
}

func handleStart(opts ManagerOptions) error {
	if opts.ID > 0 {
		target, err := db.GetSubdomainMonitorTargetByID(opts.ID)
		if err != nil {
			return err
		}
		if err := db.SetSubdomainMonitorRunningStatus(opts.ID, true); err != nil {
			return err
		}
		fmt.Printf("[OK] Started subdomain monitoring for ID %d: %s (interval: %ds)\n", target.ID, target.Domain, target.Interval)
	} else if opts.All {
		targets, err := db.ListSubdomainMonitorTargets()
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("no targets configured")
		}
		for _, t := range targets {
			if err := db.SetSubdomainMonitorRunningStatus(t.ID, true); err != nil {
				return err
			}
		}
		fmt.Printf("[OK] Started subdomain monitoring for %d target(s)\n", len(targets))
	} else if opts.Domain != "" {
		// Find target by domain and start it
		targets, err := db.ListSubdomainMonitorTargets()
		if err != nil {
			return err
		}
		found := false
		for _, t := range targets {
			if t.Domain == opts.Domain {
				if err := db.SetSubdomainMonitorRunningStatus(t.ID, true); err != nil {
					return err
				}
				fmt.Printf("[OK] Started subdomain monitoring for: %s\n", opts.Domain)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("target not found: %s", opts.Domain)
		}
	} else {
		return fmt.Errorf("either --all, --id <id>, or -d <domain> must be specified")
	}

	// Start daemon if not already running
	if !IsDaemonRunning() {
		if err := StartDaemon(); err != nil {
			fmt.Printf("[WARN] Failed to start daemon: %v\n", err)
		} else {
			fmt.Println("[OK] Subdomain monitoring daemon started")
		}
	}

	return nil
}

func handleStop(opts ManagerOptions) error {
	if opts.ID > 0 {
		target, err := db.GetSubdomainMonitorTargetByID(opts.ID)
		if err != nil {
			return err
		}
		if err := db.SetSubdomainMonitorRunningStatus(opts.ID, false); err != nil {
			return err
		}
		fmt.Printf("[OK] Stopped subdomain monitoring for ID %d: %s\n", target.ID, target.Domain)
	} else if opts.All {
		targets, err := db.ListSubdomainMonitorTargets()
		if err != nil {
			return err
		}
		for _, t := range targets {
			if err := db.SetSubdomainMonitorRunningStatus(t.ID, false); err != nil {
				return err
			}
		}
		fmt.Printf("[OK] Stopped all subdomain monitors (%d target(s))\n", len(targets))
	} else if opts.Domain != "" {
		targets, err := db.ListSubdomainMonitorTargets()
		if err != nil {
			return err
		}
		found := false
		for _, t := range targets {
			if t.Domain == opts.Domain {
				if err := db.SetSubdomainMonitorRunningStatus(t.ID, false); err != nil {
					return err
				}
				fmt.Printf("[OK] Stopped subdomain monitoring for: %s\n", opts.Domain)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("target not found: %s", opts.Domain)
		}
	} else {
		return fmt.Errorf("either --all, --id <id>, or -d <domain> must be specified")
	}
	return nil
}

