package subdomainmonitor

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
)

var (
	daemonRunning bool
	daemonMutex   sync.Mutex
	stopDaemon    chan struct{}
	daemonWg      sync.WaitGroup
	stopOnce      sync.Once
)

// StartDaemon starts the subdomain monitoring daemon
// It periodically checks all running subdomain monitor targets
func StartDaemon() error {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()

	if daemonRunning {
		return fmt.Errorf("daemon is already running")
	}

	// Initialize database
	if err := db.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	if err := db.InitSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	daemonRunning = true
	stopDaemon = make(chan struct{})
	stopOnce = sync.Once{} // Reset sync.Once for new daemon instance

	log.Println("[INFO] Starting subdomain monitoring daemon...")

	daemonWg.Add(1)
	go func() {
		defer daemonWg.Done()
		runDaemonLoop()
	}()

	return nil
}

// StopDaemon stops the subdomain monitoring daemon
func StopDaemon() error {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()

	if !daemonRunning {
		return fmt.Errorf("daemon is not running")
	}

	log.Println("[INFO] Stopping subdomain monitoring daemon...")
	
	// Use sync.Once to prevent double close panic
	stopOnce.Do(func() {
		if stopDaemon != nil {
			close(stopDaemon)
		}
	})
	
	daemonWg.Wait()
	daemonRunning = false

	log.Println("[OK] Subdomain monitoring daemon stopped")
	return nil
}

// IsDaemonRunning returns whether the daemon is currently running
func IsDaemonRunning() bool {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()
	return daemonRunning
}

// runDaemonLoop is the main daemon loop that checks targets periodically
func runDaemonLoop() {
	ticker := time.NewTicker(60 * time.Second) // Check every minute for targets that need checking
	defer ticker.Stop()

	for {
		select {
		case <-stopDaemon:
			return
		case <-ticker.C:
			checkAllRunningTargets()
		}
	}
}

// checkAllRunningTargets checks all running subdomain monitor targets
func checkAllRunningTargets() {
	targets, err := db.ListSubdomainMonitorTargets()
	if err != nil {
		log.Printf("[ERROR] Failed to list subdomain monitor targets: %v", err)
		return
	}

	now := time.Now()
	for _, target := range targets {
		if !target.IsRunning {
			continue
		}

		// Check if it's time to run this target
		lastCheck := target.UpdatedAt
		interval := time.Duration(target.Interval) * time.Second
		nextCheck := lastCheck.Add(interval)

		if now.Before(nextCheck) {
			// Not time yet, skip
			continue
		}

		// Run monitoring for this target in a goroutine
		go func(t db.SubdomainMonitorTarget) {
			log.Printf("[INFO] Running subdomain monitoring for %s (interval: %ds)", t.Domain, t.Interval)
			
			opts := MonitorOptions{
				Domain:    t.Domain,
				Threads:   t.Threads,
				CheckNew:  t.CheckNew,
				Notify:    true, // Enable notifications for daemon runs
			}

			result, err := MonitorSubdomains(opts)
			if err != nil {
				log.Printf("[ERROR] Failed to monitor subdomains for %s: %v", t.Domain, err)
				return
			}

			// Log results
			totalChanges := len(result.NewSubdomains) + len(result.StatusChanges) + len(result.BecameLive) + len(result.BecameDead)
			if totalChanges > 0 {
				log.Printf("[OK] Monitoring complete for %s: %d new, %d status changes, %d became live, %d became dead",
					t.Domain, len(result.NewSubdomains), len(result.StatusChanges), len(result.BecameLive), len(result.BecameDead))
				
				// TODO: Send notifications (Discord webhook, email, etc.)
				// For now, just log
			} else {
				log.Printf("[OK] Monitoring complete for %s: No changes detected", t.Domain)
			}
		}(target)
	}
}

