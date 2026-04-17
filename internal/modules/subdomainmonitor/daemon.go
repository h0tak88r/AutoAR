package subdomainmonitor

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

var (
	daemonRunning bool
	daemonMutex   sync.Mutex
	stopDaemon    chan struct{}
	daemonWg      sync.WaitGroup
	stopOnce      sync.Once
)

// StartDaemon starts the subdomain monitoring daemon
func StartDaemon() error {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()

	if daemonRunning {
		return fmt.Errorf("daemon is already running")
	}

	if err := db.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	if err := db.InitSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	daemonRunning = true
	stopDaemon = make(chan struct{})
	stopOnce = sync.Once{}

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
	ticker := time.NewTicker(60 * time.Second)
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

		// FIX: Use LastRunAt (dedicated column) — not UpdatedAt which changes on start/stop.
		var lastCheck time.Time
		if target.LastRunAt != nil {
			lastCheck = *target.LastRunAt
		} else {
			lastCheck = target.CreatedAt // first run ever
		}
		interval := time.Duration(target.Interval) * time.Second

		if now.Before(lastCheck.Add(interval)) {
			continue // not time yet
		}

		go func(t db.SubdomainMonitorTarget) {
			log.Printf("[INFO] Running subdomain monitoring for %s (interval: %ds)", t.Domain, t.Interval)

			result, err := MonitorSubdomains(MonitorOptions{
				Domain:   t.Domain,
				Threads:  t.Threads,
				CheckNew: t.CheckNew,
				Notify:   true,
			})
			if err != nil {
				log.Printf("[ERROR] Failed to monitor subdomains for %s: %v", t.Domain, err)
				return
			}

			// Update last_run_at (the fix for the timer bug)
			if err := db.UpdateSubdomainMonitorLastRun(t.ID); err != nil {
				log.Printf("[WARN] Failed to update last_run_at for %s: %v", t.Domain, err)
			}

			totalChanges := len(result.NewSubdomains) + len(result.StatusChanges) +
				len(result.BecameLive) + len(result.BecameDead)
			if totalChanges > 0 {
				log.Printf("[OK] Monitor %s: %d new, %d status changes, %d live, %d dead",
					t.Domain, len(result.NewSubdomains), len(result.StatusChanges),
					len(result.BecameLive), len(result.BecameDead))
				persistAndNotifyChanges(t, result)
			} else {
				log.Printf("[OK] Monitor %s: no changes", t.Domain)
			}
		}(target)
	}
}

// persistAndNotifyChanges saves each change to monitor_changes and fires a Discord alert.
func persistAndNotifyChanges(t db.SubdomainMonitorTarget, result *MonitorResult) {
	all := append(append(append(result.NewSubdomains, result.BecameLive...), result.BecameDead...), result.StatusChanges...)

	for _, change := range all {
		detail, _ := json.Marshal(map[string]interface{}{
			"subdomain":        change.Subdomain,
			"old_http_status":  change.OldHTTPStatus,
			"new_http_status":  change.NewHTTPStatus,
			"old_https_status": change.OldHTTPSStatus,
			"new_https_status": change.NewHTTPSStatus,
			"message":          change.Message,
		})
		if err := db.InsertMonitorChange(&db.MonitorChange{
			TargetType: "subdomain",
			TargetID:   t.ID,
			Domain:     t.Domain,
			ChangeType: string(change.ChangeType),
			Detail:     string(detail),
			Notified:   true,
		}); err != nil {
			log.Printf("[WARN] Failed to persist monitor change for %s: %v", change.Subdomain, err)
		}
	}

	msg := formatChangeAlert(t.Domain, result)
	log.Printf("[SUBDOMAIN-MONITOR] Alert: %s", msg)
	utils.SendMonitorWebhook(msg)
}

// formatChangeAlert returns a Discord-ready markdown summary of detected changes.
func formatChangeAlert(domain string, r *MonitorResult) string {
	msg := fmt.Sprintf("🔔 **Subdomain Monitor Alert** — `%s`\n", domain)
	if len(r.NewSubdomains) > 0 {
		msg += fmt.Sprintf("🆕 **%d new** subdomain(s) appeared\n", len(r.NewSubdomains))
		for _, c := range r.NewSubdomains {
			msg += fmt.Sprintf("  • `%s` — %s\n", c.Subdomain, c.Message)
		}
	}
	if len(r.BecameLive) > 0 {
		msg += fmt.Sprintf("✅ **%d** became **live**\n", len(r.BecameLive))
		for _, c := range r.BecameLive {
			msg += fmt.Sprintf("  • `%s` — %s\n", c.Subdomain, c.Message)
		}
	}
	if len(r.BecameDead) > 0 {
		msg += fmt.Sprintf("💀 **%d** became **dead**\n", len(r.BecameDead))
		for _, c := range r.BecameDead {
			msg += fmt.Sprintf("  • `%s` — %s\n", c.Subdomain, c.Message)
		}
	}
	if len(r.StatusChanges) > 0 {
		msg += fmt.Sprintf("🔄 **%d** status change(s)\n", len(r.StatusChanges))
		for _, c := range r.StatusChanges {
			msg += fmt.Sprintf("  • `%s` — %s\n", c.Subdomain, c.Message)
		}
	}
	return msg
}
