package subdomainmonitor

import (
	"encoding/json"
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

var (
	daemonRunning bool
	daemonMutex   sync.Mutex
	stopDaemon    chan struct{}
	daemonWg      sync.WaitGroup
	stopOnce      sync.Once

	// monitorInFlight tracks targets whose scan is currently running, so a scan
	// that outlasts its interval isn't started again by the next ticker pass
	// (which would cause duplicate DB writes and duplicate webhook alerts).
	monitorInFlight   = make(map[int]bool)
	monitorInFlightMu sync.Mutex
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

	logger.GetLogger().Infoln("[INFO] Starting subdomain monitoring daemon...")

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

	logger.GetLogger().Infoln("[INFO] Stopping subdomain monitoring daemon...")

	stopOnce.Do(func() {
		if stopDaemon != nil {
			close(stopDaemon)
		}
	})

	daemonWg.Wait()
	daemonRunning = false

	logger.GetLogger().Infoln("[OK] Subdomain monitoring daemon stopped")
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
		logger.GetLogger().Infof("[ERROR] Failed to list subdomain monitor targets: %v", err)
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

		// Skip if a scan for this target is already in flight (it outran its
		// interval) — prevents duplicate runs, DB writes and webhook alerts.
		monitorInFlightMu.Lock()
		if monitorInFlight[target.ID] {
			monitorInFlightMu.Unlock()
			continue
		}
		monitorInFlight[target.ID] = true
		monitorInFlightMu.Unlock()

		go func(t db.SubdomainMonitorTarget) {
			defer func() {
				monitorInFlightMu.Lock()
				delete(monitorInFlight, t.ID)
				monitorInFlightMu.Unlock()
			}()
			logger.GetLogger().Infof("[INFO] Running subdomain monitoring for %s (interval: %ds)", t.Domain, t.Interval)

			// First run for this target establishes a baseline (no new_subdomain /
			// new_js_endpoint spam); LastRunAt is nil until the post-run update below.
			isBaseline := t.LastRunAt == nil

			result, err := MonitorSubdomains(MonitorOptions{
				Domain:           t.Domain,
				Threads:          t.Threads,
				CheckNew:         t.CheckNew,
				Reenumerate:      t.CheckNew, // "detect new subs" also drives passive re-enumeration
				MonitorJS:        t.MonitorJS,
				SuppressBaseline: isBaseline,
				Notify:           true,
			})
			if err != nil {
				logger.GetLogger().Infof("[ERROR] Failed to monitor subdomains for %s: %v", t.Domain, err)
				return
			}

			// Update last_run_at (the fix for the timer bug)
			if err := db.UpdateSubdomainMonitorLastRun(t.ID); err != nil {
				logger.GetLogger().Infof("[WARN] Failed to update last_run_at for %s: %v", t.Domain, err)
			}

			totalChanges := len(result.NewSubdomains) + len(result.StatusChanges) +
				len(result.BecameLive) + len(result.BecameDead) + len(result.NewEndpoints)
			if totalChanges > 0 {
				logger.GetLogger().Infof("[OK] Monitor %s: %d new, %d status changes, %d live, %d dead, %d new JS endpoints",
					t.Domain, len(result.NewSubdomains), len(result.StatusChanges),
					len(result.BecameLive), len(result.BecameDead), len(result.NewEndpoints))
				persistAndNotifyChanges(t, result)
			} else {
				logger.GetLogger().Infof("[OK] Monitor %s: no changes", t.Domain)
			}
		}(target)
	}
}

// persistAndNotifyChanges saves each change to monitor_changes and fires a webhook alert.
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
			logger.GetLogger().Infof("[WARN] Failed to persist monitor change for %s: %v", change.Subdomain, err)
		}
	}

	for _, ep := range result.NewEndpoints {
		detail, _ := json.Marshal(map[string]interface{}{
			"endpoint":  ep.Endpoint,
			"source_js": ep.SourceJS,
			"message":   "New JS endpoint discovered",
		})
		if err := db.InsertMonitorChange(&db.MonitorChange{
			TargetType: "subdomain",
			TargetID:   t.ID,
			Domain:     t.Domain,
			ChangeType: string(ChangeTypeNewJSEndpoint),
			Detail:     string(detail),
			Notified:   true,
		}); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to persist JS endpoint change for %s: %v", ep.Endpoint, err)
		}
	}

	msg := formatChangeAlert(t.Domain, result)
	logger.GetLogger().Infof("[SUBDOMAIN-MONITOR] Alert: %s", msg)
	utils.SendMonitorWebhook(msg)
}

// maxAlertItemsPerCategory caps how many individual hosts are listed per change
// category in a webhook alert. A big liveness flap can produce hundreds of status
// changes; listing them all is spammy (and, before chunking, blew past Discord's
// limit). The count is always shown in full; only the itemized list is capped.
const maxAlertItemsPerCategory = 20

// formatChangeAlert returns a webhook-ready markdown summary of detected changes.
func formatChangeAlert(domain string, r *MonitorResult) string {
	msg := fmt.Sprintf(" **Subdomain Monitor Alert** — `%s`\n", domain)
	msg += changeSection("**%d new** subdomain(s) appeared", r.NewSubdomains)
	msg += changeSection("**%d** became **live**", r.BecameLive)
	msg += changeSection("**%d** became **dead**", r.BecameDead)
	msg += changeSection("**%d** status change(s)", r.StatusChanges)
	if len(r.NewEndpoints) > 0 {
		msg += fmt.Sprintf(" **%d new** JS endpoint(s) discovered\n", len(r.NewEndpoints))
		for i, e := range r.NewEndpoints {
			if i >= maxAlertItemsPerCategory {
				msg += fmt.Sprintf("  …and %d more\n", len(r.NewEndpoints)-maxAlertItemsPerCategory)
				break
			}
			msg += fmt.Sprintf("  • `%s`\n", e.Endpoint)
		}
	}
	return msg
}

// changeSection renders a "%d …" header + a capped bullet list of the changes.
func changeSection(headerFmt string, changes []SubdomainChange) string {
	if len(changes) == 0 {
		return ""
	}
	out := " " + fmt.Sprintf(headerFmt, len(changes)) + "\n"
	for i, c := range changes {
		if i >= maxAlertItemsPerCategory {
			out += fmt.Sprintf("  …and %d more\n", len(changes)-maxAlertItemsPerCategory)
			break
		}
		out += fmt.Sprintf("  • `%s` — %s\n", c.Subdomain, c.Message)
	}
	return out
}
