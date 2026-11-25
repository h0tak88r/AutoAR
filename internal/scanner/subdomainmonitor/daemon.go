package subdomainmonitor

import (
	"encoding/json"
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"strconv"
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
	go superviseLoop(stopDaemon)

	return nil
}

// superviseLoop runs the daemon loop. However the loop ends (stop, or a panic
// that escaped a tick), it clears daemonRunning so IsDaemonRunning tells the
// truth and StartDaemon can start it again.
func superviseLoop(stop chan struct{}) {
	defer daemonWg.Done()
	defer utils.RecoverPanic("subdomain-monitor:loop")
	defer func() {
		daemonMutex.Lock()
		daemonRunning = false
		daemonMutex.Unlock()
	}()
	runDaemonLoop(stop)
}

// StopDaemon stops the subdomain monitoring daemon
func StopDaemon() error {
	daemonMutex.Lock()
	if !daemonRunning {
		daemonMutex.Unlock()
		return fmt.Errorf("daemon is not running")
	}

	logger.GetLogger().Infoln("[INFO] Stopping subdomain monitoring daemon...")

	stopOnce.Do(func() {
		if stopDaemon != nil {
			close(stopDaemon)
		}
	})
	daemonMutex.Unlock()
	// Wait outside daemonMutex: the loop goroutine takes it on exit to clear
	// daemonRunning.
	daemonWg.Wait()

	logger.GetLogger().Infoln("[OK] Subdomain monitoring daemon stopped")
	return nil
}

// IsDaemonRunning returns whether the daemon is currently running
func IsDaemonRunning() bool {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()
	return daemonRunning
}

// tickInterval / tickFn drive the loop (vars so tests can run it fast).
var (
	tickInterval = 60 * time.Second
	tickFn       = checkAllRunningTargets
)

// runDaemonLoop is the main daemon loop that checks targets periodically
func runDaemonLoop(stop chan struct{}) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			// Per-tick panic barrier: one bad cycle must not end the loop.
			utils.GuardedRun("subdomain-monitor:tick", tickFn)
		}
	}
}

// minCheckInterval floors a target's interval (the API accepts 1s): each run
// re-enumerates passively and probes every known host.
const minCheckInterval = 300 * time.Second

// minRetryDelay is the first backoff step after a failed run.
const minRetryDelay = 5 * time.Minute

// effectiveInterval is the target's interval, floored at minCheckInterval.
func effectiveInterval(seconds int) time.Duration {
	d := time.Duration(seconds) * time.Second
	if d < minCheckInterval {
		d = minCheckInterval
	}
	return d
}

// failureBackoff is the wait after n consecutive failed runs: 5m, 10m, 20m, …
// capped at the target's interval.
func failureBackoff(n int, interval time.Duration) time.Duration {
	d := minRetryDelay
	for i := 1; i < n && d < interval; i++ {
		d *= 2
	}
	if d > interval {
		d = interval
	}
	return d
}

// Failed runs never advance last_run_at, so without this a failing target was
// re-run on every 60s tick. Attempts are tracked in memory and failures back off.
var (
	retryMu    sync.Mutex
	retryState = map[int]retryInfo{}
)

type retryInfo struct {
	failures int
	next     time.Time
}

// retryDue reports whether a target that recently failed may run again.
func retryDue(id int, now time.Time) bool {
	retryMu.Lock()
	defer retryMu.Unlock()
	st, ok := retryState[id]
	return !ok || !now.Before(st.next)
}

// recordAttempt clears the failure state on success, or schedules the next
// retry after failureBackoff.
func recordAttempt(id int, ok bool, interval time.Duration, now time.Time) {
	retryMu.Lock()
	defer retryMu.Unlock()
	if ok {
		delete(retryState, id)
		return
	}
	st := retryState[id]
	st.failures++
	st.next = now.Add(failureBackoff(st.failures, interval))
	retryState[id] = st
}

// Per-feature baselines. A feature's first successful run records what exists
// silently; only later runs alert. Keying this off LastRunAt alone flooded when
// a feature was enabled on an existing target (last_run_at already set) or when
// the baseline run's enumeration/JS diff failed (last_run_at set anyway). The
// set of baselined features per target lives in one settings row.
const (
	settingBaselines = "SUBDOMAIN_MONITOR_BASELINES"
	featureReenum    = "reenumerate"
	featureJS        = "js"
)

var baselineMu sync.Mutex

func readBaselines() (map[string]map[string]bool, error) {
	all := map[string]map[string]bool{}
	v, err := db.GetSetting(settingBaselines)
	if err != nil {
		return nil, err
	}
	if v != "" {
		if err := json.Unmarshal([]byte(v), &all); err != nil {
			return nil, err
		}
	}
	return all, nil
}

// loadBaselines returns the target's baselined features (empty on error, which
// errs toward a silent baseline run rather than a flood).
func loadBaselines(id int) map[string]bool {
	baselineMu.Lock()
	defer baselineMu.Unlock()
	all, err := readBaselines()
	if err != nil {
		logger.GetLogger().Infof("[WARN] Subdomain monitor: could not read baselines: %v", err)
		return map[string]bool{}
	}
	out := map[string]bool{}
	for k, v := range all[strconv.Itoa(id)] {
		out[k] = v
	}
	return out
}

// saveBaselines replaces the target's baselined-feature set (a read failure
// aborts the write so other targets' markers are never clobbered).
func saveBaselines(id int, features map[string]bool) error {
	baselineMu.Lock()
	defer baselineMu.Unlock()
	all, err := readBaselines()
	if err != nil {
		return err
	}
	key := strconv.Itoa(id)
	if len(features) == 0 {
		delete(all, key)
	} else {
		all[key] = features
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	return db.SetSetting(settingBaselines, string(b))
}

// nextBaselines computes a target's baselined features after a successful run:
// a feature is marked once its step completed with usable data, and forgotten
// when the feature is disabled (re-enabling it baselines again).
func nextBaselines(prev map[string]bool, checkNew, monitorJS, reenumOK, jsOK bool) map[string]bool {
	next := map[string]bool{}
	if checkNew && (prev[featureReenum] || reenumOK) {
		next[featureReenum] = true
	}
	if monitorJS && (prev[featureJS] || jsOK) {
		next[featureJS] = true
	}
	return next
}

func sameFeatures(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
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
		interval := effectiveInterval(target.Interval)

		if now.Before(lastCheck.Add(interval)) {
			continue // not time yet
		}
		if !retryDue(target.ID, now) {
			continue // recent failure — backing off
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
			defer utils.RecoverPanic("subdomain-monitor:check:" + t.Domain)
			defer func() {
				monitorInFlightMu.Lock()
				delete(monitorInFlight, t.ID)
				monitorInFlightMu.Unlock()
			}()
			ok := false // stays false on panic, so a panicking target backs off too
			defer func() { recordAttempt(t.ID, ok, effectiveInterval(t.Interval), time.Now()) }()
			logger.GetLogger().Infof("[INFO] Running subdomain monitoring for %s (interval: %ds)", t.Domain, t.Interval)

			// Each feature's first successful run establishes its baseline (no
			// new_subdomain / new_js_endpoint spam) — tracked per feature, not by
			// LastRunAt, so enabling a feature later or a failed baseline run can't
			// flood the next run.
			baselines := loadBaselines(t.ID)

			result, err := MonitorSubdomains(MonitorOptions{
				Domain:               t.Domain,
				Threads:              t.Threads,
				CheckNew:             t.CheckNew,
				Reenumerate:          t.CheckNew, // "detect new subs" also drives passive re-enumeration
				MonitorJS:            t.MonitorJS,
				SuppressEnumBaseline: !baselines[featureReenum],
				SuppressJSBaseline:   !baselines[featureJS],
				Notify:               true,
			})
			if err != nil {
				logger.GetLogger().Infof("[ERROR] Failed to monitor subdomains for %s: %v", t.Domain, err)
				return
			}

			// Update last_run_at (the fix for the timer bug)
			if err := db.UpdateSubdomainMonitorLastRun(t.ID); err != nil {
				logger.GetLogger().Infof("[WARN] Failed to update last_run_at for %s: %v", t.Domain, err)
			} else {
				ok = true
			}
			if next := nextBaselines(baselines, t.CheckNew, t.MonitorJS, result.ReenumOK, result.JSDiffOK); !sameFeatures(next, baselines) {
				if err := saveBaselines(t.ID, next); err != nil {
					logger.GetLogger().Infof("[WARN] Failed to save monitor baselines for %s: %v", t.Domain, err)
				}
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
