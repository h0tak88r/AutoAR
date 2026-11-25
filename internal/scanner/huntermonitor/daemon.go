package huntermonitor

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// hacktivityFetchSize is how many of the hunter's most recent hacktivity
// entries to pull per poll. Public H1 profiles rarely exceed this; the
// search API exposes no cursor/offset so a hunter with more resolved
// reports than this would have their oldest resolutions fall out of the
// window (acceptable — the monitor cares about new activity, not full history).
const hacktivityFetchSize = 100

var (
	daemonRunning bool
	daemonMutex   sync.Mutex
	stopDaemon    chan struct{}
	daemonWg      sync.WaitGroup
	stopOnce      sync.Once

	// monitorInFlight tracks targets whose check is currently running, so a
	// check that outlasts its interval isn't started again by the next ticker
	// pass (which would cause duplicate DB writes and duplicate webhook alerts).
	monitorInFlight   = make(map[int64]bool)
	monitorInFlightMu sync.Mutex
)

// StartDaemon starts the hunter monitoring daemon.
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

	logger.GetLogger().Infoln("[INFO] Starting hunter monitoring daemon...")

	daemonWg.Add(1)
	go superviseLoop(stopDaemon)

	return nil
}

// superviseLoop runs the daemon loop. However the loop ends (stop, or a panic
// that escaped a tick), it clears daemonRunning so IsDaemonRunning tells the
// truth and StartDaemon can start it again.
func superviseLoop(stop chan struct{}) {
	defer daemonWg.Done()
	defer utils.RecoverPanic("hunter-monitor:loop")
	defer func() {
		daemonMutex.Lock()
		daemonRunning = false
		daemonMutex.Unlock()
	}()
	runDaemonLoop(stop)
}

// StopDaemon stops the hunter monitoring daemon.
func StopDaemon() error {
	daemonMutex.Lock()
	if !daemonRunning {
		daemonMutex.Unlock()
		return fmt.Errorf("daemon is not running")
	}

	logger.GetLogger().Infoln("[INFO] Stopping hunter monitoring daemon...")

	stopOnce.Do(func() {
		if stopDaemon != nil {
			close(stopDaemon)
		}
	})
	daemonMutex.Unlock()
	// Wait outside daemonMutex: the loop goroutine takes it on exit to clear
	// daemonRunning.
	daemonWg.Wait()

	logger.GetLogger().Infoln("[OK] Hunter monitoring daemon stopped")
	return nil
}

// IsDaemonRunning returns whether the daemon is currently running.
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

func runDaemonLoop(stop chan struct{}) {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			// Per-tick panic barrier: one bad cycle must not end the loop.
			utils.GuardedRun("hunter-monitor:tick", tickFn)
		}
	}
}

// minCheckInterval floors a target's interval_seconds (the API accepts 1): each
// check queries HackerOne with every configured account.
const minCheckInterval = 300 * time.Second

// minRetryDelay is the first backoff step after a failed check.
const minRetryDelay = 5 * time.Minute

// effectiveInterval is the target's interval, floored at minCheckInterval.
func effectiveInterval(seconds int) time.Duration {
	d := time.Duration(seconds) * time.Second
	if d < minCheckInterval {
		d = minCheckInterval
	}
	return d
}

// failureBackoff is the wait after n consecutive failed checks: 5m, 10m, 20m, …
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

// Failed checks never advance last_run_at (only a successful snapshot does), so
// without this a failing target was retried on every 60s tick across every H1
// account. Attempts are tracked in memory and failures back off.
var (
	retryMu    sync.Mutex
	retryState = map[int64]retryInfo{}
)

type retryInfo struct {
	failures int
	next     time.Time
}

// retryDue reports whether a target that recently failed may be checked again.
func retryDue(id int64, now time.Time) bool {
	retryMu.Lock()
	defer retryMu.Unlock()
	st, ok := retryState[id]
	return !ok || !now.Before(st.next)
}

// recordAttempt clears the failure state on success, or schedules the next
// retry after failureBackoff.
func recordAttempt(id int64, ok bool, interval time.Duration, now time.Time) {
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

func checkAllRunningTargets() {
	targets, err := db.ListHunterMonitorTargets()
	if err != nil {
		logger.GetLogger().Infof("[ERROR] Failed to list hunter monitor targets: %v", err)
		return
	}

	now := time.Now()
	for _, target := range targets {
		if !target.IsRunning {
			continue
		}

		// A target that has never run baselines on the next tick instead of
		// waiting out a full interval. Counting created_at as a check would mean
		// a 12h interval leaves the dashboard showing empty reputation/rank for
		// 12h after adding a hunter, with no way to tell it from a broken monitor.
		interval := effectiveInterval(target.IntervalSeconds)
		if target.LastRunAt != nil {
			if now.Before(target.LastRunAt.Add(interval)) {
				continue // not time yet
			}
		}
		if !retryDue(target.ID, now) {
			continue // recent failure — backing off
		}

		monitorInFlightMu.Lock()
		if monitorInFlight[target.ID] {
			monitorInFlightMu.Unlock()
			continue
		}
		monitorInFlight[target.ID] = true
		monitorInFlightMu.Unlock()

		go func(t db.HunterMonitorTarget) {
			// The daemon shares the process with the gin API. A panic in checkTarget
			// (a future nil-deref in a DB or format path) would otherwise unwind past
			// this cleanup and crash the whole server. RecoverPanic (declared first,
			// so it runs last) contains it after the in-flight cleanup below.
			defer utils.RecoverPanic("hunter-monitor:check:" + t.Username)
			defer func() {
				monitorInFlightMu.Lock()
				delete(monitorInFlight, t.ID)
				monitorInFlightMu.Unlock()
			}()
			ok := false // stays false on panic, so a panicking target backs off too
			defer func() { recordAttempt(t.ID, ok, effectiveInterval(t.IntervalSeconds), time.Now()) }()
			ok = checkTarget(t)
		}(target)
	}
}

// fetchHacktivityBestSource prefers the authenticated HackerOne API, which is
// the only source that returns private/confidential-program activity. It falls
// back to the anonymous GraphQL hacktivity index when no H1 account is
// configured, or when the stored token is rejected — that view is weeks behind
// for hunters who work private programs, but it is better than no data, and
// degrading silently to it would hide a revoked token, so the caller logs which
// source produced the result.
func fetchHacktivityBestSource(username, numericUserID string) ([]ResolvedReport, string, error) {
	// Query EVERY configured H1 account and merge, rather than stopping at the
	// first that works. Private-program visibility is per-researcher: an account
	// only sees activity on programs it is itself invited to, so each token
	// exposes a different slice. Measured on this deployment, two accounts
	// returned 50 and 50 reports for one hunter but 61 distinct between them —
	// each seeing 5-8 programs the other could not. Using a single token silently
	// drops whole programs.
	seenID := make(map[string]bool)
	var merged []ResolvedReport
	var usedLabels []string
	var lastErr error

	for _, a := range accounts.For("h1") {
		if a.Username == "" || a.Token == "" {
			continue
		}
		reports, err := FetchHacktivityAPI(a.Username, a.Token, username, hacktivityFetchSize)
		if err != nil {
			lastErr = err
			logger.GetLogger().Infof("[WARN] H1 API account %q failed for %s: %v", a.Label, username, err)
			continue
		}
		usedLabels = append(usedLabels, a.Label)
		for _, r := range reports {
			if r.ID == "" || seenID[r.ID] {
				continue
			}
			seenID[r.ID] = true
			merged = append(merged, r)
		}
	}

	if len(usedLabels) > 0 {
		// Each account returns newest-first, but the concatenation is not, so
		// re-sort — downstream (the baseline snapshot) takes the head as "latest".
		sort.SliceStable(merged, func(i, j int) bool {
			return hacktivityTime(merged[i]).After(hacktivityTime(merged[j]))
		})
		return merged, fmt.Sprintf("authenticated API (%s)", strings.Join(usedLabels, "+")), nil
	}

	if lastErr != nil {
		logger.GetLogger().Infof("[WARN] All H1 API accounts failed for %s — falling back to anonymous view", username)
	}
	reports, err := FetchHacktivity(numericUserID, hacktivityFetchSize)
	if err != nil {
		return nil, "", err
	}
	return reports, "anonymous GraphQL (no private-program activity)", nil
}

// hacktivityTime parses an entry's activity timestamp; unparseable values sort
// oldest so they never displace real entries at the head of the list.
func hacktivityTime(r ResolvedReport) time.Time {
	t, err := time.Parse(time.RFC3339Nano, r.ActivityAt)
	if err != nil {
		return time.Time{}
	}
	return t
}

// checkTarget polls one hunter's public H1 profile + hacktivity feed,
// persists the new snapshot, and fires a Discord alert for newly resolved
// reports and/or a reputation increase. The very first check for a target
// establishes a baseline (records currently-resolved reports as "seen" and
// stores the current reputation) without alerting — otherwise every report
// the hunter ever resolved would fire as a "new" alert on first run. It reports
// whether the check succeeded (the snapshot, and so last_run_at, was saved).
func checkTarget(t db.HunterMonitorTarget) bool {
	isBaseline := t.LastRunAt == nil

	logger.GetLogger().Infof("[INFO] Checking hunter monitor for %s (interval: %ds)", t.Username, t.IntervalSeconds)

	snap, err := FetchUserSnapshot(t.Username)
	if err != nil {
		logger.GetLogger().Infof("[ERROR] Failed to fetch H1 snapshot for %s: %v", t.Username, err)
		return false
	}

	reports, source, err := fetchHacktivityBestSource(t.Username, snap.UserID)
	if err != nil {
		logger.GetLogger().Infof("[ERROR] Failed to fetch H1 hacktivity for %s: %v", t.Username, err)
		return false
	}
	logger.GetLogger().Infof("[INFO] Hunter monitor %s: %d hacktivity entries via %s", t.Username, len(reports), source)

	// previousLastRun gates which unseen reports count as "new": only activity
	// after the last successful check. Reports with older activity are historical
	// — e.g. months of a hunter's private-program reports that become visible only
	// after an H1 token is added in Settings — and must be recorded silently, not
	// alerted, or a source/account change floods Discord with old reports.
	var previousLastRun time.Time
	if t.LastRunAt != nil {
		previousLastRun = *t.LastRunAt
	}

	var newResolved []ResolvedReport
	for _, r := range reports {
		if !r.IsResolved() {
			continue
		}
		seen, err := db.HasSeenHunterReport(t.ID, r.ID)
		if err != nil {
			logger.GetLogger().Infof("[WARN] Failed to check seen-report state for %s/%s: %v", t.Username, r.ID, err)
			continue
		}
		if seen {
			continue
		}
		resolvedAt, parseErr := time.Parse(time.RFC3339Nano, r.ActivityAt)
		storedAt := resolvedAt
		if parseErr != nil {
			storedAt = time.Now() // for the seen-record only; we won't alert on it
		}
		// Record as seen BEFORE deciding to alert. If the write fails, skip the alert
		// this cycle rather than alerting on a report we couldn't persist — otherwise
		// it stays unseen and re-alerts every interval forever.
		if err := db.RecordSeenHunterReport(t.ID, r.ID, r.ProgramHandle, r.ProgramName, storedAt); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to record seen report for %s/%s (skipping alert this cycle): %v", t.Username, r.ID, err)
			continue
		}
		// Alert only off the baseline, for a parseable activity time newer than the
		// last check. Historical or unparseable entries are recorded but not alerted.
		if !isBaseline && parseErr == nil && resolvedAt.After(previousLastRun) {
			newResolved = append(newResolved, r)
		}
	}

	prevReputation := t.LastReputation
	repIncreased := !isBaseline && prevReputation != nil && snap.Reputation > *prevReputation

	if err := db.UpdateHunterMonitorSnapshot(t.ID, snap.UserID, snap.Reputation, snap.Signal, snap.Rank); err != nil {
		// last_run_at did not advance: count it as a failed attempt so the retry
		// backs off instead of re-running (and re-alerting) every tick.
		logger.GetLogger().Infof("[WARN] Failed to update hunter monitor snapshot for %s: %v", t.Username, err)
		return false
	}

	if isBaseline {
		// The baseline deliberately does not alert per report — a prolific hunter
		// would produce hundreds. It does post one snapshot so adding or resuming a
		// hunter visibly confirms the monitor is working and shows where they stand.
		utils.SendMonitorWebhook(formatHunterSummary(t.Username, reports, snap))
		logger.GetLogger().Infof("[OK] Hunter monitor %s: baseline established (%d resolved reports, reputation %.0f)",
			t.Username, len(newResolved), snap.Reputation)
		return true
	}

	if len(newResolved) == 0 && !repIncreased {
		logger.GetLogger().Infof("[OK] Hunter monitor %s: no changes", t.Username)
		return true
	}

	logger.GetLogger().Infof("[OK] Hunter monitor %s: %d new resolved report(s), reputation increased: %v",
		t.Username, len(newResolved), repIncreased)

	msg := formatHunterAlert(t.Username, newResolved, prevReputation, snap)
	utils.SendMonitorWebhook(msg)
	return true
}

// summaryItemCount is how many recent entries the baseline snapshot lists.
const summaryItemCount = 5

// formatHunterSummary renders the snapshot posted when a hunter is first added
// or resumed: where they stand now, plus their most recent activity. Entries
// arrive newest-first, so the head of the slice is the latest.
func formatHunterSummary(username string, reports []ResolvedReport, snap *UserSnapshot) string {
	msg := fmt.Sprintf(" **Hunter Monitor** — now watching `%s`\n", username)
	msg += fmt.Sprintf(" Reputation: **%.0f** · Rank: **#%.0f** · Signal: **%.1f**\n", snap.Reputation, snap.Rank, snap.Signal)

	var recent []ResolvedReport
	for _, r := range reports {
		if r.IsResolved() {
			recent = append(recent, r)
		}
		if len(recent) >= summaryItemCount {
			break
		}
	}

	if len(recent) == 0 {
		msg += " No resolved reports visible yet.\n"
		return msg
	}

	msg += fmt.Sprintf(" Latest activity (%d most recent):\n", len(recent))
	for _, r := range recent {
		msg += "  • " + describeReport(r) + "\n"
	}
	return msg
}

// describeReport renders one hacktivity entry as a webhook bullet.
func describeReport(r ResolvedReport) string {
	program := r.ProgramName
	if program == "" {
		program = r.ProgramHandle
	}
	if program == "" {
		program = "(program withheld)"
	}
	line := fmt.Sprintf("**%s** — %s", program, r.ActionLabel())
	if r.ProgramHandle != "" && r.ProgramName != "" {
		line += fmt.Sprintf(" (`%s`)", r.ProgramHandle)
	}
	if len(r.ActivityAt) >= 10 {
		line += " · " + r.ActivityAt[:10]
	}
	return line
}

// formatHunterAlert renders a webhook-ready markdown summary of newly
// resolved reports and/or a reputation increase for a hunter.
func formatHunterAlert(username string, newResolved []ResolvedReport, prevReputation *float64, snap *UserSnapshot) string {
	msg := fmt.Sprintf(" **Hunter Monitor Alert** — `%s`\n", username)

	if len(newResolved) > 0 {
		msg += fmt.Sprintf(" **%d new** report event(s):\n", len(newResolved))
		for _, r := range newResolved {
			msg += "  • " + describeReport(r) + "\n"
		}
	}

	if prevReputation != nil && snap.Reputation > *prevReputation {
		msg += fmt.Sprintf(" **Reputation up:** %.0f → %.0f (+%.0f)\n", *prevReputation, snap.Reputation, snap.Reputation-*prevReputation)
	}

	msg += fmt.Sprintf(" Rank: **#%.0f** · Signal: **%.1f**\n", snap.Rank, snap.Signal)

	return msg
}
