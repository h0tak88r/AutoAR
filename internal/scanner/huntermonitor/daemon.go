package huntermonitor

import (
	"fmt"
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
	go func() {
		defer daemonWg.Done()
		runDaemonLoop()
	}()

	return nil
}

// StopDaemon stops the hunter monitoring daemon.
func StopDaemon() error {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()

	if !daemonRunning {
		return fmt.Errorf("daemon is not running")
	}

	logger.GetLogger().Infoln("[INFO] Stopping hunter monitoring daemon...")

	stopOnce.Do(func() {
		if stopDaemon != nil {
			close(stopDaemon)
		}
	})

	daemonWg.Wait()
	daemonRunning = false

	logger.GetLogger().Infoln("[OK] Hunter monitoring daemon stopped")
	return nil
}

// IsDaemonRunning returns whether the daemon is currently running.
func IsDaemonRunning() bool {
	daemonMutex.Lock()
	defer daemonMutex.Unlock()
	return daemonRunning
}

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
		if target.LastRunAt != nil {
			interval := time.Duration(target.IntervalSeconds) * time.Second
			if now.Before(target.LastRunAt.Add(interval)) {
				continue // not time yet
			}
		}

		monitorInFlightMu.Lock()
		if monitorInFlight[target.ID] {
			monitorInFlightMu.Unlock()
			continue
		}
		monitorInFlight[target.ID] = true
		monitorInFlightMu.Unlock()

		go func(t db.HunterMonitorTarget) {
			defer func() {
				monitorInFlightMu.Lock()
				delete(monitorInFlight, t.ID)
				monitorInFlightMu.Unlock()
			}()
			checkTarget(t)
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
	for _, a := range accounts.For("h1") {
		if a.Username == "" || a.Token == "" {
			continue
		}
		reports, err := FetchHacktivityAPI(a.Username, a.Token, username, hacktivityFetchSize)
		if err == nil {
			return reports, "authenticated API (" + a.Label + ")", nil
		}
		logger.GetLogger().Infof("[WARN] H1 API account %q failed for %s (%v) — trying next", a.Label, username, err)
	}

	reports, err := FetchHacktivity(numericUserID, hacktivityFetchSize)
	if err != nil {
		return nil, "", err
	}
	return reports, "anonymous GraphQL (no private-program activity)", nil
}

// checkTarget polls one hunter's public H1 profile + hacktivity feed,
// persists the new snapshot, and fires a Discord alert for newly resolved
// reports and/or a reputation increase. The very first check for a target
// establishes a baseline (records currently-resolved reports as "seen" and
// stores the current reputation) without alerting — otherwise every report
// the hunter ever resolved would fire as a "new" alert on first run.
func checkTarget(t db.HunterMonitorTarget) {
	isBaseline := t.LastRunAt == nil

	logger.GetLogger().Infof("[INFO] Checking hunter monitor for %s (interval: %ds)", t.Username, t.IntervalSeconds)

	snap, err := FetchUserSnapshot(t.Username)
	if err != nil {
		logger.GetLogger().Infof("[ERROR] Failed to fetch H1 snapshot for %s: %v", t.Username, err)
		return
	}

	reports, source, err := fetchHacktivityBestSource(t.Username, snap.UserID)
	if err != nil {
		logger.GetLogger().Infof("[ERROR] Failed to fetch H1 hacktivity for %s: %v", t.Username, err)
		return
	}
	logger.GetLogger().Infof("[INFO] Hunter monitor %s: %d hacktivity entries via %s", t.Username, len(reports), source)

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
		if !isBaseline {
			newResolved = append(newResolved, r)
		}
		resolvedAt, parseErr := time.Parse(time.RFC3339Nano, r.ActivityAt)
		if parseErr != nil {
			resolvedAt = time.Now()
		}
		if err := db.RecordSeenHunterReport(t.ID, r.ID, r.ProgramHandle, r.ProgramName, resolvedAt); err != nil {
			logger.GetLogger().Infof("[WARN] Failed to record seen report for %s/%s: %v", t.Username, r.ID, err)
		}
	}

	prevReputation := t.LastReputation
	repIncreased := !isBaseline && prevReputation != nil && snap.Reputation > *prevReputation

	if err := db.UpdateHunterMonitorSnapshot(t.ID, snap.UserID, snap.Reputation, snap.Signal, snap.Rank); err != nil {
		logger.GetLogger().Infof("[WARN] Failed to update hunter monitor snapshot for %s: %v", t.Username, err)
	}

	if isBaseline {
		logger.GetLogger().Infof("[OK] Hunter monitor %s: baseline established (%d resolved reports, reputation %.0f)",
			t.Username, len(newResolved), snap.Reputation)
		return
	}

	if len(newResolved) == 0 && !repIncreased {
		logger.GetLogger().Infof("[OK] Hunter monitor %s: no changes", t.Username)
		return
	}

	logger.GetLogger().Infof("[OK] Hunter monitor %s: %d new resolved report(s), reputation increased: %v",
		t.Username, len(newResolved), repIncreased)

	msg := formatHunterAlert(t.Username, newResolved, prevReputation, snap)
	utils.SendMonitorWebhook(msg)
}

// formatHunterAlert renders a webhook-ready markdown summary of newly
// resolved reports and/or a reputation increase for a hunter.
func formatHunterAlert(username string, newResolved []ResolvedReport, prevReputation *float64, snap *UserSnapshot) string {
	msg := fmt.Sprintf(" **Hunter Monitor Alert** — `%s`\n", username)

	if len(newResolved) > 0 {
		msg += fmt.Sprintf(" **%d new** report event(s):\n", len(newResolved))
		for _, r := range newResolved {
			program := r.ProgramName
			if program == "" {
				program = r.ProgramHandle
			}
			if program == "" {
				program = "(program withheld)"
			}
			line := fmt.Sprintf("  • **%s** — %s", program, r.ActionLabel())
			if r.ProgramHandle != "" {
				line += fmt.Sprintf(" (`%s`)", r.ProgramHandle)
			}
			if len(r.ActivityAt) >= 10 {
				line += " · " + r.ActivityAt[:10]
			}
			msg += line + "\n"
		}
	}

	if prevReputation != nil && snap.Reputation > *prevReputation {
		msg += fmt.Sprintf(" **Reputation up:** %.0f → %.0f (+%.0f)\n", *prevReputation, snap.Reputation, snap.Reputation-*prevReputation)
	}

	msg += fmt.Sprintf(" Rank: **#%.0f** · Signal: **%.1f**\n", snap.Rank, snap.Signal)

	return msg
}
