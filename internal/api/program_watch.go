package api

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─── Passive program-scope watch ───────────────────────────────────────────────
// Instead of polling each program's full scope on a rolling schedule, this watch
// piggybacks on the data the warmer already fetches. Every refresh, it looks at
// programs[*].LatestTargetUpdatedAt — the most recent in-scope target update time
// the warmer captured — and:
//
//   * On the first refresh of this process: sends a "📌 Most recent scope update"
//     intro to the Discord webhook so the operator immediately sees the watch is
//     alive (and what the current freshest update is).
//   * Whenever the catalogue contains programs whose LatestTargetUpdatedAt is
//     more recent than the persisted watermark, posts a Discord alert for each
//     and advances the watermark.
//
// The watermark lives in the settings table so it survives restarts.

const (
	programWatchWatermarkKey = "program_watch_latest_seen"
	programWatchMaxAlertsCyc = 10 // cap per refresh so a one-time corpus shift can't flood
)

var (
	programWatchMu        sync.Mutex
	programWatchIntroSent bool      // process-local: send intro once per boot
	programWatchSessionN  int       // alerts fired since process start
	programWatchLastAt    time.Time // last refresh tick
)

// programWatchEnabled returns whether the watch should act on a refresh. It's a
// no-op when no webhook is configured or PROGRAM_MONITOR=off.
func programWatchEnabled() bool {
	if !utils.MonitorWebhookConfigured() {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROGRAM_MONITOR")), "off") {
		return false
	}
	return true
}

// programWatchPlatformAllowed filters by PROGRAM_MONITOR_PLATFORMS (csv of h1,bc,it).
// Empty allows all.
func programWatchPlatformAllowed(platform string) bool {
	allow := strings.ToLower(strings.TrimSpace(os.Getenv("PROGRAM_MONITOR_PLATFORMS")))
	if allow == "" {
		return true
	}
	return strings.Contains(allow, strings.ToLower(platform))
}

// ProgramWatchOnRefresh is called by the warmer after every cache rebuild. It
// inspects the freshly-fetched programs, fires Discord alerts for any newer than
// the persisted watermark, and persists the new watermark. Safe to call with an
// empty slice — it just records the last refresh time.
func ProgramWatchOnRefresh(programs []ProgramSummary) {
	programWatchMu.Lock()
	defer programWatchMu.Unlock()
	programWatchLastAt = time.Now()

	if !programWatchEnabled() {
		return
	}

	// Reduce the catalogue to programs with a usable LatestTargetUpdatedAt and the
	// configured platform filter.
	candidates := make([]ProgramSummary, 0, len(programs))
	var freshest *ProgramSummary
	for i := range programs {
		p := programs[i]
		if p.LatestTargetUpdatedAt == "" || !programWatchPlatformAllowed(p.Platform) {
			continue
		}
		candidates = append(candidates, p)
		if freshest == nil || isNewerProgramTime(p.LatestTargetUpdatedAt, freshest.LatestTargetUpdatedAt) {
			freshest = &candidates[len(candidates)-1]
		}
	}

	// Boot intro: one message per process so the operator sees the watch is alive
	// right after every container rebuild.
	if !programWatchIntroSent && freshest != nil {
		programWatchIntroSent = true
		sendProgramIntroDiscord(*freshest)
	}

	if freshest == nil {
		return
	}

	watermark, _ := db.GetSetting(programWatchWatermarkKey)
	if watermark == "" {
		// First-ever watch run: baseline silently to the freshest seen, no alerts.
		_ = db.SetSetting(programWatchWatermarkKey, freshest.LatestTargetUpdatedAt)
		return
	}

	// Find every program with LatestTargetUpdatedAt > watermark.
	var updates []ProgramSummary
	for _, p := range candidates {
		if isNewerProgramTime(p.LatestTargetUpdatedAt, watermark) {
			updates = append(updates, p)
		}
	}
	if len(updates) == 0 {
		return
	}

	// Sort most-recent first so the first N alerts (under the cap) are the freshest.
	sort.Slice(updates, func(i, j int) bool {
		return isNewerProgramTime(updates[i].LatestTargetUpdatedAt, updates[j].LatestTargetUpdatedAt)
	})

	capped := updates
	if len(capped) > programWatchMaxAlertsCyc {
		capped = capped[:programWatchMaxAlertsCyc]
	}
	for _, p := range capped {
		sendProgramUpdateDiscord(p)
	}
	if len(updates) > len(capped) {
		logger.GetLogger().Infof("[PROGRAM-WATCH] capped %d updates -> %d alerts this cycle", len(updates), len(capped))
	}

	// Advance the watermark to the freshest program in this batch so we don't
	// re-alert on the next refresh.
	_ = db.SetSetting(programWatchWatermarkKey, freshest.LatestTargetUpdatedAt)
}

func sendProgramIntroDiscord(p ProgramSummary) {
	msg := fmt.Sprintf("📌 **Scope watch ready** — most recent update: **%s** (`%s` · %s)\n• Latest asset: `%s`\n• Updated: %s",
		programWatchName(p), p.Handle, strings.ToUpper(p.Platform),
		nonEmpty(p.LatestTarget, "—"), humanizeTime(p.LatestTargetUpdatedAt))
	if p.URL != "" {
		msg += "\n" + p.URL
	}
	if err := utils.SendMonitorWebhookErr(msg); err != nil {
		logger.GetLogger().Infof("[PROGRAM-WATCH] intro send failed: %v", err)
		return
	}
	programWatchSessionN++
}

func sendProgramUpdateDiscord(p ProgramSummary) {
	msg := fmt.Sprintf("🆕 **Scope updated** — %s (`%s` · %s)\n• Latest asset: `%s`\n• Updated: %s",
		programWatchName(p), p.Handle, strings.ToUpper(p.Platform),
		nonEmpty(p.LatestTarget, "—"), humanizeTime(p.LatestTargetUpdatedAt))
	if p.LatestTargetBrief != "" && len(p.LatestTargetBrief) <= 140 {
		msg += "\n• Note: " + p.LatestTargetBrief
	}
	if p.URL != "" {
		msg += "\n" + p.URL
	}
	if err := utils.SendMonitorWebhookErr(msg); err != nil {
		logger.GetLogger().Infof("[PROGRAM-WATCH] update send failed for %s: %v", p.Handle, err)
		return
	}
	programWatchSessionN++
}

func programWatchName(p ProgramSummary) string {
	return nonEmpty(p.Name, p.Handle)
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// humanizeTime returns a short relative form ("3h ago", "2d ago") for an ISO 8601
// time string, falling back to the raw string when it can't parse.
func humanizeTime(iso string) string {
	if iso == "" {
		return "unknown"
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		// Try a couple of common variants.
		if t2, err2 := time.Parse("2006-01-02T15:04:05Z", iso); err2 == nil {
			t = t2
		} else {
			return iso
		}
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// ProgramWatchStatus is a snapshot returned by the status API.
type ProgramWatchStatus struct {
	WebhookConfigured bool      `json:"webhook_configured"`
	Enabled           bool      `json:"enabled"`
	IntroSent         bool      `json:"intro_sent"`
	AlertsThisSession int       `json:"alerts_this_session"`
	WatermarkISO      string    `json:"watermark_iso"`
	WatermarkHuman    string    `json:"watermark_human"`
	LastRefreshAt     time.Time `json:"last_refresh_at"`
	LastRefreshHuman  string    `json:"last_refresh_human"`
	FreshestProgram   string    `json:"freshest_program"`
	FreshestAsset     string    `json:"freshest_asset"`
	FreshestUpdatedAt string    `json:"freshest_updated_at"`
}

// CurrentProgramWatchStatus assembles the live status for the dashboard. It reads
// the cached programs payload to find the current freshest update.
func CurrentProgramWatchStatus() ProgramWatchStatus {
	programWatchMu.Lock()
	sessionN := programWatchSessionN
	introSent := programWatchIntroSent
	lastAt := programWatchLastAt
	programWatchMu.Unlock()

	watermark, _ := db.GetSetting(programWatchWatermarkKey)
	st := ProgramWatchStatus{
		WebhookConfigured: utils.MonitorWebhookConfigured(),
		Enabled:           programWatchEnabled(),
		IntroSent:         introSent,
		AlertsThisSession: sessionN,
		WatermarkISO:      watermark,
		WatermarkHuman:    humanizeTime(watermark),
		LastRefreshAt:     lastAt,
		LastRefreshHuman:  humanizeTime(lastAt.Format(time.RFC3339)),
	}
	if payload, ok := loadProgramsCache(); ok {
		var freshest *ProgramSummary
		for i := range payload.Programs {
			p := payload.Programs[i]
			if p.LatestTargetUpdatedAt == "" {
				continue
			}
			if freshest == nil || isNewerProgramTime(p.LatestTargetUpdatedAt, freshest.LatestTargetUpdatedAt) {
				freshest = &payload.Programs[i]
			}
		}
		if freshest != nil {
			st.FreshestProgram = programWatchName(*freshest)
			st.FreshestAsset = freshest.LatestTarget
			st.FreshestUpdatedAt = freshest.LatestTargetUpdatedAt
		}
	}
	return st
}

// GET /api/scope/watch-status — current scope-watch state for the Programs page.
func apiProgramWatchStatus(c *gin.Context) {
	c.JSON(http.StatusOK, CurrentProgramWatchStatus())
}

// POST /api/scope/watch-test — send an immediate test message to MONITOR_WEBHOOK_URL
// so the operator can confirm Discord delivery without waiting for the next refresh.
func apiProgramWatchTest(c *gin.Context) {
	if !utils.MonitorWebhookConfigured() {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "MONITOR_WEBHOOK_URL is not set"})
		return
	}
	msg := fmt.Sprintf("✅ **AutoAR scope-watch test** — webhook is reachable. Sent at %s.",
		time.Now().UTC().Format(time.RFC3339))
	if err := utils.SendMonitorWebhookErr(msg); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"ok": false, "error": err.Error()})
		return
	}
	programWatchMu.Lock()
	programWatchSessionN++
	programWatchMu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
