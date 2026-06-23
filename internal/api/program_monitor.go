package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─── Bug-bounty scope-change monitor ────────────────────────────────────────────
// A slow rolling sweep over every program that fires a Discord (MONITOR_WEBHOOK_URL)
// alert whenever a NEW in-scope asset appears. It deliberately spaces requests
// (default 3s between programs) so polling ~1000+ programs doesn't trip the
// platforms' API rate limits — a full sweep takes ~an hour, which is fine for
// catching new assets. A fetch that returns no assets (rate-limited / transient)
// is skipped, never baselined, so it can't produce a false "all assets are new" flood.

var (
	progMonRunning bool
	progMonMu      sync.Mutex
	progMonStop    chan struct{}
)

// StartProgramMonitor launches the scope-change monitor if a webhook is configured
// and it isn't explicitly disabled. Safe to call once at startup.
func StartProgramMonitor() {
	if strings.TrimSpace(os.Getenv("MONITOR_WEBHOOK_URL")) == "" {
		return // nowhere to send alerts
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("PROGRAM_MONITOR")), "off") {
		return
	}
	progMonMu.Lock()
	if progMonRunning {
		progMonMu.Unlock()
		return
	}
	progMonRunning = true
	progMonStop = make(chan struct{})
	stop := progMonStop
	progMonMu.Unlock()

	// Pass the stop channel by value so the goroutine never races on the package var.
	go runProgramMonitorLoop(stop)
}

// StopProgramMonitor signals the monitor to stop.
func StopProgramMonitor() {
	progMonMu.Lock()
	defer progMonMu.Unlock()
	if !progMonRunning {
		return
	}
	close(progMonStop)
	progMonRunning = false
}

func programMonitorSpacing() time.Duration {
	ms := 3000
	if v := strings.TrimSpace(os.Getenv("PROGRAM_MONITOR_SPACING_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 500 {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}

func runProgramMonitorLoop(stop chan struct{}) {
	logger.GetLogger().Infof("[PROGRAM-MONITOR] started (spacing %s) — alerting new in-scope assets to MONITOR_WEBHOOK_URL", programMonitorSpacing())
	for {
		programs := collectProgramsForMonitor()
		if len(programs) == 0 {
			if progMonSleep(5*time.Minute, stop) {
				return
			}
			continue
		}
		logger.GetLogger().Infof("[PROGRAM-MONITOR] sweeping %d program(s)", len(programs))
		for _, p := range programs {
			select {
			case <-stop:
				return
			default:
			}
			sweepProgram(p)
			if progMonSleep(programMonitorSpacing(), stop) {
				return
			}
		}
		// Brief pause between full sweeps.
		if progMonSleep(2*time.Minute, stop) {
			return
		}
	}
}

// progMonSleep waits d or returns true if the monitor was asked to stop.
func progMonSleep(d time.Duration, stop chan struct{}) bool {
	select {
	case <-stop:
		return true
	case <-time.After(d):
		return false
	}
}

// collectProgramsForMonitor fetches the program list (without scope — cheap) for every
// configured platform. PROGRAM_MONITOR_PLATFORMS (csv of h1,bc,it) narrows it; empty = all.
func collectProgramsForMonitor() []ProgramSummary {
	platforms := strings.ToLower(strings.TrimSpace(os.Getenv("PROGRAM_MONITOR_PLATFORMS")))
	want := func(pl string) bool { return platforms == "" || strings.Contains(platforms, pl) }

	var all []ProgramSummary
	if want("h1") && os.Getenv("H1_USERNAME") != "" && os.Getenv("H1_TOKEN") != "" {
		if progs, err := fetchH1Programs(false, false); err == nil {
			all = append(all, progs...)
		} else {
			logger.GetLogger().Infof("[PROGRAM-MONITOR] H1 list fetch failed: %v", err)
		}
	}
	if want("bc") && os.Getenv("BUGCROWD_TOKEN") != "" {
		if progs, err := fetchBCPrograms(false, false); err == nil {
			all = append(all, progs...)
		}
	}
	if want("it") && intigritiToken() != "" {
		if progs, err := fetchITPrograms(false, false); err == nil {
			all = append(all, progs...)
		}
	}
	return all
}

// programMonitorKey returns a unique-per-program key for the program_assets store.
// p.ID (the platform's stable UUID/ID) is preferred when present so a future handle
// parsing bug can't collapse multiple programs into one bucket — that exact mistake
// is what caused the Intigriti "/detail" flood: every IT program ended up with
// Handle="detail" and shared a single program_assets row.
func programMonitorKey(p ProgramSummary) string {
	id := strings.TrimSpace(p.ID)
	if id != "" {
		return strings.ToLower(p.Platform) + ":id:" + id
	}
	return strings.ToLower(p.Platform) + ":" + p.Handle
}

// floodSuspectThreshold caps a single program's "new asset" alert. Real scope
// additions are 1-5 assets at a time; a huge "diff" on a watched catalogue is
// almost always an identifier-collision/key bug. Above this we silently re-baseline
// and log a warning instead of flooding Discord.
const floodSuspectThreshold = 20

// sweepProgram fetches one program's current in-scope assets and alerts on new ones.
func sweepProgram(p ProgramSummary) {
	assets := fetchProgramAssets(p)
	if len(assets) == 0 {
		// Failed / rate-limited / genuinely empty — skip. Never baseline an empty result,
		// otherwise the next successful fetch would report every asset as "new".
		return
	}
	key := programMonitorKey(p)
	newAssets, firstRun, err := db.RecordProgramScopeAssets(key, assets)
	if err != nil {
		logger.GetLogger().Infof("[PROGRAM-MONITOR] record failed for %s: %v", key, err)
		return
	}
	if firstRun || len(newAssets) == 0 {
		return // baseline run, or nothing new
	}
	// Safety cap: a real scope change is incremental. A huge sudden delta almost
	// always means a key collision (multiple programs mapped to one row) or a
	// platform API change. Skip the alert rather than spam.
	if len(newAssets) >= floodSuspectThreshold || len(newAssets) == len(assets) {
		logger.GetLogger().Infof("[PROGRAM-MONITOR] WARN suspicious delta for %s (%s): %d/%d assets reported new — silently re-baselining, no alert sent",
			p.Handle, p.Platform, len(newAssets), len(assets))
		return
	}
	alertNewAssets(p, newAssets)
}

// fetchProgramAssets returns the current in-scope asset identifiers for a program,
// reusing the existing per-platform scope fetchers. Empty on failure.
func fetchProgramAssets(p ProgramSummary) []string {
	switch strings.ToLower(p.Platform) {
	case "h1", "hackerone":
		auth := h1BasicAuth()
		if auth == "" {
			return nil
		}
		summary, ok := fetchH1ScopeSummary(p.Handle, auth)
		if !ok {
			return nil
		}
		return summary.Assets
	case "bc", "bugcrowd":
		token := os.Getenv("BUGCROWD_TOKEN")
		if token == "" {
			return nil
		}
		return fetchBCScopeSummary(p.Handle, p.URL, token).Assets
	case "it", "intigriti":
		token := intigritiToken()
		if token == "" {
			return nil
		}
		client := &http.Client{Timeout: 20 * time.Second}
		return fetchITScopeSummary(client, token, p.ID).Assets
	}
	return nil
}

func h1BasicAuth() string {
	u, t := os.Getenv("H1_USERNAME"), os.Getenv("H1_TOKEN")
	if u == "" || t == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(u + ":" + t))
}

// alertNewAssets posts a Discord message and records a dashboard change row.
func alertNewAssets(p ProgramSummary, newAssets []string) {
	name := p.Name
	if name == "" {
		name = p.Handle
	}
	plural := ""
	if len(newAssets) != 1 {
		plural = "s"
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "🆕 **%d new in-scope asset%s** — %s `%s` (%s)\n",
		len(newAssets), plural, name, p.Handle, strings.ToUpper(p.Platform))
	const maxList = 20
	for i, a := range newAssets {
		if i >= maxList {
			fmt.Fprintf(&sb, "  • …and %d more\n", len(newAssets)-maxList)
			break
		}
		fmt.Fprintf(&sb, "  • `%s`\n", a)
	}
	if p.URL != "" {
		fmt.Fprintf(&sb, "%s\n", p.URL)
	}
	utils.SendMonitorWebhook(sb.String())

	detail, _ := json.Marshal(map[string]any{
		"program":  p.Handle,
		"platform": p.Platform,
		"name":     name,
		"url":      p.URL,
		"assets":   newAssets,
	})
	if err := db.InsertMonitorChange(&db.MonitorChange{
		TargetType: "program",
		Domain:     p.Handle,
		ChangeType: "new_program_asset",
		Detail:     string(detail),
		Notified:   true,
	}); err != nil {
		logger.GetLogger().Infof("[PROGRAM-MONITOR] failed to persist change for %s: %v", p.Handle, err)
	}
	logger.GetLogger().Infof("[PROGRAM-MONITOR] %s (%s): %d new asset(s) alerted", p.Handle, p.Platform, len(newAssets))
}
