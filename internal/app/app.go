package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/h0tak88r/AutoAR/internal/api"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/envloader"
	"github.com/h0tak88r/AutoAR/internal/scanner/monitor"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomainmonitor"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// StartAPI starts the REST API server
func StartAPI() error {
	fmt.Println("Starting AutoAR API Server...")

	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("[ + ]Loaded environment variables from .env file")
	}

	// Re-read API host and port after loading .env
	apiHostEnv := utils.GetEnv("API_HOST", "0.0.0.0")
	apiPortEnv := utils.GetEnv("API_PORT", "8000")

	// Fail closed: refuse to expose an unauthenticated dashboard on a public
	// (non-loopback) interface. Set DASHBOARD_USER/DASHBOARD_PASSWORD to enable
	// login, or AUTOAR_API_AUTH_DISABLED=true to explicitly opt out.
	if err := api.CheckAuthBindSafety(apiHostEnv); err != nil {
		fmt.Printf("\n[FATAL] %v\n\n", err)
		return err
	}

	// Initialize Logger
	logConfig := utils.LogConfigFromEnv("api.log")
	if os.Getenv("LOG_JSON") == "" {
		logConfig.JSONFormat = true
	}
	if err := utils.InitLogger(logConfig); err != nil {
		log.Printf("[WARN] Failed to initialize API logger: %v", err)
	} else {
		log.Printf("[INFO] API Logger initialized")
	}

	// Initialize database if configured
	if os.Getenv("DB_HOST") != "" {
		if err := db.Init(); err != nil {
			log.Printf("[WARN] Failed to initialize database: %v", err)
		} else {
			if err := db.InitSchema(); err != nil {
				log.Printf("[WARN] Failed to initialize database schema: %v", err)
			}
		}
	}
	// Wire DB-backed timeout resolution so scan phase timeouts configured in the
	// dashboard Settings page persist across redeployments.
	utils.InitTimeoutDB(db.GetSetting)

	// Hydrate UI-saved API keys / webhooks from the DB into the process env so they
	// survive Dokploy redeployments (which reset the container .env). DB values win
	// over the container env for these keys; keys never saved via the UI are left
	// as the container env provides them.
	if os.Getenv("DB_HOST") != "" {
		api.HydrateEnvFromDB()
	}

	// Ensure scans don't remain "running" across restarts (single-instance mode).
	reconcileStaleScansOnStartup()

	// Monitor daemons are in-memory goroutines that don't survive a process restart,
	// but the DB keeps is_running=true — so the dashboard would show monitors "running"
	// while nothing actually polls. Resume the daemons for any still-running targets so
	// the persisted state is truthful and monitoring continues after a Docker restart.
	resumeMonitorsOnStartup()

	// One-shot total reset of the program-scope monitor state. A prior build mis-parsed
	// Intigriti program handles as the literal "/detail" segment, collapsing every IT
	// program into a single bucket and flooding Discord with false "new asset" alerts.
	// This wipes all baselines AND the historical false alerts from monitor_changes.
	// Gated by a settings marker so it runs exactly once across deployments.
	resetProgramMonitorOnce()

	// Bug-bounty scope-change watch: passive — piggybacks on the programs warmer's
	// existing latest_target_updated_at field instead of polling each program's scope.
	// Alerts are posted from refreshProgramsCache directly. No goroutine to start here;
	// see internal/api/program_watch.go.

	// Pre-warm and keep the Programs catalogue cache fresh in the background so the
	// Programs page loads instantly instead of fetching ~1000 upstream calls per visit.
	if os.Getenv("DB_HOST") != "" {
		api.StartProgramsWarmer()
	}

	// Ensure database is closed on exit
	defer func() {
		if os.Getenv("DB_HOST") != "" {
			db.Close()
		}
	}()

	router := api.SetupAPI()
	addr := fmt.Sprintf("%s:%s", apiHostEnv, apiPortEnv)
	fmt.Printf("AutoAR API Server starting on %s\n", addr)

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	errCh := make(chan error, 1)

	go func() {
		if err := http.ListenAndServe(addr, router); err != nil {
			errCh <- fmt.Errorf("api server failed: %w", err)
		}
	}()

	select {
	case sig := <-sc:
		fmt.Printf("\nShutting down API server after signal: %s...\n", sig)
		return nil
	case err := <-errCh:
		return err
	}
}

// reconcileStaleScansOnStartup marks DB scans that were still "running" as failed. In-memory
// workers are gone after restart; leaving them active confuses the dashboard.
func reconcileStaleScansOnStartup() {
	if err := db.Init(); err != nil {
		return
	}
	if err := db.EnsureSchema(); err != nil {
		log.Printf("[WARN] EnsureSchema during stale scan reconcile: %v", err)
	}
	n, err := db.FailStaleActiveScans()
	if err != nil {
		log.Printf("[WARN] Stale scan reconcile: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[INFO] Marked %d interrupted scan(s) as failed (API restart — no running worker).", n)
	}
}

// resetProgramMonitorOnce performs a one-time total reset of the program-scope
// monitor: wipes every program_assets baseline AND every historical "new_program_asset"
// row from monitor_changes (the false Discord-flood records). A settings marker
// prevents it from re-running on subsequent boots — otherwise every container restart
// would re-wipe the baseline and the monitor could never establish stable state.
// Bump the marker key (programMonitorResetKey) to trigger a fresh reset in the future.
func resetProgramMonitorOnce() {
	const programMonitorResetKey = "program_monitor_reset_v2"
	if err := db.Init(); err != nil {
		return
	}
	if v, _ := db.GetSetting(programMonitorResetKey); v == "done" {
		return // already reset on a previous boot
	}
	assetsCleared, err := db.TruncateProgramScopeAssets()
	if err != nil {
		log.Printf("[WARN] Program monitor reset: failed to truncate program_assets: %v", err)
		return
	}
	alertsCleared, err := db.DeleteMonitorChangesByType("new_program_asset")
	if err != nil {
		log.Printf("[WARN] Program monitor reset: failed to clear new_program_asset history: %v", err)
		// Continue: even if alert wipe failed, the baseline wipe matters more.
	}
	if err := db.SetSetting(programMonitorResetKey, "done"); err != nil {
		log.Printf("[WARN] Program monitor reset: failed to record marker (will retry next boot): %v", err)
	}
	log.Printf("[INFO] Program monitor reset: wiped %d baseline asset row(s) and %d false alert(s). Next sweep baselines silently.",
		assetsCleared, alertsCleared)
}

// resumeMonitorsOnStartup restarts the monitor daemon goroutines (which don't survive
// a process restart) when the DB still has monitor targets marked is_running, so polling
// actually resumes instead of the dashboard merely showing a stale "running" flag.
func resumeMonitorsOnStartup() {
	if err := db.Init(); err != nil {
		return
	}
	_ = db.EnsureSchema()

	// Subdomain monitors.
	if targets, err := db.ListSubdomainMonitorTargets(); err == nil {
		running := 0
		for _, t := range targets {
			if t.IsRunning {
				running++
			}
		}
		if running > 0 {
			if err := subdomainmonitor.StartDaemon(); err != nil {
				log.Printf("[WARN] Could not resume subdomain monitor daemon: %v", err)
			} else {
				log.Printf("[INFO] Resumed subdomain monitor daemon for %d running target(s) after restart.", running)
			}
		}
	}

	// URL monitors.
	if targets, err := db.ListMonitorTargets(); err == nil {
		running := 0
		for _, t := range targets {
			if t.IsRunning {
				running++
			}
		}
		if running > 0 {
			monitor.StartURLMonitorDaemon()
			log.Printf("[INFO] Resumed URL monitor daemon for %d running target(s) after restart.", running)
		}
	}
}

// StartBoth starts the API server (legacy name kept for compatibility).
func StartBoth() error {
	return StartAPI()
}
