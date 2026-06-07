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

	// Ensure scans don't remain "running" across restarts (single-instance mode).
	reconcileStaleScansOnStartup()

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

// StartBoth starts the API server (legacy name kept for compatibility).
func StartBoth() error {
	return StartAPI()
}
