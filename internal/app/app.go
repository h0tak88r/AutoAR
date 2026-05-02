package app

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/h0tak88r/AutoAR/internal/api"
	"github.com/h0tak88r/AutoAR/internal/bot"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/envloader"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// StartAPI starts the REST API server
func StartAPI() error {
	fmt.Println("🚀 Starting AutoAR API Server...")

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

// StartBoth starts both Discord bot and API server
func StartBoth() error {
	fmt.Println("🚀 Starting AutoAR (Discord Bot + API Server)...")

	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("[ + ]Loaded environment variables from .env file")
	}

	// Re-read configuration after loading .env
	botTokenEnv := os.Getenv("DISCORD_BOT_TOKEN")
	autoarModeEnv := utils.GetEnv("AUTOAR_MODE", "both")

	// Initialize database if configured (only once for both services)
	if os.Getenv("DB_HOST") != "" {
		if err := db.Init(); err != nil {
			log.Printf("[WARN] Failed to initialize database: %v", err)
		} else {
			if err := db.InitSchema(); err != nil {
				log.Printf("[WARN] Failed to initialize database schema: %v", err)
			}
		}
	}

	// Ensure database is closed on exit
	defer func() {
		if os.Getenv("DB_HOST") != "" {
			db.Close()
		}
	}()

	var botStarted sync.WaitGroup
	errCh := make(chan error, 2)

	if botTokenEnv == "" {
		return fmt.Errorf("DISCORD_BOT_TOKEN environment variable is required")
	}

	// Start Discord bot if mode allows
	if autoarModeEnv == "discord" || autoarModeEnv == "both" {
		botStarted.Add(1)
		go func() {
			// Signal that bot initialization has started
			// This allows API to wait for the session to be ready
			go func() {
				// Wait a moment for globalDiscordSession to be set
				time.Sleep(500 * time.Millisecond)
				botStarted.Done()
			}()

			if err := bot.StartBot(); err != nil {
				errCh <- fmt.Errorf("discord bot exited: %w", err)
			}
		}()

		// Wait for bot to initialize session before starting API
		log.Println("[INFO] Waiting for Discord bot session to initialize...")
		botStarted.Wait()
		log.Println("[INFO] Discord bot session ready, starting API...")
	}

	// Start API server if mode allows
	if autoarModeEnv == "api" || autoarModeEnv == "both" {
		go func() {
			if err := StartAPI(); err != nil {
				errCh <- fmt.Errorf("api server exited: %w", err)
			}
		}()
	}

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	select {
	case sig := <-sc:
		fmt.Printf("\nShutting down after signal: %s...\n", sig)
		return nil
	case err := <-errCh:
		return err
	}
}
