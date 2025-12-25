package gobot

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/envloader"
)

// Main function for standalone bot execution (backward compatibility)
// This can be used if someone wants to run the bot standalone
func Main() {
	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("✅ Loaded environment variables from .env file")
	}

	// Read configuration from environment (after .env is loaded)
	autoarModeEnv := getEnv("AUTOAR_MODE", "discord")
	botTokenEnv := os.Getenv("DISCORD_BOT_TOKEN")
	
	var wg sync.WaitGroup

	// Start Discord bot if needed
	if autoarModeEnv == "discord" || autoarModeEnv == "both" {
		if botTokenEnv == "" {
			log.Fatal("DISCORD_BOT_TOKEN environment variable is required")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := StartBot(); err != nil {
				log.Fatalf("Discord bot error: %v", err)
			}
		}()
	}

	// Start API server if needed
	if autoarModeEnv == "api" || autoarModeEnv == "both" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := StartAPI(); err != nil {
				log.Fatalf("API server error: %v", err)
			}
		}()
	}

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	fmt.Println("\nShutting down...")
}

