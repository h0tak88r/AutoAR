package gobot

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Main function for standalone bot execution (backward compatibility)
// This can be used if someone wants to run the bot standalone
func Main() {
	var wg sync.WaitGroup

	// Start Discord bot if needed
	if autoarMode == "discord" || autoarMode == "both" {
		if botToken == "" {
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
	if autoarMode == "api" || autoarMode == "both" {
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

