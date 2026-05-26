package app

import (
	"fmt"
	"log"

	"github.com/h0tak88r/AutoAR/internal/envloader"
	"github.com/h0tak88r/AutoAR/internal/observability"
)

// Main is the entry point for standalone API server execution.
func Main() {
	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("[ + ]Loaded environment variables from .env file")
	}

	// Initialize observability package (logging, tracing)
	observability.Initialize()

	// Start API server
	if err := StartAPI(); err != nil {
		log.Fatalf("API server error: %v", err)
	}
}
