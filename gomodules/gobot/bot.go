package gobot

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"
)

var (
	botToken     = os.Getenv("DISCORD_BOT_TOKEN")
	autoarMode   = getEnv("AUTOAR_MODE", "discord")
	apiHost      = getEnv("API_HOST", "0.0.0.0")
	apiPort      = getEnv("API_PORT", "8000")
	
	// Global Discord session for file sending from modules
	globalDiscordSession *discordgo.Session
	discordSessionMutex  sync.RWMutex
	
	// Channel ID storage for file notifications
	activeChannels = make(map[string]string) // scanID -> channelID
	channelsMutex  sync.RWMutex
)

// StartBot starts the Discord bot
func StartBot() error {
	if botToken == "" {
		return fmt.Errorf("DISCORD_BOT_TOKEN environment variable is required")
	}

	// Create Discord session
	dg, err := discordgo.New("Bot " + botToken)
	if err != nil {
		return fmt.Errorf("error creating Discord session: %w", err)
	}

	// Store globally for file sending
	discordSessionMutex.Lock()
	globalDiscordSession = dg
	discordSessionMutex.Unlock()

	// Register handlers
	dg.AddHandler(ready)
	dg.AddHandler(interactionCreate)

	// Open Discord session
	err = dg.Open()
	if err != nil {
		return fmt.Errorf("error opening Discord session: %w", err)
	}

	// Register slash commands
	registerAllCommands(dg)

	fmt.Println("AutoAR Discord Bot is running.")
	
	// Keep running
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	
	fmt.Println("\nShutting down Discord bot...")
	dg.Close()
	return nil
}

// StartAPI starts the REST API server
func StartAPI() error {
	router := setupAPI()
	addr := fmt.Sprintf("%s:%s", apiHost, apiPort)
	fmt.Printf("AutoAR API Server starting on %s\n", addr)
	
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	
	go func() {
		if err := http.ListenAndServe(addr, router); err != nil {
			log.Fatalf("API server failed: %v", err)
		}
	}()
	
	<-sc
	fmt.Println("\nShutting down API server...")
	return nil
}

// StartBoth starts both Discord bot and API server
func StartBoth() error {
	var wg sync.WaitGroup

	if botToken == "" {
		return fmt.Errorf("DISCORD_BOT_TOKEN environment variable is required")
	}

	// Start Discord bot
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := StartBot(); err != nil {
			log.Printf("Discord bot error: %v", err)
		}
	}()

	// Start API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := StartAPI(); err != nil {
			log.Printf("API server error: %v", err)
		}
	}()

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	fmt.Println("\nShutting down...")
	return nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
