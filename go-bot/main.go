package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"sync"

	"github.com/bwmarrin/discordgo"
	"github.com/gin-gonic/gin"
)

var (
	botToken     = os.Getenv("DISCORD_BOT_TOKEN")
	autoarMode   = getEnv("AUTOAR_MODE", "discord")
	apiHost      = getEnv("API_HOST", "0.0.0.0")
	apiPort      = getEnv("API_PORT", "8000")
)

func main() {
	var wg sync.WaitGroup

	// Start Discord bot if needed
	if autoarMode == "discord" || autoarMode == "both" {
		if botToken == "" {
			log.Fatal("DISCORD_BOT_TOKEN environment variable is required")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			startDiscordBot()
		}()
	}

	// Start API server if needed
	if autoarMode == "api" || autoarMode == "both" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			startAPIServer()
		}()
	}

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	fmt.Println("\nShutting down...")
}

func startDiscordBot() {
	// Create Discord session
	dg, err := discordgo.New("Bot " + botToken)
	if err != nil {
		log.Fatalf("Error creating Discord session: %v", err)
	}

	// Register handlers
	dg.AddHandler(ready)
	dg.AddHandler(interactionCreate)

	// Open Discord session
	err = dg.Open()
	if err != nil {
		log.Fatalf("Error opening Discord session: %v", err)
	}
	defer dg.Close()

	// Register slash commands
	registerCommands(dg)

	fmt.Println("AutoAR Discord Bot is running.")
	
	// Keep running
	select {}
}

func startAPIServer() {
	router := setupAPI()
	addr := fmt.Sprintf("%s:%s", apiHost, apiPort)
	fmt.Printf("AutoAR API Server starting on %s\n", addr)
	
	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("API server failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func ready(s *discordgo.Session, event *discordgo.Ready) {
	fmt.Printf("Bot logged in as: %v#%v\n", event.User.Username, event.User.Discriminator)
}

func interactionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	if i.ApplicationCommandData().Name == "react2shell_scan" {
		handleReact2ShellScan(s, i)
	} else if i.ApplicationCommandData().Name == "react2shell" {
		handleReact2Shell(s, i)
	} else if i.ApplicationCommandData().Name == "livehosts" {
		handleLivehosts(s, i)
	}
	// Add more command handlers here
}

func registerCommands(s *discordgo.Session) {
	commands := []*discordgo.ApplicationCommand{
		{
			Name:        "react2shell_scan",
			Description: "Scan domain hosts for React Server Components RCE using next88 smart scan",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "domain",
					Description: "The domain to scan",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "threads",
					Description: "Number of threads (default: 100)",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "enable_source_exposure",
					Description: "Enable source code exposure check (default: false)",
					Required:    false,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "dos_test",
					Description: "Enable DoS test (default: false)",
					Required:    false,
				},
			},
		},
		{
			Name:        "react2shell",
			Description: "Test single URL for React Server Components RCE using next88 smart scan",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "url",
					Description: "Target URL to test",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionBoolean,
					Name:        "verbose",
					Description: "Enable verbose output",
					Required:    false,
				},
			},
		},
		{
			Name:        "livehosts",
			Description: "Filter live hosts from subdomains",
			Options: []*discordgo.ApplicationCommandOption{
				{
					Type:        discordgo.ApplicationCommandOptionString,
					Name:        "domain",
					Description: "The domain",
					Required:    true,
				},
				{
					Type:        discordgo.ApplicationCommandOptionInteger,
					Name:        "threads",
					Description: "Number of threads (default: 100)",
					Required:    false,
				},
			},
		},
	}

	for _, cmd := range commands {
		_, err := s.ApplicationCommandCreate(s.State.User.ID, "", cmd)
		if err != nil {
			log.Printf("Cannot create command %v: %v", cmd.Name, err)
		}
	}
}
