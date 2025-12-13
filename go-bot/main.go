package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bwmarrin/discordgo"
)

var (
	botToken     = os.Getenv("DISCORD_BOT_TOKEN")
	autoarScript = os.Getenv("AUTOAR_SCRIPT_PATH")
	configFile   = os.Getenv("AUTOAR_CONFIG_FILE")
	resultsDir   = os.Getenv("AUTOAR_RESULTS_DIR")
)

func main() {
	if botToken == "" {
		log.Fatal("DISCORD_BOT_TOKEN environment variable is required")
	}

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

	fmt.Println("AutoAR Discord Bot is running. Press CTRL-C to exit.")

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	fmt.Println("\nShutting down...")
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
