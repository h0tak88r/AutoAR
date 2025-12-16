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
	"github.com/h0tak88r/AutoAR/gomodules/db"
)

var (
	botToken   = os.Getenv("DISCORD_BOT_TOKEN")
	autoarMode = getEnv("AUTOAR_MODE", "discord")
	apiHost    = getEnv("API_HOST", "0.0.0.0")
	apiPort    = getEnv("API_PORT", "8000")

	// Global Discord session for file sending from modules
	globalDiscordSession *discordgo.Session
	discordSessionMutex  sync.RWMutex

	// Channel ID storage for file notifications
	activeChannels = make(map[string]string) // scanID -> channelID
	channelsMutex  sync.RWMutex
)

// StartBot starts the Discord bot and initializes database
func StartBot() error {
	// Initialize database if configured
	if os.Getenv("DB_HOST") != "" {
		log.Println("[INFO] Initializing database...")
		if err := db.Init(); err != nil {
			log.Printf("[WARN] Failed to initialize database: %v", err)
		} else {
			if err := db.InitSchema(); err != nil {
				log.Printf("[WARN] Failed to initialize database schema: %v", err)
			}
		}
	}
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
	dg.AddHandler(Ready)
	dg.AddHandler(InteractionCreate)

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

// Ready is called when the bot is ready
func Ready(s *discordgo.Session, event *discordgo.Ready) {
	fmt.Printf("Bot logged in as: %v#%v\n", event.User.Username, event.User.Discriminator)
}

// InteractionCreate handles Discord slash command interactions
func InteractionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Handle modal submissions
	if i.Type == discordgo.InteractionModalSubmit {
		handleModalSubmit(s, i)
		return
	}

	cmdName := i.ApplicationCommandData().Name

	// Route to appropriate handler (handlers are in commands*.go files)
	switch cmdName {
	case "react2shell_scan":
		handleReact2ShellScan(s, i)
	case "react2shell":
		handleReact2Shell(s, i)
	case "scan_domain":
		handleScanDomain(s, i)
	case "scan_subdomain":
		handleScanSubdomain(s, i)
	case "lite_scan":
		handleLiteScan(s, i)
	case "fast_look":
		handleFastLook(s, i)
	case "domain_run":
		handleDomainRun(s, i)
	case "subdomains":
		handleSubdomains(s, i)
	case "cnames":
		handleCnames(s, i)
	case "livehosts":
		handleLivehosts(s, i)
	case "urls":
		handleURLs(s, i)
	case "reflection":
		handleReflection(s, i)
	case "tech":
		handleTech(s, i)
	case "ports":
		handlePorts(s, i)
	case "nuclei":
		handleNuclei(s, i)
	case "js_scan":
		handleJSScan(s, i)
	case "gf_scan":
		handleGFScan(s, i)
	case "sqlmap":
		handleSQLMap(s, i)
	case "dalfox":
		handleDalfox(s, i)
	case "dns_takeover":
		handleDNSTakeover(s, i)
	case "dns_cname":
		handleDNSCname(s, i)
	case "dns_ns":
		handleDNSNs(s, i)
	case "dns_azure_aws":
		handleDNSAzureAws(s, i)
	case "dns_dnsreaper":
		handleDNSDNSReaper(s, i)
	case "s3_scan":
		handleS3Scan(s, i)
	case "s3_enum":
		handleS3Enum(s, i)
	case "github_scan":
		handleGitHubScan(s, i)
	case "github_org_scan":
		handleGitHubOrgScan(s, i)
	case "github_experimental_scan":
		handleGitHubExperimentalScan(s, i)
	case "github_wordlist":
		handleGitHubWordlist(s, i)
	case "githubdepconf":
		handleGitHubDepConf(s, i)
	case "db_domains":
		handleDBDomains(s, i)
	case "db_subdomains":
		handleDBSubdomains(s, i)
	case "db_delete_domain":
		handleDBDeleteDomain(s, i)
	case "keyhack_list":
		handleKeyhackList(s, i)
	case "keyhack_search":
		handleKeyhackSearch(s, i)
	case "monitor_updates":
		handleMonitorUpdates(s, i)
	case "monitor_updates_manage":
		handleMonitorUpdatesManage(s, i)
	case "jwt_scan":
		handleJWTScan(s, i)
	case "backup_scan":
		handleBackupScan(s, i)
	case "check_tools":
		handleCheckTools(s, i)
	case "misconfig":
		handleMisconfig(s, i)
	case "webdepconf":
		handleWebDepConf(s, i)
	case "scan_status":
		handleScanStatus(s, i)
	case "scan_from_file":
		handleScanFromFile(s, i)
	case "Scan File":
		handleScanFromFileContext(s, i)
	default:
		log.Printf("Unknown command: %s", cmdName)
		respond(s, i, fmt.Sprintf("❌ Unknown command: %s", cmdName), false)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
