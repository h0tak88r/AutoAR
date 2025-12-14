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

	// Start API server if needed (always start in discord/both mode for internal file sending)
	if autoarMode == "api" || autoarMode == "both" || autoarMode == "discord" {
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
		log.Fatalf("Error opening Discord session: %v", err)
	}
	defer dg.Close()

	// Register slash commands
	registerAllCommands(dg)

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
	cmdName := i.ApplicationCommandData().Name
	
	// Route to appropriate handler
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
	case "keyhack_add":
		handleKeyhackAdd(s, i)
	case "keyhack_validate":
		handleKeyhackValidate(s, i)
	case "monitor_updates_add":
		handleMonitorUpdatesAdd(s, i)
	case "monitor_updates_remove":
		handleMonitorUpdatesRemove(s, i)
	case "monitor_updates_start":
		handleMonitorUpdatesStart(s, i)
	case "monitor_updates_stop":
		handleMonitorUpdatesStop(s, i)
	case "monitor_updates_list":
		handleMonitorUpdatesList(s, i)
	case "jwt_scan":
		handleJWTScan(s, i)
	case "jwt_query":
		handleJWTQuery(s, i)
	case "backup_scan":
		handleBackupScan(s, i)
	case "check_tools":
		handleCheckTools(s, i)
	case "cleanup":
		handleCleanup(s, i)
	case "misconfig":
		handleMisconfig(s, i)
	case "live_depconfusion_scan":
		handleLiveDepconfusionScan(s, i)
	case "webdepconf":
		handleWebDepConf(s, i)
	case "wp_depconf":
		handleWPDepConf(s, i)
	case "help_autoar":
		handleHelp(s, i)
	case "scan_status":
		handleScanStatus(s, i)
	default:
		log.Printf("Unknown command: %s", cmdName)
		respond(s, i, fmt.Sprintf("❌ Unknown command: %s", cmdName), false)
	}
}

