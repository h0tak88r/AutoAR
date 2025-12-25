package gobot

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/envloader"
)

var (
	botToken   = os.Getenv("DISCORD_BOT_TOKEN")
	autoarMode = getEnv("AUTOAR_MODE", "discord")
	apiHost    = getEnv("API_HOST", "0.0.0.0")
	apiPort    = getEnv("API_PORT", "8000")
	allowedGuild = getEnv("DISCORD_ALLOWED_GUILD", "Zhunterz") // Restrict bot to specific guild

	// Global Discord session for file sending from modules
	globalDiscordSession *discordgo.Session
	discordSessionMutex  sync.RWMutex

	// Channel ID storage for file notifications
	activeChannels = make(map[string]string) // scanID -> channelID
	channelsMutex  sync.RWMutex
)

// SendFileToChannel sends a file directly to a Discord channel using the global session
// This is used by modules to send files without requiring the HTTP API
func SendFileToChannel(channelID, filePath, description string) error {
	// Get Discord session
	discordSessionMutex.RLock()
	session := globalDiscordSession
	discordSessionMutex.RUnlock()

	if session == nil {
		return fmt.Errorf("Discord bot session not available")
	}

	// Check if file exists
	if info, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	} else if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	} else if info.Size() == 0 {
		return fmt.Errorf("file is empty: %s", filePath)
	}

	// Read file
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Send file to Discord channel
	fileName := filepath.Base(filePath)
	if description == "" {
		description = fmt.Sprintf("📁 %s", fileName)
	}

	_, err = session.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
		Content: description,
		Files: []*discordgo.File{
			{
				Name:        fileName,
				ContentType: http.DetectContentType(fileData),
				Reader:      strings.NewReader(string(fileData)),
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to send file to Discord: %w", err)
	}

	return nil
}

// StartBot starts the Discord bot and initializes database
func StartBot() error {
	fmt.Println("🚀 Starting AutoAR Discord Bot...")
	
	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("✅ Loaded environment variables from .env file")
	}

	// Re-read bot token after loading .env
	botToken = os.Getenv("DISCORD_BOT_TOKEN")
	
	// Initialize directories
	if err := initializeDirectories(); err != nil {
		log.Printf("[WARN] Failed to initialize directories: %v", err)
	} else {
		fmt.Println("✅ Initialized directories")
	}
	
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

	// Validate token format (Discord bot tokens are typically 59-72 characters)
	// Remove any whitespace
	botToken = strings.TrimSpace(botToken)
	if len(botToken) < 50 || len(botToken) > 100 {
		log.Printf("[WARN] Discord bot token length (%d) seems unusual. Expected 59-72 characters.", len(botToken))
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
	log.Println("[INFO] Attempting to connect to Discord...")
	err = dg.Open()
	if err != nil {
		// Provide more helpful error messages
		errMsg := err.Error()
		if strings.Contains(errMsg, "4000") || strings.Contains(errMsg, "4004") {
			return fmt.Errorf("error opening Discord session: %w\n\nTroubleshooting:\n"+
				"1. Verify your DISCORD_BOT_TOKEN is correct in .env file\n"+
				"2. Check if the bot token is valid in Discord Developer Portal\n"+
				"3. Ensure the bot has been properly invited to your server\n"+
				"4. Check your network connection to Discord API\n"+
				"5. Verify the token doesn't have extra spaces or quotes", err)
		}
		return fmt.Errorf("error opening Discord session: %w", err)
	}

	// Register slash commands
	registerAllCommands(dg)

	fmt.Println("✅ AutoAR Discord Bot is running and connected!")
	fmt.Println("   Bot is ready to receive commands.")

	// Ensure database is closed on exit
	defer func() {
		if os.Getenv("DB_HOST") != "" {
			db.Close()
		}
	}()

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

	// Ensure database is closed on exit
	defer func() {
		if os.Getenv("DB_HOST") != "" {
			db.Close()
		}
	}()

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
	// Check if command is from allowed guild (if restriction is enabled)
	if allowedGuild != "" {
		// Reject DMs (commands must be in a server)
		if i.GuildID == "" {
			log.Printf("[INFO] Rejected command from DM (not in a server)")
			respond(s, i, fmt.Sprintf("❌ This bot only works in the **%s** server. Please use commands in that server.", allowedGuild), true)
			return
		}

		// Fetch guild information
		guild, err := s.Guild(i.GuildID)
		if err != nil {
			log.Printf("[WARN] Failed to fetch guild info: %v", err)
			respond(s, i, "❌ Error: Unable to verify server. Please try again.", true)
			return
		}
		
		// Check if guild name matches allowed guild
		if guild.Name != allowedGuild {
			log.Printf("[INFO] Rejected command from unauthorized guild: %s (expected: %s)", guild.Name, allowedGuild)
			respond(s, i, fmt.Sprintf("❌ This bot is restricted to the **%s** server only. Your server: **%s**", allowedGuild, guild.Name), true)
			return
		}
		
		log.Printf("[DEBUG] Command allowed from guild: %s", guild.Name)
	}

	// Handle modal submissions
	if i.Type == discordgo.InteractionModalSubmit {
		handleModalSubmit(s, i)
		return
	}

	cmdName := i.ApplicationCommandData().Name

	// Route to appropriate handler (handlers are in commands*.go files)
	switch cmdName {
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
	case "apkx_scan":
		handleApkXScan(s, i)
	case "apkx_scan_package":
		// Backwards-compatible alias; prefer /apkx_scan with package argument.
		handleApkXScanPackage(s, i)
	case "apkx_scan_ios":
		// Backwards-compatible alias; prefer /apkx_ios.
		handleApkXScanIOS(s, i)
	case "apkx_ios":
		handleApkXScanIOS(s, i)
	case "dns":
		handleDNS(s, i)
	case "s3_scan":
		handleS3Scan(s, i)
	case "s3_enum":
		handleS3Enum(s, i)
	case "github":
		handleGitHub(s, i)
	case "db":
		handleDB(s, i)
	case "keyhack":
		handleKeyhack(s, i)
	case "monitor_subdomains_manage":
		handleMonitorSubdomainsManage(s, i)
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
	case "scope":
		handleScope(s, i)
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

// getResultsDir returns the results directory path
// Tries: AUTOAR_RESULTS_DIR env var -> ./new-results -> /app/new-results (Docker fallback)
// Normalizes absolute paths at root (like /new-results) to relative paths when not in Docker
func getResultsDir() string {
	dir := os.Getenv("AUTOAR_RESULTS_DIR")
	if dir == "" {
	// Try current directory first (for native runs)
	if cwd, err := os.Getwd(); err == nil {
			return filepath.Join(cwd, "new-results")
	}
	// Docker fallback
	return "/app/new-results"
	}

	// Normalize absolute paths at root when not in Docker
	if filepath.IsAbs(dir) && !strings.HasPrefix(dir, "/app") {
		// Check if we're in Docker
		isDocker := false
		if _, err := os.Stat("/app"); err == nil {
			if err := os.MkdirAll("/app", 0755); err == nil {
				testPath := "/app/.test-write"
				if f, err := os.Create(testPath); err == nil {
					f.Close()
					os.Remove(testPath)
					isDocker = true
				}
			}
		}
		
		// If not in Docker and path is absolute (like /new-results), convert to relative
		if !isDocker {
			if cwd, err := os.Getwd(); err == nil {
				return filepath.Join(cwd, "new-results")
			}
			return "new-results"
		}
	}

	return dir
}

// cleanupDomainDirectory removes the domain's result directory
func cleanupDomainDirectory(domain string) error {
	resultsDir := getResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}
	
	log.Printf("[INFO] Cleaning up domain directory: %s", domainDir)
	if err := os.RemoveAll(domainDir); err != nil {
		log.Printf("[WARN] Failed to cleanup domain directory %s: %v", domainDir, err)
		return err
	}
	log.Printf("[OK] Cleaned up domain directory: %s", domainDir)
	return nil
}

// initializeDirectories creates necessary directories for AutoAR
func initializeDirectories() error {
	root := getRootDir()
	dirs := []string{
		filepath.Join(root, "new-results"),
		filepath.Join(root, "Wordlists"),
		filepath.Join(root, "nuclei_templates"),
		filepath.Join(root, "regexes"),
	}
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

// getRootDir returns the AutoAR root directory
func getRootDir() string {
	if root := os.Getenv("AUTOAR_ROOT"); root != "" {
		return root
	}
	// Try current working directory
	if cwd, err := os.Getwd(); err == nil {
		return cwd
	}
	// Docker fallback
	return "/app"
}
