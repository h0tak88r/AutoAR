package gobot

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/envloader"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
)

var (
	botToken   = os.Getenv("DISCORD_BOT_TOKEN")
	autoarMode = getEnv("AUTOAR_MODE", "discord")
	apiHost    = getEnv("API_HOST", "0.0.0.0")
	apiPort    = getEnv("API_PORT", "8000")
	allowedGuildID = getEnv("DISCORD_ALLOWED_GUILD_ID", "") // Restrict bot to specific guild by ID (GUID)
	allowedGuildName = getEnv("DISCORD_ALLOWED_GUILD", "")  // Legacy: Restrict bot to specific guild by name (deprecated, use GUID)

	// Global Discord session for file sending from modules
	globalDiscordSession *discordgo.Session
	discordSessionMutex  sync.RWMutex

	// Channel ID storage for file notifications
	activeChannels = make(map[string]string) // scanID -> channelID
	channelsMutex  sync.RWMutex
)

// getMetricsSnapshot returns empty metrics to avoid import cycle
// Metrics are tracked internally by workflows
func getMetricsSnapshot() map[string]interface{} {
	// Return basic metrics without importing utils
	scansMutex.RLock()
	activeCount := len(activeScans)
	scansMutex.RUnlock()
	
	return map[string]interface{}{
		"active_scans": activeCount,
		"message": "Full metrics available after resolving import cycle",
	}
}

// SendFileToChannel sends a file directly to a Discord channel using the global session
// This is used by modules to send files without requiring the HTTP API
// Sends files in real-time immediately when called
func SendFileToChannel(channelID, filePath, description string) error {
	// Get Discord session
	discordSessionMutex.RLock()
	session := globalDiscordSession
	discordSessionMutex.RUnlock()

	if session == nil {
		log.Printf("[DISCORD] ❌ Discord bot session is nil - cannot send file")
		return fmt.Errorf("Discord bot session not available")
	}

	// Check if we should send to a thread instead of the channel
	threadID := ""
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	if scanID != "" {
		scansMutex.RLock()
		if scan, ok := activeScans[scanID]; ok && scan.ThreadID != "" {
			threadID = scan.ThreadID
			log.Printf("[DISCORD] 📤 Found thread ID %s for scan %s, sending to thread instead of channel", threadID, scanID)
		}
		scansMutex.RUnlock()
	}
	
	// If no thread found by scanID, try to find by channel ID
	if threadID == "" {
		scansMutex.RLock()
		for _, scan := range activeScans {
			if scan.ChannelID == channelID && scan.ThreadID != "" {
				threadID = scan.ThreadID
				log.Printf("[DISCORD] 📤 Found thread ID %s for channel %s, sending to thread", threadID, channelID)
				break
			}
		}
		scansMutex.RUnlock()
	}

	// Use thread ID if available, otherwise use channel ID
	targetID := channelID
	if threadID != "" {
		targetID = threadID
		log.Printf("[DISCORD] 📤 Sending file to thread %s (instead of channel %s)", threadID, channelID)
	} else {
		log.Printf("[DISCORD] 📤 Sending file to channel %s (no thread found)", channelID)
	}

	log.Printf("[DISCORD] 📤 Attempting to send file via Discord bot: %s to %s", filepath.Base(filePath), targetID)

	// Check if file exists
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		log.Printf("[DISCORD] ❌ File not found: %s", filePath)
		return fmt.Errorf("file not found: %s", filePath)
	} else if err != nil {
		log.Printf("[DISCORD] ❌ Failed to stat file: %v", err)
		return fmt.Errorf("failed to stat file: %w", err)
	} else if info.Size() == 0 {
		log.Printf("[DISCORD] ❌ File is empty: %s (size: 0)", filePath)
		return fmt.Errorf("file is empty: %s", filePath)
	}

	log.Printf("[DISCORD] [ + ]File found: %s (size: %d bytes)", filePath, info.Size())

	fileName := filepath.Base(filePath)
	if description == "" {
		description = fmt.Sprintf("📁 %s", fileName)
	}

	// Check if file is too large for Discord or if R2 is enabled and file should use R2
	useR2 := r2storage.ShouldUseR2(filePath) || (r2storage.IsEnabled() && info.Size() > r2storage.GetFileSizeLimit())

	if useR2 {
		// Upload to R2 and send link (use timestamp for regular files)
		log.Printf("[DISCORD] 📦 File is large (%d bytes), uploading to R2...", info.Size())
		publicURL, err := r2storage.UploadFile(filePath, fileName, false)
		if err != nil {
			log.Printf("[DISCORD] ⚠️  Failed to upload to R2, trying direct Discord upload: %v", err)
			// Fallback to direct upload if R2 fails
			useR2 = false
		} else {
			// Send R2 link to Discord
			message := fmt.Sprintf("%s\n\n📦 **File too large for Discord** (%.2f MB)\n🔗 **Download:** %s", description, float64(info.Size())/1024/1024, publicURL)
			_, err = session.ChannelMessageSend(targetID, message)
			if err != nil {
				log.Printf("[DISCORD] ❌ Failed to send R2 link to Discord: %v", err)
				return fmt.Errorf("failed to send R2 link to Discord: %w", err)
			}
			log.Printf("[DISCORD] [ + ]Successfully sent R2 link to Discord: %s", publicURL)
			return nil
		}
	}

	// Stream file directly to Discord (memory efficient - no loading into RAM)
	log.Printf("[DISCORD] 🚀 Streaming file to Discord %s: %s (%d bytes)", targetID, fileName, info.Size())
	
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[DISCORD] ❌ Failed to open file: %v", err)
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Send file to Discord channel/thread immediately (streaming)
	_, err = session.ChannelMessageSendComplex(targetID, &discordgo.MessageSend{
		Content: description,
		Files: []*discordgo.File{
			{
				Name:   fileName,
				Reader: file, // Stream directly from file
			},
		},
	})

	if err != nil {
		// If direct upload fails due to size, try R2 as fallback
		if strings.Contains(err.Error(), "413") || strings.Contains(err.Error(), "too large") || strings.Contains(err.Error(), "Request entity too large") {
			log.Printf("[DISCORD] ⚠️  Discord upload failed due to size, uploading to R2 as fallback...")
			if r2storage.IsEnabled() {
				publicURL, r2Err := r2storage.UploadFile(filePath, fileName, false)
				if r2Err != nil {
					log.Printf("[DISCORD] ❌ Failed to upload to R2: %v", r2Err)
					return fmt.Errorf("failed to send file to Discord and R2 upload failed: %w (R2 error: %v)", err, r2Err)
				}
				message := fmt.Sprintf("%s\n\n📦 **File too large for Discord** (%.2f MB)\n🔗 **Download:** %s", description, float64(info.Size())/1024/1024, publicURL)
				_, err = session.ChannelMessageSend(targetID, message)
				if err != nil {
					log.Printf("[DISCORD] ❌ Failed to send R2 link to Discord: %v", err)
					return fmt.Errorf("failed to send R2 link to Discord: %w", err)
				}
				log.Printf("[DISCORD] [ + ]Successfully sent R2 link to Discord (fallback): %s", publicURL)
				return nil
			}
		}
		log.Printf("[DISCORD] ❌ Failed to send file to Discord: %v", err)
		return fmt.Errorf("failed to send file to Discord: %w", err)
	}

	log.Printf("[DISCORD] [ + ]Successfully sent file to Discord channel: %s", fileName)
	return nil
}

// StartBot starts the Discord bot and initializes database
func StartBot() error {
	fmt.Println("🚀 Starting AutoAR Discord Bot...")
	
	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("[ + ]Loaded environment variables from .env file")
	}

	// NOTE: Logger, metrics, rate limiter, and shutdown manager initialization
	// moved to workflow modules to avoid import cycle (utils/discord.go imports gobot)
	// These utilities are available in domain.go, subdomain.go, and other workflow files

	// Re-read bot token and guild settings after loading .env
	botToken = os.Getenv("DISCORD_BOT_TOKEN")
	allowedGuildID = getEnv("DISCORD_ALLOWED_GUILD_ID", "")
	allowedGuildName = getEnv("DISCORD_ALLOWED_GUILD", "")
	
	// Initialize directories
	if err := initializeDirectories(); err != nil {
		log.Printf("[WARN] Failed to initialize directories: %v", err)
	} else {
		fmt.Println("[ + ]Initialized directories")
	}
	
	// Initialize database if configured
	if os.Getenv("DB_HOST") != "" {
		log.Println("[INFO] Initializing database...")
		if err := db.Init(); err != nil {
			log.Printf("[WARN] Failed to initialize database: %v", err)
		} else {
			if err := db.InitSchema(); err != nil {
				log.Printf("[WARN] Failed to initialize database schema: %v", err)
			} else {
				log.Println("[INFO] Database initialized successfully")
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

	// Set global session IMMEDIATELY after creation (before opening connection)
	// This ensures the API can access it even if the bot is still connecting
	discordSessionMutex.Lock()
	globalDiscordSession = dg
	discordSessionMutex.Unlock()
	log.Println("[INFO] Global Discord session initialized")

	// Set intents
	dg.Identify.Intents = discordgo.IntentsGuildMessages |
		discordgo.IntentsDirectMessages |
		discordgo.IntentsMessageContent |
		discordgo.IntentsGuilds

	// Register event handlers
	dg.AddHandler(Ready)
	dg.AddHandler(Disconnect)
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

	// Start HTTP API server in background BEFORE command registration
	// This ensures the API is available immediately for subprocesses (like lite scan)
	// Command registration can take 2+ minutes, so we start the API first
	apiHostEnv := getEnv("API_HOST", "localhost")
	apiPortEnv := getEnv("API_PORT", "8000")
	router := setupAPI()
	apiAddr := fmt.Sprintf("%s:%s", apiHostEnv, apiPortEnv)
	
	log.Printf("[INFO] Starting internal HTTP API server on %s", apiAddr)
	
	// Start API server with error handling
	apiStarted := make(chan bool, 1)
	go func() {
		if err := http.ListenAndServe(apiAddr, router); err != nil {
			log.Printf("[ERROR] Internal API server failed: %v", err)
			if strings.Contains(err.Error(), "address already in use") {
				log.Printf("[WARN] Port %s is already in use. The HTTP API fallback will not be available.", apiPortEnv)
				log.Printf("[INFO] Files will be sent via webhook fallback instead")
			}
			apiStarted <- false
		} else {
			apiStarted <- true
		}
	}()
	
	// Give API a moment to start
	time.Sleep(100 * time.Millisecond)

	// Register slash commands (this can take 2+ minutes for 39 commands)
	registerAllCommands(dg)

	fmt.Println("[ + ]AutoAR Discord Bot is running and connected!")
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
	fmt.Println("🚀 Starting AutoAR API Server...")
	
	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("[ + ]Loaded environment variables from .env file")
	}

	// Re-read API host and port after loading .env
	apiHostEnv := getEnv("API_HOST", "0.0.0.0")
	apiPortEnv := getEnv("API_PORT", "8000")
	
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
	addr := fmt.Sprintf("%s:%s", apiHostEnv, apiPortEnv)
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
	fmt.Println("🚀 Starting AutoAR (Discord Bot + API Server)...")
	
	// Load .env file if it exists
	if err := envloader.LoadEnv(); err != nil {
		log.Printf("[WARN] Failed to load .env file: %v", err)
	} else {
		fmt.Println("[ + ]Loaded environment variables from .env file")
	}

	// Re-read configuration after loading .env
	botTokenEnv := os.Getenv("DISCORD_BOT_TOKEN")
	autoarModeEnv := getEnv("AUTOAR_MODE", "both")
	
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
	var botStarted sync.WaitGroup

	if botTokenEnv == "" {
		return fmt.Errorf("DISCORD_BOT_TOKEN environment variable is required")
	}

	// Start Discord bot if mode allows
	if autoarModeEnv == "discord" || autoarModeEnv == "both" {
		botStarted.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			// Signal that bot initialization has started
			// This allows API to wait for the session to be ready
			go func() {
				// Wait a moment for globalDiscordSession to be set
				time.Sleep(500 * time.Millisecond)
				botStarted.Done()
			}()
			
			if err := StartBot(); err != nil {
				log.Printf("Discord bot error: %v", err)
			}
		}()
		
		// Wait for bot to initialize session before starting API
		log.Println("[INFO] Waiting for Discord bot session to initialize...")
		botStarted.Wait()
		log.Println("[INFO] Discord bot session ready, starting API...")
	}

	// Start API server if mode allows
	if autoarModeEnv == "api" || autoarModeEnv == "both" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := StartAPI(); err != nil {
				log.Printf("API server error: %v", err)
			}
		}()
	}

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

// Disconnect handles websocket disconnections and attempts reconnection
func Disconnect(s *discordgo.Session, event *discordgo.Disconnect) {
	log.Printf("[WARN] Discord websocket disconnected: %v", event)
	// discordgo library handles automatic reconnection, but we log it for monitoring
}

// UpdateInteractionMessage safely updates a Discord interaction message, handling token expiration
// Uses threads when available to avoid token expiration issues
func UpdateInteractionMessage(s *discordgo.Session, i *discordgo.InteractionCreate, scanID string, embed *discordgo.MessageEmbed) error {
	if i == nil || i.Interaction == nil {
		return fmt.Errorf("invalid interaction")
	}

	channelID := i.ChannelID
	threadID := ""
	messageID := ""
	
	// Try to find scan by scanID first (most reliable), then by channel ID
	scansMutex.RLock()
	var foundScan *ScanInfo
	if scanID != "" {
		if scan, ok := activeScans[scanID]; ok {
			foundScan = scan
		}
	}
	// If not found by scanID, try channel ID
	if foundScan == nil {
		for _, scan := range activeScans {
			if scan.ChannelID == channelID {
				foundScan = scan
				break
			}
		}
	}
	if foundScan != nil {
		if foundScan.ThreadID != "" {
			threadID = foundScan.ThreadID
		}
		if foundScan.MessageID != "" {
			messageID = foundScan.MessageID
		}
	}
	scansMutex.RUnlock()

	// If we have a thread ID, send message to thread (best option - no token needed)
	if threadID != "" {
		_, err := s.ChannelMessageSendEmbed(threadID, embed)
		if err == nil {
			log.Printf("[DEBUG] Successfully sent update to thread %s (no token required)", threadID)
			return nil
		}
		log.Printf("[WARN] Failed to send message to thread %s: %v, trying alternatives", threadID, err)
	}

	// If we have a stored message ID, use ChannelMessageEdit (doesn't require interaction token)
	if messageID != "" && channelID != "" && threadID == "" {
		_, err := s.ChannelMessageEditEmbed(channelID, messageID, embed)
		if err == nil {
			log.Printf("[DEBUG] Successfully updated message using stored message ID (no token required)")
			return nil
		}
		log.Printf("[WARN] Failed to edit message by ID, falling back to interaction methods: %v", err)
	}

	// Try to edit the interaction response first (only works if token hasn't expired)
	_, err := s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		// Check if error is due to expired token (401 Unauthorized or "Invalid Webhook Token")
		errStr := err.Error()
		isExpiredToken := strings.Contains(errStr, "401") || 
			strings.Contains(errStr, "Invalid Webhook Token") ||
			strings.Contains(errStr, "50027") // Discord error code for invalid webhook token
		
		if isExpiredToken {
			log.Printf("[DEBUG] Interaction token expired, using thread or follow-up message")
		} else {
			log.Printf("[WARN] InteractionResponseEdit failed: %v, trying alternative methods", err)
		}
		
		// If we have a thread, we already tried it above, so try follow-up as fallback
		if threadID == "" {
			// Try follow-up message
			followupMsg, followErr := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Embeds: []*discordgo.MessageEmbed{embed},
			})
			if followErr == nil && followupMsg != nil {
				log.Printf("[DEBUG] Created follow-up message as fallback")
				return nil
			}
			
			// Last resort: send new message to channel
			if channelID != "" {
				log.Printf("[WARN] Follow-up also failed, trying channel message: %v", followErr)
				_, channelErr := s.ChannelMessageSendEmbed(channelID, embed)
				if channelErr != nil {
					// Check if it's a permission issue
					errStr := channelErr.Error()
					if strings.Contains(errStr, "403") || strings.Contains(errStr, "Missing Access") || strings.Contains(errStr, "50001") {
						log.Printf("[ERROR] Bot lacks permission to send messages in channel %s. Please ensure the bot has 'Send Messages' permission.", channelID)
					}
					if isExpiredToken {
						log.Printf("[WARN] All update methods failed due to expired token. This is expected for long-running scans (>15 min).")
						return nil // Don't fail completely for expired tokens
					}
					return fmt.Errorf("all update methods failed: edit=%v, followup=%v, channel=%v", err, followErr, channelErr)
				}
				log.Printf("[INFO] Successfully sent message via channel (fallback)")
				return nil
			}
			
			if isExpiredToken {
				log.Printf("[WARN] Token expired and no thread/channel available. This is expected for scans taking >15 minutes.")
				return nil // Don't fail completely
			}
			return fmt.Errorf("edit and follow-up both failed: edit=%v, followup=%v", err, followErr)
		}
		// If we have a thread but sending to it failed, we already logged the error above
		return nil
	}

	return nil
}

// UpdateInteractionContent safely updates a Discord interaction message with text content
// Uses stored message IDs when available to avoid token expiration issues
func UpdateInteractionContent(s *discordgo.Session, i *discordgo.InteractionCreate, content string) error {
	if i == nil || i.Interaction == nil {
		return fmt.Errorf("invalid interaction")
	}

	// First, try to get stored message ID from scan info (if available)
	channelID := i.ChannelID
	messageID := ""
	
	// Try to find scan by channel ID and get its message ID
	scansMutex.RLock()
	for _, scan := range activeScans {
		if scan.ChannelID == channelID && scan.MessageID != "" {
			messageID = scan.MessageID
			break
		}
	}
	scansMutex.RUnlock()

	// If we have a stored message ID, use ChannelMessageEdit (doesn't require interaction token)
	if messageID != "" && channelID != "" {
		_, err := s.ChannelMessageEdit(channelID, messageID, content)
		if err == nil {
			log.Printf("[INFO] Successfully updated message content using stored message ID (no token required)")
			return nil
		}
		log.Printf("[WARN] Failed to edit message by ID, falling back to interaction methods: %v", err)
	}

	// Try to edit the interaction response first
	_, err := s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
	})
	if err != nil {
		// Check if error is due to expired token
		errStr := err.Error()
		isExpiredToken := strings.Contains(errStr, "401") || 
			strings.Contains(errStr, "Invalid Webhook Token") ||
			strings.Contains(errStr, "50027")
		
		if isExpiredToken {
			log.Printf("[INFO] Interaction token expired, trying alternative methods")
		} else {
			log.Printf("[WARN] InteractionResponseEdit failed: %v, trying follow-up message", err)
		}
		
		// Try follow-up as fallback
		followupMsg, followErr := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: content,
		})
		if followErr != nil {
			// Last resort: try channel message
			if channelID != "" {
				log.Printf("[WARN] Follow-up also failed, trying channel message: %v", followErr)
				_, channelErr := s.ChannelMessageSend(channelID, content)
				if channelErr != nil {
					// Check if it's a permission issue
					errStr := channelErr.Error()
					if strings.Contains(errStr, "403") || strings.Contains(errStr, "Missing Access") || strings.Contains(errStr, "50001") {
						log.Printf("[ERROR] Bot lacks permission to send messages in channel %s. Please ensure the bot has 'Send Messages' permission.", channelID)
					}
					if isExpiredToken {
						log.Printf("[WARN] All update methods failed due to expired token. This is expected for long-running scans (>15 min).")
						return nil // Don't fail completely
					}
					return fmt.Errorf("all update methods failed: edit=%v, followup=%v, channel=%v", err, followErr, channelErr)
				}
				log.Printf("[INFO] Successfully sent message via channel (fallback)")
				return nil
			}
			if isExpiredToken {
				log.Printf("[WARN] Interaction token expired and no channel ID available. This is expected for scans taking >15 minutes.")
				return nil // Don't fail completely
			}
			return fmt.Errorf("edit and follow-up both failed: edit=%v, followup=%v", err, followErr)
		}
		
		// Store follow-up message ID for future updates
		if followupMsg != nil && channelID != "" {
			scansMutex.Lock()
			for _, scan := range activeScans {
				if scan.ChannelID == channelID && scan.MessageID == "" {
					scan.MessageID = followupMsg.ID
					break
				}
			}
			scansMutex.Unlock()
		}
		
		if isExpiredToken {
			log.Printf("[INFO] Successfully sent follow-up message (token expired)")
		} else {
			log.Printf("[INFO] Successfully sent follow-up message (edit failed)")
		}
		return nil
	}

	return nil
}

// InteractionCreate handles Discord slash command interactions
func InteractionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Read guild restriction from environment variables dynamically (supports .env file)
	// This ensures values are read after .env is loaded, not from package-level initialization
	allowedGuildIDEnv := getEnv("DISCORD_ALLOWED_GUILD_ID", "")
	allowedGuildNameEnv := getEnv("DISCORD_ALLOWED_GUILD", "")
	
	// Check guild restriction by ID (GUID) - preferred method
	if allowedGuildIDEnv != "" {
		// Reject DMs (commands must be in a server)
		if i.GuildID == "" {
			log.Printf("[INFO] Rejected command from DM (not in a server)")
			respond(s, i, fmt.Sprintf("❌ This bot is restricted to a specific server (Guild ID: %s). Please use commands in that server.", allowedGuildIDEnv), true)
			return
		}
		if i.GuildID != allowedGuildIDEnv {
			log.Printf("[INFO] Rejected command from unauthorized guild ID: %s (expected: %s)", i.GuildID, allowedGuildIDEnv)
			respond(s, i, fmt.Sprintf("❌ This bot is restricted to a specific server (Guild ID: %s). Your server ID: %s", allowedGuildIDEnv, i.GuildID), true)
			return
		}
		log.Printf("[DEBUG] Command allowed from guild ID: %s", i.GuildID)
	} else if allowedGuildNameEnv != "" {
		// Legacy: Check by guild name (deprecated, but kept for backward compatibility)
		// Reject DMs (commands must be in a server)
		if i.GuildID == "" {
			log.Printf("[INFO] Rejected command from DM (not in a server)")
			respond(s, i, fmt.Sprintf("❌ This bot only works in the **%s** server. Please use commands in that server.", allowedGuildNameEnv), true)
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
		if guild.Name != allowedGuildNameEnv {
			log.Printf("[INFO] Rejected command from unauthorized guild: %s (expected: %s)", guild.Name, allowedGuildNameEnv)
			respond(s, i, fmt.Sprintf("❌ This bot is restricted to the **%s** server only. Your server: **%s**", allowedGuildNameEnv, guild.Name), true)
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
	case "zerodays", "0days":
		handleZerodays(s, i)
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
	case "subdomain_run":
		handleSubdomainRun(s, i)
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
	case "aem_scan":
		handleAEMScan(s, i)
	case "check_tools":
		handleCheckTools(s, i)
	case "cleanup":
		handleCleanup(s, i)
	case "misconfig":
		handleMisconfig(s, i)
	case "webdepconf":
		handleWebDepConf(s, i)
	case "scan_status":
		handleScanStatus(s, i)
	case "cancel_scan":
		handleCancelScan(s, i)
	case "scope":
		handleScope(s, i)
	default:
		log.Printf("Unknown command: %s", cmdName)
		respond(s, i, fmt.Sprintf("Unknown command: %s", cmdName), false)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt returns an environment variable as an integer with a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
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

// cleanupDomainDirectory uploads domain results to R2 (if enabled) and removes the domain's result directory
func cleanupDomainDirectory(domain string) error {
	resultsDir := getResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	return cleanupResultsDirectory(domain, domainDir)
}

// cleanupResultsDirectory uploads results to R2 (if enabled) and removes the local directory
// prefix: R2 prefix path (e.g., "domain", "apkx/com.example.app", "github/repos/owner/repo")
// localPath: Full local path to the results directory
func cleanupResultsDirectory(prefix, localPath string) error {
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}
	
	// Upload to R2 first if enabled
	if r2storage.IsEnabled() && os.Getenv("USE_R2_STORAGE") == "true" {
		log.Printf("[INFO] Uploading results to R2 before cleanup: %s", localPath)
		urls, err := r2storage.UploadResultsDirectory(prefix, localPath, true) // Upload and remove local
		if err != nil {
			log.Printf("[WARN] Failed to upload results to R2: %v, proceeding with local cleanup", err)
		} else {
			log.Printf("[OK] Uploaded %d files to R2 for %s", len(urls), prefix)
			// Files already removed by UploadResultsDirectory, just return
			return nil
		}
	}
	
	// If R2 not enabled or upload failed, do local cleanup
	log.Printf("[INFO] Cleaning up results directory: %s", localPath)
	if err := os.RemoveAll(localPath); err != nil {
		log.Printf("[WARN] Failed to cleanup results directory %s: %v", localPath, err)
		return err
	}
	log.Printf("[OK] Cleaned up results directory: %s", localPath)
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
