package bot

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/h0tak88r/AutoAR/internal/api"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/envloader"
	"github.com/h0tak88r/AutoAR/internal/r2storage"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

func init() {
	utils.SendFileFunc = SendFileToChannel
}

var (
	botToken = os.Getenv("DISCORD_BOT_TOKEN")

	allowedGuildID   = utils.GetEnv("DISCORD_ALLOWED_GUILD_ID", "") // Restrict bot to specific guild by ID (GUID)
	allowedGuildName = utils.GetEnv("DISCORD_ALLOWED_GUILD", "")    // Legacy: Restrict bot to specific guild by name (deprecated, use GUID)
)

// SendFileToChannel sends a file directly to a Discord channel using the global session
// This is used by modules to send files without requiring the HTTP API
// Sends files in real-time immediately when called
func SendFileToChannel(channelID, filePath, description string) error {
	// Get Discord session
	api.DiscordSessionMutex.RLock()
	session := api.GlobalDiscordSession
	api.DiscordSessionMutex.RUnlock()

	if session == nil {
		log.Printf("[DISCORD] ❌ Discord bot session is nil - cannot send file")
		return fmt.Errorf("Discord bot session not available")
	}

	// Check if we should send to a thread instead of the channel
	threadID := ""
	scanID := os.Getenv("AUTOAR_CURRENT_SCAN_ID")
	if scanID != "" {
		api.ScansMutex.RLock()
		if scan, ok := api.ActiveScans[scanID]; ok && scan.ThreadID != "" {
			threadID = scan.ThreadID
			log.Printf("[DISCORD] 📤 Found thread ID %s for scan %s, sending to thread instead of channel", threadID, scanID)
		}
		api.ScansMutex.RUnlock()
	}

	// If no thread found by scanID, try to find by channel ID
	if threadID == "" {
		api.ScansMutex.RLock()
		for _, scan := range api.ActiveScans {
			if scan.ChannelID == channelID && scan.ThreadID != "" {
				threadID = scan.ThreadID
				log.Printf("[DISCORD] 📤 Found thread ID %s for channel %s, sending to thread", threadID, channelID)
				break
			}
		}
		api.ScansMutex.RUnlock()
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

// cleanupOrphanedScans marks in-progress scans as failed on bot startup (same as API restart).
func cleanupOrphanedScans() {
	log.Println("[INFO] Cleaning up orphaned scans from previous bot sessions...")
	n, err := db.FailStaleActiveScans()
	if err != nil {
		log.Printf("[WARN] Failed to fail stale scans: %v", err)
		return
	}
	if n > 0 {
		log.Printf("[INFO] Marked %d interrupted scan(s) as failed (no running worker after restart).", n)
	} else {
		log.Println("[INFO] No orphaned scans in database")
	}
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
	allowedGuildID = utils.GetEnv("DISCORD_ALLOWED_GUILD_ID", "")
	allowedGuildName = utils.GetEnv("DISCORD_ALLOWED_GUILD", "")

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

				// Clean up orphaned scans from previous bot sessions
				cleanupOrphanedScans()
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
	api.DiscordSessionMutex.Lock()
	api.GlobalDiscordSession = dg
	api.DiscordSessionMutex.Unlock()
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
	apiHostEnv := utils.GetEnv("API_HOST", "0.0.0.0")
	apiPortEnv := utils.GetEnv("API_PORT", "8000")
	router := api.SetupAPI()
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
	api.ScansMutex.RLock()
	var foundScan *api.ScanInfo
	if scanID != "" {
		if scan, ok := api.ActiveScans[scanID]; ok {
			foundScan = scan
		}
	}
	// If not found by scanID, try channel ID
	if foundScan == nil {
		for _, scan := range api.ActiveScans {
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
	api.ScansMutex.RUnlock()

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
	api.ScansMutex.RLock()
	for _, scan := range api.ActiveScans {
		if scan.ChannelID == channelID && scan.MessageID != "" {
			messageID = scan.MessageID
			break
		}
	}
	api.ScansMutex.RUnlock()

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
			api.ScansMutex.Lock()
			for _, scan := range api.ActiveScans {
				if scan.ChannelID == channelID && scan.MessageID == "" {
					scan.MessageID = followupMsg.ID
					break
				}
			}
			api.ScansMutex.Unlock()
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
	allowedGuildIDEnv := utils.GetEnv("DISCORD_ALLOWED_GUILD_ID", "")
	allowedGuildNameEnv := utils.GetEnv("DISCORD_ALLOWED_GUILD", "")

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

		// Fetch guild information (try state cache first to avoid blocking API calls and 3s timeouts)
		guild, err := s.State.Guild(i.GuildID)
		if err != nil {
			// Fallback to API if not in state cache
			guild, err = s.Guild(i.GuildID)
			if err != nil {
				log.Printf("[WARN] Failed to fetch guild info: %v", err)
				respond(s, i, "❌ Error: Unable to verify server. Please try again.", true)
				return
			}
		}

		// Check if guild name matches allowed guild
		if guild.Name != allowedGuildNameEnv {
			log.Printf("[INFO] Rejected command from unauthorized guild: %s (expected: %s)", guild.Name, allowedGuildNameEnv)
			respond(s, i, fmt.Sprintf("❌ This bot is restricted to the **%s** server only. Your server: **%s**", allowedGuildNameEnv, guild.Name), true)
			return
		}

		log.Printf("[DEBUG] Command allowed from guild: %s", guild.Name)
	}

	cmdName := i.ApplicationCommandData().Name

	// Route to appropriate handler (handlers are in commands*.go files)
	switch cmdName {
	case "asr", "asr_mode":
		handleASRBotCommand(s, i)
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
	case "git_scan":
		handleGitScan(s, i)
	case "cancel_scan":
		handleCancelScan(s, i)
	case "scope":
		handleScope(s, i)
	case "ssrf_bypass":
		handleSSRFBypass(s, i)
	case "fuzz":
		handleFuzz(s, i)
	case "brain":
		HandleBrainCommand(s, i)
	case "scans":
		HandleScansCommand(s, i)
	case "ai":
		handleAIChat(s, i)
	case "help":
		handleHelp(s, i)
	default:
		log.Printf("Unknown command: %s", cmdName)
		respond(s, i, fmt.Sprintf("Unknown command: %s", cmdName), false)
	}
}

// cleanupDomainDirectory uploads domain results to R2 (if enabled) and removes the domain's result directory
func cleanupDomainDirectory(domain string) error {
	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	return cleanupResultsDirectory(domainDir)
}

// cleanupResultsDirectory uploads results to R2 (if enabled) and removes the local directory
// localPath: Full local path to the results directory
func cleanupResultsDirectory(localPath string) error {
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}

	// R2 upload disabled - files are already sent to Discord thread in real-time
	// No need for redundant R2 upload at the end
	// if r2storage.IsEnabled() && os.Getenv("USE_R2_STORAGE") == "true" {
	// 	log.Printf("[INFO] Uploading results to R2 before cleanup: %s", localPath)
	// 	urls, err := r2storage.UploadResultsDirectory(prefix, localPath, true) // Upload and remove local
	// 	if err != nil {
	// 		log.Printf("[WARN] Failed to upload results to R2: %v, proceeding with local cleanup", err)
	// 	} else {
	// 		log.Printf("[OK] Uploaded %d files to R2 for %s", len(urls), prefix)
	// 		// Files already removed by UploadResultsDirectory, just return
	// 		return nil
	// 	}
	// }

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
