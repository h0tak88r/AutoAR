package gobot

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// handleScanFromFile processes a file from a message (reply or message_id) and runs a scan on each target
func handleScanFromFile(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var scanType string
	var messageID string

	// Parse options
	for _, opt := range options {
		switch opt.Name {
		case "scan_type":
			scanType = opt.StringValue()
		case "message_id":
			messageID = opt.StringValue()
		}
	}

	// Validate scan type
	validScanTypes := []string{"subdomains", "livehosts", "nuclei", "urls", "tech", "ports", "dalfox", "sqlmap", "reflection", "gf"}
	isValid := false
	for _, valid := range validScanTypes {
		if scanType == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		respond(s, i, fmt.Sprintf("❌ Invalid scan type: %s. Valid types: %s", scanType, strings.Join(validScanTypes, ", ")), false)
		return
	}

	// Respond immediately (Discord requires response within 3 seconds)
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "📥 Looking for file attachment...",
		},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to respond to interaction: %v", err)
		return
	}

	// Get attachment from message
	var attachment *discordgo.MessageAttachment
	
	// Method 1: Check for file attached directly to the slash command
	if i.ApplicationCommandData().Resolved != nil && i.ApplicationCommandData().Resolved.Attachments != nil {
		// Check all resolved attachments (files attached directly to command)
		for attID, att := range i.ApplicationCommandData().Resolved.Attachments {
			if att != nil {
				attachment = att
				log.Printf("[INFO] Found attachment directly attached to command (ID: %s): %s", attID, attachment.Filename)
				break
			}
		}
	}
	
	// Method 2: Check if this is a message context command (right-click on message)
	if attachment == nil && i.ApplicationCommandData().TargetID != "" {
		// This is a message context command - fetch the target message
		msg, err := s.ChannelMessage(i.ChannelID, i.ApplicationCommandData().TargetID)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error fetching target message: %v", err),
			})
			return
		}
		if len(msg.Attachments) == 0 {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: "❌ No file attachments found in the target message",
			})
			return
		}
		attachment = msg.Attachments[0]
		log.Printf("[INFO] Found attachment from message context command: %s", attachment.Filename)
	}
	
	// Method 3: Fetch message by ID (from slash command parameter)
	if attachment == nil && messageID != "" {
		// Method 2: Fetch message by ID
		msg, err := s.ChannelMessage(i.ChannelID, messageID)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error fetching message: %v", err),
			})
			return
		}
		if len(msg.Attachments) == 0 {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: "❌ No file attachments found in the specified message",
			})
			return
		}
		attachment = msg.Attachments[0]
		log.Printf("[INFO] Found attachment from message ID %s: %s", messageID, attachment.Filename)
	}
	
	// If still no attachment found
	if attachment == nil || attachment.URL == "" {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: "❌ No file found. Please:\n1. **Attach a file** directly to this command, OR\n2. **Right-click** on a message with a file → Apps → Scan File, OR\n3. Use `/scan_from_file` with **message_id** parameter (get ID by right-clicking message → Copy ID)",
		})
		return
	}
	
	if attachment == nil || attachment.URL == "" {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: "❌ Error: Could not find valid attachment",
		})
		return
	}

	// Download the file
	log.Printf("[INFO] Downloading file from: %s", attachment.URL)
	resp, err := http.Get(attachment.URL)
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error downloading file: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	// Create temp file
	tmpFile, err := os.CreateTemp("", "autoar-upload-*.txt")
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error creating temp file: %v", err),
		})
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Copy file content
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error saving file: %v", err),
		})
		return
	}
	tmpFile.Close()

	// Read targets from file
	targets, err := readTargetsFromFile(tmpFile.Name())
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error reading file: %v", err),
		})
		return
	}

	if len(targets) == 0 {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: "❌ No valid targets found in file",
		})
		return
	}

	// Update initial response
	content := fmt.Sprintf("📋 Found %d targets in file. Starting %s scan...", len(targets), scanType)
	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
	})
	if err != nil {
		log.Printf("[WARN] Failed to update interaction: %v", err)
	}

	// Process each target
	resultsDir := getEnv("AUTOAR_RESULTS_DIR", "/app/new-results")
	successCount := 0
	failCount := 0
	var resultFiles []string

	for idx, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		log.Printf("[INFO] Processing target %d/%d: %s", idx+1, len(targets), target)

		// Build command based on scan type
		var command []string
		switch scanType {
		case "subdomains":
			command = []string{autoarScript, "subdomains", "get", "-d", target}
		case "livehosts":
			command = []string{autoarScript, "livehosts", "get", "-d", target}
		case "nuclei":
			command = []string{autoarScript, "nuclei", "run", "-d", target}
		case "urls":
			command = []string{autoarScript, "urls", "collect", "-d", target}
		case "tech":
			command = []string{autoarScript, "tech", "detect", "-d", target}
		case "ports":
			command = []string{autoarScript, "ports", "scan", "-d", target}
		case "dalfox":
			command = []string{autoarScript, "dalfox", "run", "-d", target}
		case "sqlmap":
			command = []string{autoarScript, "sqlmap", "run", "-d", target}
		case "reflection":
			command = []string{autoarScript, "reflection", "scan", "-d", target}
		case "gf":
			command = []string{autoarScript, "gf", "scan", "-d", target}
		default:
			log.Printf("[WARN] Unknown scan type: %s", scanType)
			continue
		}

		// Execute command
		cmd := exec.Command(command[0], command[1:]...)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("AUTOAR_CURRENT_CHANNEL_ID=%s", i.ChannelID),
		)
		err := cmd.Run()

		if err != nil {
			log.Printf("[ERROR] Scan failed for %s: %v", target, err)
			failCount++
		} else {
			successCount++
			// Try to find result files
			targetDir := filepath.Join(resultsDir, target)
			if scanType == "subdomains" {
				resultFile := filepath.Join(targetDir, "subs", "all-subs.txt")
				if _, err := os.Stat(resultFile); err == nil {
					resultFiles = append(resultFiles, resultFile)
				}
			} else if scanType == "livehosts" {
				resultFile := filepath.Join(targetDir, "subs", "live-hosts.txt")
				if _, err := os.Stat(resultFile); err == nil {
					resultFiles = append(resultFiles, resultFile)
				}
			}
		}

		// Small delay between scans
		time.Sleep(1 * time.Second)
	}

	// Send summary
	summary := fmt.Sprintf("✅ **Scan Complete**\n\n**Scan Type:** %s\n**Total Targets:** %d\n**Successful:** %d\n**Failed:** %d",
		scanType, len(targets), successCount, failCount)

	// Send result files if any
	if len(resultFiles) > 0 {
		var files []*discordgo.File
		for _, filePath := range resultFiles {
			if fileData, err := os.ReadFile(filePath); err == nil {
				fileName := filepath.Base(filePath)
				files = append(files, &discordgo.File{
					Name:        fileName,
					ContentType: "text/plain",
					Reader:      strings.NewReader(string(fileData)),
				})
			}
		}
		if len(files) > 0 {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: summary,
				Files:   files,
			})
		} else {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: summary,
			})
		}
	} else {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: summary,
		})
	}
}

// readTargetsFromFile reads targets from a file (one per line)
func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

// handleScanFromFileContext handles message context command (right-click on message)
// This shows a modal to get scan type, then processes the file
func handleScanFromFileContext(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// For context commands, we need to ask for scan type via modal
	if i.ApplicationCommandData().TargetID == "" {
		respond(s, i, "❌ No target message found", false)
		return
	}

	msg, err := s.ChannelMessage(i.ChannelID, i.ApplicationCommandData().TargetID)
	if err != nil {
		respond(s, i, fmt.Sprintf("❌ Error fetching message: %v", err), false)
		return
	}

	if len(msg.Attachments) == 0 {
		respond(s, i, "❌ No file attachments found in this message", false)
		return
	}

	// Show modal to get scan type
	err = s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseModal,
		Data: &discordgo.InteractionResponseData{
			CustomID: "scan_file_modal_" + i.ApplicationCommandData().TargetID,
			Title:    "Scan File",
			Components: []discordgo.MessageComponent{
				discordgo.ActionsRow{
					Components: []discordgo.MessageComponent{
						discordgo.TextInput{
							CustomID:    "scan_type",
							Label:       "Scan Type",
							Style:       discordgo.TextInputShort,
							Placeholder: "subdomains, livehosts, nuclei, etc.",
							Required:    true,
							MaxLength:   50,
						},
					},
				},
			},
		},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to show modal: %v", err)
	}
}

// handleModalSubmit processes modal submissions (for context menu scan file)
func handleModalSubmit(s *discordgo.Session, i *discordgo.InteractionCreate) {
	customID := i.ModalSubmitData().CustomID
	
	// Check if this is a scan file modal
	if strings.HasPrefix(customID, "scan_file_modal_") {
		messageID := strings.TrimPrefix(customID, "scan_file_modal_")
		
		// Get scan type from modal
		var scanType string
		for _, row := range i.ModalSubmitData().Components {
			for _, comp := range row.(*discordgo.ActionsRow).Components {
				if textInput, ok := comp.(*discordgo.TextInput); ok && textInput.CustomID == "scan_type" {
					scanType = textInput.Value
					break
				}
			}
		}
		
		if scanType == "" {
			respond(s, i, "❌ Scan type is required", false)
			return
		}
		
		// Now process the file with the scan type
		// We'll call handleScanFromFile with the message ID and scan type
		// But we need to modify it to accept these parameters directly
		processFileScan(s, i, messageID, scanType)
	}
}

// processFileScan processes a file scan given message ID and scan type
func processFileScan(s *discordgo.Session, i *discordgo.InteractionCreate, messageID, scanType string) {
	// Validate scan type
	validScanTypes := []string{"subdomains", "livehosts", "nuclei", "urls", "tech", "ports", "dalfox", "sqlmap", "reflection", "gf"}
	isValid := false
	for _, valid := range validScanTypes {
		if scanType == valid {
			isValid = true
			break
		}
	}
	if !isValid {
		respond(s, i, fmt.Sprintf("❌ Invalid scan type: %s. Valid types: %s", scanType, strings.Join(validScanTypes, ", ")), false)
		return
	}

	// Respond immediately
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "📥 Downloading file and processing targets...",
		},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to respond to interaction: %v", err)
		return
	}

	// Fetch message by ID
	msg, err := s.ChannelMessage(i.ChannelID, messageID)
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error fetching message: %v", err),
		})
		return
	}
	if len(msg.Attachments) == 0 {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: "❌ No file attachments found in the message",
		})
		return
	}
	attachment := msg.Attachments[0]

	// Download and process the file (reuse the rest of handleScanFromFile logic)
	// ... (copy the download and processing logic from handleScanFromFile)
	log.Printf("[INFO] Downloading file from: %s", attachment.URL)
	resp, err := http.Get(attachment.URL)
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error downloading file: %v", err),
		})
		return
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "autoar-upload-*.txt")
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error creating temp file: %v", err),
		})
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error saving file: %v", err),
		})
		return
	}
	tmpFile.Close()

	targets, err := readTargetsFromFile(tmpFile.Name())
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Error reading file: %v", err),
		})
		return
	}

	if len(targets) == 0 {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: "❌ No valid targets found in file",
		})
		return
	}

	content := fmt.Sprintf("📋 Found %d targets in file. Starting %s scan...", len(targets), scanType)
	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: &content,
	})
	if err != nil {
		log.Printf("[WARN] Failed to update interaction: %v", err)
	}

	// Process each target (same as handleScanFromFile)
	resultsDir := getEnv("AUTOAR_RESULTS_DIR", "/app/new-results")
	successCount := 0
	failCount := 0
	var resultFiles []string

	for idx, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		log.Printf("[INFO] Processing target %d/%d: %s", idx+1, len(targets), target)

		var command []string
		switch scanType {
		case "subdomains":
			command = []string{autoarScript, "subdomains", "get", "-d", target}
		case "livehosts":
			command = []string{autoarScript, "livehosts", "get", "-d", target}
		case "nuclei":
			command = []string{autoarScript, "nuclei", "run", "-d", target}
		case "urls":
			command = []string{autoarScript, "urls", "collect", "-d", target}
		case "tech":
			command = []string{autoarScript, "tech", "detect", "-d", target}
		case "ports":
			command = []string{autoarScript, "ports", "scan", "-d", target}
		case "dalfox":
			command = []string{autoarScript, "dalfox", "run", "-d", target}
		case "sqlmap":
			command = []string{autoarScript, "sqlmap", "run", "-d", target}
		case "reflection":
			command = []string{autoarScript, "reflection", "scan", "-d", target}
		case "gf":
			command = []string{autoarScript, "gf", "scan", "-d", target}
		default:
			log.Printf("[WARN] Unknown scan type: %s", scanType)
			continue
		}

		cmd := exec.Command(command[0], command[1:]...)
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("AUTOAR_CURRENT_CHANNEL_ID=%s", i.ChannelID),
		)
		err := cmd.Run()

		if err != nil {
			log.Printf("[ERROR] Scan failed for %s: %v", target, err)
			failCount++
		} else {
			successCount++
			targetDir := filepath.Join(resultsDir, target)
			if scanType == "subdomains" {
				resultFile := filepath.Join(targetDir, "subs", "all-subs.txt")
				if _, err := os.Stat(resultFile); err == nil {
					resultFiles = append(resultFiles, resultFile)
				}
			} else if scanType == "livehosts" {
				resultFile := filepath.Join(targetDir, "subs", "live-hosts.txt")
				if _, err := os.Stat(resultFile); err == nil {
					resultFiles = append(resultFiles, resultFile)
				}
			}
		}

		time.Sleep(1 * time.Second)
	}

	summary := fmt.Sprintf("✅ **Scan Complete**\n\n**Scan Type:** %s\n**Total Targets:** %d\n**Successful:** %d\n**Failed:** %d",
		scanType, len(targets), successCount, failCount)

	if len(resultFiles) > 0 {
		var files []*discordgo.File
		for _, filePath := range resultFiles {
			if fileData, err := os.ReadFile(filePath); err == nil {
				fileName := filepath.Base(filePath)
				files = append(files, &discordgo.File{
					Name:        fileName,
					ContentType: "text/plain",
					Reader:      strings.NewReader(string(fileData)),
				})
			}
		}
		if len(files) > 0 {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: summary,
				Files:   files,
			})
		} else {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: summary,
			})
		}
	} else {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: summary,
		})
	}
}
