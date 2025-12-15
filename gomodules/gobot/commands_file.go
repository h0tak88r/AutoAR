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

// handleScanFromFile processes a file upload and runs a scan on each target in the file
func handleScanFromFile(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var scanType string
	var attachmentID string
	threads := 100

	// Parse options
	for _, opt := range options {
		switch opt.Name {
		case "scan_type":
			scanType = opt.StringValue()
		case "file":
			attachmentID = opt.Value.(string)
		case "threads":
			threads = int(opt.IntValue())
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
		respondWithError(s, i, fmt.Sprintf("Invalid scan type: %s. Valid types: %s", scanType, strings.Join(validScanTypes, ", ")))
		return
	}

	// Respond immediately (Discord requires response within 3 seconds)
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

	// Get attachment details from resolved attachments
	var attachment *discordgo.MessageAttachment
	if i.ApplicationCommandData().Resolved != nil && i.ApplicationCommandData().Resolved.Attachments != nil {
		attachment = i.ApplicationCommandData().Resolved.Attachments[attachmentID]
	}
	
	// Fallback: try to get from options directly
	if attachment == nil {
		for _, opt := range options {
			if opt.Name == "file" {
				// Try to get attachment URL from option value
				if attachmentURL, ok := opt.Value.(string); ok && attachmentURL != "" {
					// Create a temporary attachment object
					attachment = &discordgo.MessageAttachment{
						URL: attachmentURL,
					}
					break
				}
			}
		}
	}
	
	if attachment == nil || attachment.URL == "" {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: "❌ Error: Could not find attachment",
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
	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Content: fmt.Sprintf("📋 Found %d targets in file. Starting %s scan...", len(targets), scanType),
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
		output, err := cmd.CombinedOutput()

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
