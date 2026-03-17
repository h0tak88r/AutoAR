package gobot

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/modules/brain"
	"github.com/h0tak88r/AutoAR/internal/modules/config"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

func HandleBrainCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var scanID string
	var attachment *discordgo.MessageAttachment
	mode := "execute" // Default to execute

	for _, opt := range options {
		switch opt.Name {
		case "scan_id":
			scanID = opt.StringValue()
		case "attachment":
			attachmentID := opt.Value.(string)
			attachment = i.ApplicationCommandData().Resolved.Attachments[attachmentID]
		case "mode":
			mode = opt.StringValue()
		}
	}

	if scanID == "" && attachment == nil {
		respond(s, i, "❌ Either Scan ID or an Attachment is required.", true)
		return
	}

	// Defer response to allow for AI processing time
	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})
	if err != nil {
		log.Printf("[ERROR] Failed to respond to brain command: %v", err)
		return
	}

	var content []byte
	var targetName string

	if attachment != nil {
		targetName = attachment.Filename
		resp, err := utils.GetHTTPClient().Get(attachment.URL)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error downloading attachment: %v", err),
			})
			return
		}
		defer resp.Body.Close()
		content, err = io.ReadAll(resp.Body)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error reading attachment: %v", err),
			})
			return
		}
	} else {
		// Fetch scan result content
		scan, err := db.GetScan(scanID)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error fetching scan: %v", err),
			})
			return
		}
		targetName = scan.Target

		resultsDir := config.GetResultsDir()
		resultsPath := ""
		switch scan.ScanType {
		case "ports":
			resultsPath = filepath.Join(resultsDir, scan.Target, "ports", "ports.txt")
		case "nuclei":
			resultsPath = filepath.Join(resultsDir, scan.Target, "nuclei", "nuclei.txt")
		default:
			resultsPath = filepath.Join(resultsDir, scan.Target, scan.ScanType, scan.ScanType+".txt")
		}

		if _, err := os.Stat(resultsPath); os.IsNotExist(err) {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Results not found for scan %s at %s", scanID, resultsPath),
			})
			return
		}

		content, err = os.ReadFile(resultsPath)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Error reading results: %v", err),
			})
			return
		}
	}

	var result string
	if mode == "execute" {
		// Update user that we're starting execution
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("🧠 **Autonomous Brain Initialized**\nAnalyzing results for %s and running follow-up tests... (this may take a minute)", targetName),
		})
		result, err = brain.ExecuteAutonomous(string(content))
	} else {
		result, err = brain.AnalyzeResults(string(content))
	}

	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Brain operation failed: %v", err),
		})
		return
	}

	// Send final findings
	embed := &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("🧠 AI Findings: %s (%s)", targetName, mode),
		Description: result,
		Color:       0xFF0000, // Red for findings
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Powered by Gemini 2.0 Flash via OpenRouter",
		},
	}

	if len(result) > 4096 {
		// Too large for an embed, send as file
		file := &discordgo.File{
			Name:        "ai-findings.md",
			ContentType: "text/markdown",
			Reader:      strings.NewReader(result),
		}
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("🧠 **AI Findings for %s** (too large for embed, attached as file):", targetName),
			Files:   []*discordgo.File{file},
		})
	} else {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
	}
}

func HandleScansCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	limit := 10
	options := i.ApplicationCommandData().Options
	for _, opt := range options {
		if opt.Name == "limit" {
			limit = int(opt.IntValue())
		}
	}

	scans, err := db.ListRecentScans(limit)
	if err != nil {
		respond(s, i, fmt.Sprintf("❌ Error listing scans: %v", err), true)
		return
	}

	if len(scans) == 0 {
		respond(s, i, "📭 No recent scans found.", true)
		return
	}

	var fields []*discordgo.MessageEmbedField
	for _, scan := range scans {
		fields = append(fields, &discordgo.MessageEmbedField{
			Name:   fmt.Sprintf("📁 %s (%s)", scan.Target, scan.ScanType),
			Value:  fmt.Sprintf("Scan ID: `%s`\nStatus: %s\nDate: %s", scan.ScanID, scan.Status, scan.StartedAt.Format("2006-01-02 15:04")),
			Inline: false,
		})
	}

	embed := &discordgo.MessageEmbed{
		Title:  "📜 Recent Scans History",
		Fields: fields,
		Color:  0x00AAFF,
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
}
