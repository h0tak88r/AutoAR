package gobot

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/modules/git"
)

// handleGitScan handles the /git_scan command
func handleGitScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	targetURL := ""
	for _, opt := range options {
		if opt.Name == "url" {
			targetURL = opt.StringValue()
		}
	}

	if targetURL == "" {
		respond(s, i, "❌ URL is required", false)
		return
	}

	// Defer response
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	// Setup paths
	resultsDir := getResultsDir()
	// Basic sanitization
	safeName := sanitizeFilename(targetURL)
	ts := time.Now().Format("20060102_150405")
	dumpDir := filepath.Join(resultsDir, "git_dumps", fmt.Sprintf("%s_%s", safeName, ts))
	scannerDir := filepath.Join(getRootDir(), "regexes")

	embed := &discordgo.MessageEmbed{
		Title:       "🔍 Git Scan Started",
		Description: fmt.Sprintf("Target: `%s`\nOutput: `%s`", targetURL, dumpDir),
		Color:       0x3498db,
	}
	UpdateInteractionMessage(s, i, "", embed)

	// Run scan
	res, err := git.Run(git.Options{
		URL:        targetURL,
		OutputDir:  dumpDir,
		ScannerDir: scannerDir,
	})

	if err != nil {
		embed.Color = 0xe74c3c
		embed.Title = "❌ Git Scan Failed"
		embed.Description = fmt.Sprintf("Error: %v", err)
		UpdateInteractionMessage(s, i, "", embed)
		return
	}

	// Success
	embed.Color = 0x00ff00
	embed.Title = "✅ Git Scan Completed"
	stats := fmt.Sprintf("**Target:** `%s`\n**Secrets Found:** %d\n**Dump:** `%s`", targetURL, res.SecretCount, res.DumpDir)
	embed.Description = stats
	UpdateInteractionMessage(s, i, "", embed)

	// Upload secrets file if findings > 0
	if res.SecretCount > 0 {
		f, err := os.Open(res.SecretsFile)
		if err == nil {
			defer f.Close()
			// Send file as edit to original response
			_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
				Files: []*discordgo.File{
					{
						Name:   "git-secrets.txt",
						Reader: f,
					},
				},
			})
			if err != nil {
				// Fallback to channel message if edit fails (token/size issues)
				s.ChannelMessageSendComplex(i.ChannelID, &discordgo.MessageSend{
					Content: fmt.Sprintf("Secrets found for %s", targetURL),
					Files: []*discordgo.File{
						{
							Name:   "git-secrets.txt",
							Reader: f,
						},
					},
				})
			}
		}
	}
}

func sanitizeFilename(s string) string {
	// Parse if it's a URL
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Host
	}
	s = strings.ReplaceAll(s, "http://", "")
	s = strings.ReplaceAll(s, "https://", "")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	// Keep reasonable chars
	return s
}
