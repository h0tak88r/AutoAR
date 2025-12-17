package gobot

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bwmarrin/discordgo"
	apkxmod "github.com/h0tak88r/AutoAR/internal/modules/apkx"
)

// handleApkXScan handles the /apkx_scan command.
// It accepts an APK/IPA attachment, runs apkX via the internal module,
// and posts a summary + log file back to Discord.
func handleApkXScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()

	var mitm bool
	for _, opt := range data.Options {
		if opt.Name == "mitm" {
			mitm = opt.BoolValue()
		}
	}

	// Respond quickly while we download and analyze
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: "📱 Starting apkX analysis...",
		},
	}); err != nil {
		log.Printf("[ERROR] failed to respond to apkx_scan: %v", err)
		return
	}

	// Locate the attachment
	var att *discordgo.MessageAttachment
	if data.Resolved != nil && data.Resolved.Attachments != nil {
		for _, opt := range data.Options {
			if opt.Type == discordgo.ApplicationCommandOptionAttachment {
				if a, ok := data.Resolved.Attachments[opt.Value.(string)]; ok && a != nil && a.URL != "" {
					att = a
					break
				}
			}
		}
	}

	if att == nil || att.URL == "" {
		msg := "❌ No file attachment found. Please attach an APK or IPA file."
		_, _ = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{Content: msg})
		return
	}

	// Download attachment to a temp file
	resp, err := http.Get(att.URL)
	if err != nil {
		msg := fmt.Sprintf("❌ Error downloading file: %v", err)
		_, _ = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{Content: msg})
		return
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "autoar-apkx-*"+filepath.Ext(att.Filename))
	if err != nil {
		msg := fmt.Sprintf("❌ Error creating temp file: %v", err)
		_, _ = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{Content: msg})
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		msg := fmt.Sprintf("❌ Error saving file: %v", err)
		_, _ = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{Content: msg})
		return
	}
	if err := tmpFile.Close(); err != nil {
		log.Printf("[WARN] closing temp file failed: %v", err)
	}

	// Run analysis in background so we don't block the handler
	go func(filename, path string, mitm bool) {
		opts := apkxmod.Options{
			InputPath: path,
			MITM:      mitm,
		}

		start := time.Now()
		res, err := apkxmod.Run(opts)

		title := "📱 apkX Analysis"
		desc := fmt.Sprintf("File: `%s`", filename)
		color := 0x00ff00
		status := "✅ Completed"
		fields := []*discordgo.MessageEmbedField{}

		if err != nil {
			color = 0xff0000
			status = "❌ Failed"
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "Error",
				Value: fmt.Sprintf("```%v```", err),
			})
		}

		if res != nil {
			fields = append(fields,
				&discordgo.MessageEmbedField{
					Name:  "Report Directory",
					Value: fmt.Sprintf("`%s`", res.ReportDir),
				},
				&discordgo.MessageEmbedField{
					Name:  "Duration",
					Value: res.Duration.String(),
				},
			)
		} else {
			fields = append(fields,
				&discordgo.MessageEmbedField{
					Name:  "Duration",
					Value: time.Since(start).String(),
				},
			)
		}

		embed := &discordgo.MessageEmbed{
			Title:       title,
			Description: desc,
			Color:       color,
			Fields: append([]*discordgo.MessageEmbedField{
				{Name: "Status", Value: status, Inline: false},
			}, fields...),
			Timestamp: time.Now().Format(time.RFC3339),
		}

		files := []*discordgo.File{}
		if res != nil && res.LogFile != "" {
			if f, err := os.Open(res.LogFile); err == nil {
				defer f.Close()
				files = append(files, &discordgo.File{
					Name:        filepath.Base(res.LogFile),
					ContentType: "text/plain",
					Reader:      f,
				})
			}
		}

		if len(files) > 0 {
			_, _ = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Embeds: []*discordgo.MessageEmbed{embed},
				Files:  files,
			})
		} else {
			_, _ = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Embeds: []*discordgo.MessageEmbed{embed},
			})
		}
	}(att.Filename, tmpFile.Name(), mitm)
}
