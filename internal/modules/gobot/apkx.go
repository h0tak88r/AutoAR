package gobot

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	apkxmod "github.com/h0tak88r/AutoAR/internal/modules/apkx"
)

// handleApkXScan handles the /apkx_scan command.
// It accepts an APK/IPA attachment, runs apkX via the internal module,
// and posts a summary + log file back to Discord.
func handleApkXScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()

	var (
		mitm       bool
		packageStr string
	)
	for _, opt := range data.Options {
		switch opt.Name {
		case "mitm":
			mitm = opt.BoolValue()
		case "package":
			packageStr = opt.StringValue()
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

	// If a package name was provided, prefer package-based scan (download + analyze).
	if strings.TrimSpace(packageStr) != "" {
		go handleApkXScanFromPackage(s, i, packageStr, mitm)
		return
	}

	// Otherwise fall back to attachment-based scan.
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
		msg := "❌ Provide either an APK/IPA attachment (`file`) or an Android package name (`package`)."
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
		// Ensure temp file is cleaned up after analysis
		defer os.Remove(path)
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
			errMsg := fmt.Sprintf("%v", err)
			// Format 2FA errors more nicely for Discord
			if strings.Contains(errMsg, "2FA code required") {
				errMsg = strings.ReplaceAll(errMsg, "\\n", "\n")
			}
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "Error",
				Value: fmt.Sprintf("```%s```", errMsg),
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

// handleApkXScanFromPackage performs the Android package-based workflow used by
// /apkx_scan when the "package" argument is supplied.
func handleApkXScanFromPackage(s *discordgo.Session, i *discordgo.InteractionCreate, pkg string, mitm bool) {
	start := time.Now()
	res, err := apkxmod.RunFromPackage(apkxmod.PackageOptions{
		Package:  pkg,
		Platform: "android",
		MITM:     mitm,
	})

	title := "📱 apkX Analysis (Android Package)"
	desc := fmt.Sprintf("Package: `%s`", pkg)
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
}

// handleApkXScanPackage handles /apkx_scan_package:
// it takes an Android package name, delegates the actual download to an
// external helper (configured via APKX_ANDROID_DOWNLOAD_CMD) and then runs
// the embedded apkX analysis.
func handleApkXScanPackage(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()

	var pkg string
	var mitm bool
	for _, opt := range data.Options {
		switch opt.Name {
		case "package":
			pkg = opt.StringValue()
		case "mitm":
			mitm = opt.BoolValue()
		}
	}

	if pkg == "" {
		respond(s, i, "❌ Package name is required", false)
		return
	}

	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("📱 Starting apkX analysis for Android package `%s`...", pkg),
		},
	}); err != nil {
		log.Printf("[ERROR] failed to respond to apkx_scan_package: %v", err)
		return
	}

	go func(packageName string, mitm bool) {
		start := time.Now()
		res, err := apkxmod.RunFromPackage(apkxmod.PackageOptions{
			Package:  packageName,
			Platform: "android",
			MITM:     mitm,
		})

		title := "📱 apkX Analysis (Android Package)"
		desc := fmt.Sprintf("Package: `%s`", packageName)
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
	}(pkg, mitm)
}

// handleApkXScanIOS handles /apkx_scan_ios for iOS bundle identifiers.
// As with Android, the actual download is delegated to an external helper
// configured via APKX_IOS_DOWNLOAD_CMD.
func handleApkXScanIOS(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()

	var bundle string
	for _, opt := range data.Options {
		if opt.Name == "bundle" {
			bundle = opt.StringValue()
		}
	}

	if bundle == "" {
		respond(s, i, "❌ iOS bundle identifier is required", false)
		return
	}

	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("📱 Starting apkX analysis for iOS bundle `%s`...", bundle),
		},
	}); err != nil {
		log.Printf("[ERROR] failed to respond to apkx_scan_ios: %v", err)
		return
	}

	go func(bundleID string) {
		start := time.Now()
		res, err := apkxmod.RunFromPackage(apkxmod.PackageOptions{
			Package:  bundleID,
			Platform: "ios",
		})

		title := "📱 apkX Analysis (iOS App)"
		desc := fmt.Sprintf("Bundle: `%s`", bundleID)
		color := 0x00ff00
		status := "✅ Completed"
		fields := []*discordgo.MessageEmbedField{}

		if err != nil {
			color = 0xff0000
			status = "❌ Failed"
			errMsg := fmt.Sprintf("%v", err)
			// Format 2FA errors more nicely for Discord
			if strings.Contains(errMsg, "2FA code required") {
				errMsg = strings.ReplaceAll(errMsg, "\\n", "\n")
			}
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "Error",
				Value: fmt.Sprintf("```%s```", errMsg),
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
	}(bundle)
}
