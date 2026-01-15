package gobot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	apkxmod "github.com/h0tak88r/AutoAR/v3/internal/modules/apkx"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/db"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
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
			log.Printf("[DEBUG] Parsed mitm option: %v", mitm)
		case "package":
			packageStr = opt.StringValue()
			log.Printf("[DEBUG] Parsed package option: %s", packageStr)
		}
	}
	log.Printf("[DEBUG] Final parsed values - mitm: %v, package: %q", mitm, packageStr)

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
		log.Printf("[DEBUG] Starting file-based apkX scan - file: %s, mitm: %v", filename, mitm)
		// Ensure temp file is cleaned up after analysis
		defer os.Remove(path)

		// Check APK cache
		apkHash, hashErr := db.HashAPKFile(path)
		if hashErr == nil {
			if entry, err := db.GetAPKCache(apkHash); err == nil {
				log.Printf("[CACHE] HIT: Using cached results for APK hash %s", apkHash[:16])
				
				// Create fields from cache
				var fields []*discordgo.MessageEmbedField
				if entry.HTMLReportURL != "" {
					fields = append(fields, &discordgo.MessageEmbedField{
						Name: "📄 HTML Report (R2)", Value: fmt.Sprintf("🔗 [View Report](%s)", entry.HTMLReportURL),
					})
				}
				if entry.JSONResultsURL != "" {
					fields = append(fields, &discordgo.MessageEmbedField{
						Name: "📋 JSON Results (R2)", Value: fmt.Sprintf("🔗 [Download](%s)", entry.JSONResultsURL),
					})
				}
				if entry.OriginalAPKURL != "" {
					fields = append(fields, &discordgo.MessageEmbedField{
						Name: "📱 Original APK (R2)", Value: fmt.Sprintf("🔗 [Download](%s)", entry.OriginalAPKURL),
					})
				}
				if entry.MITMPatchedURL != "" {
					fields = append(fields, &discordgo.MessageEmbedField{
						Name: "🔓 MITM Patched APK (R2)", Value: fmt.Sprintf("🔗 [Download](%s)", entry.MITMPatchedURL),
					})
				}
				
				// Add summary stats if available manually? No, we skip stats in cache mode for now to keep it simple, 
				// or we could cache stats too. For now just links.
				
				embed := &discordgo.MessageEmbed{
					Title:       "📱 apkX Analysis (Cached)",
					Description: fmt.Sprintf("File: `%s`\nAnalysis loaded from cache (no new scan performed).", filename),
					Color:       0x00ff00,
					Fields:      fields,
					Timestamp:   entry.CreatedAt.Format(time.RFC3339),
				}
				
				// Create findings table attachment from cached content
				var cachedFiles []*discordgo.File
				if entry.FindingsTable != "" {
					cachedFiles = append(cachedFiles, &discordgo.File{
						Name:        "findings-table.md",
						ContentType: "text/markdown",
						Reader:      strings.NewReader(entry.FindingsTable),
					})
				}
				
				msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
					Embeds: []*discordgo.MessageEmbed{embed},
					Files:  cachedFiles,
				})
				if err != nil {
					log.Printf("[ERROR] Failed to send cached result message: %v", err)
				} else if msg != nil {
					log.Printf("[DEBUG] Sent cached results (message ID: %s)", msg.ID)
				}
				return
			}
		}

		opts := apkxmod.Options{
			InputPath: path,
			MITM:      mitm,
		}

		start := time.Now()
		res, err := apkxmod.Run(opts)
		log.Printf("[DEBUG] apkX Run completed - error: %v, result MITMPatchedAPK: %q", err, func() string {
			if res == nil {
				return "res is nil"
			}
			return res.MITMPatchedAPK
		}())

		title := "📱 apkX Analysis"
		desc := fmt.Sprintf("File: `%s`", filename)
		color := 0x00ff00
		status := "[ + ]Completed"
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
		// Parse manifest info and summary stats
		manifestInfo := parseAPKManifestInfo(res.ReportDir)
		if manifestInfo != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📱 App Information",
				Value: manifestInfo,
				Inline: false,
			})
		}
		
		// Add summary stats (total findings and categories)
		if stats := parseAPKSummaryStats(res.LogFile); stats != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📊 Summary Stats",
				Value: stats,
				Inline: false,
			})
		}
		
		fields = append(fields,
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

	// Upload to R2 and add link fields
	var htmlURL, jsonURL, originalURL, mitmURL string
	if err == nil {
		htmlURL, jsonURL, originalURL, mitmURL = uploadFileBasedScanToR2(res, filename, path, mitm, &fields)
	}

	files := prepareAPKFiles(res, mitm, &fields)

	// Save to cache if successful
	if err == nil && apkHash != "" {
		// Read findings table content if exists
		var tableContent string
		tablePath := filepath.Join(res.ReportDir, "findings-table.md")
		if data, err := os.ReadFile(tablePath); err == nil {
			tableContent = string(data)
		}
		
		entry := &db.APKCacheEntry{
			Hash:           apkHash,
			Filename:       filename,
			FindingsTable:  tableContent,
			HTMLReportURL:  htmlURL,
			JSONResultsURL: jsonURL,
			OriginalAPKURL: originalURL,
			MITMPatchedURL: mitmURL,
			CreatedAt:      time.Now(),
		}
		if saveErr := db.SaveAPKCache(entry); saveErr != nil {
			log.Printf("[WARN] Failed to save APK to cache: %v", saveErr)
		}
	}

	// Create embed AFTER prepareAPKFiles so R2 links are included in fields
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: desc,
		Color:       color,
		Fields: append([]*discordgo.MessageEmbedField{
			{Name: "Status", Value: status, Inline: false},
		}, fields...),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	log.Printf("[DEBUG] Preparing to send Discord message with %d files", len(files))
	if len(files) > 0 {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
			Files:  files,
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message with files: %v", err)
			// Try sending to channel as fallback if interaction expired
			if i.ChannelID != "" {
				_, channelErr := s.ChannelMessageSendEmbed(i.ChannelID, embed)
				if channelErr != nil {
					log.Printf("[ERROR] Failed to send fallback channel message: %v", channelErr)
		} else {
					log.Printf("[INFO] Sent message to channel as fallback (interaction may have expired)")
				}
			}
		} else if msg != nil {
			log.Printf("[DEBUG] Successfully sent Discord message with files (message ID: %s)", msg.ID)
		} else {
			log.Printf("[WARN] FollowupMessageCreate returned nil message without error")
		}
	} else {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message: %v", err)
			// Try sending to channel as fallback if interaction expired
			if i.ChannelID != "" {
				_, channelErr := s.ChannelMessageSendEmbed(i.ChannelID, embed)
				if channelErr != nil {
					log.Printf("[ERROR] Failed to send fallback channel message: %v", channelErr)
		} else {
					log.Printf("[INFO] Sent message to channel as fallback (interaction may have expired)")
				}
			}
		} else if msg != nil {
			log.Printf("[DEBUG] Successfully sent Discord message (message ID: %s)", msg.ID)
		} else {
			log.Printf("[WARN] FollowupMessageCreate returned nil message without error")
		}
	}

	// Upload to R2 and cleanup local files after scan completes
	if err == nil && res != nil && res.ReportDir != "" {
		resultsDir := getResultsDir()
		apkPrefix := strings.TrimPrefix(res.ReportDir, resultsDir+"/")
		if apkPrefix == res.ReportDir {
			apkPrefix = "apkx/" + filepath.Base(res.ReportDir)
		}
		if err := cleanupResultsDirectory(apkPrefix, res.ReportDir); err != nil {
			log.Printf("[WARN] Failed to cleanup APK results directory: %v", err)
		}
	}
}(att.Filename, tmpFile.Name(), mitm)
}

// handleApkXScanFromPackage performs the Android package-based workflow used by
// /apkx_scan when the "package" argument is supplied.
func handleApkXScanFromPackage(s *discordgo.Session, i *discordgo.InteractionCreate, pkg string, mitm bool) {
	log.Printf("[DEBUG] handleApkXScanFromPackage called - package: %s, mitm: %v", pkg, mitm)
	start := time.Now()
	
	// RunFromPackage now checks cache automatically and returns cached results if version matches
	res, err := apkxmod.RunFromPackage(apkxmod.PackageOptions{
		Package:  pkg,
		Platform: "android",
		MITM:     mitm,
	})
	log.Printf("[DEBUG] RunFromPackage completed - error: %v, result MITMPatchedAPK: %q", err, func() string {
		if res == nil {
			return "res is nil"
		}
		return res.MITMPatchedAPK
	}())

	title := "📱 apkX Analysis (Android Package)"
	desc := fmt.Sprintf("Package: `%s`", pkg)
	color := 0x00ff00
	status := "[ + ]Completed"
	if res != nil && res.FromCache {
		status = "[ + ]Completed (Cached)"
		desc = fmt.Sprintf("Package: `%s`\n💾 **Using cached results**", pkg)
	}
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
		// Parse manifest info and summary stats
		manifestInfo := parseAPKManifestInfo(res.ReportDir)
		if manifestInfo != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📱 App Information",
				Value: manifestInfo,
				Inline: false,
			})
		}
		
		// Add summary stats (total findings and categories)
		if stats := parseAPKSummaryStats(res.LogFile); stats != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📊 Summary Stats",
				Value: stats,
				Inline: false,
			})
		}
		
		fields = append(fields,
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

	// Upload to R2 BEFORE creating Discord message to get URLs
	var r2URLs map[string]string
	var originalAPKURL, mitmAPKURL string
	if err == nil && res != nil && !res.FromCache && res.ReportDir != "" {
		// Extract package name from report dir for R2 prefix
		resultsDir := getResultsDir()
		apkPrefix := strings.TrimPrefix(res.ReportDir, resultsDir+"/")
		if apkPrefix == res.ReportDir {
			apkPrefix = "apkx/" + filepath.Base(res.ReportDir)
		}
		
		// Upload results directory to R2 (but don't remove local files yet)
		if r2storage.IsEnabled() && os.Getenv("USE_R2_STORAGE") == "true" {
			log.Printf("[INFO] Uploading results to R2 before Discord message: %s", res.ReportDir)
			var uploadErr error
			r2URLs, uploadErr = r2storage.UploadResultsDirectory(apkPrefix, res.ReportDir, false) // Don't remove local files yet
			if uploadErr != nil {
				log.Printf("[WARN] Failed to upload results to R2: %v", uploadErr)
			} else {
				log.Printf("[OK] Uploaded %d files to R2 for %s", len(r2URLs), apkPrefix)
			}
		}
		
		// Upload original APK if we have it
		if res.OriginalAPKPath != "" {
			if _, statErr := os.Stat(res.OriginalAPKPath); statErr == nil {
				if r2storage.IsEnabled() && os.Getenv("USE_R2_STORAGE") == "true" {
					uploadedURL, _, uploadErr := r2storage.UploadFileIfNotExists(res.OriginalAPKPath, filepath.Base(res.OriginalAPKPath))
					if uploadErr == nil {
						originalAPKURL = uploadedURL
						log.Printf("[DEBUG] Original APK uploaded to R2: %s", originalAPKURL)
					} else {
						log.Printf("[WARN] Failed to upload original APK to R2: %v", uploadErr)
					}
				}
			}
		}
	}
	
	// Upload MITM patched APK to R2 if it exists
	if mitm && res != nil && res.MITMPatchedAPK != "" {
		if _, statErr := os.Stat(res.MITMPatchedAPK); statErr == nil {
			if r2storage.IsEnabled() && os.Getenv("USE_R2_STORAGE") == "true" {
				publicURL, _, uploadErr := r2storage.UploadFileIfNotExists(res.MITMPatchedAPK, filepath.Base(res.MITMPatchedAPK))
				if uploadErr == nil {
					mitmAPKURL = publicURL
					log.Printf("[DEBUG] MITM patched APK uploaded to R2: %s", publicURL)
				} else {
					log.Printf("[WARN] Failed to upload MITM patched APK to R2: %v", uploadErr)
				}
			}
		}
	}
	
	// Prepare files and add R2 links to fields
	prepareAPKFilesWithR2Links(res, mitm, &fields, r2URLs, mitmAPKURL)
	
	// Add original APK link if available
	if originalAPKURL != "" && res != nil && res.OriginalAPKPath != "" {
		if stat, statErr := os.Stat(res.OriginalAPKPath); statErr == nil {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📱 Original APK",
				Value: fmt.Sprintf("`%s` (%.2f MB)\n🔗 [Download from R2](%s)", filepath.Base(res.OriginalAPKPath), float64(stat.Size())/1024/1024, originalAPKURL),
				Inline: false,
			})
		}
	}

	// Create embed AFTER prepareAPKFilesWithR2Links so R2 links are included in fields
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: desc,
		Color:       color,
		Fields: append([]*discordgo.MessageEmbedField{
			{Name: "Status", Value: status, Inline: false},
		}, fields...),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	// Send Discord message without file attachments (only links)
	msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to send Discord message: %v", err)
		// Try sending to channel as fallback if interaction expired
		if i.ChannelID != "" {
			_, channelErr := s.ChannelMessageSendEmbed(i.ChannelID, embed)
			if channelErr != nil {
				log.Printf("[ERROR] Failed to send fallback channel message: %v", channelErr)
			} else {
				log.Printf("[INFO] Sent message to channel as fallback (interaction may have expired)")
			}
		}
	} else if msg != nil {
		log.Printf("[DEBUG] Successfully sent Discord message (message ID: %s)", msg.ID)
	} else {
		log.Printf("[WARN] FollowupMessageCreate returned nil message without error - message may have been sent but response was nil")
	}

	// Cleanup local files after Discord message is sent (if not from cache)
	if err == nil && res != nil && !res.FromCache && res.ReportDir != "" {
		resultsDir := getResultsDir()
		apkPrefix := strings.TrimPrefix(res.ReportDir, resultsDir+"/")
		if apkPrefix == res.ReportDir {
			apkPrefix = "apkx/" + filepath.Base(res.ReportDir)
		}
		// Now remove local files since we've uploaded to R2 and sent Discord message
		if err := cleanupResultsDirectory(apkPrefix, res.ReportDir); err != nil {
			log.Printf("[WARN] Failed to cleanup APK results directory: %v", err)
		}
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
		log.Printf("[DEBUG] Starting apkX scan for package: %s, MITM: %v", packageName, mitm)
		start := time.Now()
		res, err := apkxmod.RunFromPackage(apkxmod.PackageOptions{
			Package:  packageName,
			Platform: "android",
			MITM:     mitm,
		})
		
		log.Printf("[DEBUG] apkX scan completed. Error: %v, Result: %+v", err, func() string {
			if res == nil {
				return "nil"
			}
			return fmt.Sprintf("ReportDir=%s, LogFile=%s, MITMPatchedAPK=%s", res.ReportDir, res.LogFile, res.MITMPatchedAPK)
		}())

		title := "📱 apkX Analysis (Android Package)"
		desc := fmt.Sprintf("Package: `%s`", packageName)
		color := 0x00ff00
		status := "[ + ]Completed"
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
		// Parse manifest info and summary stats
		manifestInfo := parseAPKManifestInfo(res.ReportDir)
		if manifestInfo != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📱 App Information",
				Value: manifestInfo,
				Inline: false,
			})
		}
		
		// Add summary stats (total findings and categories)
		if stats := parseAPKSummaryStats(res.LogFile); stats != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📊 Summary Stats",
				Value: stats,
				Inline: false,
			})
		}
		
		fields = append(fields,
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

	files := prepareAPKFiles(res, mitm, &fields)

	// Create embed AFTER prepareAPKFiles so R2 links are included in fields
	embed := &discordgo.MessageEmbed{
		Title:       title,
		Description: desc,
		Color:       color,
		Fields: append([]*discordgo.MessageEmbedField{
			{Name: "Status", Value: status, Inline: false},
		}, fields...),
		Timestamp: time.Now().Format(time.RFC3339),
	}

	log.Printf("[DEBUG] Preparing to send Discord message with %d files", len(files))
	if len(files) > 0 {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
			Files:  files,
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message with files: %v", err)
			// Try sending to channel as fallback if interaction expired
			if i.ChannelID != "" {
				_, channelErr := s.ChannelMessageSendEmbed(i.ChannelID, embed)
				if channelErr != nil {
					log.Printf("[ERROR] Failed to send fallback channel message: %v", channelErr)
		} else {
					log.Printf("[INFO] Sent message to channel as fallback (interaction may have expired)")
				}
			}
		} else if msg != nil {
			log.Printf("[DEBUG] Successfully sent Discord message with files (message ID: %s)", msg.ID)
		} else {
			log.Printf("[WARN] FollowupMessageCreate returned nil message without error - message may have been sent but response was nil")
		}
	} else {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message: %v", err)
			// Try sending to channel as fallback if interaction expired
			if i.ChannelID != "" {
				_, channelErr := s.ChannelMessageSendEmbed(i.ChannelID, embed)
				if channelErr != nil {
					log.Printf("[ERROR] Failed to send fallback channel message: %v", channelErr)
		} else {
					log.Printf("[INFO] Sent message to channel as fallback (interaction may have expired)")
				}
			}
		} else if msg != nil {
			log.Printf("[DEBUG] Successfully sent Discord message (message ID: %s)", msg.ID)
		} else {
			log.Printf("[WARN] FollowupMessageCreate returned nil message without error - message may have been sent but response was nil")
		}
	}

	// Upload to R2 and cleanup local files after scan completes (if not from cache)
	if err == nil && res != nil && !res.FromCache && res.ReportDir != "" {
		resultsDir := getResultsDir()
		apkPrefix := strings.TrimPrefix(res.ReportDir, resultsDir+"/")
		if apkPrefix == res.ReportDir {
			apkPrefix = "apkx/" + filepath.Base(res.ReportDir)
		}
		if err := cleanupResultsDirectory(apkPrefix, res.ReportDir); err != nil {
			log.Printf("[WARN] Failed to cleanup APK results directory: %v", err)
		}
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
		status := "[ + ]Completed"
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
		// Parse manifest info and summary stats
		manifestInfo := parseAPKManifestInfo(res.ReportDir)
		if manifestInfo != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📱 App Information",
				Value: manifestInfo,
				Inline: false,
			})
		}
		
		// Add summary stats (total findings and categories)
		if stats := parseAPKSummaryStats(res.LogFile); stats != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "📊 Summary Stats",
				Value: stats,
				Inline: false,
			})
		}
		
		fields = append(fields,
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

	// Note: MITM patching is typically only for Android APKs, not iOS IPAs
	// But we check anyway in case it's implemented in the future
	files := prepareAPKFiles(res, false, &fields)

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

	// Upload to R2 and cleanup local files after scan completes (if not from cache)
	if err == nil && res != nil && !res.FromCache && res.ReportDir != "" {
		resultsDir := getResultsDir()
		apkPrefix := strings.TrimPrefix(res.ReportDir, resultsDir+"/")
		if apkPrefix == res.ReportDir {
			apkPrefix = "apkx/" + filepath.Base(res.ReportDir)
		}
		if err := cleanupResultsDirectory(apkPrefix, res.ReportDir); err != nil {
			log.Printf("[WARN] Failed to cleanup iOS results directory: %v", err)
		}
	}
}(bundle)
}

// prepareAPKFilesWithR2Links adds R2 links to Discord embed fields instead of uploading files
func prepareAPKFilesWithR2Links(res *apkxmod.Result, mitm bool, fields *[]*discordgo.MessageEmbedField, r2URLs map[string]string, mitmAPKURL string) {
	if res == nil {
		return
	}
	
	// Add links for HTML report and JSON report from R2 URLs
	if r2URLs != nil && len(r2URLs) > 0 {
		var htmlURL, jsonURL string
		for localPath, url := range r2URLs {
			if strings.HasSuffix(localPath, "security-report.html") {
				htmlURL = url
			} else if strings.HasSuffix(localPath, "results.json") {
				jsonURL = url
			}
		}
		
		if htmlURL != "" {
			*fields = append(*fields, &discordgo.MessageEmbedField{
				Name:  "📄 HTML Report",
				Value: fmt.Sprintf("🔗 [View Report](%s)", htmlURL),
				Inline: false,
			})
		}
		
		if jsonURL != "" {
			*fields = append(*fields, &discordgo.MessageEmbedField{
				Name:  "📋 JSON Results",
				Value: fmt.Sprintf("🔗 [Download JSON](%s)", jsonURL),
				Inline: false,
			})
		}
	}
	
	// Add MITM patched APK link if available
	if mitm && mitmAPKURL != "" {
		if stat, statErr := os.Stat(res.MITMPatchedAPK); statErr == nil {
			*fields = append(*fields, &discordgo.MessageEmbedField{
				Name:  "🔒 MITM Patched APK",
				Value: fmt.Sprintf("`%s` (%.2f MB)\n🔗 [Download from R2](%s)", filepath.Base(res.MITMPatchedAPK), float64(stat.Size())/1024/1024, mitmAPKURL),
				Inline: false,
			})
		}
	}
}

// prepareAPKFiles prepares file attachments for Discord (table, JSON, and MITM patched APK)
// DEPRECATED: Use prepareAPKFilesWithR2Links instead to send links instead of files
func prepareAPKFiles(res *apkxmod.Result, mitm bool, fields *[]*discordgo.MessageEmbedField) []*discordgo.File {
	files := []*discordgo.File{}
	
	if res == nil {
		return files
	}
	
	// Generate and add table file if results exist
	if res.LogFile != "" {
		tablePath := filepath.Join(res.ReportDir, "findings-table.md")
		if err := generateAPKResultsTable(res.LogFile, tablePath); err == nil {
			if data, err := os.ReadFile(tablePath); err == nil {
				files = append(files, &discordgo.File{
					Name:        "findings-table.md",
					ContentType: "text/markdown",
					Reader:      bytes.NewReader(data),
				})
			}
		}
	}
	
	// JSON and MITM APK are now sent as R2 links only (no attachments)
	// This reduces Discord message size and makes messages cleaner
	
	return files
}

// parseAPKManifestInfo extracts package name, version, and minSdk from AndroidManifest.xml
func parseAPKManifestInfo(reportDir string) string {
	if reportDir == "" {
		return ""
	}
	
	// Look for AndroidManifest.xml in common decompilation output locations
	manifestPaths := []string{
		filepath.Join(reportDir, "AndroidManifest.xml"),
		filepath.Join(reportDir, "sources", "AndroidManifest.xml"),
		filepath.Join(reportDir, "resources", "AndroidManifest.xml"),
		filepath.Join(reportDir, "res", "AndroidManifest.xml"),
	}
	
	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}
	
	if manifestPath == "" {
		return ""
	}
	
	// Read the AndroidManifest.xml file
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return ""
	}
	
	manifestContent := string(content)
	var info strings.Builder
	
	// Extract package name
	packageRegex := regexp.MustCompile(`package\s*=\s*["']([^"']+)["']`)
	if matches := packageRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		info.WriteString(fmt.Sprintf("**Package:** `%s`\n", matches[1]))
	}
	
	// Extract version name
	versionRegex := regexp.MustCompile(`android:versionName\s*=\s*["']([^"']+)["']`)
	versionCodeRegex := regexp.MustCompile(`android:versionCode\s*=\s*["']([^"']+)["']`)
	var versionName, versionCode string
	if matches := versionRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		versionName = matches[1]
	}
	if matches := versionCodeRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		versionCode = matches[1]
	}
	if versionName != "" {
		if versionCode != "" {
			info.WriteString(fmt.Sprintf("**Version:** `%s` (code: %s)\n", versionName, versionCode))
		} else {
			info.WriteString(fmt.Sprintf("**Version:** `%s`\n", versionName))
		}
	} else if versionCode != "" {
		info.WriteString(fmt.Sprintf("**Version Code:** `%s`\n", versionCode))
	}
	
	// Extract minSdkVersion
	minSdkRegex := regexp.MustCompile(`android:minSdkVersion\s*=\s*["'](\d+)["']`)
	if matches := minSdkRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		info.WriteString(fmt.Sprintf("**Min SDK:** `%s`\n", matches[1]))
	} else {
		// Try alternative pattern without quotes
		minSdkRegex2 := regexp.MustCompile(`android:minSdkVersion\s*=\s*(\d+)`)
		if matches := minSdkRegex2.FindStringSubmatch(manifestContent); len(matches) > 1 {
			info.WriteString(fmt.Sprintf("**Min SDK:** `%s`\n", matches[1]))
		}
	}
	
	result := info.String()
	if result == "" {
		return ""
	}
	
	// Remove trailing newline
	result = strings.TrimSuffix(result, "\n")
	return result
}

// parseAPKSummaryStats extracts summary statistics from results.json
func parseAPKSummaryStats(jsonPath string) string {
	if jsonPath == "" {
		return ""
	}
	
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return ""
	}
	
	var results map[string][]string
	if err := json.Unmarshal(data, &results); err != nil {
		return ""
	}
	
	if len(results) == 0 {
		return "No findings detected."
	}
	
	// Count total findings
	totalFindings := 0
	for _, findings := range results {
		totalFindings += len(findings)
	}
	
	return fmt.Sprintf("**Total Findings:** %d\n**Categories:** %d", totalFindings, len(results))
}

// parseAPKResultsSummary parses the results.json file and creates a markdown table
// showing secret name, secret value, and file location
func parseAPKResultsSummary(jsonPath string) string {
	if jsonPath == "" {
		return ""
	}
	
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		log.Printf("[WARN] Failed to read results.json: %v", err)
		return ""
	}
	
	var results map[string][]string
	if err := json.Unmarshal(data, &results); err != nil {
		log.Printf("[WARN] Failed to parse results.json: %v", err)
		return ""
	}
	
	if len(results) == 0 {
		return "No secrets found."
	}
	
	// Count total findings
	totalFindings := 0
	for _, findings := range results {
		totalFindings += len(findings)
	}
	
	// Build summary with total count
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("**Total: %d findings in %d categories**\n\n", totalFindings, len(results)))
	
	// Discord embed field value limit is 1024 characters, so we'll show a summary
	// The full table will be sent as a file attachment
	maxDisplay := 10
	displayedFindings := 0
	
	// Display findings by category (limited for embed)
	for category, findings := range results {
		if len(findings) == 0 || displayedFindings >= maxDisplay {
			continue
		}
		
		// Show first finding from each category
		for _, finding := range findings {
			if displayedFindings >= maxDisplay {
				break
			}
			
			// Parse finding: "file: match (Context: ...)" or "file:line: match (Context: ...)"
			var file, match string
			
			firstColonSpace := strings.Index(finding, ": ")
			if firstColonSpace == -1 {
				continue
			}
			
			file = finding[:firstColonSpace]
			rest := finding[firstColonSpace+2:]
			
			// Check if there's a line number (file:line: match)
			if strings.Contains(file, ":") {
				fileParts := strings.SplitN(file, ":", 2)
				if len(fileParts) == 2 {
					file = fileParts[0]
				}
			}
			
			// Extract match (secret value)
			if ctxIdx := strings.Index(rest, " (Context: "); ctxIdx != -1 {
				match = strings.TrimSpace(rest[:ctxIdx])
			} else {
				match = strings.TrimSpace(rest)
			}
			
			// Truncate for embed display
			if len(match) > 50 {
				match = match[:47] + "..."
			}
			
			fileName := filepath.Base(file)
			if len(fileName) > 30 {
				fileName = fileName[:27] + "..."
			}
			
			summary.WriteString(fmt.Sprintf("• **%s** | `%s` | `%s`\n", category, match, fileName))
			displayedFindings++
			break // Only show first from each category in embed
		}
	}
	
	if totalFindings > maxDisplay {
		summary.WriteString(fmt.Sprintf("\n*Showing first %d findings. See table file for complete details.*", maxDisplay))
	}
	
	result := summary.String()
	if len(result) > 1024 {
		result = result[:1021] + "..."
	}
	
	return result
}

// generateAPKResultsTable creates a markdown table file with all findings
func generateAPKResultsTable(jsonPath, outputPath string) error {
	if jsonPath == "" {
		return fmt.Errorf("json path is empty")
	}
	
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to read results.json: %w", err)
	}
	
	var results map[string][]string
	if err := json.Unmarshal(data, &results); err != nil {
		return fmt.Errorf("failed to parse results.json: %w", err)
	}
	
	if len(results) == 0 {
		return fmt.Errorf("no results to generate table")
	}
	
	// Create markdown table
	var table strings.Builder
	table.WriteString("# APK Analysis Results\n\n")
	table.WriteString("| Secret Name | Secret Value | File |\n")
	table.WriteString("|-------------|-------------|------|\n")
	
	// Process all findings
	for category, findings := range results {
		for _, finding := range findings {
			// Parse finding: "file: match (Context: ...)" or "file:line: match"
			var file, match string
			
			firstColonSpace := strings.Index(finding, ": ")
			if firstColonSpace == -1 {
				continue
			}
			
			file = finding[:firstColonSpace]
			rest := finding[firstColonSpace+2:]
			
			// Check if there's a line number
			if strings.Contains(file, ":") {
				fileParts := strings.SplitN(file, ":", 2)
				if len(fileParts) == 2 {
					file = fileParts[0]
				}
			}
			
			// Extract match (secret value)
			if ctxIdx := strings.Index(rest, " (Context: "); ctxIdx != -1 {
				match = strings.TrimSpace(rest[:ctxIdx])
			} else {
				match = strings.TrimSpace(rest)
			}
			
			// Escape pipe characters in markdown table
			categoryEscaped := strings.ReplaceAll(category, "|", "\\|")
			matchEscaped := strings.ReplaceAll(match, "|", "\\|")
			fileEscaped := strings.ReplaceAll(file, "|", "\\|")
			
			// Truncate very long values to keep table readable
			if len(matchEscaped) > 200 {
				matchEscaped = matchEscaped[:197] + "..."
			}
			if len(fileEscaped) > 150 {
				fileEscaped = fileEscaped[:147] + "..."
			}
			
			table.WriteString(fmt.Sprintf("| %s | `%s` | `%s` |\n", categoryEscaped, matchEscaped, fileEscaped))
		}
	}
	
	// Write table to file
	if err := os.WriteFile(outputPath, []byte(table.String()), 0644); err != nil {
		return fmt.Errorf("failed to write table file: %w", err)
	}
	
	return nil
}
