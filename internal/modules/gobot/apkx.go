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
		// Parse and add secrets summary
		if summary := parseAPKResultsSummary(res.LogFile); summary != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "🔍 Secrets Summary",
				Value: summary,
				Inline: false,
			})
		}
		
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

	files := prepareAPKFiles(res, mitm, &fields)

	log.Printf("[DEBUG] Preparing to send Discord message with %d files", len(files))
	if len(files) > 0 {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
			Files:  files,
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message with files: %v", err)
		} else {
			log.Printf("[DEBUG] Successfully sent Discord message with files (message ID: %s)", msg.ID)
		}
	} else {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message: %v", err)
		} else {
			log.Printf("[DEBUG] Successfully sent Discord message (message ID: %s)", msg.ID)
		}
	}
}(att.Filename, tmpFile.Name(), mitm)
}

// handleApkXScanFromPackage performs the Android package-based workflow used by
// /apkx_scan when the "package" argument is supplied.
func handleApkXScanFromPackage(s *discordgo.Session, i *discordgo.InteractionCreate, pkg string, mitm bool) {
	log.Printf("[DEBUG] handleApkXScanFromPackage called - package: %s, mitm: %v", pkg, mitm)
	start := time.Now()
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
		// Parse and add secrets summary
		if summary := parseAPKResultsSummary(res.LogFile); summary != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "🔍 Secrets Summary",
				Value: summary,
				Inline: false,
			})
		}
		
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

	files := prepareAPKFiles(res, mitm, &fields)

	log.Printf("[DEBUG] Preparing to send Discord message with %d files", len(files))
	if len(files) > 0 {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
			Files:  files,
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message with files: %v", err)
		} else {
			log.Printf("[DEBUG] Successfully sent Discord message with files (message ID: %s)", msg.ID)
		}
	} else {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message: %v", err)
		} else {
			log.Printf("[DEBUG] Successfully sent Discord message (message ID: %s)", msg.ID)
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
		// Parse and add secrets summary
		if summary := parseAPKResultsSummary(res.LogFile); summary != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "🔍 Secrets Summary",
				Value: summary,
				Inline: false,
			})
		}
		
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

	files := prepareAPKFiles(res, mitm, &fields)

	log.Printf("[DEBUG] Preparing to send Discord message with %d files", len(files))
	if len(files) > 0 {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
			Files:  files,
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message with files: %v", err)
		} else {
			log.Printf("[DEBUG] Successfully sent Discord message with files (message ID: %s)", msg.ID)
		}
	} else {
		msg, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send Discord message: %v", err)
		} else {
			log.Printf("[DEBUG] Successfully sent Discord message (message ID: %s)", msg.ID)
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
		// Parse and add secrets summary
		if summary := parseAPKResultsSummary(res.LogFile); summary != "" {
			fields = append(fields, &discordgo.MessageEmbedField{
				Name:  "🔍 Secrets Summary",
				Value: summary,
				Inline: false,
			})
		}
		
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
	}(bundle)
}

// prepareAPKFiles prepares file attachments for Discord (table, JSON, and MITM patched APK)
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
		
		// Also include results.json
		if data, err := os.ReadFile(res.LogFile); err == nil {
			files = append(files, &discordgo.File{
				Name:        filepath.Base(res.LogFile),
				ContentType: "application/json",
				Reader:      bytes.NewReader(data),
			})
		}
	}
	
	// Add MITM patched APK if it exists
	log.Printf("[DEBUG] Checking MITM patched APK - mitm flag: %v, res.MITMPatchedAPK: %q", mitm, func() string {
		if res == nil {
			return "res is nil"
		}
		return res.MITMPatchedAPK
	}())
	
	if mitm {
		log.Printf("[DEBUG] MITM flag is true, checking for patched APK...")
		if res != nil && res.MITMPatchedAPK != "" {
			log.Printf("[DEBUG] MITM patched APK path found: %s", res.MITMPatchedAPK)
			// Verify file exists before trying to send
			if stat, statErr := os.Stat(res.MITMPatchedAPK); statErr == nil {
				log.Printf("[DEBUG] MITM patched APK file exists, size: %d bytes", stat.Size())
				// Read file into memory to avoid closing issues
				if data, err := os.ReadFile(res.MITMPatchedAPK); err == nil {
					files = append(files, &discordgo.File{
						Name:        filepath.Base(res.MITMPatchedAPK),
						ContentType: "application/vnd.android.package-archive",
						Reader:      bytes.NewReader(data),
					})
					*fields = append(*fields, &discordgo.MessageEmbedField{
						Name:  "🔒 MITM Patched APK",
						Value: fmt.Sprintf("`%s` (%.2f MB)", filepath.Base(res.MITMPatchedAPK), float64(stat.Size())/1024/1024),
					})
					log.Printf("[DEBUG] Successfully added MITM patched APK to Discord files")
				} else {
					log.Printf("[ERROR] Failed to read MITM patched APK file: %v", err)
				}
			} else {
				log.Printf("[ERROR] MITM patched APK file not found: %s (stat error: %v)", res.MITMPatchedAPK, statErr)
			}
		} else {
			log.Printf("[WARN] MITM flag is true but res.MITMPatchedAPK is empty (res is nil: %v)", res == nil)
		}
	} else {
		log.Printf("[DEBUG] MITM flag is false, skipping MITM patched APK")
	}
	
	return files
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
