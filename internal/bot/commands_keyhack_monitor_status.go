package bot

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/api"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// KeyHack Commands
func handleKeyhack(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	action := ""
	query := ""

	for _, opt := range options {
		switch opt.Name {
		case "action":
			action = opt.StringValue()
		case "query":
			query = opt.StringValue()
		}
	}

	if action == "" {
		respond(s, i, "❌ Action is required", false)
		return
	}

	switch action {
	case "list":
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		})

		command := []string{utils.GetAutoarScriptPath(), "keyhack", "list"}

		output, stderr, err := runCommandSync(command)

		embed := &discordgo.MessageEmbed{
			Title:       "📋 KeyHack Templates List",
			Description: "All available API key validation templates",
			Color:       0x3498db,
		}

		if err != nil {
			embed.Title = "❌ KeyHack List Failed"
			embed.Color = 0xff0000
			errorMsg := stderr
			if errorMsg == "" {
				errorMsg = "Failed to list templates"
			}
			if len(errorMsg) > 1000 {
				errorMsg = errorMsg[:1000] + "..."
			}
			embed.Fields = []*discordgo.MessageEmbedField{
				{Name: "Error", Value: fmt.Sprintf("```\n%s\n```", errorMsg), Inline: false},
			}
		} else {
			// Parse output to count templates and show first few examples
			lines := strings.Split(output, "\n")
			templateCount := 0
			var examples []string

			for _, line := range lines {
				if strings.HasPrefix(line, "Provider: ") {
					templateCount++
					if len(examples) < 5 {
						provider := strings.TrimPrefix(line, "Provider: ")
						examples = append(examples, fmt.Sprintf("• **%s**", provider))
					}
				}
			}

			description := fmt.Sprintf("**Total Templates:** `%d`\n\n", templateCount)
			if len(examples) > 0 {
				description += "**Sample Providers:**\n" + strings.Join(examples, "\n")
				if templateCount > 5 {
					description += fmt.Sprintf("\n\n*Showing first 5 of %d templates. Use `/keyhack search` to find specific providers.*", templateCount)
				}
			} else {
				description += "*No templates found.*"
			}

			embed.Description = description
			embed.Fields = []*discordgo.MessageEmbedField{
				{
					Name:   "💡 Tip",
					Value:  "Use `/keyhack search <provider>` to get detailed information about a specific provider.",
					Inline: false,
				},
			}
		}

		if err := UpdateInteractionMessage(s, i, "", embed); err != nil {
			log.Printf("[WARN] Failed to update interaction: %v", err)
		}

	case "search":
		if query == "" {
			respond(s, i, "❌ Search query is required for search action", false)
			return
		}

		command := []string{utils.GetAutoarScriptPath(), "keyhack", "search", query}

		output, stderr, err := runCommandSync(command)

		// Check if output indicates "not found" before deferring response
		if err == nil && (strings.Contains(output, "No matching KeyHack templates found") || strings.TrimSpace(output) == "") {
			respond(s, i, fmt.Sprintf("❌ **No KeyHack templates found** for query: `%s`", query), false)
			return
		}

		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		})

		if err != nil {
			embed := &discordgo.MessageEmbed{
				Title:       "❌ KeyHack Search Failed",
				Description: fmt.Sprintf("**Query:** `%s`", query),
				Color:       0xff0000,
			}
			errorMsg := stderr
			if errorMsg == "" {
				errorMsg = "Search failed"
			}
			if len(errorMsg) > 1000 {
				errorMsg = errorMsg[:1000] + "..."
			}
			embed.Fields = []*discordgo.MessageEmbedField{
				{Name: "Error", Value: fmt.Sprintf("```\n%s\n```", errorMsg), Inline: false},
			}
			s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
				Embeds: &[]*discordgo.MessageEmbed{embed},
			})
			return
		}

		// Parse the output to extract template information
		// Format: Provider: <name>\nDescription: <desc>\nMethod: <method>\nCommand:\n<command>\n\n
		lines := strings.Split(output, "\n")
		var templates []map[string]string
		currentTemplate := make(map[string]string)
		currentCommand := ""
		inCommand := false

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				if len(currentTemplate) > 0 {
					if currentCommand != "" {
						currentTemplate["command"] = strings.TrimSpace(currentCommand)
					}
					templates = append(templates, currentTemplate)
					currentTemplate = make(map[string]string)
					currentCommand = ""
					inCommand = false
				}
				continue
			}

			if strings.HasPrefix(line, "Provider: ") {
				if len(currentTemplate) > 0 {
					if currentCommand != "" {
						currentTemplate["command"] = strings.TrimSpace(currentCommand)
					}
					templates = append(templates, currentTemplate)
				}
				currentTemplate = make(map[string]string)
				currentTemplate["provider"] = strings.TrimPrefix(line, "Provider: ")
				currentCommand = ""
				inCommand = false
			} else if strings.HasPrefix(line, "Description: ") {
				currentTemplate["description"] = strings.TrimPrefix(line, "Description: ")
				inCommand = false
			} else if strings.HasPrefix(line, "Method: ") {
				currentTemplate["method"] = strings.TrimPrefix(line, "Method: ")
				inCommand = false
			} else if strings.HasPrefix(line, "Command:") {
				inCommand = true
				currentCommand = ""
			} else if strings.HasPrefix(line, "Notes: ") {
				currentTemplate["notes"] = strings.TrimPrefix(line, "Notes: ")
				inCommand = false
			} else if inCommand {
				currentCommand += line + "\n"
			}
		}

		// Add last template if exists
		if len(currentTemplate) > 0 {
			if currentCommand != "" {
				currentTemplate["command"] = strings.TrimSpace(currentCommand)
			}
			templates = append(templates, currentTemplate)
		}

		// Create beautiful embeds for each template (Discord allows up to 10 embeds per message)
		maxEmbeds := 10
		if len(templates) > maxEmbeds {
			templates = templates[:maxEmbeds]
		}

		var embeds []*discordgo.MessageEmbed
		for idx, t := range templates {
			provider := t["provider"]
			if provider == "" {
				continue
			}

			description := t["description"]
			if description == "" {
				description = "*No description available*"
			}

			method := t["method"]
			if method == "" {
				method = "GET"
			}

			command := t["command"]
			if command == "" {
				command = "*No command template available*"
			}

			// Truncate command if too long
			if len(command) > 1000 {
				command = command[:1000] + "\n... (truncated)"
			}

			embed := &discordgo.MessageEmbed{
				Title:       fmt.Sprintf("🔑 %s", provider),
				Description: description,
				Color:       0x3498db,
				Fields: []*discordgo.MessageEmbedField{
					{
						Name:   "📋 Method",
						Value:  fmt.Sprintf("`%s`", method),
						Inline: true,
					},
					{
						Name:   "💻 Command",
						Value:  fmt.Sprintf("```bash\n%s\n```", command),
						Inline: false,
					},
				},
				Footer: &discordgo.MessageEmbedFooter{
					Text: fmt.Sprintf("Template %d of %d", idx+1, len(templates)),
				},
				Timestamp: time.Now().Format(time.RFC3339),
			}

			if notes := t["notes"]; notes != "" {
				if len(notes) > 500 {
					notes = notes[:500] + "..."
				}
				embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
					Name:   "📝 Notes",
					Value:  notes,
					Inline: false,
				})
			}

			embeds = append(embeds, embed)
		}

		if len(embeds) == 0 {
			// Fallback if parsing failed
			if len(output) > 1900 {
				output = output[:1900] + "\n... (truncated)"
			}
			embeds = []*discordgo.MessageEmbed{{
				Title:       "🔍 KeyHack Search Results",
				Description: fmt.Sprintf("**Query:** `%s`", query),
				Color:       0x3498db,
				Fields: []*discordgo.MessageEmbedField{
					{Name: "Results", Value: fmt.Sprintf("```\n%s\n```", output), Inline: false},
				},
			}}
		}

		s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
			Embeds: &embeds,
		})

	default:
		respond(s, i, fmt.Sprintf("❌ Unknown action: %s", action), false)
		return
	}
}

// Monitoring Commands
func handleMonitorUpdatesManage(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	action := ""
	var id *int
	var url *string
	strategy := "hash"
	pattern := ""
	interval := 86400
	all := false

	for _, opt := range options {
		switch opt.Name {
		case "action":
			action = opt.StringValue()
		case "id":
			val := int(opt.IntValue())
			id = &val
		case "url":
			val := opt.StringValue()
			url = &val
		case "strategy":
			strategy = opt.StringValue()
		case "pattern":
			pattern = opt.StringValue()
		case "interval":
			interval = int(opt.IntValue())
		case "all":
			all = opt.BoolValue()
		}
	}

	if action == "" {
		respond(s, i, "❌ Action is required", false)
		return
	}

	var cmd []string
	var targetDesc string
	var title string
	color := 0x00ff00

	switch action {
	case "add":
		if url == nil || *url == "" {
			respond(s, i, "❌ URL is required for add action", false)
			return
		}
		if strategy == "regex" && pattern == "" {
			pattern = `([A-Z][a-z]{2,9} [0-9]{1,2}, [0-9]{4}|[0-9]{4}-[0-9]{2}-[0-9]{2})`
		}
		cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "add", "-u", *url, "--strategy", strategy}
		if pattern != "" {
			cmd = append(cmd, "--pattern", pattern)
		}
		targetDesc = *url
		title = "[ + ]Target Added"

	case "remove":
		if id != nil && *id > 0 {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "remove", "--id", strconv.Itoa(*id)}
			targetDesc = fmt.Sprintf("ID %d", *id)
		} else if url != nil && *url != "" {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "remove", "-u", *url}
			targetDesc = *url
		} else {
			respond(s, i, "❌ ID or URL is required for remove action", false)
			return
		}
		title = "🗑️ Target Removed"

	case "start":
		if id != nil && *id > 0 {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "start", "--id", strconv.Itoa(*id), "--interval", fmt.Sprintf("%d", interval)}
			targetDesc = fmt.Sprintf("ID %d", *id)
		} else if all {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "start", "--all", "--interval", fmt.Sprintf("%d", interval)}
			targetDesc = "all targets"
		} else if url != nil && *url != "" {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "start", "-u", *url, "--interval", fmt.Sprintf("%d", interval)}
			targetDesc = *url
		} else {
			respond(s, i, "❌ ID, URL, or 'all' is required for start action", false)
			return
		}
		title = "📡 Monitor Started"

	case "stop":
		if id != nil && *id > 0 {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "stop", "--id", strconv.Itoa(*id)}
			targetDesc = fmt.Sprintf("ID %d", *id)
		} else if all {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "stop", "--all"}
			targetDesc = "all targets"
		} else if url != nil && *url != "" {
			cmd = []string{utils.GetAutoarScriptPath(), "monitor", "updates", "stop", "-u", *url}
			targetDesc = *url
		} else {
			respond(s, i, "❌ ID, URL, or 'all' is required for stop action", false)
			return
		}
		title = "🛑 Monitor Stopped"

	default:
		respond(s, i, fmt.Sprintf("❌ Unknown action: %s", action), false)
		return
	}

	embed := createScanEmbed(title, targetDesc, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	output, stderr, err := runCommandSync(cmd)
	if err != nil {
		color = 0xff0000
	}

	desc := fmt.Sprintf("**Action:** %s\n**Target:** %s", action, targetDesc)
	if action == "add" && pattern != "" {
		desc += fmt.Sprintf("\n**Pattern:** %s", pattern)
	}
	if action == "start" {
		desc += fmt.Sprintf("\n**Interval:** %ds (%dh)", interval, interval/3600)
	}

	embed = &discordgo.MessageEmbed{
		Title:       title,
		Description: desc,
		Color:       color,
	}

	if output != "" {
		outputDisplay := output
		if len(outputDisplay) > 1000 {
			outputDisplay = outputDisplay[:1000]
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Output",
			Value: fmt.Sprintf("```%s```", outputDisplay),
		})
	}

	if stderr != "" && err != nil {
		stderrDisplay := stderr
		if len(stderrDisplay) > 1000 {
			stderrDisplay = stderrDisplay[:1000]
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Error",
			Value: fmt.Sprintf("```%s```", stderrDisplay),
		})
	}

	if err := UpdateInteractionMessage(s, i, "", embed); err != nil {
		log.Printf("[WARN] Failed to update interaction: %v", err)
	}
}

// Scan Status - List all scans
func handleScanStatus(s *discordgo.Session, i *discordgo.InteractionCreate) {
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	// Get active scans from database (non-blocking!)
	activeScans, err := db.ListActiveScans()
	if err != nil {
		log.Printf("[ERROR] Failed to list active scans: %v", err)
		respond(s, i, fmt.Sprintf("❌ Error fetching scans: %v", err), false)
		return
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📊 Scan Status",
		Description: fmt.Sprintf("**Active Scans:** %d", len(activeScans)),
		Color:       0x3498db,
		Fields:      []*discordgo.MessageEmbedField{},
	}

	// Add active scans
	if len(activeScans) > 0 {
		activeText := ""
		for idx, scan := range activeScans {
			if idx >= 10 {
				activeText += fmt.Sprintf("\n... and %d more active scans", len(activeScans)-10)
				break
			}
			statusEmoji := "🟡"
			switch scan.Status {
			case "completed":
				statusEmoji = "✅"
			case "failed":
				statusEmoji = "❌"
			case "cancelled", "cancelling":
				statusEmoji = "⏹️"
			}

			// Calculate elapsed time
			elapsed := time.Since(scan.StartedAt)
			elapsedStr := formatDuration(elapsed)

			// Show progress if available
			progressStr := ""
			if scan.TotalPhases > 0 {
				percentage := float64(scan.CurrentPhase) / float64(scan.TotalPhases) * 100
				progressStr = fmt.Sprintf("\n**Progress:** Phase %d/%d (%.1f%%)", scan.CurrentPhase, scan.TotalPhases, percentage)
				if scan.PhaseName != "" {
					progressStr += fmt.Sprintf(" - %s", scan.PhaseName)
				}
			}

			// Show statistics
			statsStr := ""
			if scan.FilesUploaded > 0 || scan.ErrorCount > 0 {
				statsStr = fmt.Sprintf("\n**Stats:** %d files uploaded", scan.FilesUploaded)
				if scan.ErrorCount > 0 {
					statsStr += fmt.Sprintf(", %d errors", scan.ErrorCount)
				}
			}

			activeText += fmt.Sprintf("%s **%s** - `%s`\n**Status:** %s\n**Scan ID:** `%s`\n**Elapsed:** %s%s%s\n\n",
				statusEmoji, scan.ScanType, scan.Target, scan.Status, scan.ScanID, elapsedStr, progressStr, statsStr)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  fmt.Sprintf("Active Scans (%d)", len(activeScans)),
			Value: activeText,
		})
	} else {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Active Scans",
			Value: "✅ No active scans",
		})
	}

	// Use InteractionResponseEdit to update the deferred response
	_, err = s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
	if err != nil {
		log.Printf("[ERROR] Failed to update scan status interaction: %v", err)
		// Try follow-up as fallback
		_, err = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
		if err != nil {
			log.Printf("[ERROR] Failed to send scan status follow-up: %v", err)
		}
	}
}

// formatDuration formats a duration in human-readable format
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	} else if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	} else {
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// Cancel Scan - Cancel a running scan
func handleCancelScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var scanID string
	var target string
	var scanType string

	for _, opt := range options {
		switch opt.Name {
		case "scan_id":
			scanID = opt.StringValue()
		case "target":
			target = opt.StringValue()
		case "scan_type":
			scanType = opt.StringValue()
		}
	}

	// If scan_id is provided, use it directly
	if scanID != "" {
		api.ScansMutex.Lock()
		scan, ok := api.ActiveScans[scanID]
		if !ok {
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan with ID `%s` not found or already completed", scanID), false)
			return
		}
		if scan.Status != "running" && scan.Status != "starting" && scan.Status != "paused" {
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan `%s` is not running (status: %s)", scanID, scan.Status), false)
			return
		}
		scan.CancelRequested = true
		if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
			_ = scan.ExecCmd.Process.Kill()
			scan.Status = "cancelling"
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Stopping API scan `%s`…", scanID), false)
			return
		}
		if scan.CancelFunc == nil {
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan `%s` cannot be cancelled (no cancel support)", scanID), false)
			return
		}
		// Cancel the scan (Discord / CommandContext)
		scan.CancelFunc()
		scan.Status = "cancelling"
		api.ScansMutex.Unlock()

		st := scan.ScanType
		if st == "" {
			st = scan.Type
		}
		respond(s, i, fmt.Sprintf("Cancelling scan `%s` (%s on `%s`)", scanID, st, scan.Target), false)
		return
	}

	// If target and scan_type are provided, find matching scan
	if target != "" && scanType != "" {
		api.ScansMutex.Lock()
		var foundScan *api.ScanInfo
		var foundScanID string
		for id, scan := range api.ActiveScans {
			st := scan.ScanType
			if st == "" {
				st = scan.Type
			}
			active := scan.Status == "running" || scan.Status == "starting" || scan.Status == "paused"
			if scan.Target == target && st == scanType && active {
				foundScan = scan
				foundScanID = id
				break
			}
		}
		if foundScan == nil {
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("No running scan found for type `%s` on target `%s`", scanType, target), false)
			return
		}
		foundScan.CancelRequested = true
		if foundScan.ExecCmd != nil && foundScan.ExecCmd.Process != nil {
			_ = foundScan.ExecCmd.Process.Kill()
			foundScan.Status = "cancelling"
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Stopping API scan `%s`…", foundScanID), false)
			return
		}
		if foundScan.CancelFunc == nil {
			api.ScansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan `%s` cannot be cancelled (no cancel support)", foundScanID), false)
			return
		}
		foundScan.CancelFunc()
		foundScan.Status = "cancelling"
		api.ScansMutex.Unlock()

		respond(s, i, fmt.Sprintf("Cancelling scan `%s` (%s on `%s`)", foundScanID, foundScan.Type, foundScan.Target), false)
		return
	}

	// If only target is provided, list all running scans for that target
	if target != "" {
		api.ScansMutex.RLock()
		var matchingScans []*api.ScanInfo
		for _, scan := range api.ActiveScans {
			if scan.Target == target && scan.Status == "running" {
				matchingScans = append(matchingScans, scan)
			}
		}
		api.ScansMutex.RUnlock()

		if len(matchingScans) == 0 {
			respond(s, i, fmt.Sprintf("No running scans found for target `%s`", target), false)
			return
		}

		// List all matching scans
		scanList := ""
		for i, scan := range matchingScans {
			if i >= 10 {
				scanList += fmt.Sprintf("\n... and %d more scans", len(matchingScans)-10)
				break
			}
			scanList += fmt.Sprintf("- `%s` (%s) - %s\n", scan.ScanID, scan.Type, scan.Status)
		}
		respond(s, i, fmt.Sprintf("Found %d running scan(s) for target `%s`:\n%s\nUse `/cancel_scan scan_id:<scan_id>` to cancel a specific scan", len(matchingScans), target, scanList), false)
		return
	}

	// No parameters provided
	respond(s, i, "Please provide either `scan_id` or both `target` and `scan_type` to cancel a scan. Use `/scan_status` to see active scans.", false)
}
