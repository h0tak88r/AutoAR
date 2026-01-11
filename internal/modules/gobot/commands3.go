package gobot

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
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

	command := []string{autoarScript, "keyhack", "list"}

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

	command := []string{autoarScript, "keyhack", "search", query}

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
		cmd = []string{autoarScript, "monitor", "updates", "add", "-u", *url, "--strategy", strategy}
		if pattern != "" {
			cmd = append(cmd, "--pattern", pattern)
		}
		targetDesc = *url
		title = "[ + ]Target Added"

	case "remove":
		if id != nil && *id > 0 {
			cmd = []string{autoarScript, "monitor", "updates", "remove", "--id", strconv.Itoa(*id)}
			targetDesc = fmt.Sprintf("ID %d", *id)
		} else if url != nil && *url != "" {
			cmd = []string{autoarScript, "monitor", "updates", "remove", "-u", *url}
			targetDesc = *url
		} else {
			respond(s, i, "❌ ID or URL is required for remove action", false)
			return
		}
		title = "🗑️ Target Removed"

	case "start":
		if id != nil && *id > 0 {
			cmd = []string{autoarScript, "monitor", "updates", "start", "--id", strconv.Itoa(*id), "--interval", fmt.Sprintf("%d", interval)}
			targetDesc = fmt.Sprintf("ID %d", *id)
		} else if all {
			cmd = []string{autoarScript, "monitor", "updates", "start", "--all", "--interval", fmt.Sprintf("%d", interval)}
			targetDesc = "all targets"
		} else if url != nil && *url != "" {
			cmd = []string{autoarScript, "monitor", "updates", "start", "-u", *url, "--interval", fmt.Sprintf("%d", interval)}
			targetDesc = *url
		} else {
			respond(s, i, "❌ ID, URL, or 'all' is required for start action", false)
			return
		}
		title = "📡 Monitor Started"

	case "stop":
		if id != nil && *id > 0 {
			cmd = []string{autoarScript, "monitor", "updates", "stop", "--id", strconv.Itoa(*id)}
			targetDesc = fmt.Sprintf("ID %d", *id)
		} else if all {
			cmd = []string{autoarScript, "monitor", "updates", "stop", "--all"}
			targetDesc = "all targets"
		} else if url != nil && *url != "" {
			cmd = []string{autoarScript, "monitor", "updates", "stop", "-u", *url}
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

// Old handlers - kept for reference but not used
func handleMonitorUpdatesAdd_OLD(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	url := ""
	strategy := "hash"
	pattern := ""

	for _, opt := range options {
		switch opt.Name {
		case "url":
			url = opt.StringValue()
		case "strategy":
			strategy = opt.StringValue()
		case "pattern":
			pattern = opt.StringValue()
		}
	}

	if url == "" {
		respond(s, i, "❌ URL is required", false)
		return
	}

	embed := createScanEmbed("Monitor Updates: Add", url, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	cmd := []string{autoarScript, "monitor", "updates", "add", "-u", url, "--strategy", strategy}
	if pattern != "" {
		cmd = append(cmd, "--pattern", pattern)
	}

	output, stderr, err := runCommandSync(cmd)
	_ = stderr // Used in error handling below

	color := 0x00ff00
	if err != nil {
		color = 0xff0000
	}

	patternSection := ""
	if pattern != "" {
		patternSection = fmt.Sprintf("\n**Pattern:** %s", pattern)
	}

	embed = &discordgo.MessageEmbed{
		Title:       "[ + ]Target Added",
		Description: fmt.Sprintf("**URL:** `%s`\n**Strategy:** %s%s", url, strategy, patternSection),
		Color:       color,
	}

	if output != "" {
		outputDisplay := output
		if len(outputDisplay) > 500 {
			outputDisplay = outputDisplay[:500]
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Output",
			Value: fmt.Sprintf("```%s```", outputDisplay),
		})
	}

	if stderr != "" && err != nil {
		stderrDisplay := stderr
		if len(stderrDisplay) > 500 {
			stderrDisplay = stderrDisplay[:500]
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

func handleMonitorUpdatesRemove(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	url := ""

	for _, opt := range options {
		if opt.Name == "url" {
			url = opt.StringValue()
		}
	}

	if url == "" {
		respond(s, i, "❌ URL is required", false)
		return
	}

	embed := createScanEmbed("Monitor Updates: Remove", url, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	cmd := []string{autoarScript, "monitor", "updates", "remove", "-u", url}

	output, stderr, err := runCommandSync(cmd)
	_ = stderr // May be used in error handling

	color := 0x00ff00
	if err != nil {
		color = 0xff0000
	}

	embed = &discordgo.MessageEmbed{
		Title:       "🗑️ Target Removed",
		Description: fmt.Sprintf("`%s`", url),
		Color:       color,
	}

	if output != "" {
		outputDisplay := output
		if len(outputDisplay) > 500 {
			outputDisplay = outputDisplay[:500]
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Output",
			Value: fmt.Sprintf("```%s```", outputDisplay),
		})
	}

	if stderr != "" && err != nil {
		stderrDisplay := stderr
		if len(stderrDisplay) > 500 {
			stderrDisplay = stderrDisplay[:500]
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

func handleMonitorUpdatesStart(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var url *string
	var id *int
	interval := 86400

	for _, opt := range options {
		switch opt.Name {
		case "id":
			val := int(opt.IntValue())
			id = &val
		case "url":
			val := opt.StringValue()
			url = &val
		case "interval":
			interval = int(opt.IntValue())
		}
	}

	var cmd []string
	var targetDesc string

	if id != nil && *id > 0 {
		cmd = []string{autoarScript, "monitor", "updates", "start", "--id", strconv.Itoa(*id), "--interval", fmt.Sprintf("%d", interval), "--daemon"}
		targetDesc = fmt.Sprintf("ID %d", *id)
	} else if url != nil && *url != "" {
		cmd = []string{autoarScript, "monitor", "updates", "start", "-u", *url, "--interval", fmt.Sprintf("%d", interval), "--daemon"}
		targetDesc = *url
	} else {
		cmd = []string{autoarScript, "monitor", "updates", "start", "--all", "--interval", fmt.Sprintf("%d", interval), "--daemon"}
		targetDesc = "all targets"
	}

	embed := createScanEmbed("Monitor Updates: Start", targetDesc, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	output, stderr, err := runCommandSync(cmd)

	color := 0x00ff00
	if err != nil {
		color = 0xff0000
	}

	modeText := "All targets"
	if id != nil && *id > 0 {
		modeText = fmt.Sprintf("Target ID: %d", *id)
	} else if url != nil && *url != "" {
		modeText = fmt.Sprintf("Single target: `%s`", *url)
	}

	embed = &discordgo.MessageEmbed{
		Title:       "📡 Updates Monitor Started",
		Description: fmt.Sprintf("**Mode:** %s\n**Interval:** %ds (%dh)", modeText, interval, interval/3600),
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

func handleMonitorUpdatesStop(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var url *string
	var id *int

	for _, opt := range options {
		switch opt.Name {
		case "id":
			val := int(opt.IntValue())
			id = &val
		case "url":
			val := opt.StringValue()
			url = &val
		}
	}

	var cmd []string
	var targetDesc string

	if id != nil && *id > 0 {
		cmd = []string{autoarScript, "monitor", "updates", "stop", "--id", strconv.Itoa(*id)}
		targetDesc = fmt.Sprintf("ID %d", *id)
	} else if url != nil && *url != "" {
		cmd = []string{autoarScript, "monitor", "updates", "stop", "-u", *url}
		targetDesc = *url
	} else {
		cmd = []string{autoarScript, "monitor", "updates", "stop", "--all"}
		targetDesc = "all targets"
	}

	embed := createScanEmbed("Monitor Updates: Stop", targetDesc, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	output, stderr, err := runCommandSync(cmd)

	color := 0x00ff00
	if err != nil {
		color = 0xff0000
	}

	modeText := "All targets"
	if id != nil && *id > 0 {
		modeText = fmt.Sprintf("Target ID: %d", *id)
	} else if url != nil && *url != "" {
		modeText = fmt.Sprintf("Single target: `%s`", *url)
	}

	embed = &discordgo.MessageEmbed{
		Title:       "🛑 Updates Monitor Stopped",
		Description: fmt.Sprintf("**Mode:** %s", modeText),
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


// Help
func handleHelp(s *discordgo.Session, i *discordgo.InteractionCreate) {
	embed := &discordgo.MessageEmbed{
		Title:       "📖 AutoAR Help",
		Description: "Loading AutoAR help information...",
		Color:       0x3498db,
	}
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	command := []string{autoarScript, "help"}
	output, _, err := runCommandSync(command)

	embed.Description = "AutoAR Security Scanning Tool - Available Commands"
	if err == nil && output != "" {
		helpText := output
		if len(helpText) > 1900 {
			helpText = helpText[:1900] + "\n... (truncated)"
		}
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Commands", Value: fmt.Sprintf("```%s```", helpText), Inline: false},
		}
	} else {
		// Fallback to manual command list
		embed.Fields = []*discordgo.MessageEmbedField{
			{
				Name:   "Core Workflows",
				Value:  "• `/scan_domain` - Full domain workflow\n• `/lite_scan` - Comprehensive automated scan: livehosts → reflection → JS → CNAME → backup → DNS → misconfig → nuclei\n• `/fast_look` - Quick reconnaissance: subdomain enumeration → live host filtering → URL/JS collection\n• `/zerodays` - Zerodays scan (CVE-2025-55182 React2Shell, CVE-2025-14847 MongoDB)",
				Inline: false,
			},
			{
				Name:   "Recon & Vuln Scans",
				Value:  "• `/subdomains` - Enumerate subdomains\n• `/livehosts` - Filter live hosts\n• `/urls` - Collect URLs & JS URLs\n• `/js_scan` - JavaScript scan (JS URLs)\n• `/reflection` - Reflection (kxss)\n• `/nuclei` - Nuclei templates\n• `/gf_scan` - GF patterns\n• `/sqlmap` - SQLMap on GF results\n• `/dalfox` - Dalfox XSS\n• `/ports` - Naabu port scan\n• `/tech` - Tech detection",
				Inline: false,
			},
			{
				Name:   "DNS & Cloud",
				Value:  "• `/dns_takeover` - Full DNS takeover workflow\n• `/dns_cname` - CNAME takeover\n• `/dns_ns` - NS takeover\n• `/dns_azure_aws` - Azure/AWS takeover\n• `/dns_dnsreaper` - DNSReaper only",
				Inline: false,
			},
			{
				Name:   "GitHub & JWT",
				Value:  "• `/github_scan` - Repo secrets (TruffleHog)\n• `/github_org_scan` - Org secrets\n• `/github_experimental_scan` - Experimental mode\n• `/github_wordlist` - GitHub-based wordlist\n• `/jwt_scan` - JWT token scan (jwt-hack)",
				Inline: false,
			},
			{
				Name:   "Database & Misc",
				Value:  "• `/db_domains` - List DB domains (file + output)\n• `/db_subdomains` - List DB subdomains (file + output)\n• `/db_delete_domain` - Delete domain from DB\n• `/check_tools` - Check required tools\n• `/scan_status` - Show scans",
				Inline: false,
			},
		}
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

	scansMutex.RLock()
	activeCount := len(activeScans)
	activeList := make([]*ScanInfo, 0, activeCount)
	for _, scan := range activeScans {
		activeList = append(activeList, scan)
	}
	scansMutex.RUnlock()

	// Get completed scans from API results (if available)
	completedList := getCompletedScans(20)

	embed := &discordgo.MessageEmbed{
		Title:       "📊 All Scan Status",
		Description: fmt.Sprintf("**Active Scans:** %d\n**Recent Completed Scans:** %d", activeCount, len(completedList)),
		Color:       0x3498db,
		Fields:      []*discordgo.MessageEmbedField{},
	}

	// Add active scans
	if activeCount > 0 {
		activeText := ""
		for i, scan := range activeList {
			if i >= 10 {
				activeText += fmt.Sprintf("\n... and %d more active scans", activeCount-10)
				break
			}
			statusEmoji := "🟡"
			if scan.Status == "completed" {
				statusEmoji = "✅"
			} else if scan.Status == "failed" {
				statusEmoji = "❌"
			} else if scan.Status == "cancelled" || scan.Status == "cancelling" {
				statusEmoji = "⏹️"
			}
			activeText += fmt.Sprintf("%s **%s** - `%s` (%s)\n**Scan ID:** `%s`\n", statusEmoji, scan.Type, scan.Target, scan.Status, scan.ScanID)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  fmt.Sprintf("Active Scans (%d)", activeCount),
			Value: activeText,
		})
	} else {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Active Scans",
			Value: "No active scans",
		})
	}

	// Add completed scans
	if len(completedList) > 0 {
		completedText := ""
		for i, result := range completedList {
			if i >= 10 {
				completedText += fmt.Sprintf("\n... and %d more completed scans", len(completedList)-10)
				break
			}
			statusEmoji := "✅"
			if result.Status == "failed" {
				statusEmoji = "❌"
			} else if result.Status == "cancelled" {
				statusEmoji = "⏹️"
			}
			// ScanResult doesn't have Target field, so we show ScanType and ScanID
			completedText += fmt.Sprintf("%s **%s** (%s)\n**Scan ID:** `%s`\n", statusEmoji, result.ScanType, result.Status, result.ScanID)
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  fmt.Sprintf("Recent Completed Scans (%d)", len(completedList)),
			Value: completedText,
		})
	} else {
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Completed Scans",
			Value: "No completed scans",
		})
	}

	if err := UpdateInteractionMessage(s, i, "", embed); err != nil {
		log.Printf("[WARN] Failed to update interaction: %v", err)
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
		scansMutex.Lock()
		scan, ok := activeScans[scanID]
		if !ok {
			scansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan with ID `%s` not found or already completed", scanID), false)
			return
		}
		if scan.Status != "running" {
			scansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan `%s` is not running (status: %s)", scanID, scan.Status), false)
			return
		}
		if scan.CancelFunc == nil {
			scansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan `%s` cannot be cancelled (no cancel function available)", scanID), false)
			return
		}
		// Cancel the scan
		scan.CancelFunc()
		scan.Status = "cancelling"
		scansMutex.Unlock()

		respond(s, i, fmt.Sprintf("Cancelling scan `%s` (%s on `%s`)", scanID, scan.Type, scan.Target), false)
		return
	}

	// If target and scan_type are provided, find matching scan
	if target != "" && scanType != "" {
		scansMutex.Lock()
		var foundScan *ScanInfo
		var foundScanID string
		for id, scan := range activeScans {
			if scan.Target == target && scan.Type == scanType && scan.Status == "running" {
				foundScan = scan
				foundScanID = id
				break
			}
		}
		if foundScan == nil {
			scansMutex.Unlock()
			respond(s, i, fmt.Sprintf("No running scan found for type `%s` on target `%s`", scanType, target), false)
			return
		}
		if foundScan.CancelFunc == nil {
			scansMutex.Unlock()
			respond(s, i, fmt.Sprintf("Scan cannot be cancelled (no cancel function available)", foundScanID), false)
			return
		}
		// Cancel the scan
		foundScan.CancelFunc()
		foundScan.Status = "cancelling"
		scansMutex.Unlock()

		respond(s, i, fmt.Sprintf("Cancelling scan `%s` (%s on `%s`)", foundScanID, foundScan.Type, foundScan.Target), false)
		return
	}

	// If only target is provided, list all running scans for that target
	if target != "" {
		scansMutex.RLock()
		var matchingScans []*ScanInfo
		for _, scan := range activeScans {
			if scan.Target == target && scan.Status == "running" {
				matchingScans = append(matchingScans, scan)
			}
		}
		scansMutex.RUnlock()

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
