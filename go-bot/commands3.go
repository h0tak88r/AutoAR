package main

import (
	"fmt"
	"regexp"
	"time"

	"github.com/bwmarrin/discordgo"
)

// KeyHack Commands
func handleKeyhackList(s *discordgo.Session, i *discordgo.InteractionCreate) {
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
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Error", Value: fmt.Sprintf("```\n%s\n```", errorMsg), Inline: false},
		}
	} else {
		if len(output) > 1900 {
			output = output[:1900] + "\n... (truncated - use search for specific templates)"
		}
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Templates", Value: fmt.Sprintf("```\n%s\n```", output), Inline: false},
		}
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func handleKeyhackSearch(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	query := ""

	for _, opt := range options {
		if opt.Name == "query" {
			query = opt.StringValue()
		}
	}

	if query == "" {
		respond(s, i, "❌ Search query is required", false)
		return
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	command := []string{autoarScript, "keyhack", "search", query}

	output, stderr, err := runCommandSync(command)

	embed := &discordgo.MessageEmbed{
		Title:       "🔍 KeyHack Search Results",
		Description: fmt.Sprintf("**Query:** `%s`", query),
		Color:       0x3498db,
	}

	if err != nil {
		embed.Title = "❌ KeyHack Search Failed"
		embed.Color = 0xff0000
		errorMsg := stderr
		if errorMsg == "" {
			errorMsg = "Search failed"
		}
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Error", Value: fmt.Sprintf("```\n%s\n```", errorMsg), Inline: false},
		}
	} else {
		if len(output) > 1900 {
			output = output[:1900] + "\n... (truncated)"
		}
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Results", Value: fmt.Sprintf("```\n%s\n```", output), Inline: false},
		}
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func handleKeyhackAdd(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	keyname := ""
	commandStr := ""
	description := ""
	notes := ""

	for _, opt := range options {
		switch opt.Name {
		case "keyname":
			keyname = opt.StringValue()
		case "command":
			commandStr = opt.StringValue()
		case "description":
			description = opt.StringValue()
		case "notes":
			notes = opt.StringValue()
		}
	}

	if keyname == "" || commandStr == "" || description == "" {
		respond(s, i, "❌ keyname, command, and description are required", false)
		return
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	cmd := []string{autoarScript, "keyhack", "add", keyname, commandStr, description}
	if notes != "" {
		cmd = append(cmd, notes)
	}

	output, stderr, err := runCommandSync(cmd)

	embed := &discordgo.MessageEmbed{
		Title:       "✅ Template Added Successfully",
		Description: fmt.Sprintf("**Template:** `%s`", keyname),
		Color:       0x00ff00,
	}

	if err != nil {
		embed.Title = "❌ Failed to Add Template"
		embed.Color = 0xff0000
		errorMsg := stderr
		if errorMsg == "" {
			errorMsg = output
		}
		if errorMsg == "" {
			errorMsg = "Failed to add template"
		}
		if len(errorMsg) > 1000 {
			errorMsg = errorMsg[:1000]
		}
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Error", Value: fmt.Sprintf("```\n%s\n```", errorMsg), Inline: false},
		}
	} else {
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Description", Value: description, Inline: false},
		}
		if notes != "" {
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:  "Notes",
				Value: notes,
			})
		}
		cmdDisplay := commandStr
		if len(cmdDisplay) > 500 {
			cmdDisplay = cmdDisplay[:500]
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Command",
			Value: fmt.Sprintf("```bash\n%s\n```", cmdDisplay),
		})
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func handleKeyhackValidate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	provider := ""
	apiKey := ""

	for _, opt := range options {
		switch opt.Name {
		case "provider":
			provider = opt.StringValue()
		case "api_key":
			apiKey = opt.StringValue()
		}
	}

	if provider == "" || apiKey == "" {
		respond(s, i, "❌ Provider and API key are required", false)
		return
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	command := []string{autoarScript, "keyhack", "validate", provider, apiKey}

	output, stderr, err := runCommandSync(command)

	embed := &discordgo.MessageEmbed{
		Title:       "🔐 API Key Validation Command",
		Description: fmt.Sprintf("**Provider:** `%s`", provider),
		Color:       0x00ff00,
	}

	if err != nil {
		embed.Title = "❌ API Key Validation Failed"
		embed.Color = 0xff0000
		errorMsg := stderr
		if errorMsg == "" {
			errorMsg = "Validation failed"
		}
		embed.Fields = []*discordgo.MessageEmbedField{
			{Name: "Error", Value: fmt.Sprintf("```\n%s\n```", errorMsg), Inline: false},
		}
	} else {
		// Extract curl command from output
		re := regexp.MustCompile(`curl[^\n]+`)
		commandMatch := re.FindString(output)
		if commandMatch != "" {
			embed.Fields = []*discordgo.MessageEmbedField{
				{Name: "Validation Command", Value: fmt.Sprintf("```bash\n%s\n```", commandMatch), Inline: false},
			}
		} else {
			if len(output) > 1900 {
				output = output[:1900] + "\n... (truncated)"
			}
			embed.Fields = []*discordgo.MessageEmbedField{
				{Name: "Output", Value: fmt.Sprintf("```\n%s\n```", output), Inline: false},
			}
		}
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

// Monitoring Commands
func handleMonitorUpdatesAdd(s *discordgo.Session, i *discordgo.InteractionCreate) {
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
		Title:       "✅ Target Added",
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

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
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

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func handleMonitorUpdatesStart(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var url *string
	interval := 86400

	for _, opt := range options {
		switch opt.Name {
		case "url":
			val := opt.StringValue()
			url = &val
		case "interval":
			interval = int(opt.IntValue())
		}
	}

	var cmd []string
	var targetDesc string

	if url != nil && *url != "" {
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

	modeText := fmt.Sprintf("Single target: `%s`", *url)
	if url == nil || *url == "" {
		modeText = "All targets"
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

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func handleMonitorUpdatesStop(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var url *string

	for _, opt := range options {
		if opt.Name == "url" {
			val := opt.StringValue()
			url = &val
		}
	}

	var cmd []string
	var targetDesc string

	if url != nil && *url != "" {
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

	modeText := fmt.Sprintf("Single target: `%s`", *url)
	if url == nil || *url == "" {
		modeText = "All targets"
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

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func handleMonitorUpdatesList(s *discordgo.Session, i *discordgo.InteractionCreate) {
	embed := createScanEmbed("Monitor Updates: List", "monitors", "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	cmd := []string{autoarScript, "monitor", "updates", "list"}

	output, _, err := runCommandSync(cmd)

	color := 0x00ff00
	if err != nil {
		color = 0xff0000
	}

	desc := output
	if desc == "" {
		desc = "No targets configured"
	}
	if len(desc) > 1900 {
		desc = desc[:1900]
	}

	embed = &discordgo.MessageEmbed{
		Title:       "📡 Updates Monitors",
		Description: fmt.Sprintf("```\n%s\n```", desc),
		Color:       color,
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
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
				Name: "Core Commands",
				Value: "• `/lite_scan` - Quick scan\n• `/fast_look` - Fast lookup\n• `/scan_domain` - Full scan\n• `/js_scan` - JavaScript scan\n• `/gf_scan` - GF pattern scans\n• `/sqlmap` - SQLMap scan\n• `/dalfox` - Dalfox XSS scan",
				Inline: false,
			},
			{
				Name: "Database Commands",
				Value: "• `/db_domains` - List domains\n• `/db_subdomains` - List subdomains\n• `/db_delete_domain` - Delete domain",
				Inline: false,
			},
			{
				Name: "Other Commands",
				Value: "• `/nuclei` - Nuclei scan\n• `/ports` - Port scan\n• `/tech` - Tech detection\n• `/s3_scan` - S3 bucket scan\n• `/github_scan` - GitHub secrets scan",
				Inline: false,
			},
		}
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

// Scan Status
func handleScanStatus(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	scanID := ""

	for _, opt := range options {
		if opt.Name == "scan_id" {
			scanID = opt.StringValue()
		}
	}

	if scanID == "" {
		respond(s, i, "❌ Scan ID is required", false)
		return
	}

	scansMutex.RLock()
	scan, ok := activeScans[scanID]
	scansMutex.RUnlock()

	if !ok {
		respond(s, i, fmt.Sprintf("❌ Scan ID `%s` not found", scanID), false)
		return
	}

	embed := &discordgo.MessageEmbed{
		Title:       "📊 Scan Status",
		Description: fmt.Sprintf("**Scan ID:** `%s`\n**Type:** %s\n**Target:** `%s`\n**Status:** %s", scanID, scan.Type, scan.Target, scan.Status),
		Color:       0x3498db,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Started", Value: scan.StartTime.Format(time.RFC3339), Inline: false},
			{Name: "Command", Value: fmt.Sprintf("```%s```", scan.Command), Inline: false},
		},
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})
}
