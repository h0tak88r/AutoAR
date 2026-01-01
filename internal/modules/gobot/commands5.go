package gobot

import (
	"fmt"
	"log"

	"github.com/bwmarrin/discordgo"
)

// handleMonitorSubdomainsManage handles the /monitor_subdomains_manage Discord command
func handleMonitorSubdomainsManage(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	action := ""
	var domain *string
	var id *int
	interval := 3600
	threads := 100
	checkNew := true
	all := false

	for _, opt := range options {
		switch opt.Name {
		case "action":
			action = opt.StringValue()
		case "domain":
			val := opt.StringValue()
			domain = &val
		case "id":
			val := int(opt.IntValue())
			id = &val
		case "interval":
			interval = int(opt.IntValue())
		case "threads":
			threads = int(opt.IntValue())
		case "check_new":
			checkNew = opt.BoolValue()
		case "all":
			all = opt.BoolValue()
		}
	}

	if action == "" {
		respond(s, i, "❌ Error: Action is required", true)
		return
	}

	// Build command
	command := []string{autoarScript, "monitor", "subdomains", "manage", action}

	switch action {
	case "list":
		// For list, we can show results directly without running command
		// But we'll still run it to get formatted output
		// No additional parameters needed

	case "add":
		if domain == nil {
			respond(s, i, "❌ Error: Domain is required for add action", true)
			return
		}
		command = append(command, "-d", *domain)
		command = append(command, "-i", fmt.Sprintf("%d", interval))
		command = append(command, "-t", fmt.Sprintf("%d", threads))
		if !checkNew {
			command = append(command, "--no-check-new")
		}

	case "remove":
		if id != nil {
			command = append(command, "--id", fmt.Sprintf("%d", *id))
		} else if domain != nil {
			command = append(command, "-d", *domain)
		} else {
			respond(s, i, "❌ Error: Domain or ID is required for remove action", true)
			return
		}

	case "start", "stop":
		if id != nil {
			command = append(command, "--id", fmt.Sprintf("%d", *id))
		} else if all {
			command = append(command, "--all")
		} else if domain != nil {
			command = append(command, "-d", *domain)
		} else {
			respond(s, i, "❌ Error: Domain, ID, or --all is required for start/stop action", true)
			return
		}
	}

	// Send initial response
	desc := fmt.Sprintf("**Action:** %s\n", action)
	if domain != nil {
		desc += fmt.Sprintf("**Domain:** %s\n", *domain)
	}
	if id != nil {
		desc += fmt.Sprintf("**ID:** %d\n", *id)
	}
	if action == "add" {
		desc += fmt.Sprintf("**Interval:** %ds (%dh)\n", interval, interval/3600)
		desc += fmt.Sprintf("**Threads:** %d\n", threads)
		desc += fmt.Sprintf("**Check New:** %v\n", checkNew)
	}
	if all {
		desc += "**All:** Yes\n"
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🔍 Managing Subdomain Monitoring Target",
		Description: desc,
		Color:       0x00ff00,
	}

	// For list action, use deferred response since it might take a moment
	if action == "list" {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
		})
	} else {
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Embeds: []*discordgo.MessageEmbed{embed},
			},
		})
	}

	// Run command
	output, _, err := runCommandSync(command)

	color := 0x00ff00
	if err != nil {
		color = 0xff0000
	}

	desc = output
	if desc == "" {
		desc = "Command completed"
	}
	if len(desc) > 1900 {
		desc = desc[:1900] + "..."
	}

	embed = &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("✅ Subdomain Monitoring: %s", action),
		Description: fmt.Sprintf("```\n%s\n```", desc),
		Color:       color,
	}

	if action == "list" {
		// For list, use followup message since we used deferred response
		_, _ = s.FollowupMessageCreate(i.Interaction, true, &discordgo.WebhookParams{
			Embeds: []*discordgo.MessageEmbed{embed},
		})
	} else {
		// For other actions, edit the original response
		if err := UpdateInteractionMessage(s, i, embed); err != nil {
			log.Printf("[WARN] Failed to update interaction: %v", err)
		}
	}
}

