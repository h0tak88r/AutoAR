package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// JWT Commands
func handleJWTScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	url := ""
	var cookie, header, canary, postData *string
	mode := "pb"

	for _, opt := range options {
		switch opt.Name {
		case "url":
			url = opt.StringValue()
		case "cookie":
			val := opt.StringValue()
			cookie = &val
		case "header":
			val := opt.StringValue()
			header = &val
		case "canary":
			val := opt.StringValue()
			canary = &val
		case "post_data":
			val := opt.StringValue()
			postData = &val
		case "mode":
			mode = opt.StringValue()
		}
	}

	if url == "" {
		respond(s, i, "❌ URL is required", false)
		return
	}

	if cookie == nil && header == nil {
		respond(s, i, "❌ You must provide either cookie or header parameter", true)
		return
	}

	if cookie != nil && header != nil {
		respond(s, i, "❌ You cannot provide both cookie and header. Choose one.", true)
		return
	}

	command := []string{autoarScript, "jwt", "scan", "-t", url}

	via := "cookie"
	if cookie != nil {
		command = append(command, "--cookie", *cookie)
	} else {
		command = append(command, "--header", *header)
		via = "header"
	}

	if canary != nil && *canary != "" {
		command = append(command, "--canary", *canary)
	}
	if postData != nil && *postData != "" {
		command = append(command, "--post-data", *postData)
	}
	if mode != "" {
		command = append(command, "-M", mode)
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🔐 JWT Security Test",
		Description: fmt.Sprintf("**Target:** `%s`\n**Mode:** `%s`\n**Via:** `%s`", url, mode, via),
		Color:       0x3498db,
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	scanID := fmt.Sprintf("jwt_%d", time.Now().Unix())
	go runScanBackground(scanID, "jwt", url, command, s, i)
}

func handleJWTQuery(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	queryID := ""

	for _, opt := range options {
		if opt.Name == "query_id" {
			queryID = opt.StringValue()
		}
	}

	if queryID == "" {
		respond(s, i, "❌ Query ID is required", false)
		return
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	})

	command := []string{autoarScript, "jwt", "query", queryID}

	output, stderr, err := runCommandSync(command)

	embed := &discordgo.MessageEmbed{
		Title:       "🔍 JWT Query Results",
		Description: fmt.Sprintf("**Query ID:** `%s`", queryID),
		Color:       0x3498db,
	}

	if err != nil {
		embed.Title = "❌ JWT Query Failed"
		embed.Color = 0xff0000
		errorMsg := stderr
		if errorMsg == "" {
			errorMsg = "Query failed"
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

// Other Commands
func handleBackupScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	threads := 100
	delay := 0

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		case "delay":
			delay = int(opt.IntValue())
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("backup_%d", time.Now().Unix())
	command := []string{autoarScript, "backup", "scan", "-d", domain, "-t", fmt.Sprintf("%d", threads)}
	if delay > 0 {
		command = append(command, "-d", fmt.Sprintf("%d", delay))
	}

	embed := createScanEmbed("Backup Scan", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "backup_scan", domain, command, s, i)
}

func handleCheckTools(s *discordgo.Session, i *discordgo.InteractionCreate) {
	scanID := fmt.Sprintf("check_tools_%d", time.Now().Unix())
	command := []string{autoarScript, "check-tools"}

	embed := createScanEmbed("Check Tools", "system", "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "check_tools", "system", command, s, i)
}

func handleMisconfig(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	target := ""
	var service *string
	delay := 0

	for _, opt := range options {
		switch opt.Name {
		case "target":
			target = opt.StringValue()
		case "service":
			val := opt.StringValue()
			service = &val
		case "delay":
			delay = int(opt.IntValue())
		}
	}

	if target == "" {
		respond(s, i, "❌ Target is required", false)
		return
	}

	scanID := fmt.Sprintf("misconfig_%d", time.Now().Unix())
	command := []string{autoarScript, "misconfig", "scan", target}
	if service != nil && *service != "" {
		command = append(command, *service)
	}
	if delay > 0 {
		command = append(command, fmt.Sprintf("%d", delay))
	}

	embed := createScanEmbed("Misconfig Scan", target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "misconfig", target, command, s, i)
}

func handleLiveDepconfusionScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("live_depconfusion_%d", time.Now().Unix())
	command := []string{autoarScript, "depconfusion", "scan", "-d", domain}

	embed := createScanEmbed("Live DepConfusion", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "live_depconfusion", domain, command, s, i)
}

func handleWebDepConf(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var urls []string

	for _, opt := range options {
		if opt.Name == "url" {
			urls = append(urls, opt.StringValue())
		}
	}

	if len(urls) == 0 {
		respond(s, i, "❌ At least one URL is required", false)
		return
	}

	scanID := fmt.Sprintf("webdepconf_%d", time.Now().Unix())
	command := []string{autoarScript, "depconfusion", "web"}
	command = append(command, urls...)

	target := strings.Join(urls, ", ")
	embed := createScanEmbed("Web DepConfusion", target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "webdepconf", target, command, s, i)
}

func handleWPDepConf(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""

	for _, opt := range options {
		if opt.Name == "domain" {
			domain = opt.StringValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("wp_depconf_%d", time.Now().Unix())
	command := []string{autoarScript, "wpDepConf", "scan", "-d", domain}

	embed := createScanEmbed("WordPress DepConfusion", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "wp_depconf", domain, command, s, i)
}
