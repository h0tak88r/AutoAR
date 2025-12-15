package gobot

import (
	"fmt"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// JWT Commands
func handleJWTScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	token := ""
	skipCrack := false
	skipPayloads := false
	var wordlist *string
	var maxCrackAttempts *int

	for _, opt := range options {
		switch opt.Name {
		case "token":
			token = opt.StringValue()
		case "skip_crack":
			skipCrack = opt.BoolValue()
		case "skip_payloads":
			skipPayloads = opt.BoolValue()
		case "wordlist":
			val := opt.StringValue()
			wordlist = &val
		case "max_crack_attempts":
			val := int(opt.IntValue())
			maxCrackAttempts = &val
		}
	}

	if token == "" {
		respond(s, i, "❌ JWT token is required", true)
		return
	}

	// Build command
	command := []string{autoarScript, "jwt", "scan", "--token", token}
	
	if skipCrack {
		command = append(command, "--skip-crack")
	}
	if skipPayloads {
		command = append(command, "--skip-payloads")
	}
	if wordlist != nil && *wordlist != "" {
		command = append(command, "-w", *wordlist)
	}
	if maxCrackAttempts != nil && *maxCrackAttempts > 0 {
		command = append(command, "--max-crack-attempts", fmt.Sprintf("%d", *maxCrackAttempts))
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🔐 JWT Security Scan",
		Description: fmt.Sprintf("**Token:** `%s...`\n**Tool:** jwt-hack", token[:min(20, len(token))]),
		Color:       0x3498db,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "🟡 Running", Inline: false},
		},
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	scanID := fmt.Sprintf("jwt_%d", time.Now().Unix())
	go runScanBackground(scanID, "jwt", "JWT Token", command, s, i)
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
