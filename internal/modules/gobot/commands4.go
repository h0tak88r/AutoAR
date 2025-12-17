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

func handleWebDepConf(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var urls []string
	var domain string
	full := false

	for _, opt := range options {
		switch opt.Name {
		case "url":
			urls = append(urls, opt.StringValue())
		case "domain":
			domain = opt.StringValue()
		case "full":
			full = opt.BoolValue()
		}
	}

	if full {
		if domain == "" {
			respond(s, i, "❌ Domain is required for full scan", false)
			return
		}
		scanID := fmt.Sprintf("webdepconf_full_%d", time.Now().Unix())
		command := []string{autoarScript, "depconfusion", "web", "--full", "-d", domain}
		embed := createScanEmbed("Web DepConfusion (Full)", domain, "running")
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Embeds: []*discordgo.MessageEmbed{embed},
			},
		})
		go runScanBackground(scanID, "webdepconf", domain, command, s, i)
	} else {
		if len(urls) == 0 && domain == "" {
			respond(s, i, "❌ At least one URL or domain is required", false)
			return
		}
		scanID := fmt.Sprintf("webdepconf_%d", time.Now().Unix())
		command := []string{autoarScript, "depconfusion", "web"}
		if domain != "" {
			// If domain provided, convert to URL
			if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
				command = append(command, "https://"+domain)
			} else {
				command = append(command, domain)
			}
		} else {
			command = append(command, urls...)
		}
		target := domain
		if target == "" {
			target = strings.Join(urls, ", ")
		}
		embed := createScanEmbed("Web DepConfusion", target, "running")
		s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
			Type: discordgo.InteractionResponseChannelMessageWithSource,
			Data: &discordgo.InteractionResponseData{
				Embeds: []*discordgo.MessageEmbed{embed},
			},
		})
		go runScanBackground(scanID, "webdepconf", target, command, s, i)
	}
}
