package main

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

var (
	autoarScript = getEnv("AUTOAR_SCRIPT_PATH", "/app/main.sh")
	activeScans  = make(map[string]*ScanInfo)
	scansMutex   sync.RWMutex
)

type ScanInfo struct {
	ScanID      string
	Type        string
	ScanType    string // For API compatibility
	Target      string
	Status      string
	StartTime   time.Time
	StartedAt   time.Time // For API compatibility
	CompletedAt *time.Time
	Command     string
}

// Note: ScanInfo is shared between commands.go and api.go

// Helper function to run scan in background
func runScanBackground(scanID, scanType, target string, command []string, s *discordgo.Session, i *discordgo.InteractionCreate) {
	scansMutex.Lock()
	now := time.Now()
	activeScans[scanID] = &ScanInfo{
		ScanID:    scanID,
		Type:      scanType,
		ScanType:  scanType,
		Target:    target,
		Status:    "running",
		StartTime: now,
		StartedAt: now,
		Command:   strings.Join(command, " "),
	}
	scansMutex.Unlock()

	// Execute command
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()

	// Update status
	scansMutex.Lock()
	if scan, ok := activeScans[scanID]; ok {
		if err != nil {
			scan.Status = "failed"
		} else {
			scan.Status = "completed"
		}
	}
	scansMutex.Unlock()

	// Update Discord message
	embed := createScanEmbed(scanType, target, activeScans[scanID].Status)
	if err != nil {
		embed.Color = 0xff0000 // Red
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Error",
			Value: fmt.Sprintf("```%s```", string(output)),
		})
	} else {
		embed.Color = 0x00ff00 // Green
		if len(output) > 0 {
			outputStr := string(output)
			if len(outputStr) > 1000 {
				outputStr = outputStr[:1000] + "..."
			}
			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:  "Output",
				Value: fmt.Sprintf("```%s```", outputStr),
			})
		}
	}

	s.InteractionResponseEdit(i.Interaction, &discordgo.WebhookEdit{
		Embeds: &[]*discordgo.MessageEmbed{embed},
	})
}

func createScanEmbed(scanType, target, status string) *discordgo.MessageEmbed {
	statusEmoji := "🟡"
	if status == "completed" {
		statusEmoji = "✅"
	} else if status == "failed" {
		statusEmoji = "❌"
	}

	return &discordgo.MessageEmbed{
		Title:       fmt.Sprintf("🔍 %s Scan", scanType),
		Description: fmt.Sprintf("**Target:** `%s`\n**Status:** %s %s", target, statusEmoji, status),
		Color:       0x3498db,
		Fields:     []*discordgo.MessageEmbedField{},
	}
}

// Scan Domain
func handleScanDomain(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	verbose := false
	keepResults := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		case "keep_results":
			keepResults = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("domain_%d", time.Now().Unix())
	command := []string{autoarScript, "domain", "run", "-d", domain}
	if verbose {
		command = append(command, "-v")
	}
	if keepResults {
		command = append(command, "--keep-results")
	}

	embed := createScanEmbed("Domain", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "domain", domain, command, s, i)
}

// Scan Subdomain
func handleScanSubdomain(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	subdomain := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "subdomain":
			subdomain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if subdomain == "" {
		respond(s, i, "❌ Subdomain is required", false)
		return
	}

	scanID := fmt.Sprintf("subdomain_%d", time.Now().Unix())
	command := []string{autoarScript, "subdomains", "get", "-d", subdomain}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("Subdomain", subdomain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "subdomain", subdomain, command, s, i)
}

// Lite Scan
func handleLiteScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	verbose := false
	skipJS := false
	phaseTimeout := 3600
	var timeoutLivehosts, timeoutReflection, timeoutJS, timeoutNuclei *int

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		case "skip_js":
			skipJS = opt.BoolValue()
		case "phase_timeout":
			phaseTimeout = int(opt.IntValue())
		case "timeout_livehosts":
			val := int(opt.IntValue())
			timeoutLivehosts = &val
		case "timeout_reflection":
			val := int(opt.IntValue())
			timeoutReflection = &val
		case "timeout_js":
			val := int(opt.IntValue())
			timeoutJS = &val
		case "timeout_nuclei":
			val := int(opt.IntValue())
			timeoutNuclei = &val
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("lite_%d", time.Now().Unix())
	command := []string{autoarScript, "lite", "run", "-d", domain}
	if verbose {
		command = append(command, "-v")
	}
	if skipJS {
		command = append(command, "--skip-js")
	}
	if phaseTimeout > 0 {
		command = append(command, "--phase-timeout", strconv.Itoa(phaseTimeout))
	}
	if timeoutLivehosts != nil && *timeoutLivehosts >= 0 {
		command = append(command, "--timeout-livehosts", strconv.Itoa(*timeoutLivehosts))
	}
	if timeoutReflection != nil && *timeoutReflection >= 0 {
		command = append(command, "--timeout-reflection", strconv.Itoa(*timeoutReflection))
	}
	if timeoutJS != nil && *timeoutJS >= 0 {
		command = append(command, "--timeout-js", strconv.Itoa(*timeoutJS))
	}
	if timeoutNuclei != nil && *timeoutNuclei >= 0 {
		command = append(command, "--timeout-nuclei", strconv.Itoa(*timeoutNuclei))
	}

	desc := fmt.Sprintf("**Target:** `%s`\n**Default per-phase timeout:** %ds", domain, phaseTimeout)
	if skipJS {
		desc += "\n**JS Phase:** skipped"
	}
	embed := &discordgo.MessageEmbed{
		Title:       "🔍 AutoAR Lite Scan",
		Description: desc,
		Color:       0x3498db,
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "lite", domain, command, s, i)
}

// Fast Look
func handleFastLook(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("fast_%d", time.Now().Unix())
	command := []string{autoarScript, "fastlook", "run", "-d", domain}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("Fast Look", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "fast", domain, command, s, i)
}

// Domain Run
func handleDomainRun(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("domain_run_%d", time.Now().Unix())
	command := []string{autoarScript, "domain", "run", "-d", domain}

	embed := createScanEmbed("Domain Workflow", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "domain_run", domain, command, s, i)
}

// Subdomains
func handleSubdomains(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	threads := 100

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("subdomains_%d", time.Now().Unix())
	command := []string{autoarScript, "subdomains", "get", "-d", domain, "-t", strconv.Itoa(threads)}

	embed := createScanEmbed("Subdomains", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "subdomains", domain, command, s, i)
}

// CNAMEs
func handleCnames(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("cnames_%d", time.Now().Unix())
	command := []string{autoarScript, "cnames", "get", "-d", domain}

	embed := createScanEmbed("CNAMEs", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "cnames", domain, command, s, i)
}

// URLs
func handleURLs(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	threads := 100

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("urls_%d", time.Now().Unix())
	command := []string{autoarScript, "urls", "collect", "-d", domain, "-t", strconv.Itoa(threads)}

	embed := createScanEmbed("URLs", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "urls", domain, command, s, i)
}

// Reflection
func handleReflection(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("reflection_%d", time.Now().Unix())
	command := []string{autoarScript, "reflection", "scan", "-d", domain}

	embed := createScanEmbed("Reflection", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "reflection", domain, command, s, i)
}

// Tech Detection
func handleTech(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	threads := 100

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("tech_%d", time.Now().Unix())
	command := []string{autoarScript, "tech", "detect", "-d", domain, "-t", strconv.Itoa(threads)}

	embed := createScanEmbed("Tech Detection", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "tech", domain, command, s, i)
}

// Ports
func handlePorts(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("ports_%d", time.Now().Unix())
	command := []string{autoarScript, "ports", "scan", "-d", domain}

	embed := createScanEmbed("Ports", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "ports", domain, command, s, i)
}

// Nuclei
func handleNuclei(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var domain, url, mode *string
	enum := false
	threads := 100

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			val := opt.StringValue()
			domain = &val
		case "url":
			val := opt.StringValue()
			url = &val
		case "mode":
			val := opt.StringValue()
			mode = &val
		case "enum":
			enum = opt.BoolValue()
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	if domain == nil && url == nil {
		respond(s, i, "❌ Either domain or url must be provided", true)
		return
	}

	if domain != nil && url != nil {
		respond(s, i, "❌ Cannot use both domain and url together", true)
		return
	}

	scanID := fmt.Sprintf("nuclei_%d", time.Now().Unix())
	command := []string{autoarScript, "nuclei", "run"}

	var target string
	if domain != nil {
		command = append(command, "-d", *domain)
		target = *domain
	} else {
		command = append(command, "-u", *url)
		target = *url
	}

	modeVal := "full"
	if mode != nil {
		modeVal = *mode
	}
	command = append(command, "-m", modeVal)

	if enum && domain != nil {
		command = append(command, "-e")
	}

	command = append(command, "-t", strconv.Itoa(threads))

	modeDesc := map[string]string{
		"full":          "Full (All Templates)",
		"cves":          "CVEs Only",
		"panels":        "Panels Discovery",
		"default-logins": "Default Logins Only",
		"vulnerabilities": "Generic Vulnerabilities",
	}[modeVal]

	enumText := ""
	if enum && domain != nil {
		enumText = " with enum"
	}

	embed := createScanEmbed(fmt.Sprintf("Nuclei %s%s", modeDesc, enumText), target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, fmt.Sprintf("nuclei-%s", modeVal), target, command, s, i)
}

// JS Scan
func handleJSScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	var subdomain *string

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "subdomain":
			val := opt.StringValue()
			subdomain = &val
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("js_%d", time.Now().Unix())
	command := []string{autoarScript, "js", "scan", "-d", domain}
	if subdomain != nil && *subdomain != "" {
		command = append(command, "-s", *subdomain)
	}

	embed := createScanEmbed("JS Scan", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "js", domain, command, s, i)
}

// GF Scan
func handleGFScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("gf_%d", time.Now().Unix())
	command := []string{autoarScript, "gf", "scan", "-d", domain}

	embed := createScanEmbed("GF Scan", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "gf", domain, command, s, i)
}

// SQLMap
func handleSQLMap(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("sqlmap_%d", time.Now().Unix())
	command := []string{autoarScript, "sqlmap", "run", "-d", domain}

	embed := createScanEmbed("SQLMap", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "sqlmap", domain, command, s, i)
}

// Dalfox
func handleDalfox(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dalfox_%d", time.Now().Unix())
	command := []string{autoarScript, "dalfox", "run", "-d", domain}

	embed := createScanEmbed("Dalfox", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dalfox", domain, command, s, i)
}

// Helper function for responding to interactions
func respond(s *discordgo.Session, i *discordgo.InteractionCreate, message string, ephemeral bool) {
	flags := discordgo.MessageFlagsEphemeral
	if !ephemeral {
		flags = 0
	}

	err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: message,
			Flags:   flags,
		},
	})
	if err != nil {
		log.Printf("Error responding: %v", err)
	}
}
