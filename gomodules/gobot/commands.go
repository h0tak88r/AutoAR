package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
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
// Store channel ID for file notifications
func storeChannelID(scanID, channelID string) {
	channelsMutex.Lock()
	activeChannels[scanID] = channelID
	channelsMutex.Unlock()
}

// Get channel ID for file notifications
func getChannelID(scanID string) string {
	channelsMutex.RLock()
	defer channelsMutex.RUnlock()
	return activeChannels[scanID]
}

func runScanBackground(scanID, scanType, target string, command []string, s *discordgo.Session, i *discordgo.InteractionCreate) {
	// Store channel ID for file notifications from modules
	storeChannelID(scanID, i.ChannelID)
	
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

	// Execute command with environment variables for modules
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("AUTOAR_CURRENT_SCAN_ID=%s", scanID),
		fmt.Sprintf("AUTOAR_CURRENT_CHANNEL_ID=%s", i.ChannelID),
	)
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
		outputStr := string(output)
		// Truncate very long error messages
		if len(outputStr) > 1500 {
			outputStr = outputStr[:1500] + "\n... (truncated)"
		}
		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:  "Error",
			Value: fmt.Sprintf("```%s```", outputStr),
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

	// Send result files directly from bot (like livehosts does)
	if err == nil {
		// Small delay to ensure files are written to disk
		time.Sleep(500 * time.Millisecond)
		sendResultFiles(s, i, scanType, target)
	}
}

// sendResultFiles sends result files directly from the bot using FollowupMessageCreate
// This works like livehosts and doesn't require an HTTP API
func sendResultFiles(s *discordgo.Session, i *discordgo.InteractionCreate, scanType, target string) {
	resultsDir := getEnv("AUTOAR_RESULTS_DIR", "/app/new-results")
	
	// Map scan types to their expected result file paths
	var resultFiles []string
	
	switch scanType {
	case "cnames":
		resultFiles = []string{filepath.Join(resultsDir, target, "subs", "cname-records.txt")}
	case "urls":
		resultFiles = []string{
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, target, "urls", "js-urls.txt"),
		}
	case "reflection":
		resultFiles = []string{filepath.Join(resultsDir, target, "vulnerabilities", "kxss-results.txt")}
	case "tech":
		resultFiles = []string{filepath.Join(resultsDir, target, "subs", "tech-detect.txt")}
	case "ports":
		resultFiles = []string{filepath.Join(resultsDir, target, "ports", "ports.txt")}
	case "sqlmap":
		resultFiles = []string{filepath.Join(resultsDir, target, "vulnerabilities", "sqli", "sqlmap-results.txt")}
	case "dalfox":
		resultFiles = []string{filepath.Join(resultsDir, target, "dalfox-results.txt")}
	case "subdomains":
		resultFiles = []string{filepath.Join(resultsDir, target, "subs", "all-subs.txt")}
	case "jwt":
		// JWT scan results - find the most recent file with retry logic
		jwtDir := filepath.Join(resultsDir, "jwt-scan", "vulnerabilities", "jwt")
		log.Printf("[DEBUG] Looking for JWT result files in: %s", jwtDir)
		
		// Retry up to 3 times with delays (file might still be writing)
		var latestFile string
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
			}
			if matches, err := filepath.Glob(filepath.Join(jwtDir, "jwt_hack_*.txt")); err == nil && len(matches) > 0 {
				log.Printf("[DEBUG] Found %d JWT result file(s) on attempt %d", len(matches), attempt+1)
				// Get the most recent file
				var latestTime time.Time
				for _, match := range matches {
					if info, err := os.Stat(match); err == nil {
						if info.ModTime().After(latestTime) {
							latestTime = info.ModTime()
							latestFile = match
						}
					}
				}
				if latestFile != "" {
					// Verify file has content
					if info, err := os.Stat(latestFile); err == nil && info.Size() > 0 {
						log.Printf("[DEBUG] Selected most recent JWT file: %s (size: %d bytes)", latestFile, info.Size())
						resultFiles = []string{latestFile}
						break
					}
				}
			}
		}
		if latestFile == "" {
			log.Printf("[WARN] No JWT result files found in %s after retries", jwtDir)
		}
	case "fast":
		// Fast look sends multiple files from different modules
		resultFiles = []string{
			filepath.Join(resultsDir, target, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, target, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, target, "urls", "js-urls.txt"),
		}
	case "lite":
		// Lite scan can send multiple result files - use glob pattern
		jsDir := filepath.Join(resultsDir, target, "vulnerabilities", "js")
		if matches, err := filepath.Glob(filepath.Join(jsDir, "*.txt")); err == nil {
			resultFiles = append(resultFiles, matches...)
		}
		resultFiles = append(resultFiles,
			filepath.Join(resultsDir, target, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, target, "subs", "live-subs.txt"),
			filepath.Join(resultsDir, target, "urls", "all-urls.txt"),
		)
	// Add more scan types as needed
	}
	
	// Send each result file that exists
	for _, filePath := range resultFiles {
		// Handle glob patterns (e.g., *.txt)
		if strings.Contains(filePath, "*") {
			matches, err := filepath.Glob(filePath)
			if err == nil {
				for _, match := range matches {
					sendSingleFile(s, i, match)
				}
			}
		} else {
			sendSingleFile(s, i, filePath)
		}
	}
}

// sendSingleFile sends a single file via FollowupMessageCreate
func sendSingleFile(s *discordgo.Session, i *discordgo.InteractionCreate, filePath string) {
	log.Printf("[DEBUG] Attempting to send file: %s", filePath)
	if fileInfo, err := os.Stat(filePath); err == nil {
		if fileInfo.Size() == 0 {
			log.Printf("[WARN] File %s exists but is empty (size: 0)", filePath)
			return
		}
		log.Printf("[DEBUG] File found: %s (size: %d bytes)", filePath, fileInfo.Size())
		fileData, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("[ERROR] Failed to read file %s: %v", filePath, err)
			return
		}
		fileName := filepath.Base(filePath)
		_, err = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Files: []*discordgo.File{
				{
					Name:        fileName,
					ContentType: "text/plain",
					Reader:      strings.NewReader(string(fileData)),
				},
			},
		})
		if err != nil {
			log.Printf("[WARN] Failed to send result file %s: %v", fileName, err)
		} else {
			log.Printf("[INFO] Successfully sent result file via bot: %s", fileName)
		}
	} else {
		log.Printf("[WARN] File not found or cannot access: %s (err: %v)", filePath, err)
	}
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
