package bot

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// DNS Commands
func handleDNS(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	subdomain := ""
	scanType := "takeover" // Default to takeover

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "subdomain":
			subdomain = opt.StringValue()
		case "type":
			scanType = opt.StringValue()
		}
	}

	// Strip URL scheme prefixes so users can paste URLs directly
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	domain = strings.TrimSuffix(domain, "/")
	subdomain = strings.TrimPrefix(strings.TrimPrefix(subdomain, "https://"), "http://")
	subdomain = strings.TrimSuffix(subdomain, "/")

	if domain == "" && subdomain == "" {
		respond(s, i, "❌ Either **domain** or **subdomain** is required.", false)
		return
	}

	// Determine target label for Discord embed
	target := domain
	if subdomain != "" {
		target = subdomain
	}

	// Build CLI command — subdomain mode passes -s instead of -d (skips enumeration)
	var command []string
	var scanName string
	switch scanType {
	case "cname":
		scanName = "DNS CNAME"
		if subdomain != "" {
			command = []string{utils.GetAutoarScriptPath(), "dns", "cname", "-d", subdomain}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "cname", "-d", domain}
		}
	case "ns":
		scanName = "DNS NS"
		if subdomain != "" {
			command = []string{utils.GetAutoarScriptPath(), "dns", "ns", "-d", subdomain}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "ns", "-d", domain}
		}
	case "azure-aws":
		scanName = "DNS Azure/AWS"
		if subdomain != "" {
			command = []string{utils.GetAutoarScriptPath(), "dns", "azure-aws", "-d", subdomain}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "azure-aws", "-d", domain}
		}
	case "dnsreaper":
		scanName = "DNSReaper"
		if subdomain != "" {
			command = []string{utils.GetAutoarScriptPath(), "dns", "dnsreaper", "-d", subdomain}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "dnsreaper", "-d", domain}
		}
	case "dangling-ip":
		scanName = "DNS Dangling IP"
		if subdomain != "" {
			command = []string{utils.GetAutoarScriptPath(), "dns", "dangling-ip", "-d", subdomain}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "dangling-ip", "-d", domain}
		}
	case "cf1016":
		scanName = "Cloudflare 1016 Dangling DNS"
		if subdomain != "" {
			// -s mode: scan the single subdomain directly, no live-subs.txt needed
			command = []string{utils.GetAutoarScriptPath(), "dns", "cf1016", "-s", subdomain}
			if domain != "" {
				command = append(command, "-d", domain)
			}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "cf1016", "-d", domain}
		}
	default: // takeover
		scanName = "DNS Takeover"
		if subdomain != "" {
			command = []string{utils.GetAutoarScriptPath(), "dns", "takeover", "-d", subdomain}
		} else {
			command = []string{utils.GetAutoarScriptPath(), "dns", "takeover", "-d", domain}
		}
	}

	scanID := fmt.Sprintf("dns_%s_%d", scanType, time.Now().Unix())
	embed := createScanEmbed(scanName, target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, fmt.Sprintf("dns_%s", scanType), target, command, s, i)
}

// S3 Commands
func handleS3Scan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	bucket := ""
	var region *string
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "bucket":
			bucket = opt.StringValue()
		case "region":
			val := opt.StringValue()
			region = &val
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if bucket == "" {
		respond(s, i, "❌ Bucket name is required", false)
		return
	}

	scanID := fmt.Sprintf("s3_%d", time.Now().Unix())
	command := []string{utils.GetAutoarScriptPath(), "s3", "scan", "-b", bucket}
	if region != nil && *region != "" {
		command = append(command, "-r", *region)
	}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("S3 Scan", bucket, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "s3", bucket, command, s, i)
}

func handleS3Enum(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	root := ""

	for _, opt := range options {
		if opt.Name == "root" {
			root = opt.StringValue()
		}
	}

	if root == "" {
		respond(s, i, "❌ Root domain is required", false)
		return
	}

	scanID := fmt.Sprintf("s3enum_%d", time.Now().Unix())
	command := []string{utils.GetAutoarScriptPath(), "s3", "enum", "-b", root}

	embed := createScanEmbed("S3 Enum", root, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "s3_enum", root, command, s, i)
}

// GitHub Commands
// GitHub Commands
func handleGitHub(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	mode := ""
	repo := ""
	org := ""
	maxRepos := 50
	token := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "mode":
			mode = opt.StringValue()
		case "repo":
			repo = opt.StringValue()
		case "org":
			org = opt.StringValue()
		case "max_repos":
			maxRepos = int(opt.IntValue())
		case "token":
			token = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if mode == "" {
		respond(s, i, "❌ Mode is required", false)
		return
	}

	var command []string
	var scanName string
	var target string
	var scanID string

	switch mode {
	case "scan":
		if repo == "" {
			respond(s, i, "❌ Repository (owner/repo) is required for scan mode", false)
			return
		}
		// Normalize repo URL to match the directory name written by githubscan module
		// e.g. "https://github.com/clerk/javascript/" -> "clerk/javascript"
		repo = strings.TrimPrefix(repo, "https://github.com/")
		repo = strings.TrimPrefix(repo, "http://github.com/")
		repo = strings.TrimSuffix(repo, ".git")
		repo = strings.TrimSuffix(repo, "/")
		scanID = fmt.Sprintf("github_scan_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "github", "scan", "-r", repo}
		if verbose {
			command = append(command, "-v")
		}
		scanName = "GitHub Scan"
		target = repo

	case "org":
		if org == "" {
			respond(s, i, "❌ Organization name is required for org mode", false)
			return
		}
		scanID = fmt.Sprintf("github_org_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "github", "org", "-o", org, "-m", strconv.Itoa(maxRepos)}
		if verbose {
			command = append(command, "-v")
		}
		scanName = "GitHub Org Scan"
		target = org

	case "experimental":
		if repo == "" {
			respond(s, i, "❌ Repository (owner/repo) is required for experimental mode", false)
			return
		}
		// Normalize repo URL
		repo = strings.TrimPrefix(repo, "https://github.com/")
		repo = strings.TrimPrefix(repo, "http://github.com/")
		repo = strings.TrimSuffix(repo, ".git")
		repo = strings.TrimSuffix(repo, "/")
		scanID = fmt.Sprintf("github_exp_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "github", "experimental", "-r", repo}
		scanName = "GitHub Experimental"
		target = repo

	case "wordlist":
		if org == "" {
			respond(s, i, "❌ Organization name is required for wordlist mode", false)
			return
		}
		scanID = fmt.Sprintf("github_wordlist_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "github-wordlist", "scan", "-o", org}
		if token != "" {
			command = append(command, "-t", token)
		}
		scanName = "GitHub Wordlist"
		target = org

	case "depconf":
		if repo == "" && org == "" {
			respond(s, i, "❌ Either repository (owner/repo) or organization is required for depconf mode", false)
			return
		}
		scanID = fmt.Sprintf("githubdepconf_%d", time.Now().Unix())
		if repo != "" {
			command = []string{utils.GetAutoarScriptPath(), "depconfusion", "github", "repo", repo}
			target = repo
		} else {
			command = []string{utils.GetAutoarScriptPath(), "depconfusion", "github", "org", org}
			target = org
		}
		scanName = "GitHub DepConfusion"

	default:
		respond(s, i, fmt.Sprintf("❌ Unknown mode: %s", mode), false)
		return
	}

	embed := createScanEmbed(scanName, target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	// Create a thread for scan updates (avoids token expiration, mirrors domain/subdomain scan behavior)
	threadLabel := "GitHub Scan"
	switch mode {
	case "org":
		threadLabel = "GitHub Org Scan"
	case "experimental":
		threadLabel = "GitHub Experimental"
	case "wordlist":
		threadLabel = "GitHub Wordlist"
	case "depconf":
		threadLabel = "GitHub DepConfusion"
	}
	threadID := createScanThread(s, i, scanID, threadLabel, target)
	if threadID != "" {
		log.Printf("[INFO] Created thread %s for github scan %s", threadID, scanID)
	}

	go runScanBackground(scanID, fmt.Sprintf("github_%s", mode), target, command, s, i)
}

// Database Commands
func handleDB(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	action := ""
	domain := ""
	force := false

	for _, opt := range options {
		switch opt.Name {
		case "action":
			action = opt.StringValue()
		case "domain":
			domain = opt.StringValue()
		case "force":
			force = opt.BoolValue()
		}
	}

	if action == "" {
		respond(s, i, "❌ Action is required", false)
		return
	}

	var command []string
	var scanName string
	var target string
	var scanID string

	switch action {
	case "list-domains":
		scanID = fmt.Sprintf("dbdomains_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "db", "domains", "list"}
		dbName := utils.GetEnv("DB_NAME", "autoar")
		scanName = "DB Domains"
		target = fmt.Sprintf("%s (PostgreSQL)", dbName)

	case "list-subdomains":
		if domain == "" {
			respond(s, i, "❌ Domain is required for list-subdomains action", false)
			return
		}
		scanID = fmt.Sprintf("dbsubs_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "db", "subdomains", "list", "-d", domain}
		scanName = "DB Subdomains"
		target = domain

	case "delete-domain":
		if domain == "" {
			respond(s, i, "❌ Domain is required for delete-domain action", false)
			return
		}
		scanID = fmt.Sprintf("dbdel_%d", time.Now().Unix())
		command = []string{utils.GetAutoarScriptPath(), "db", "domains", "delete", "-d", domain}
		if force {
			command = append(command, "-f")
		}
		scanName = "DB Delete Domain"
		target = domain

	default:
		respond(s, i, fmt.Sprintf("❌ Unknown action: %s", action), false)
		return
	}

	embed := createScanEmbed(scanName, target, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, fmt.Sprintf("db_%s", action), target, command, s, i)
}

// Helper function to run command and get output synchronously
func runCommandSync(command []string) (string, string, error) {
	cmd := exec.Command(command[0], command[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", string(output), err
	}
	return string(output), "", nil
}
