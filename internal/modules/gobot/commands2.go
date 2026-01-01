package gobot

import (
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/bwmarrin/discordgo"
)

// DNS Commands
func handleDNS(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	scanType := "takeover" // Default to takeover

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "type":
			scanType = opt.StringValue()
		}
	}

	if domain == "" {
		respond(s, i, "Domain is required", false)
		return
	}

	// Map scan type to CLI command
	var command []string
	var scanName string
	switch scanType {
	case "cname":
		command = []string{autoarScript, "dns", "cname", "-d", domain}
		scanName = "DNS CNAME"
	case "ns":
		command = []string{autoarScript, "dns", "ns", "-d", domain}
		scanName = "DNS NS"
	case "azure-aws":
		command = []string{autoarScript, "dns", "azure-aws", "-d", domain}
		scanName = "DNS Azure/AWS"
	case "dnsreaper":
		command = []string{autoarScript, "dns", "dnsreaper", "-d", domain}
		scanName = "DNSReaper"
	case "dangling-ip":
		command = []string{autoarScript, "dns", "dangling-ip", "-d", domain}
		scanName = "DNS Dangling IP"
	default: // takeover
		command = []string{autoarScript, "dns", "takeover", "-d", domain}
		scanName = "DNS Takeover"
	}

	scanID := fmt.Sprintf("dns_%s_%d", scanType, time.Now().Unix())
	embed := createScanEmbed(scanName, domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, fmt.Sprintf("dns_%s", scanType), domain, command, s, i)
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
	command := []string{autoarScript, "s3", "scan", "-b", bucket}
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
	command := []string{autoarScript, "s3", "enum", "-b", root}

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
		scanID = fmt.Sprintf("github_scan_%d", time.Now().Unix())
		command = []string{autoarScript, "github", "scan", "-r", repo}
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
		command = []string{autoarScript, "github", "org", "-o", org, "-m", strconv.Itoa(maxRepos)}
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
		scanID = fmt.Sprintf("github_exp_%d", time.Now().Unix())
		command = []string{autoarScript, "github", "experimental", "-r", repo}
		scanName = "GitHub Experimental"
		target = repo

	case "wordlist":
	if org == "" {
			respond(s, i, "❌ Organization name is required for wordlist mode", false)
		return
	}
		scanID = fmt.Sprintf("github_wordlist_%d", time.Now().Unix())
		command = []string{autoarScript, "github-wordlist", "scan", "-o", org}
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
		command = []string{autoarScript, "depconfusion", "github", "repo", repo}
		target = repo
	} else {
		command = []string{autoarScript, "depconfusion", "github", "org", org}
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
		command = []string{autoarScript, "db", "domains", "list"}
		dbName := getEnv("DB_NAME", "autoar")
		scanName = "DB Domains"
		target = fmt.Sprintf("%s (PostgreSQL)", dbName)

	case "list-subdomains":
		if domain == "" {
			respond(s, i, "❌ Domain is required for list-subdomains action", false)
			return
		}
		scanID = fmt.Sprintf("dbsubs_%d", time.Now().Unix())
		command = []string{autoarScript, "db", "subdomains", "list", "-d", domain}
		scanName = "DB Subdomains"
		target = domain

	case "delete-domain":
		if domain == "" {
			respond(s, i, "❌ Domain is required for delete-domain action", false)
			return
		}
		scanID = fmt.Sprintf("dbdel_%d", time.Now().Unix())
		command = []string{autoarScript, "db", "domains", "delete", "-d", domain}
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
