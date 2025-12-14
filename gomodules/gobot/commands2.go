package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/bwmarrin/discordgo"
)

// DNS Commands
func handleDNSTakeover(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dnstko_%d", time.Now().Unix())
	command := []string{autoarScript, "dns", "takeover", "-d", domain}

	embed := createScanEmbed("DNS Takeover", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dns_takeover", domain, command, s, i)
}

func handleDNSCname(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dnscname_%d", time.Now().Unix())
	command := []string{autoarScript, "dns", "cname", "-d", domain}

	embed := createScanEmbed("DNS CNAME", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dns_cname", domain, command, s, i)
}

func handleDNSNs(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dnsns_%d", time.Now().Unix())
	command := []string{autoarScript, "dns", "ns", "-d", domain}

	embed := createScanEmbed("DNS NS", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dns_ns", domain, command, s, i)
}

func handleDNSAzureAws(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dnscloud_%d", time.Now().Unix())
	command := []string{autoarScript, "dns", "azure-aws", "-d", domain}

	embed := createScanEmbed("DNS Azure/AWS", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dns_azure_aws", domain, command, s, i)
}

func handleDNSDNSReaper(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dnsreaper_%d", time.Now().Unix())
	command := []string{autoarScript, "dns", "dnsreaper", "-d", domain}

	embed := createScanEmbed("DNSReaper", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "dns_dnsreaper", domain, command, s, i)
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
func handleGitHubScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	repo := ""
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "repo":
			repo = opt.StringValue()
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if repo == "" {
		respond(s, i, "❌ Repository (owner/repo) is required", false)
		return
	}

	scanID := fmt.Sprintf("github_%d", time.Now().Unix())
	command := []string{autoarScript, "github", "scan", "-r", repo}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("GitHub Scan", repo, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "github", repo, command, s, i)
}

func handleGitHubOrgScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	org := ""
	maxRepos := 50
	verbose := false

	for _, opt := range options {
		switch opt.Name {
		case "org":
			org = opt.StringValue()
		case "max_repos":
			maxRepos = int(opt.IntValue())
		case "verbose":
			verbose = opt.BoolValue()
		}
	}

	if org == "" {
		respond(s, i, "❌ Organization name is required", false)
		return
	}

	scanID := fmt.Sprintf("github_org_%d", time.Now().Unix())
	command := []string{autoarScript, "github", "org", "-o", org, "-m", strconv.Itoa(maxRepos)}
	if verbose {
		command = append(command, "-v")
	}

	embed := createScanEmbed("GitHub Org Scan", org, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "github_org", org, command, s, i)
}

func handleGitHubExperimentalScan(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	repo := ""

	for _, opt := range options {
		if opt.Name == "repo" {
			repo = opt.StringValue()
		}
	}

	if repo == "" {
		respond(s, i, "❌ Repository (owner/repo) is required", false)
		return
	}

	scanID := fmt.Sprintf("github_exp_%d", time.Now().Unix())
	command := []string{autoarScript, "github", "experimental", "-r", repo}

	embed := createScanEmbed("GitHub Experimental", repo, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "github_experimental", repo, command, s, i)
}

func handleGitHubWordlist(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	org := ""
	var token *string

	for _, opt := range options {
		switch opt.Name {
		case "org":
			org = opt.StringValue()
		case "token":
			val := opt.StringValue()
			token = &val
		}
	}

	if org == "" {
		respond(s, i, "❌ Organization name is required", false)
		return
	}

	scanID := fmt.Sprintf("github_wordlist_%d", time.Now().Unix())
	command := []string{autoarScript, "github-wordlist", "scan", "-o", org}
	if token != nil && *token != "" {
		command = append(command, "-t", *token)
	}

	embed := createScanEmbed("GitHub Wordlist", org, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "github_wordlist", org, command, s, i)
}

func handleGitHubDepConf(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	repo := ""

	for _, opt := range options {
		if opt.Name == "repo" {
			repo = opt.StringValue()
		}
	}

	if repo == "" {
		respond(s, i, "❌ Repository (owner/repo) is required", false)
		return
	}

	scanID := fmt.Sprintf("githubdepconf_%d", time.Now().Unix())
	command := []string{autoarScript, "depconfusion", "github", "repo", repo}

	embed := createScanEmbed("GitHub DepConfusion", repo, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "githubdepconf", repo, command, s, i)
}

// Database Commands
func handleDBDomains(s *discordgo.Session, i *discordgo.InteractionCreate) {
	scanID := fmt.Sprintf("dbdomains_%d", time.Now().Unix())
	command := []string{autoarScript, "db", "domains", "list"}

	dbName := getEnv("DB_NAME", "autoar")
	embed := createScanEmbed("DB Domains", fmt.Sprintf("%s (PostgreSQL)", dbName), "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "db_domains", "db", command, s, i)
}

func handleDBSubdomains(s *discordgo.Session, i *discordgo.InteractionCreate) {
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

	scanID := fmt.Sprintf("dbsubs_%d", time.Now().Unix())
	command := []string{autoarScript, "db", "subdomains", "list", "-d", domain}

	embed := createScanEmbed("DB Subdomains", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "db_subdomains", domain, command, s, i)
}

func handleDBDeleteDomain(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	force := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "force":
			force = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("dbdel_%d", time.Now().Unix())
	command := []string{autoarScript, "db", "domains", "delete", "-d", domain}
	if force {
		command = append(command, "-f")
	}

	embed := createScanEmbed("DB Delete Domain", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "db_delete_domain", domain, command, s, i)
}

// Cleanup
func handleCleanup(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	domain := ""
	keep := false

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "keep":
			keep = opt.BoolValue()
		}
	}

	if domain == "" {
		respond(s, i, "❌ Domain is required", false)
		return
	}

	scanID := fmt.Sprintf("cleanup_%d", time.Now().Unix())
	command := []string{autoarScript, "cleanup", "run", "--domain", domain}
	if keep {
		command = append(command, "--keep")
	}

	embed := createScanEmbed("Cleanup", domain, "running")
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	go runScanBackground(scanID, "cleanup", domain, command, s, i)
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
