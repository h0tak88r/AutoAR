package gobot

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Main function for standalone bot execution (backward compatibility)
// This can be used if someone wants to run the bot standalone
func Main() {
	var wg sync.WaitGroup

	// Start Discord bot if needed
	if autoarMode == "discord" || autoarMode == "both" {
		if botToken == "" {
			log.Fatal("DISCORD_BOT_TOKEN environment variable is required")
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := StartBot(); err != nil {
				log.Fatalf("Discord bot error: %v", err)
			}
		}()
	}

	// Start API server if needed
	if autoarMode == "api" || autoarMode == "both" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := StartAPI(); err != nil {
				log.Fatalf("API server error: %v", err)
			}
		}()
	}

	// Wait for interrupt signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	fmt.Println("\nShutting down...")
}

func ready(s *discordgo.Session, event *discordgo.Ready) {
	fmt.Printf("Bot logged in as: %v#%v\n", event.User.Username, event.User.Discriminator)
}

func interactionCreate(s *discordgo.Session, i *discordgo.InteractionCreate) {
	cmdName := i.ApplicationCommandData().Name
	
	// Route to appropriate handler
	switch cmdName {
	case "react2shell_scan":
		handleReact2ShellScan(s, i)
	case "react2shell":
		handleReact2Shell(s, i)
	case "scan_domain":
		handleScanDomain(s, i)
	case "scan_subdomain":
		handleScanSubdomain(s, i)
	case "lite_scan":
		handleLiteScan(s, i)
	case "fast_look":
		handleFastLook(s, i)
	case "domain_run":
		handleDomainRun(s, i)
	case "subdomains":
		handleSubdomains(s, i)
	case "cnames":
		handleCnames(s, i)
	case "livehosts":
		handleLivehosts(s, i)
	case "urls":
		handleURLs(s, i)
	case "reflection":
		handleReflection(s, i)
	case "tech":
		handleTech(s, i)
	case "ports":
		handlePorts(s, i)
	case "nuclei":
		handleNuclei(s, i)
	case "js_scan":
		handleJSScan(s, i)
	case "gf_scan":
		handleGFScan(s, i)
	case "sqlmap":
		handleSQLMap(s, i)
	case "dalfox":
		handleDalfox(s, i)
	case "dns_takeover":
		handleDNSTakeover(s, i)
	case "dns_cname":
		handleDNSCname(s, i)
	case "dns_ns":
		handleDNSNs(s, i)
	case "dns_azure_aws":
		handleDNSAzureAws(s, i)
	case "dns_dnsreaper":
		handleDNSDNSReaper(s, i)
	case "s3_scan":
		handleS3Scan(s, i)
	case "s3_enum":
		handleS3Enum(s, i)
	case "github_scan":
		handleGitHubScan(s, i)
	case "github_org_scan":
		handleGitHubOrgScan(s, i)
	case "github_experimental_scan":
		handleGitHubExperimentalScan(s, i)
	case "github_wordlist":
		handleGitHubWordlist(s, i)
	case "githubdepconf":
		handleGitHubDepConf(s, i)
	case "db_domains":
		handleDBDomains(s, i)
	case "db_subdomains":
		handleDBSubdomains(s, i)
	case "db_delete_domain":
		handleDBDeleteDomain(s, i)
	case "keyhack_list":
		handleKeyhackList(s, i)
	case "keyhack_search":
		handleKeyhackSearch(s, i)
	case "keyhack_add":
		handleKeyhackAdd(s, i)
	case "keyhack_validate":
		handleKeyhackValidate(s, i)
	case "monitor_updates_add":
		handleMonitorUpdatesAdd(s, i)
	case "monitor_updates_remove":
		handleMonitorUpdatesRemove(s, i)
	case "monitor_updates_start":
		handleMonitorUpdatesStart(s, i)
	case "monitor_updates_stop":
		handleMonitorUpdatesStop(s, i)
	case "monitor_updates_list":
		handleMonitorUpdatesList(s, i)
	case "jwt_scan":
		handleJWTScan(s, i)
	case "backup_scan":
		handleBackupScan(s, i)
	case "check_tools":
		handleCheckTools(s, i)
	case "cleanup":
		handleCleanup(s, i)
	case "misconfig":
		handleMisconfig(s, i)
	case "live_depconfusion_scan":
		handleLiveDepconfusionScan(s, i)
	case "webdepconf":
		handleWebDepConf(s, i)
	case "wp_depconf":
		handleWPDepConf(s, i)
	case "help_autoar":
		handleHelp(s, i)
	case "scan_status":
		handleScanStatus(s, i)
	default:
		log.Printf("Unknown command: %s", cmdName)
		respond(s, i, fmt.Sprintf("❌ Unknown command: %s", cmdName), false)
	}
}

