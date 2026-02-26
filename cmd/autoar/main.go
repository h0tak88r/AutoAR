package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/backup"
	asrmod "github.com/h0tak88r/AutoAR/internal/modules/asr"
	aemmod "github.com/h0tak88r/AutoAR/internal/modules/aem"
	apkxmod "github.com/h0tak88r/AutoAR/internal/modules/apkx"
	"github.com/h0tak88r/AutoAR/internal/modules/checktools"
	"github.com/h0tak88r/AutoAR/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/internal/modules/dalfox"
	"github.com/h0tak88r/AutoAR/internal/modules/depconfusion"
	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/dns"
	domainmod "github.com/h0tak88r/AutoAR/internal/modules/domain"
	"github.com/h0tak88r/AutoAR/internal/modules/fastlook"
	subdomainmod "github.com/h0tak88r/AutoAR/internal/modules/subdomain"
	"github.com/h0tak88r/AutoAR/internal/modules/ffuf"
	"github.com/h0tak88r/AutoAR/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/internal/modules/github-wordlist"
	"github.com/h0tak88r/AutoAR/internal/modules/githubscan"
	"github.com/h0tak88r/AutoAR/internal/modules/gobot"
	"github.com/h0tak88r/AutoAR/internal/modules/jsscan"
	jwtmod "github.com/h0tak88r/AutoAR/internal/modules/jwt"
	"github.com/h0tak88r/AutoAR/internal/modules/lite"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/misconfig"
	"github.com/h0tak88r/AutoAR/internal/modules/monitor"
	"github.com/h0tak88r/AutoAR/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/internal/modules/reflection"
	s3mod 	"github.com/h0tak88r/AutoAR/internal/modules/s3"
	"github.com/h0tak88r/AutoAR/internal/modules/setup"
	"github.com/h0tak88r/AutoAR/internal/modules/sqlmap"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	subdomainmonitor "github.com/h0tak88r/AutoAR/internal/modules/subdomainmonitor"
	"github.com/h0tak88r/AutoAR/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/h0tak88r/AutoAR/internal/modules/wp-confusion"
	"github.com/h0tak88r/AutoAR/internal/modules/envloader"
	scopemod "github.com/h0tak88r/AutoAR/internal/modules/scope"
	"github.com/h0tak88r/AutoAR/internal/modules/zerodays"
	"github.com/h0tak88r/AutoAR/internal/tools/apkx/downloader"
	"github.com/h0tak88r/AutoAR/internal/tools/apkx/mitm"
	next88 "github.com/h0tak88r/AutoAR/internal/tools/next88"
)

var (
	rootDir      string
	modulesDir   string
	autoarScript string
)

func init() {
	// Priority order for finding root directory:
	// 1. Check /app (Docker default)
	// 2. Check current working directory
	// 3. Check executable directory
	// 4. Fallback to "."

	if _, err := os.Stat("/app/modules"); err == nil {
		// Docker environment - use /app
		rootDir = "/app"
		modulesDir = "/app/modules"
	} else if cwd, err := os.Getwd(); err == nil {
		// Try current working directory
		if _, err := os.Stat(filepath.Join(cwd, "modules")); err == nil {
			rootDir = cwd
			modulesDir = filepath.Join(cwd, "modules")
		} else if exe, err := os.Executable(); err == nil {
			// Try executable directory
			exeDir := filepath.Dir(exe)
			if _, err := os.Stat(filepath.Join(exeDir, "modules")); err == nil {
				rootDir = exeDir
				modulesDir = filepath.Join(exeDir, "modules")
			} else {
				// Fallback
				rootDir = cwd
				modulesDir = filepath.Join(cwd, "modules")
			}
		} else {
			rootDir = cwd
			modulesDir = filepath.Join(cwd, "modules")
		}
	} else {
		rootDir = "."
		modulesDir = "./modules"
	}

	// Use the autoar binary directly
	autoarScript = os.Args[0]
}

func printUsage() {
	usage := `Usage: autoar <command> <action> [options]

Commands:
  subdomains get      -d <domain>
  livehosts get       -d <domain>
  cnames get          -d <domain>
  urls collect        -d <domain> [--subdomain]
  js scan             -d <domain> [-s <subdomain>]
  reflection scan     -d <domain>
  nuclei run          -d <domain>
  tech detect         -d <domain>
  ports scan          -d <domain>
  gf scan             -d <domain>
  sqlmap run          -d <domain>
  dalfox run          -d <domain>
  
  monitor updates add    -u <url> [--strategy ...] [--pattern <regex>]
  monitor updates remove -u <url>
  monitor updates start  [--interval <sec>] [--daemon] [--all]
  monitor updates stop   [--all]
  monitor updates list
  wpDepConf scan      -d <domain> | -l <live_hosts_file>
  dns takeover        -d <domain>     (comprehensive scan)
  dns cname           -d <domain>     (CNAME takeover only)
  dns ns              -d <domain>     (NS takeover only)
  dns azure-aws       -d <domain>     (Azure/AWS takeover only)
  dns dnsreaper       -d <domain>     (DNSReaper scan only)
  dns dangling-ip     -d <domain>     (Dangling IP detection only)
  dns all             -d <domain>     (comprehensive scan)
  s3 scan             -b <bucket> [-r <region>]
  s3 enum             -b <root_domain>
  github scan         -r <owner/repo>
  github org          -o <org> [-m <max-repos>]
  github depconfusion -r <owner/repo>
  github experimental -r <owner/repo>
  github-wordlist scan -o <github_org> [-t <github_token>]
  backup scan            -d <domain> [-m <method>] [-ex <extensions>] [-o <output_dir>] [-t <threads>] [--delay <ms>]
  backup scan            -l <live_hosts_file> [-m <method>] [-ex <extensions>] [-o <output_dir>] [-t <threads>] [--delay <ms>]
  backup scan            -f <domains_file> [-m <method>] [-ex <extensions>] [-o <output_dir>] [-t <threads>] [--delay <ms>]
                         Methods: regular, withoutdots, withoutvowels, reverse, mixed, withoutdv, shuffle, all
                         Extensions: comma-separated (e.g., .rar,.zip,.tar.gz) - default: all (uses all common backup extensions)
  aem scan               -d <domain> | -l <live_hosts_file> [-o <output_dir>] [-t <threads>] [--ssrf-host <host>] [--ssrf-port <port>] [--proxy <proxy>] [--debug] [--handler <handler>...]
                         Scans for AEM webapps and tests for vulnerabilities
  apkx scan              -i <apk_or_ipa_path> | -p <package_id> [--platform android|ios] [-o <output_dir>] [--mitm]
  apkx mitm              -i <apk_path> [-o <output_dir>] | -p <package_name> [-o <output_dir>]
  depconfusion scan <file>                    Scan local dependency file
  depconfusion github repo <owner/repo>       Scan GitHub repository
  depconfusion github org <org>               Scan GitHub organization
  depconfusion web <url> [url2] [url3]...     Scan web targets
  depconfusion web-file <file>                Scan targets from file
  misconfig scan <target> [--service <id>] [--delay <ms>] [--permutations]   Scan for misconfigurations
  misconfig service <target> <service-id>     Scan specific service
  scope -p <platform> [options]              Fetch scope from bug bounty platforms
                         Platforms: h1 (HackerOne), bc (Bugcrowd), it (Intigriti), ywh (YesWeHack), immunefi
                         Options:
                           -u, --username     Username (for HackerOne)
                           -t, --token        API token (required for most platforms)
                           -e, --email        Email (for Bugcrowd/YesWeHack login)
                           -P, --password     Password (for Bugcrowd/YesWeHack login)
                           -c, --categories   Categories filter (default: all)
                           -o, --output       Output file path (default: stdout)
                           --bbp-only         Only fetch programs offering monetary rewards
                           --pvt-only         Only fetch private programs
                           --include-oos      Include out-of-scope items
                           --public-only      Only fetch public programs (HackerOne)
                           --active-only      Only fetch active programs (HackerOne)
                           --extract-roots    Extract root domains (default: true)
                           --no-extract-roots Output raw targets instead of root domains
                           --concurrency      Concurrency level (default: 3)
  misconfig list                              List available services
  misconfig update                            Update templates
  keyhack list                                List all API key validation templates
  keyhack search <query>                      Search API key validation templates
  keyhack validate <provider> <api_key>       Generate validation command for API key
  keyhack add <keyname> <command> <desc> [notes] Add a new template
  jwt scan             --token <JWT_TOKEN> [OPTIONS]                Scan JWT token for vulnerabilities using jwt-hack
                                                                    Options: --skip-crack, --skip-payloads, --test-attacks, -w wordlist, --max-crack-attempts N
  zerodays scan        -d <domain> | -s <subdomain> | -f <domains_file> [-t <threads>] [--cve <cve>] [--dos-test] [--enable-source-exposure] [--mongodb-host <host>] [--mongodb-port <port>] [--silent]
                                                                    For each domain: collects live hosts, then runs smart scan
                                                                    --silent: Output only vulnerable hosts (one per line, no progress)
  ffuf fuzz            -u <url> | -d <domain> [-w <wordlist>] [-t <threads>] [--concurrency <n>] [--recursion] [--recursion-depth <depth>] [--bypass-403] [-e <extensions>] [--header <key:value>]
                                                                    Fuzz URLs with ffuf, filtering only 200 status codes
                                                                    Real-time size-based deduplication (skips duplicate response sizes)
                                                                    --bypass-403: Attempts 403 bypass techniques (headers and path modifications)
                                                                    Default wordlist: Wordlists/quick_fuzz.txt
                                                                    Single URL mode (-u): URL must contain FUZZ placeholder (e.g., https://target.com/FUZZ)
                                                                    Domain mode (-d): Fuzz all live hosts for the domain with concurrency (default: 5 hosts)
                                                                    Domain mode: searches live-subs.txt, checks database, or runs livehosts module if needed
  monitor subdomains   -d <domain> [-t <threads>] [--check-new]   Monitor subdomain status changes (one-time check)
                                                                    Detects: new subdomains, status changes, live/dead changes
  monitor subdomains manage <action> [options]                     Manage automatic subdomain monitoring targets
                                                                    Actions: list, add, remove, start, stop
                                                                    Options for add: -d <domain> -i <interval> -t <threads> [--check-new]
                                                                    Options for start/stop: --id <id> | -d <domain> | --all

Workflows:
  lite run            -d <domain>
  fastlook run        -d <domain>
  domain run          -d <domain>

Database:
  db domains list
  db domains delete   -d <domain>
  db subdomains list  -d <domain>
  db subdomains export -d <domain> [-o file]
  db js list          -d <domain>
  db backup           [--upload-r2]  Create database backup (optionally upload to R2)

Utilities:
  check-tools         Check if all required tools are installed
  setup               Install all AutoAR dependencies
  cleanup             Clean up the entire results directory
  help

Special:
  bot                 Start Discord bot
  api                 Start REST API server
  both                Start both bot and API
`
	fmt.Print(usage)
}

// runBashModule removed - all modules are now Go-based

func handleGitHubWordlist(args []string) error {
	var org, token string
	outputDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if outputDir == "" {
		outputDir = "new-results"
	}

	// Parse arguments: scan -o <org> [-t <token>]
	if len(args) < 2 || args[0] != "scan" {
		return fmt.Errorf("usage: github-wordlist scan -o <org> [-t <token>]")
	}

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-o", "--org":
			if i+1 < len(args) {
				org = args[i+1]
				i++
			}
		case "-t", "--token":
			if i+1 < len(args) {
				token = args[i+1]
				i++
			}
		}
	}

	if org == "" {
		return fmt.Errorf("organization (-o) is required")
	}

	return githubwordlist.GenerateWordlist(org, token, outputDir)
}

func handleWPConfusion(args []string) error {
	opts := wpconfusion.ScanOptions{}

	// Support both legacy bash-style and new AutoAR-style CLI:
	// - Legacy:  wpDepConf -u <url> [-t] [-p] [-o <output>]
	// - AutoAR:  wpDepConf scan -d <domain> | -l <live_hosts_file>
	//
	// We normalize:
	// - Leading "scan" subcommand is ignored
	// - "-d <domain>" is converted to URL "https://<domain>"
	// - At least one of Theme/Plugins is enabled (default: plugins only)
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// Ignore optional "scan" subcommand
		if arg == "scan" {
			continue
		}

		switch arg {
		case "-u", "--url":
			if i+1 < len(args) {
				opts.URL = args[i+1]
				i++
			}
		case "-d", "--domain":
			if i+1 < len(args) {
				domain := strings.TrimSpace(args[i+1])
				i++
				if domain != "" {
					// If the user passed bare domain (example.com), turn it into https://example.com
					if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
						opts.URL = "https://" + domain
					} else {
						opts.URL = domain
					}
				}
			}
		case "-l", "--list":
			if i+1 < len(args) {
				opts.List = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				opts.Output = args[i+1]
				i++
			}
		case "-t", "--theme":
			opts.Theme = true
		case "-p", "--plugins":
			opts.Plugins = true
		case "-s", "--silent":
			opts.Silent = true
		case "--discord":
			opts.Discord = true
		}
	}

	// If neither theme nor plugins explicitly set, default to plugins scan
	if !opts.Theme && !opts.Plugins {
		opts.Plugins = true
	}

	return wpconfusion.ScanWPConfusion(opts)
}

// handleCnamesCommand parses: autoar cnames get -d <domain>
// handleDomainCommand parses: autoar domain run -d <domain> [--skip-ffuf]
func handleDomainCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: domain run -d <domain> [--skip-ffuf]")
	}
	if args[0] == "run" {
		args = args[1:]
	}
	var domain string
	var skipFFuf bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "--skip-ffuf":
			skipFFuf = true
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	_, err := domainmod.RunDomain(domainmod.ScanOptions{
		Domain:   domain,
		SkipFFuf: skipFFuf,
	})
	
	// Cleanup domain directory after scan completes (on exit, not before)
	if cleanupErr := cleanupDomainDirectoryForCLI(domain); cleanupErr != nil {
		fmt.Printf("[WARN] Failed to cleanup domain directory for %s: %v\n", domain, cleanupErr)
	}
	
	return err
}

// handleCnamesCommand parses: autoar cnames get -d <domain>
// handleCnamesCommand parses: autoar cnames get -d <domain>
func handleCnamesCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: cnames get -d <domain>")
	}
	// Support legacy shape: cnames get -d <domain>
	if args[0] == "get" {
		args = args[1:]
	}
	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	// Simple collection call matching signature (domain string)
	_, err := cnames.CollectCNAMEs(domain)
	return err
}

// handleFastlookCommand parses: autoar fastlook run -d <domain>
func handleFastlookCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fastlook run -d <domain>")
	}
	if args[0] == "run" {
		args = args[1:]
	}
	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	// Run fastlook with no file callback
	_, err := fastlook.RunFastlook(domain, nil)
	return err
}



// handleSubdomainCommand parses: autoar subdomain run -s <subdomain>
func handleSubdomainCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: subdomain run -s <subdomain>")
	}
	if args[0] == "run" {
		args = args[1:]
	}
	var subdomain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-s", "--subdomain":
			if i+1 < len(args) {
				subdomain = args[i+1]
				i++
			}
		}
	}
	if subdomain == "" {
		return fmt.Errorf("subdomain (-s) is required; usage: subdomain run -s <subdomain>")
	}
	
	// Extract root domain from subdomain for cleanup
	rootDomain := extractRootDomainFromSubdomain(subdomain)
	
	_, err := subdomainmod.RunSubdomain(subdomain)
	
	// Cleanup domain directory after scan completes (on exit, not before)
	if cleanupErr := cleanupDomainDirectoryForCLI(rootDomain); cleanupErr != nil {
		fmt.Printf("[WARN] Failed to cleanup domain directory for %s: %v\n", rootDomain, cleanupErr)
	}
	
	return err
}

// extractRootDomainFromSubdomain extracts the root domain from a subdomain
// e.g., "www.example.com" -> "example.com", "sub.sub.example.com" -> "example.com"
func extractRootDomainFromSubdomain(host string) string {
	// Remove protocol if present
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	
	// Remove path if present
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		// Return last two parts (e.g., example.com)
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

// handleLiteCommand parses: autoar lite run -d <domain> [--skip-js] [--phase-timeout <seconds>] [--timeout-* <seconds>]
func handleLiteCommand(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: lite run -d <domain> [--skip-js] [--phase-timeout <seconds>] [--timeout-livehosts <seconds>] [--timeout-reflection <seconds>] [--timeout-js <seconds>] [--timeout-cnames <seconds>] [--timeout-backup <seconds>] [--timeout-dns <seconds>] [--timeout-misconfig <seconds>] [--timeout-nuclei <seconds>]")
	}
	args = args[1:]

	opts := lite.Options{
		PhaseTimeoutDefault: 3600, // 1 hour default
		Timeouts:            make(map[string]int),
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "--skip-js":
			opts.SkipJS = true
		case "--phase-timeout":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.PhaseTimeoutDefault = t
				}
				i++
			}
		case "--timeout-livehosts":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["livehosts"] = t
				}
				i++
			}
		case "--timeout-reflection":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["reflection"] = t
				}
				i++
			}
		case "--timeout-js":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["js"] = t
				}
				i++
			}
		case "--timeout-cnames":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["cnames"] = t
				}
				i++
			}
		case "--timeout-backup":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["backup"] = t
				}
				i++
			}
		case "--timeout-dns":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["dns"] = t
				}
				i++
			}
		case "--timeout-misconfig":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["misconfig"] = t
				}
				i++
			}
		case "--timeout-nuclei":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Timeouts["nuclei"] = t
				}
				i++
			}
		}
	}

	if opts.Domain == "" {
		return fmt.Errorf("domain (-d) is required; usage: lite run -d <domain>")
	}

	_, err := lite.RunLite(opts)
	return err
}

// handleNucleiCommand parses: autoar nuclei run -d <domain> | -u <url> [-m <mode>] [-t <threads>]
func handleNucleiCommand(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: nuclei run -d <domain> | -u <url> [-m <mode>] [-t <threads>]")
	}
	args = args[1:]

	opts := nuclei.Options{Threads: 100, Mode: nuclei.ModeFull}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-u", "--url":
			if i+1 < len(args) {
				opts.URL = args[i+1]
				i++
			}
		case "-m", "--mode":
			if i+1 < len(args) {
				opts.Mode = nuclei.ScanMode(args[i+1])
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Threads = t
				}
				i++
			}
		}
	}
	_, err := nuclei.RunNuclei(opts)
	return err
}

// handleReflectionCommand parses: autoar reflection scan -d <domain>
func handleReflectionCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: reflection scan -d <domain>")
	}
	args = args[1:]

	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}
	_, err := reflection.ScanReflection(domain)
	return err
}

// handleDalfoxCommand parses: autoar dalfox run -d <domain> [-t <threads>]
func handleDalfoxCommand(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: dalfox run -d <domain> [-t <threads>]")
	}
	args = args[1:]

	var domain string
	threads := 100
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}
	_, err := dalfox.RunDalfox(domain, threads)
	return err
}

// handleTechCommand parses: autoar tech detect -d <domain> [-t <threads>]
func handleTechCommand(args []string) error {
	if len(args) == 0 || args[0] != "detect" {
		return fmt.Errorf("usage: tech detect -d <domain> [-t <threads>]")
	}
	args = args[1:]

	var domain string
	threads := 100
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}
	_, err := tech.DetectTech(domain, threads)
	return err
}

// handleGFCommand parses: autoar gf scan -d <domain>
func handleGFCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: gf scan -d <domain>")
	}
	args = args[1:]

	var domain string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}
	_, err := gf.ScanGF(domain)
	return err
}

// handleSQLMapCommand parses: autoar sqlmap run -d <domain> [-t <threads>]
func handleSQLMapCommand(args []string) error {
	if len(args) == 0 || args[0] != "run" {
		return fmt.Errorf("usage: sqlmap run -d <domain> [-t <threads>]")
	}
	args = args[1:]

	var domain string
	threads := 100
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}
	_, err := sqlmap.RunSQLMap(domain, threads)
	return err
}

// handlePortsCommand parses: autoar ports scan -d <domain> [-t <threads>]
func handlePortsCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: ports scan -d <domain> [-t <threads>]")
	}
	args = args[1:]

	var domain string
	threads := 100
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}
	_, err := ports.ScanPorts(domain, threads)
	return err
}

// handleJSCommand parses:
//
//	autoar js scan -d <domain> [-s <subdomain>] [-t <threads>]
func handleJSCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: js scan -d <domain> [-s <subdomain>] [-t <threads>]")
	}
	args = args[1:]

	opts := jsscan.Options{Threads: 100}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-s", "--subdomain":
			if i+1 < len(args) {
				opts.Subdomain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Threads = t
				}
				i++
			}
		}
	}

	if opts.Domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	res, err := jsscan.Run(opts)
	if err != nil {
		return err
	}

	fmt.Printf("[OK] JS scan completed for %s; found %d JS URLs\n", res.Domain, res.TotalJS)
	fmt.Printf("[INFO] All URLs: %s\n", res.URLsFile)
	fmt.Printf("[INFO] JS URLs (vulnerabilities): %s\n", res.VulnJSFile)
	return nil
}

// handleFFufCommand parses: autoar ffuf fuzz -u <url> | -d <domain> [-w <wordlist>] [-t <threads>] [--recursion] [--bypass-403] [-e <extensions>] [--header <key:value>] [--concurrency <n>]
func handleFFufCommand(args []string) error {
	if len(args) == 0 || args[0] != "fuzz" {
		return fmt.Errorf("usage: ffuf fuzz -u <url> | -d <domain> [-w <wordlist>] [-t <threads>] [--recursion] [--recursion-depth <depth>] [--bypass-403] [-e <extensions>] [--header <key:value>] [--concurrency <n>]")
	}
	args = args[1:]

	opts := ffuf.Options{
		Threads:         40,
		FollowRedirects: true,
		CustomHeaders:    make(map[string]string),
		Concurrency:     5, // Default concurrency for domain mode
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u", "--url", "--target":
			if i+1 < len(args) {
				opts.Target = args[i+1]
				i++
			}
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-w", "--wordlist":
			if i+1 < len(args) {
				opts.Wordlist = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Threads = t
				}
				i++
			}
		case "--concurrency", "-c":
			if i+1 < len(args) {
				if c, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Concurrency = c
				}
				i++
			}
		case "--recursion", "-r":
			opts.Recursion = true
		case "--recursion-depth":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					opts.RecursionDepth = d
				}
				i++
			}
		case "--bypass-403", "--bypass403":
			opts.Bypass403 = true
		case "-e", "--extensions":
			if i+1 < len(args) {
				exts := strings.Split(args[i+1], ",")
				for _, ext := range exts {
					ext = strings.TrimSpace(ext)
					if ext != "" {
						if !strings.HasPrefix(ext, ".") {
							ext = "." + ext
						}
						opts.Extensions = append(opts.Extensions, ext)
					}
				}
				i++
			}
		case "--header", "-H":
			if i+1 < len(args) {
				header := args[i+1]
				if idx := strings.Index(header, ":"); idx != -1 {
					key := strings.TrimSpace(header[:idx])
					value := strings.TrimSpace(header[idx+1:])
					opts.CustomHeaders[key] = value
				}
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				opts.OutputFile = args[i+1]
				i++
			}
		}
	}

	// Validate that either -u or -d is provided, but not both
	if opts.Target == "" && opts.Domain == "" {
		return fmt.Errorf("either target URL (-u) or domain (-d) is required")
	}
	if opts.Target != "" && opts.Domain != "" {
		return fmt.Errorf("cannot use both -u and -d together; use -u for single URL or -d for domain mode")
	}

	// Domain mode: no need to add FUZZ placeholder (handled in domain mode)
	// Single target mode: ensure URL has FUZZ placeholder or add it
	if opts.Target != "" && !strings.Contains(opts.Target, "FUZZ") {
		if !strings.HasSuffix(opts.Target, "/") {
			opts.Target += "/"
		}
		opts.Target += "FUZZ"
	}

	result, err := ffuf.RunFFuf(opts)
	if err != nil {
		return err
	}

	if opts.Domain != "" {
		fmt.Printf("[OK] FFuf domain mode completed for %s\n", opts.Domain)
		fmt.Printf("[INFO] Scanned %d hosts, found %d total unique results\n", result.HostsScanned, result.TotalFound)
	} else {
	fmt.Printf("[OK] FFuf fuzzing completed for %s\n", opts.Target)
	fmt.Printf("[INFO] Found %d unique results\n", result.TotalFound)
	}
	fmt.Printf("[INFO] Results saved to: %s\n", result.OutputFile)
	return nil
}

// handleBackupCommand parses:
//
//	autoar backup scan -d <domain> [-m <method>] [-ex <extensions>] [-t <threads>] [--delay <ms>]
//	autoar backup scan -l <live_hosts_file> [-m <method>] [-ex <extensions>] [-t <threads>] [--delay <ms>]
//	autoar backup scan -f <domains_file> [-m <method>] [-ex <extensions>] [-t <threads>] [--delay <ms>]
func handleBackupCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: backup scan -d <domain> | -l <live_hosts_file> | -f <domains_file> [-m <method>] [-ex <extensions>] [-t <threads>] [--delay <ms>]")
	}
	args = args[1:]

	opts := backup.Options{Threads: 100, Method: "all"} // Default to "all" for comprehensive scanning

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-l", "--live-hosts", "-f", "--file":
			if i+1 < len(args) {
				opts.LiveHostsFile = args[i+1]
				i++
			}
		case "-m", "--method":
			if i+1 < len(args) {
				opts.Method = args[i+1]
				i++
			}
		case "-ex", "--extensions":
			if i+1 < len(args) {
				// Parse comma-separated extensions
				extStr := args[i+1]
				extensions := strings.Split(extStr, ",")
				for j := range extensions {
					ext := strings.TrimSpace(extensions[j])
					// Ensure extension starts with dot
					if ext != "" && !strings.HasPrefix(ext, ".") {
						ext = "." + ext
					}
					if ext != "" {
						opts.Extensions = append(opts.Extensions, ext)
					}
				}
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				opts.OutputDir = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Threads = t
				}
				i++
			}
		case "--delay":
			if i+1 < len(args) {
				if d, err := strconv.Atoi(args[i+1]); err == nil {
					opts.DelayMS = d
				}
				i++
			}
		}
	}

	if opts.Domain == "" && opts.LiveHostsFile == "" {
		return fmt.Errorf("either -d <domain> or -l <live_hosts_file> must be provided")
	}
	if opts.Domain != "" && opts.LiveHostsFile != "" {
		return fmt.Errorf("cannot use both -d and -l together")
	}

	res, err := backup.Run(opts)
	if err != nil {
		return err
	}

	if opts.Domain != "" {
		fmt.Printf("[OK] Backup scan completed for %s; found ~%d potential backup files\n", opts.Domain, res.FoundCount)
	} else {
		fmt.Printf("[OK] Backup scan completed for %d live hosts; found ~%d potential backup files\n", res.LiveHostsCount, res.FoundCount)
	}
	fmt.Printf("[INFO] Results saved to %s\n", res.ResultsFile)
	fmt.Printf("[INFO] Log saved to %s\n", res.LogFile)

	return nil
}

// handleApkXCommand parses:
//
//	autoar apkx scan -i <apk_or_ipa_path> | -p <package_id> [--platform android|ios] [-o <output_dir>] [--mitm]
//	autoar apkx mitm -i <apk_path> [-o <output_dir>] | -p <package_name> [-o <output_dir>]
func handleApkXCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apkx <scan|mitm> [options]")
	}

	subcommand := args[0]
	args = args[1:]

	switch subcommand {
	case "scan":
		return handleApkXScan(args)
	case "mitm":
		return handleApkXMitm(args)
	default:
		return fmt.Errorf("unknown apkx subcommand: %s (use 'scan' or 'mitm')", subcommand)
	}
}

func handleApkXScan(args []string) error {
	opts := apkxmod.Options{}
	var packageName string
	var platform string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--input":
			if i+1 < len(args) {
				opts.InputPath = args[i+1]
				i++
			}
		case "-p", "--package":
			if i+1 < len(args) {
				packageName = args[i+1]
				i++
			}
		case "--platform":
			if i+1 < len(args) {
				platform = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				opts.OutputDir = args[i+1]
				i++
			}
		case "--mitm":
			opts.MITM = true
		}
	}

	// If package name is provided, use RunFromPackage instead of Run
	if packageName != "" {
		if platform == "" {
			platform = "android" // Default to android
		}
		
		packageOpts := apkxmod.PackageOptions{
			Package:  packageName,
			Platform:  platform,
			OutputDir: opts.OutputDir,
			MITM:      opts.MITM,
		}
		
		res, err := apkxmod.RunFromPackage(packageOpts)
		if err != nil {
			return err
		}
		
		fmt.Printf("[OK] apkX scan completed. Reports in: %s\n", res.ReportDir)
		fmt.Printf("[INFO] Log: %s\n", res.LogFile)
		if res.FromCache {
			fmt.Printf("[INFO] ✅ Results loaded from cache\n")
		}
		if res.MITMPatchedAPK != "" {
			fmt.Printf("[OK] MITM patched APK: %s\n", res.MITMPatchedAPK)
		}
		return nil
	}

	// Otherwise, require input path
	if opts.InputPath == "" {
		return fmt.Errorf("input path (-i) or package name (-p) is required")
	}

	res, err := apkxmod.Run(opts)
	if err != nil {
		return err
	}

	fmt.Printf("[OK] apkX scan completed. Reports in: %s\n", res.ReportDir)
	fmt.Printf("[INFO] Log: %s\n", res.LogFile)
	if res.MITMPatchedAPK != "" {
		fmt.Printf("[OK] MITM patched APK: %s\n", res.MITMPatchedAPK)
	}
	return nil
}

func handleApkXMitm(args []string) error {
	var inputPath, outputDir, packageName string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--input":
			if i+1 < len(args) {
				inputPath = args[i+1]
				i++
			}
		case "-p", "--package":
			if i+1 < len(args) {
				packageName = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				outputDir = args[i+1]
				i++
			}
		}
	}

	// If package name provided, download APK first
	if packageName != "" {
		fmt.Printf("[INFO] Downloading APK for package: %s\n", packageName)
		tmpDir, err := os.MkdirTemp("", "autoar-mitm-dl-*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		client, err := downloader.NewApkPureClient()
		if err != nil {
			return fmt.Errorf("failed to create ApkPure client: %w", err)
		}

		downloadedPath, err := client.DownloadAPKByPackage(context.Background(), packageName, tmpDir)
		if err != nil {
			return fmt.Errorf("failed to download APK: %w", err)
		}
		inputPath = downloadedPath
		fmt.Printf("[OK] Downloaded APK: %s\n", inputPath)
	}

	if inputPath == "" {
		return fmt.Errorf("either input path (-i) or package name (-p) is required")
	}

	// Set default output directory if not provided
	if outputDir == "" {
		outputDir = filepath.Join(filepath.Dir(inputPath), "mitm-patched")
		os.MkdirAll(outputDir, 0755)
	}

	fmt.Printf("[INFO] Starting MITM patching for: %s\n", inputPath)
	fmt.Printf("[INFO] Output directory: %s\n", outputDir)

	// Initialize patcher
	patcher, err := mitm.NewPatcher()
	if err != nil {
		return fmt.Errorf("failed to initialize MITM patcher: %w", err)
	}

	// Patch the APK
	patchedPath, err := patcher.PatchAPK(inputPath, outputDir)
	if err != nil {
		return fmt.Errorf("MITM patching failed: %w", err)
	}

	if patchedPath == "" {
		return fmt.Errorf("MITM patching returned empty path")
	}

	// Verify file exists
	if info, err := os.Stat(patchedPath); err != nil {
		return fmt.Errorf("patched APK file not found: %w", err)
	} else {
		fmt.Printf("[OK] MITM patched APK created successfully!\n")
		fmt.Printf("[OK] Path: %s\n", patchedPath)
		fmt.Printf("[OK] Size: %d bytes (%.2f MB)\n", info.Size(), float64(info.Size())/1024/1024)
	}

	return nil
}

// handleJWTCommand parses:
//
//	autoar jwt scan --token <JWT_TOKEN> [--skip-crack] [--skip-payloads] [--test-attacks] [-w wordlist] [--max-crack-attempts N]
//	autoar jwt scan <JWT_TOKEN> [--skip-crack] [--skip-payloads] [--test-attacks] [-w wordlist] [--max-crack-attempts N]
//
// Internally this is normalized to:
//
//	jwt-hack scan <JWT_TOKEN> [flags...]
func handleJWTCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: jwt scan --token <JWT_TOKEN> [--skip-crack] [--skip-payloads] [--test-attacks] [-w wordlist] [--max-crack-attempts N]")
	}
	raw := args[1:]
	if len(raw) == 0 {
		return fmt.Errorf("JWT token and options are required; see: jwt scan --token <JWT>")
	}

	// Normalize CLI flags/positionals so jwt-hack always sees:
	//   jwt-hack scan <TOKEN> [flags...]
	var (
		token      string
		jwtArgs    []string
		skipNext   bool
	)

	for i := 0; i < len(raw); i++ {
		if skipNext {
			// Previous iteration already consumed this as a value
			skipNext = false
			continue
		}

		arg := raw[i]

		switch arg {
		case "--token", "-t":
			// Explicit token flag
			if i+1 < len(raw) {
				token = raw[i+1]
				skipNext = true
			}
		case "-w", "--wordlist", "--max-crack-attempts":
			// Flags that expect a value – keep them (and their value) as-is
			if i+1 < len(raw) {
				jwtArgs = append(jwtArgs, arg, raw[i+1])
				skipNext = true
			} else {
				jwtArgs = append(jwtArgs, arg)
			}
		default:
			if strings.HasPrefix(arg, "-") {
				// Boolean-style flags (e.g. --skip-crack, --skip-payloads)
				jwtArgs = append(jwtArgs, arg)
			} else if token == "" {
				// First non-flag positional is treated as the token
				token = arg
			} else {
				// Any extra positionals are passed through as-is
				jwtArgs = append(jwtArgs, arg)
			}
		}
	}

	if token == "" {
		return fmt.Errorf("JWT token is required; pass it positionally or via --token <JWT>")
	}

	finalArgs := append([]string{token}, jwtArgs...)

	outPath, err := jwtmod.RunScan(finalArgs)
	if err != nil {
		return err
	}
	fmt.Printf("[OK] JWT scan completed; results saved to %s\n", outPath)
	return nil
}

// generateKeyhackCommand generates a CLI POC command from a KeyhackTemplate.
// It handles HTTP methods (GET, POST, etc.) by generating curl commands,
// and SHELL methods by returning the command_template directly.
func generateKeyhackCommand(t db.KeyhackTemplate, apiKey string) string {
	method := strings.ToUpper(t.Method)
	if method == "" {
		method = "GET"
	}

	// For SHELL methods, use the command_template directly and substitute API key
	if method == "SHELL" {
		cmd := t.CommandTemplate
		if apiKey != "" {
			cmd = strings.ReplaceAll(cmd, "$API_KEY", apiKey)
			cmd = strings.ReplaceAll(cmd, "${API_KEY}", apiKey)
			cmd = strings.ReplaceAll(cmd, "YOUR_API_KEY", apiKey)
		}
		return cmd
	}

	// For HTTP methods, generate curl command
	url := t.URL
	if url == "" && t.CommandTemplate != "" {
		// Try to extract URL from command_template JSON if URL is empty
		// This handles cases where URL might be in the JSON
		if strings.Contains(t.CommandTemplate, `"url"`) {
			// Simple extraction - look for "url": "value"
			urlStart := strings.Index(t.CommandTemplate, `"url":`)
			if urlStart != -1 {
				urlValueStart := strings.Index(t.CommandTemplate[urlStart:], `"`)
				if urlValueStart != -1 {
					urlValueStart += urlStart + 1
					urlValueEnd := strings.Index(t.CommandTemplate[urlValueStart:], `"`)
					if urlValueEnd != -1 {
						url = t.CommandTemplate[urlValueStart : urlValueStart+urlValueEnd]
					}
				}
			}
		}
	}

	if url == "" {
		url = "https://api.example.com"
	}

	// Build curl command
	curlParts := []string{"curl", "-X", method}

	// Add headers
	if t.Header != "" {
		header := t.Header
		if apiKey != "" {
			header = strings.ReplaceAll(header, "$API_KEY", apiKey)
			header = strings.ReplaceAll(header, "${API_KEY}", apiKey)
			header = strings.ReplaceAll(header, "YOUR_API_KEY", apiKey)
		}
		curlParts = append(curlParts, "-H", fmt.Sprintf(`"%s"`, header))
	} else if apiKey != "" {
		// Default Authorization header if no header specified
		curlParts = append(curlParts, "-H", fmt.Sprintf(`"Authorization: Bearer %s"`, apiKey))
	}

	// Add body for POST/PUT/PATCH
	if (method == "POST" || method == "PUT" || method == "PATCH") && t.Body != "" {
		body := t.Body
		if apiKey != "" {
			body = strings.ReplaceAll(body, "$API_KEY", apiKey)
			body = strings.ReplaceAll(body, "${API_KEY}", apiKey)
			body = strings.ReplaceAll(body, "YOUR_API_KEY", apiKey)
		}
		curlParts = append(curlParts, "-d", fmt.Sprintf(`'%s'`, body))
	}

	// Add URL (with API key substitution if needed)
	if apiKey != "" {
		url = strings.ReplaceAll(url, "$API_KEY", apiKey)
		url = strings.ReplaceAll(url, "${API_KEY}", apiKey)
		url = strings.ReplaceAll(url, "YOUR_API_KEY", apiKey)
		url = strings.ReplaceAll(url, "{API_KEY}", apiKey)
		// Handle common query parameter patterns
		url = strings.ReplaceAll(url, "?key=", fmt.Sprintf("?key=%s", apiKey))
		url = strings.ReplaceAll(url, "&key=", fmt.Sprintf("&key=%s", apiKey))
		url = strings.ReplaceAll(url, "?api_key=", fmt.Sprintf("?api_key=%s", apiKey))
		url = strings.ReplaceAll(url, "&api_key=", fmt.Sprintf("&api_key=%s", apiKey))
	}
	curlParts = append(curlParts, url)

	return strings.Join(curlParts, " ")
}

// handleZerodaysCommand handles CLI zerodays scan
// Usage: zerodays scan -d <domain> | -s <subdomain> | -f <domains_file> [-t <threads>] [--cve <cve>] [--dos-test] [--enable-source-exposure] [--mongodb-host <host>] [--mongodb-port <port>] [--silent]
func handleZerodaysCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: zerodays scan -d <domain> | -s <subdomain> | -f <domains_file> [-t <threads>] [--cve <cve>] [--dos-test] [--enable-source-exposure] [--mongodb-host <host>] [--mongodb-port <port>] [--silent]")
	}
	args = args[1:]

	var domain, subdomain, domainsFile string
	threads := 100
	dosTest := false
	enableSourceExposure := false
	silent := false
	var cves []string
	mongoDBHost := ""
	mongoDBPort := 27017

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-s", "--subdomain":
			if i+1 < len(args) {
				// Clean URL: remove http:// or https:// prefix
				subdomain = strings.TrimPrefix(strings.TrimPrefix(args[i+1], "https://"), "http://")
				// Remove trailing slash if present
				subdomain = strings.TrimSuffix(subdomain, "/")
				i++
			}
		case "-f", "--file":
			if i+1 < len(args) {
				domainsFile = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		case "--cve":
			if i+1 < len(args) {
				cves = append(cves, args[i+1])
				i++
			}
		case "--dos-test":
			dosTest = true
		case "--enable-source-exposure":
			enableSourceExposure = true
		case "--mongodb-host":
			if i+1 < len(args) {
				mongoDBHost = args[i+1]
				i++
			}
		case "--mongodb-port":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil {
					mongoDBPort = p
				}
				i++
			}
		case "--silent":
			silent = true
		}
	}

	// Validate that exactly one input method is provided
	inputCount := 0
	if domain != "" {
		inputCount++
	}
	if subdomain != "" {
		inputCount++
	}
	if domainsFile != "" {
		inputCount++
	}

	if inputCount == 0 {
		return fmt.Errorf("either -d <domain>, -s <subdomain>, or -f <domains_file> must be provided")
	}
	if inputCount > 1 {
		return fmt.Errorf("cannot use -d, -s, and -f together - use only one")
	}

	var domains []string
	var isSubdomainMode bool
	
	if subdomain != "" {
		// Single subdomain mode
		domains = []string{subdomain}
		isSubdomainMode = true
	} else if domain != "" {
		// Single domain mode
		domains = []string{domain}
		isSubdomainMode = false
	} else {
		// Read domains from file
		file, err := os.Open(domainsFile)
		if err != nil {
			return fmt.Errorf("failed to open domains file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				domains = append(domains, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading domains file: %w", err)
		}
		if len(domains) == 0 {
			return fmt.Errorf("no valid domains found in file")
		}
		isSubdomainMode = false // File mode defaults to domain mode
	}

	// Set silent mode for file scanning
	os.Setenv("AUTOAR_SILENT", "true")
	defer os.Unsetenv("AUTOAR_SILENT")

	// Print initial status (only if not silent)
	if !silent {
		if isSubdomainMode {
			fmt.Fprintf(os.Stderr, "Starting zerodays scan for subdomain: %s\n", subdomain)
		} else {
			fmt.Fprintf(os.Stderr, "Starting zerodays scan for %d domain(s)...\n", len(domains))
		}
		if len(cves) > 0 {
			fmt.Fprintf(os.Stderr, "CVEs to check: %s\n", strings.Join(cves, ", "))
		} else {
			fmt.Fprintf(os.Stderr, "CVEs to check: All (CVE-2025-55182, CVE-2025-14847)\n")
		}
		if len(domains) > 1 {
			fmt.Fprintf(os.Stderr, "Processing sequentially...\n\n")
		}
	}

	// Process each domain
	for idx, targetDomain := range domains {
		// Print progress immediately (only if not silent)
		if !silent && len(domains) > 1 {
			fmt.Fprintf(os.Stderr, "[%d/%d] Processing %s...\n", idx+1, len(domains), targetDomain)
		}

		// Prepare zerodays options
		zerodaysOpts := zerodays.Options{
			Threads:             threads,
			DOSTest:             dosTest,
			EnableSourceExposure: enableSourceExposure,
			Silent:              silent,
			CVEs:                cves,
			MongoDBHost:         mongoDBHost,
			MongoDBPort:         mongoDBPort,
		}

		// Set Domain or Subdomain based on input mode
		if isSubdomainMode {
			zerodaysOpts.Subdomain = targetDomain
		} else {
			// For file mode, try to detect if it's a subdomain
			parts := strings.Split(targetDomain, ".")
			if len(parts) > 2 {
				zerodaysOpts.Subdomain = targetDomain
			} else {
				zerodaysOpts.Domain = targetDomain
			}
		}

		// Run zerodays scan
		result, err := zerodays.Run(zerodaysOpts)
		if err != nil {
			if !silent {
				fmt.Printf("[%d/%d] %s: ERROR - %v\n", idx+1, len(domains), targetDomain, err)
			}
			continue
		}

		// Save results (always save, even in silent mode)
		resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
		if resultsDir == "" {
			resultsDir = "new-results"
		}
		outputDir := filepath.Join(resultsDir, targetDomain, "zerodays")
		// Always save results, regardless of silent mode
		// Log save attempt even in silent mode for debugging
		if !silent {
			fmt.Printf("[%d/%d] %s: Saving results to %s...\n", idx+1, len(domains), targetDomain, outputDir)
		}
		if err := zerodays.SaveResults(result, outputDir); err != nil {
			// Always log save errors, even in silent mode (this is critical)
			fmt.Fprintf(os.Stderr, "[WARN] Failed to save zerodays results to %s: %v\n", outputDir, err)
		} else {
			// Verify files were created (even in silent mode)
			react2ShellFile := filepath.Join(outputDir, "react2shell-cve-2025-55182.txt")
			mongoFile := filepath.Join(outputDir, "mongodb-cve-2025-14847.txt")
			jsonFile := filepath.Join(outputDir, "zerodays-results.json")
			
			// Check all expected files
			filesExist := true
			if _, err := os.Stat(react2ShellFile); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] React2Shell results file not found: %s (error: %v)\n", react2ShellFile, err)
				filesExist = false
			}
			if _, err := os.Stat(mongoFile); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] MongoDB results file not found: %s (error: %v)\n", mongoFile, err)
				filesExist = false
			}
			if _, err := os.Stat(jsonFile); err != nil {
				fmt.Fprintf(os.Stderr, "[WARN] Zerodays JSON file not found: %s (error: %v)\n", jsonFile, err)
				filesExist = false
			}
			
			if filesExist && !silent {
				fmt.Printf("[%d/%d] %s: Results saved to %s\n", idx+1, len(domains), targetDomain, outputDir)
			}
		}

		// Print output
		if len(result.React2ShellVulns) > 0 || len(result.MongoDBVulns) > 0 {
			if silent {
				// Silent mode: output vulnerable hosts
				for _, vuln := range result.React2ShellVulns {
					fmt.Printf("%s [React2Shell:%s]\n", vuln.URL, vuln.Type)
				}
				for _, vuln := range result.MongoDBVulns {
					if vuln.Vulnerable {
						fmt.Printf("%s:%d [MongoDB:CVE-2025-14847]\n", vuln.Host, vuln.Port)
					}
				}
			} else {
				// Verbose mode: show full details
				fmt.Printf("[%d/%d] %s: %d hosts scanned, %d vulnerable:\n", idx+1, len(domains), targetDomain, result.TotalHostsScanned, result.TotalVulnerable)
				for _, vuln := range result.React2ShellVulns {
					fmt.Printf("  - %s [React2Shell:%s] - %s\n", vuln.URL, vuln.Type, vuln.Severity)
				}
				for _, vuln := range result.MongoDBVulns {
					if vuln.Vulnerable {
						fmt.Printf("  - %s:%d [MongoDB:CVE-2025-14847] - Leaked %d bytes\n", vuln.Host, vuln.Port, len(vuln.LeakedData))
					}
				}
			}
		} else {
			if !silent {
				fmt.Printf("[%d/%d] %s: %d hosts scanned\n", idx+1, len(domains), targetDomain, result.TotalHostsScanned)
			}
		}

		// Cleanup domain directory after each domain scan
		// BUT: Skip cleanup if running from subdomain/domain workflow (they need the files)
		// Check if we're being called from another workflow by checking for workflow environment variables
		isWorkflowRun := os.Getenv("AUTOAR_CURRENT_CHANNEL_ID") != "" || os.Getenv("AUTOAR_CURRENT_SCAN_ID") != ""
		// Also skip cleanup for subdomain mode (when -s flag is used) as files are needed by workflow
		if !isWorkflowRun && !isSubdomainMode {
			if err := cleanupDomainDirectoryForCLI(targetDomain); err != nil {
				if !silent {
					fmt.Printf("[WARN] Failed to cleanup domain directory for %s: %v\n", targetDomain, err)
				}
			}
		} else if !silent {
			// Log that we're skipping cleanup
			if isWorkflowRun {
				fmt.Printf("[DEBUG] Skipping cleanup (workflow run detected)\n")
			} else if isSubdomainMode {
				fmt.Printf("[DEBUG] Skipping cleanup (subdomain mode - files needed by workflow)\n")
			}
		}
	}

	return nil
}

// cleanupDomainDirectoryForCLI removes the domain's result directory
func cleanupDomainDirectoryForCLI(domain string) error {
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}
	
	domainDir := filepath.Join(resultsDir, domain)
	
	if _, err := os.Stat(domainDir); os.IsNotExist(err) {
		return nil // Directory doesn't exist, nothing to clean
	}
	
	if err := os.RemoveAll(domainDir); err != nil {
		return fmt.Errorf("failed to cleanup domain directory: %w", err)
	}
	return nil
}

// handleScopeCommand handles CLI scope fetching from bug bounty platforms
// Usage: scope -p <platform> [options]
func handleScopeCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: scope -p <platform> [options]\nPlatforms: h1, bc, it, ywh, immunefi")
	}

	opts := scopemod.Options{
		Categories:   "all",
		Concurrency:  3,
		ActiveOnly:   false,
		PublicOnly:   false,
		ExtractRoots: true, // Default to true for backward compatibility
	}

	var platform string
	var outputFile string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-p", "--platform":
			if i+1 < len(args) {
				platform = args[i+1]
				i++
			}
		case "-u", "--username":
			if i+1 < len(args) {
				opts.Username = args[i+1]
				i++
			}
		case "-t", "--token":
			if i+1 < len(args) {
				opts.Token = args[i+1]
				i++
			}
		case "-e", "--email":
			if i+1 < len(args) {
				opts.Email = args[i+1]
				i++
			}
		case "-P", "--password":
			if i+1 < len(args) {
				opts.Password = args[i+1]
				i++
			}
		case "-c", "--categories":
			if i+1 < len(args) {
				opts.Categories = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "--bbp-only":
			opts.BBPOnly = true
		case "--pvt-only":
			opts.PvtOnly = true
		case "--include-oos":
			opts.IncludeOOS = true
		case "--public-only":
			opts.PublicOnly = true
		case "--active-only":
			opts.ActiveOnly = true
		case "--extract-roots":
			opts.ExtractRoots = true
		case "--no-extract-roots":
			opts.ExtractRoots = false
		case "--concurrency":
			if i+1 < len(args) {
				if c, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Concurrency = c
				}
				i++
			}
		}
	}

	if platform == "" {
		return fmt.Errorf("platform (-p) is required")
	}

	// Map platform string to Platform type
	switch platform {
	case "h1", "hackerone":
		opts.Platform = scopemod.PlatformHackerOne
	case "bc", "bugcrowd":
		opts.Platform = scopemod.PlatformBugcrowd
	case "it", "intigriti":
		opts.Platform = scopemod.PlatformIntigriti
	case "ywh", "yeswehack":
		opts.Platform = scopemod.PlatformYesWeHack
	case "immunefi":
		opts.Platform = scopemod.PlatformImmunefi
	default:
		return fmt.Errorf("unsupported platform: %s (supported: h1, bc, it, ywh, immunefi)", platform)
	}

	// Fetch scope
	fmt.Fprintf(os.Stderr, "Fetching scope from %s...\n", platform)
	programs, err := scopemod.FetchScope(opts)
	if err != nil {
		return fmt.Errorf("failed to fetch scope: %w", err)
	}

	var results []string
	var resultType string

	if opts.ExtractRoots {
		// Extract root domains
		fmt.Fprintf(os.Stderr, "Extracting root domains...\n")
		results, err = scopemod.ExtractRootDomains(programs)
		if err != nil {
			return fmt.Errorf("failed to extract root domains: %w", err)
		}
		resultType = "root domains"
	} else {
		// Extract raw targets
		fmt.Fprintf(os.Stderr, "Extracting raw targets...\n")
		results = scopemod.ExtractRawTargets(programs)
		resultType = "targets"
	}

	// Write output
	if err := scopemod.WriteRootDomains(results, outputFile); err != nil {
		return fmt.Errorf("failed to write %s: %w", resultType, err)
	}

	if outputFile != "" {
		fmt.Fprintf(os.Stderr, "Found %d %s, written to %s\n", len(results), resultType, outputFile)
	} else {
		fmt.Fprintf(os.Stderr, "Found %d %s\n", len(results), resultType)
	}

	return nil
}

// Helper functions for CLI
func getLiveHostsForCLI(domain string, threads int) (string, error) {
	return getLiveHostsForCLIWithContext(context.Background(), domain, threads)
}

func getLiveHostsForCLIWithContext(ctx context.Context, domain string, threads int) (string, error) {
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}

	subsDir := filepath.Join(resultsDir, domain, "subs")

	// Check if subdomains exist in database first
	shouldCollect := true
	silent := os.Getenv("AUTOAR_SILENT") == "true"
	if os.Getenv("DB_HOST") != "" || os.Getenv("SAVE_TO_DB") == "true" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			count, err := db.CountSubdomains(domain)
			if err == nil && count > 0 {
				if !silent {
					fmt.Printf("[INFO] Found %d subdomains in database for %s, skipping collection\n", count, domain)
				}
				shouldCollect = false
				// Load subdomains from DB and write to file for compatibility
				subs, err := db.ListSubdomains(domain)
				if err == nil && len(subs) > 0 {
					allSubsFile := filepath.Join(subsDir, "all-subs.txt")
					os.MkdirAll(subsDir, 0755)
					if err := writeLinesToFileForCLI(allSubsFile, subs); err != nil {
						if !silent {
							fmt.Printf("[WARN] Failed to write subdomains from DB to file: %v\n", err)
						}
					}
				}
			}
		}
	}

	// Only collect subdomains if not in database
	if shouldCollect {
		// Ensure subdomains exist first
		subCmd := exec.CommandContext(ctx, os.Args[0], "subdomains", "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "-s")
		if err := subCmd.Run(); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return "", context.DeadlineExceeded
			}
			return "", fmt.Errorf("subdomain enumeration failed: %w", err)
		}
	}

	// Run livehosts
	cmd := exec.CommandContext(ctx, os.Args[0], "livehosts", "get", "-d", domain, "-t", fmt.Sprintf("%d", threads), "--silent")
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", context.DeadlineExceeded
		}
		return "", fmt.Errorf("livehosts failed: %w", err)
	}

	// Check for live hosts file
	liveHostsFile := filepath.Join(subsDir, "live-subs.txt")
	if fileInfo, err := os.Stat(liveHostsFile); err == nil && fileInfo.Size() > 0 {
		return liveHostsFile, nil
	}

	// Fallback to all-subs.txt
	allSubsFile := filepath.Join(subsDir, "all-subs.txt")
	if fileInfo, err := os.Stat(allSubsFile); err == nil && fileInfo.Size() > 0 {
		return allSubsFile, nil
	}

	return "", fmt.Errorf("no live hosts file found")
}

func normalizeHostsForCLI(hostsFile string) ([]string, error) {
	data, err := os.ReadFile(hostsFile)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	normalized := make([]string, 0, len(lines))

	for _, line := range lines {
		host := strings.TrimSpace(line)
		if host == "" {
			continue
		}
		host = strings.TrimSuffix(host, "/")
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "https://" + host
		}
		normalized = append(normalized, host)
	}

	return normalized, nil
}

func runNext88ScanForCLI(hosts []string, extraFlags []string) ([]string, error) {
	return runNext88ScanForCLIWithContext(context.Background(), hosts, extraFlags)
}

// runNext88ScanForCLIWithTypes returns a map of host -> vulnerability type
func runNext88ScanForCLIWithTypes(ctx context.Context, hosts []string, extraFlags []string) (map[string]string, error) {
	if len(hosts) == 0 {
		return make(map[string]string), nil
	}

	opts := next88.ScanOptions{
		Timeout:         10 * time.Second,
		VerifySSL:       false,
		FollowRedirects: true,
		SafeCheck:       false,
		Windows:         false,
		WAFBypass:       false,
		WAFBypassSizeKB: 128,
		VercelWAFBypass: false,
		Paths:           nil,
		DoubleEncode:    false,
		SemicolonBypass: false,
		CheckSourceExp:  false,
		CustomHeaders:   make(map[string]string),
		Threads:         10,
		Quiet:           true,
		Verbose:         false,
		NoColor:         true,
		AllResults:      true,
		DiscordWebhook:  "",
		DOSTest:         false,
		DOSRequests:     100,
		SmartScan:       false,
	}

	if len(hosts) < opts.Threads {
		opts.Threads = len(hosts)
		if opts.Threads == 0 {
			opts.Threads = 1
		}
	}

	for i := 0; i < len(extraFlags); i++ {
		flag := extraFlags[i]
		switch flag {
		case "-smart-scan":
			opts.SmartScan = true
		case "-dos-test":
			opts.DOSTest = true
		case "-dos-requests":
			if i+1 < len(extraFlags) {
				if v, err := strconv.Atoi(extraFlags[i+1]); err == nil && v > 0 {
					opts.DOSRequests = v
				}
				i++
			}
		case "-check-source-exposure":
			opts.CheckSourceExp = true
		}
	}

	// Check context before running
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	results, err := next88.Run(hosts, opts)
	if err != nil {
		// Check if context was cancelled during execution
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, err
		}
	}

	vulnerableHosts := make(map[string]string) // host -> vuln type
	for _, res := range results {
		if res.Vulnerable != nil && *res.Vulnerable {
			host := res.Host
			if host == "" {
				host = res.TestedURL
			}
			if host == "" {
				continue
			}
			hostname := extractHostnameForCLI(host)
			if hostname != "" {
				vulnType := res.VulnType
				if vulnType == "" {
					// Default based on scan type
					if opts.DOSTest {
						vulnType = "dos-test"
					} else if opts.CheckSourceExp {
						vulnType = "source-exposure"
					} else {
						vulnType = "normal"
					}
				}
				// If host already exists, combine types (e.g., "normal,source-exposure")
				if existingType, exists := vulnerableHosts[hostname]; exists {
					if existingType != vulnType && !strings.Contains(existingType, vulnType) {
						vulnerableHosts[hostname] = existingType + "," + vulnType
					}
				} else {
					vulnerableHosts[hostname] = vulnType
				}
			}
		}
	}

	return vulnerableHosts, nil
}

func runNext88ScanForCLIWithContext(ctx context.Context, hosts []string, extraFlags []string) ([]string, error) {
	if len(hosts) == 0 {
		return []string{}, nil
	}

	opts := next88.ScanOptions{
		Timeout:         10 * time.Second,
		VerifySSL:       false,
		FollowRedirects: true,
		SafeCheck:       false,
		Windows:         false,
		WAFBypass:       false,
		WAFBypassSizeKB: 128,
		VercelWAFBypass: false,
		Paths:           nil,
		DoubleEncode:    false,
		SemicolonBypass: false,
		CheckSourceExp:  false,
		CustomHeaders:   make(map[string]string),
		Threads:         10,
		Quiet:           true,
		Verbose:         false,
		NoColor:         true,
		AllResults:      true,
		DiscordWebhook:  "",
		DOSTest:         false,
		DOSRequests:     100,
		SmartScan:       false,
	}

	if len(hosts) < opts.Threads {
		opts.Threads = len(hosts)
		if opts.Threads == 0 {
			opts.Threads = 1
		}
	}

	for i := 0; i < len(extraFlags); i++ {
		flag := extraFlags[i]
		switch flag {
		case "-smart-scan":
			opts.SmartScan = true
		case "-dos-test":
			opts.DOSTest = true
		case "-dos-requests":
			if i+1 < len(extraFlags) {
				if v, err := strconv.Atoi(extraFlags[i+1]); err == nil && v > 0 {
					opts.DOSRequests = v
				}
				i++
			}
		case "-check-source-exposure":
			opts.CheckSourceExp = true
		}
	}

	// Check context before running
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	results, err := next88.Run(hosts, opts)
	if err != nil {
		// Check if context was cancelled during execution
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			return nil, err
		}
	}

	vulnerableHosts := make(map[string]string) // host -> vuln type
	for _, res := range results {
		if res.Vulnerable != nil && *res.Vulnerable {
			host := res.Host
			if host == "" {
				host = res.TestedURL
			}
			if host == "" {
				continue
			}
			hostname := extractHostnameForCLI(host)
			if hostname != "" {
				vulnType := res.VulnType
				if vulnType == "" {
					// Default to "normal" if not set (for backward compatibility)
					vulnType = "normal"
				}
				// If host already exists, combine types (e.g., "normal,source-exposure")
				if existingType, exists := vulnerableHosts[hostname]; exists {
					if existingType != vulnType && !strings.Contains(existingType, vulnType) {
						vulnerableHosts[hostname] = existingType + "," + vulnType
					}
				} else {
					vulnerableHosts[hostname] = vulnType
				}
			}
		}
	}

	out := make([]string, 0, len(vulnerableHosts))
	for h := range vulnerableHosts {
		out = append(out, h)
	}

	return out, nil
}

func extractHostnameForCLI(url string) string {
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	parts := strings.Split(url, "/")
	host := parts[0]
	parts = strings.Split(host, ":")
	return parts[0]
}

// writeLinesToFileForCLI writes lines to a file
func writeLinesToFileForCLI(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			return err
		}
	}
	return nil
}

// handleAEMCommand routes AEM scan commands
func handleAEMCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: aem scan -d <domain> | -l <live_hosts_file> [options]")
	}

	subcommand := args[0]
	if subcommand != "scan" {
		return fmt.Errorf("unknown aem subcommand: %s (use 'scan')", subcommand)
	}

	return handleAEMScan(args[1:])
}

func handleAEMScan(args []string) error {
	opts := aemmod.Options{}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-l", "--live-hosts", "--livehosts":
			if i+1 < len(args) {
				opts.LiveHostsFile = args[i+1]
				i++
			}
		case "-o", "--output":
			if i+1 < len(args) {
				opts.OutputDir = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					opts.Threads = t
				}
				i++
			}
		case "--ssrf-host":
			if i+1 < len(args) {
				opts.SSRFHost = args[i+1]
				i++
			}
		case "--ssrf-port":
			if i+1 < len(args) {
				if p, err := strconv.Atoi(args[i+1]); err == nil {
					opts.SSRFPort = p
				}
				i++
			}
		case "--proxy":
			if i+1 < len(args) {
				opts.Proxy = args[i+1]
				i++
			}
		case "--debug":
			opts.Debug = true
		case "--handler":
			if i+1 < len(args) {
				opts.Handlers = append(opts.Handlers, args[i+1])
				i++
			}
		}
	}

	if opts.Domain == "" && opts.LiveHostsFile == "" {
		return fmt.Errorf("either -d (domain) or -l (live_hosts_file) is required")
	}

	// Set defaults
	if opts.Threads == 0 {
		opts.Threads = 50
	}

	res, err := aemmod.Run(opts)
	if err != nil {
		return err
	}

	fmt.Printf("[OK] AEM scan completed\n")
	fmt.Printf("[INFO] Discovered AEM instances: %d\n", res.DiscoveredCount)
	fmt.Printf("[INFO] Vulnerabilities found: %d\n", res.Vulnerabilities)
	fmt.Printf("[INFO] Results: %s\n", res.ResultsFile)
	if res.DiscoveredFile != "" {
		fmt.Printf("[INFO] Discovered AEM instances: %s\n", res.DiscoveredFile)
	}
	if res.ScannedFile != "" {
		fmt.Printf("[INFO] Scan results: %s\n", res.ScannedFile)
	}

	return nil
}

// handleMisconfigCommand routes misconfig subcommands
//
//	autoar misconfig scan <target> [service] [delay]
//	autoar misconfig service <target> <service-id>
//	autoar misconfig list
//	autoar misconfig update
func handleMisconfigCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: misconfig <scan|service|list|update> [options]")
	}

	action := args[0]
	subArgs := args[1:]

	opts := misconfig.Options{
		Action: action,
		Delay:  0,
	}

	switch action {
	case "list":
		return misconfig.Run(opts)

	case "update":
		return misconfig.Run(opts)

	case "scan":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: misconfig scan <target> [--service <service-id>] [--delay <ms>] [--permutations]")
		}
		opts.Target = subArgs[0]
		
		for i := 1; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--service", "-s":
				if i+1 < len(subArgs) {
					opts.ServiceID = subArgs[i+1]
					i++
				}
			case "--delay", "-d":
				if i+1 < len(subArgs) {
					if d, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.Delay = d
					}
					i++
				}
			case "--permutations", "-p", "--perms":
				opts.EnablePerms = true
			}
		}
		return misconfig.Run(opts)

	case "service":
		if len(subArgs) < 2 {
			return fmt.Errorf("usage: misconfig service <target> <service-id>")
		}
		opts.Target = subArgs[0]
		opts.ServiceID = subArgs[1]
		return misconfig.Run(opts)

	default:
		return fmt.Errorf("unknown misconfig action: %s", action)
	}
}

// handleSubdomainMonitorManageCommand handles subdomain monitoring target management
// Usage: monitor subdomains manage <action> [options]
func handleSubdomainMonitorManageCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: monitor subdomains manage <action> [options]\nActions: list, add, remove, start, stop")
	}

	action := args[0]
	subArgs := args[1:]

	opts := subdomainmonitor.ManagerOptions{
		Action:   action,
		Interval: 3600, // Default 1 hour
		Threads:  100,
		CheckNew: true,
	}

	switch action {
	case "list":
		return subdomainmonitor.ManageTargets(opts)

	case "add":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "-d", "--domain":
				if i+1 < len(subArgs) {
					opts.Domain = subArgs[i+1]
					i++
				}
			case "-i", "--interval":
				if i+1 < len(subArgs) {
					interval, err := strconv.Atoi(subArgs[i+1])
					if err == nil {
						opts.Interval = interval
					}
					i++
				}
			case "-t", "--threads":
				if i+1 < len(subArgs) {
					threads, err := strconv.Atoi(subArgs[i+1])
					if err == nil {
						opts.Threads = threads
					}
					i++
				}
			case "--check-new":
				opts.CheckNew = true
			case "--no-check-new":
				opts.CheckNew = false
			}
		}
		return subdomainmonitor.ManageTargets(opts)

	case "remove":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--id":
				if i+1 < len(subArgs) {
					if id, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.ID = id
					}
					i++
				}
			case "-d", "--domain":
				if i+1 < len(subArgs) {
					opts.Domain = subArgs[i+1]
					i++
				}
			}
		}
		return subdomainmonitor.ManageTargets(opts)

	case "start":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--id":
				if i+1 < len(subArgs) {
					if id, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.ID = id
					}
					i++
				}
			case "--all", "-a":
				opts.All = true
			case "-d", "--domain":
				if i+1 < len(subArgs) {
					opts.Domain = subArgs[i+1]
					i++
				}
			}
		}
		return subdomainmonitor.ManageTargets(opts)

	case "stop":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--id":
				if i+1 < len(subArgs) {
					if id, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.ID = id
					}
					i++
				}
			case "--all", "-a":
				opts.All = true
			case "-d", "--domain":
				if i+1 < len(subArgs) {
					opts.Domain = subArgs[i+1]
					i++
				}
			}
		}
		return subdomainmonitor.ManageTargets(opts)

	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

// handleSubdomainMonitorCommand handles subdomain status monitoring
// Usage: monitor subdomains -d <domain> [options]
func handleSubdomainMonitorCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: monitor subdomains -d <domain> [options]\nOptions:\n  -d, --domain    Domain to monitor (required)\n  -t, --threads   Threads for httpx (default: 100)\n  --check-new     Check for new subdomains (404 -> 200)")
	}

	opts := subdomainmonitor.MonitorOptions{
		Threads:  100,
		CheckNew: true,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				threads, err := strconv.Atoi(args[i+1])
				if err == nil {
					opts.Threads = threads
				}
				i++
			}
		case "--check-new":
			opts.CheckNew = true
		case "--no-check-new":
			opts.CheckNew = false
		}
	}

	if opts.Domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	result, err := subdomainmonitor.MonitorSubdomains(opts)
	if err != nil {
		return fmt.Errorf("failed to monitor subdomains: %w", err)
	}

	subdomainmonitor.PrintResults(result)

	return nil
}

// handleMonitorCommand routes monitor updates subcommands
//
//	autoar monitor updates list
//	autoar monitor updates add -u <url> [--strategy <strategy>] [--pattern <pattern>]
//	autoar monitor updates remove -u <url>
//	autoar monitor updates start [--all] [-u <url>] [--interval <sec>]
//	autoar monitor updates stop [--all] [-u <url>]
//	autoar monitor subdomains -d <domain> [options]
func handleMonitorCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: monitor <updates|subdomains> [options]")
	}

	subcommand := args[0]
	
	if subcommand == "subdomains" {
		if len(args) > 1 && args[1] == "manage" {
			return handleSubdomainMonitorManageCommand(args[2:])
		}
		return handleSubdomainMonitorCommand(args[1:])
	}
	
	if subcommand != "updates" {
		return fmt.Errorf("unknown monitor subcommand: %s (use 'updates' or 'subdomains')", subcommand)
	}
	
	if len(args) < 2 {
		return fmt.Errorf("usage: monitor updates <list|add|remove|start|stop> [options]")
	}

	action := args[1]
	subArgs := args[2:]

	opts := monitor.Options{
		Action:   action,
		Strategy: "hash",
		Interval: 86400,
	}

	switch action {
	case "list":
		return monitor.Run(opts)

	case "add":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "-u", "--url":
				if i+1 < len(subArgs) {
					opts.URL = subArgs[i+1]
					i++
				}
			case "--strategy", "-s":
				if i+1 < len(subArgs) {
					opts.Strategy = subArgs[i+1]
					i++
				}
			case "--pattern", "-p":
				if i+1 < len(subArgs) {
					opts.Pattern = subArgs[i+1]
					i++
				}
			}
		}
		return monitor.Run(opts)

	case "remove":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--id":
				if i+1 < len(subArgs) {
					if id, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.ID = id
					}
					i++
				}
			case "-u", "--url":
				if i+1 < len(subArgs) {
					opts.URL = subArgs[i+1]
					i++
				}
			}
		}
		return monitor.Run(opts)

	case "start":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--id":
				if i+1 < len(subArgs) {
					if id, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.ID = id
					}
					i++
				}
			case "--all", "-a":
				opts.All = true
			case "-u", "--url":
				if i+1 < len(subArgs) {
					opts.URL = subArgs[i+1]
					i++
				}
			case "--interval", "-i":
				if i+1 < len(subArgs) {
					if interval, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.Interval = interval
					}
					i++
				}
			case "--daemon":
				// Ignored, handled by the module
			}
		}
		return monitor.Run(opts)

	case "stop":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--id":
				if i+1 < len(subArgs) {
					if id, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.ID = id
					}
					i++
				}
			case "--all", "-a":
				opts.All = true
			case "-u", "--url":
				if i+1 < len(subArgs) {
					opts.URL = subArgs[i+1]
					i++
				}
			}
		}
		return monitor.Run(opts)

	default:
		return fmt.Errorf("unknown monitor updates action: %s", action)
	}
}

// handleS3Command routes s3 subcommands
//
//	autoar s3 enum -b <root_domain>
//	autoar s3 scan -b <bucket> [-r <region>] [-v]
func handleS3Command(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: s3 <enum|scan> [options]")
	}

	action := args[0]
	subArgs := args[1:]

	opts := s3mod.Options{
		Action: action,
	}

	switch action {
	case "enum":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "-b", "--root":
				if i+1 < len(subArgs) {
					opts.Root = subArgs[i+1]
					i++
				}
			case "-v", "--verbose":
				opts.Verbose = true
			}
		}
		if opts.Root == "" {
			return fmt.Errorf("root domain (-b) is required for enum action")
		}
		return s3mod.Run(opts)

	case "scan":
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "-b", "--bucket":
				if i+1 < len(subArgs) {
					opts.Bucket = subArgs[i+1]
					i++
				}
			case "-r", "--region":
				if i+1 < len(subArgs) {
					opts.Region = subArgs[i+1]
					i++
				}
			case "-v", "--verbose":
				opts.Verbose = true
			}
		}
		if opts.Bucket == "" {
			return fmt.Errorf("bucket name (-b) is required for scan action")
		}
		return s3mod.Run(opts)

	default:
		return fmt.Errorf("unknown s3 action: %s", action)
	}
}

func handleDepconfusionCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: depconfusion <web|github> [options]")
	}

	mode := args[0]
	subArgs := args[1:]

	opts := depconfusion.Options{
		Mode:    mode,
		Workers: 10,
	}

	switch mode {
	case "web":
		// Parse web options: web [--full] [-d domain] [url1] [url2] ... [--target-file file]
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--full", "-f":
				opts.Full = true
			case "-d", "--domain":
				if i+1 < len(subArgs) {
					opts.Target = subArgs[i+1]
					i++
				}
			case "--target-file", "-tf":
				if i+1 < len(subArgs) {
					opts.TargetFile = subArgs[i+1]
					i++
				}
			case "-w", "--workers":
				if i+1 < len(subArgs) {
					if w, err := strconv.Atoi(subArgs[i+1]); err == nil {
						opts.Workers = w
					}
					i++
				}
			case "-v", "--verbose":
				opts.Verbose = true
			case "-o", "--output":
				if i+1 < len(subArgs) {
					opts.OutputDir = subArgs[i+1]
					i++
				}
			default:
				// Treat as URL if it starts with http:// or https://
				if strings.HasPrefix(subArgs[i], "http://") || strings.HasPrefix(subArgs[i], "https://") {
					opts.Targets = append(opts.Targets, subArgs[i])
				}
			}
		}

		if opts.Full {
			if opts.Target == "" {
				return fmt.Errorf("domain (-d) is required for full scan")
			}
		} else if opts.TargetFile == "" && len(opts.Targets) == 0 {
			return fmt.Errorf("either URLs, target file (--target-file), or full scan (--full -d <domain>) is required")
		}

	case "github":
		// Parse github options: github [repo <owner/repo> | org <org>]
		if len(subArgs) < 2 {
			return fmt.Errorf("usage: depconfusion github <repo <owner/repo> | org <org>>")
		}

		subMode := subArgs[0]
		switch subMode {
		case "repo":
			if len(subArgs) < 2 {
				return fmt.Errorf("usage: depconfusion github repo <owner/repo>")
			}
			opts.GitHubRepo = subArgs[1]
		case "org":
			if len(subArgs) < 2 {
				return fmt.Errorf("usage: depconfusion github org <org>")
			}
			opts.GitHubOrg = subArgs[1]
		default:
			return fmt.Errorf("unknown github subcommand: %s. Use 'repo' or 'org'", subMode)
		}

		// Parse additional options
		for i := 2; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "-t", "--token":
				if i+1 < len(subArgs) {
					opts.GitHubToken = subArgs[i+1]
					i++
				}
			case "-o", "--output":
				if i+1 < len(subArgs) {
					opts.OutputDir = subArgs[i+1]
					i++
				}
			case "-v", "--verbose":
				opts.Verbose = true
			}
		}

	default:
		return fmt.Errorf("unknown mode: %s. Use 'web' or 'github'", mode)
	}

	return depconfusion.Run(opts)
}

// handleKeyhackCommand routes keyhack subcommands to the DB-backed implementation:
//
//	autoar keyhack list
//	autoar keyhack search <query>
//	autoar keyhack validate <provider> <api_key>
//	autoar keyhack add <keyname> <command> <description> [notes]
func handleKeyhackCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: keyhack <list|search|validate|add> [options]")
	}

	action := args[0]
	sub := args[1:]

	switch action {
	case "list":
		templates, err := db.ListKeyhackTemplates()
		if err != nil {
			return err
		}
		if len(templates) == 0 {
			fmt.Println("No KeyHack templates found. Use 'autoar db insert-keyhack-template' or 'keyhack add' to add templates.")
			return nil
		}
		for _, t := range templates {
			cmd := generateKeyhackCommand(t, "")
			fmt.Printf("Provider: %s\nDescription: %s\nMethod: %s\nCommand:\n%s\n", t.Keyname, t.Description, t.Method, cmd)
			if t.Notes != "" {
				fmt.Printf("Notes: %s\n", t.Notes)
			}
			fmt.Println()
		}
		return nil

	case "search":
		if len(sub) < 1 {
			return fmt.Errorf("usage: keyhack search <query>")
		}
		query := strings.Join(sub, " ")
		results, err := db.SearchKeyhackTemplates(query)
		if err != nil {
			return err
		}
		if len(results) == 0 {
			fmt.Println("No matching KeyHack templates found.")
			return nil
		}
		for _, t := range results {
			cmd := generateKeyhackCommand(t, "")
			fmt.Printf("Provider: %s\nDescription: %s\nMethod: %s\nCommand:\n%s\n", t.Keyname, t.Description, t.Method, cmd)
			if t.Notes != "" {
				fmt.Printf("Notes: %s\n", t.Notes)
			}
			fmt.Println()
		}
		return nil

	case "validate":
		if len(sub) < 2 {
			return fmt.Errorf("usage: keyhack validate <provider> <api_key>")
		}
		provider := sub[0]
		apiKey := sub[1]

		// Fetch matching template
		results, err := db.SearchKeyhackTemplates(provider)
		if err != nil {
			return err
		}
		if len(results) == 0 {
			return fmt.Errorf("no KeyHack template found for provider: %s", provider)
		}

		// Generate command with API key substituted
		t := results[0]
		cmd := generateKeyhackCommand(t, apiKey)
		fmt.Println(cmd)
		return nil

	case "add":
		if len(sub) < 3 {
			return fmt.Errorf("usage: keyhack add <keyname> <command> <description> [notes]")
		}
		keyname := sub[0]
		commandTemplate := sub[1]
		description := sub[2]
		notes := ""
		if len(sub) > 3 {
			notes = strings.Join(sub[3:], " ")
		}

		// Minimal implementation: store essential fields; others left empty.
		method := "GET"
		url := ""
		header := ""
		body := ""

		if err := db.InsertKeyhackTemplate(keyname, commandTemplate, method, url, header, body, notes, description); err != nil {
			return err
		}

		fmt.Printf("[OK] KeyHack template '%s' saved.\n", keyname)
		return nil

	default:
		return fmt.Errorf("unknown keyhack action: %s", action)
	}
}

// handleGitHubCommand parses:
//
//	autoar github scan -r <owner/repo> [-v]
//	autoar github org -o <org> [-v]
//	autoar github experimental -r <owner/repo> [-v]
func handleGitHubCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: github <scan|org|experimental> [options]")
	}

	modeStr := args[0]
	subArgs := args[1:]

	opts := githubscan.Options{}
	switch modeStr {
	case "scan":
		opts.Mode = githubscan.ModeRepo
	case "org":
		opts.Mode = githubscan.ModeOrg
	case "experimental":
		opts.Mode = githubscan.ModeExperimental
	default:
		return fmt.Errorf("unknown github action: %s", modeStr)
	}

	for i := 0; i < len(subArgs); i++ {
		switch subArgs[i] {
		case "-r", "--repo":
			if i+1 < len(subArgs) {
				opts.Repo = subArgs[i+1]
				i++
			}
		case "-o", "--org":
			if i+1 < len(subArgs) {
				opts.Org = subArgs[i+1]
				i++
			}
		case "-v", "--verbose":
			opts.Verbose = true
		}
	}

	res, err := githubscan.Run(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "github scan error: %v\n", err)
	}
	if res != nil {
		fmt.Printf("[INFO] GitHub scan results directory: %s\n", res.BaseDir)
		fmt.Printf("[INFO] TruffleHog JSON output: %s\n", res.JSONPath)
		fmt.Printf("[INFO] TruffleHog log: %s\n", res.LogPath)
	}
	return err
}

func handleSubdomainsGo(args []string) error {
	var domain string
	threads := 100

	// Parse arguments: get -d <domain> [-t <threads>] [-s|--silent]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		case "-s", "--silent":
			// Silent mode - just ignore for now
		}
	}

	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	// Use Go subdomains module
	results, err := subdomains.EnumerateSubdomains(domain, threads)
	if err != nil {
		return fmt.Errorf("failed to enumerate subdomains: %v", err)
	}

	// Save to file (same location as bash module)
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}
	domainDir := filepath.Join(resultsDir, domain, "subs")
	if err := os.MkdirAll(domainDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	outputFile := filepath.Join(domainDir, "all-subs.txt")
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	for _, subdomain := range results {
		fmt.Fprintln(file, subdomain)
	}

	fmt.Printf("[OK] Found %d unique subdomains for %s\n", len(results), domain)

	// Save to database if configured
	if os.Getenv("DB_HOST") != "" {
		if err := db.Init(); err == nil {
			db.InitSchema() // Ignore errors
			if err := db.BatchInsertSubdomains(domain, results, false); err != nil {
				fmt.Printf("[WARN] Failed to save subdomains to database: %v\n", err)
			}
		}
	}

	return nil
}

// handleLivehostsGo runs live host discovery for a given domain using the Go livehosts module.
// Live host filtering implemented in Go.
func handleLivehostsGo(args []string) error {
	var domain string
	threads := 100
	silent := false

	// Parse arguments: get -d <domain> [-t <threads>] [-s|--silent]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		case "-s", "--silent":
			silent = true
		}
	}

	if domain == "" {
		fmt.Println("Usage: livehosts get -d <domain> [-t <threads>] [-s|--silent]")
		return fmt.Errorf("domain is required")
	}

	res, err := livehosts.FilterLiveHosts(domain, threads, silent)
	if err != nil {
		return err
	}

	fmt.Printf("[INFO] Filtering live hosts via httpx with %d threads\n", res.Threads)
	fmt.Printf("[OK] Found %d live subdomains out of %d for %s\n", res.LiveSubs, res.TotalSubs, res.Domain)
	fmt.Printf("[INFO] Live hosts saved to %s\n", res.LiveSubsFile)

	return nil
}

// handleURLsGo runs URL collection for a given domain using the Go urls module.
// URL collection implemented in Go.
func handleURLsGo(args []string) error {
	var domain string
	threads := 100
	skipSubdomainEnum := false

	// Parse arguments: collect -d <domain> [-t <threads>] [--subdomain]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		case "--subdomain":
			skipSubdomainEnum = true
		}
	}

	if domain == "" {
		fmt.Println("Usage: urls collect -d <domain> [-t <threads>] [--subdomain]")
		fmt.Println("  --subdomain: Treat input as a single subdomain (skip subdomain enumeration)")
		return fmt.Errorf("domain is required")
	}

	res, err := urls.CollectURLs(domain, threads, skipSubdomainEnum)
	if err != nil {
		return err
	}

	mode := "domain"
	if skipSubdomainEnum {
		mode = "subdomain"
	}
	fmt.Printf("[OK] Found %d total URLs; %d JavaScript URLs for %s (mode: %s)\n", res.TotalURLs, res.JSURLs, res.Domain, mode)
	fmt.Printf("[INFO] All URLs saved to %s\n", res.AllFile)
	if res.JSURLs > 0 {
		fmt.Printf("[INFO] JS URLs saved to %s\n", res.JSFile)
	}

	return nil
}

// handleDNSCommand routes `autoar dns ...` to the dns Go module.
// It keeps the existing subcommand shapes but lets Go own the entrypoint,
// while the underlying implementation still uses the existing bash tooling.
func handleDNSCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: autoar dns <takeover|cname|ns|azure-aws|dnsreaper|dangling-ip|all> -d <domain>")
	}

	sub := args[0]
	subArgs := args[1:]

	// parse -d/--domain
	var domain string
	for i := 0; i < len(subArgs); i++ {
		switch subArgs[i] {
		case "-d", "--domain":
			if i+1 < len(subArgs) {
				domain = subArgs[i+1]
				i++
			}
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required")
	}

	switch sub {
	case "takeover", "all":
		return dns.Takeover(domain)
	case "cname":
		return dns.CNAME(domain)
	case "ns":
		return dns.NS(domain)
	case "azure-aws":
		return dns.AzureAWS(domain)
	case "dnsreaper":
		return dns.DNSReaper(domain)
	case "dangling-ip":
		return dns.DanglingIP(domain)
	default:
		return fmt.Errorf("unknown dns action: %s", sub)
	}
}

func handleDBCommand(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: autoar db <command> [args...]")
	}

	command := args[0]
	subArgs := args[1:]

	// Initialize database connection
	if err := db.Init(); err != nil {
		return fmt.Errorf("failed to initialize database: %v", err)
	}

	switch command {
	case "init-schema":
		if err := db.InitSchema(); err != nil {
			return fmt.Errorf("failed to initialize schema: %v", err)
		}
		fmt.Println("[OK] Database schema initialized")
		return nil

	case "check-connection":
		fmt.Println("[OK] Database connection successful")
		return nil

	case "insert-domain":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: autoar db insert-domain <domain>")
		}
		domain := subArgs[0]
		domainID, err := db.InsertOrGetDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to insert/get domain: %v", err)
		}
		fmt.Println(domainID)
		return nil

	case "batch-insert-subdomains":
		if len(subArgs) < 2 {
			return fmt.Errorf("usage: autoar db batch-insert-subdomains <domain> <file> [is_live]")
		}
		domain := subArgs[0]
		filePath := subArgs[1]
		isLive := false
		if len(subArgs) >= 3 {
			isLive = subArgs[2] == "true" || subArgs[2] == "1" || subArgs[2] == "TRUE"
		}

		// Read subdomains from file
		file, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer file.Close()

		var subs []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				subs = append(subs, line)
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}

		if err := db.BatchInsertSubdomains(domain, subs, isLive); err != nil {
			return fmt.Errorf("failed to batch insert subdomains: %v", err)
		}
		return nil

	case "insert-subdomain":
		if len(subArgs) < 2 {
			return fmt.Errorf("usage: autoar db insert-subdomain <domain> <subdomain> [is_live] [http_url] [https_url] [http_status] [https_status]")
		}
		domain := subArgs[0]
		subdomain := subArgs[1]
		isLive := false
		httpURL := ""
		httpsURL := ""
		httpStatus := 0
		httpsStatus := 0

		if len(subArgs) >= 3 {
			isLive = subArgs[2] == "true" || subArgs[2] == "1" || subArgs[2] == "TRUE"
		}
		if len(subArgs) >= 4 {
			httpURL = subArgs[3]
		}
		if len(subArgs) >= 5 {
			httpsURL = subArgs[4]
		}
		if len(subArgs) >= 6 {
			if s, err := strconv.Atoi(subArgs[5]); err == nil {
				httpStatus = s
			}
		}
		if len(subArgs) >= 7 {
			if s, err := strconv.Atoi(subArgs[6]); err == nil {
				httpsStatus = s
			}
		}

		if err := db.InsertSubdomain(domain, subdomain, isLive, httpURL, httpsURL, httpStatus, httpsStatus); err != nil {
			return fmt.Errorf("failed to insert subdomain: %v", err)
		}
		return nil

	case "insert-js-file":
		if len(subArgs) < 2 {
			return fmt.Errorf("usage: autoar db insert-js-file <domain> <js_url> [content_hash]")
		}
		domain := subArgs[0]
		jsURL := subArgs[1]
		contentHash := ""
		if len(subArgs) >= 3 {
			contentHash = subArgs[2]
		}

		if err := db.InsertJSFile(domain, jsURL, contentHash); err != nil {
			return fmt.Errorf("failed to insert JS file: %v", err)
		}
		return nil

	case "insert-keyhack-template":
		if len(subArgs) < 8 {
			return fmt.Errorf("usage: autoar db insert-keyhack-template <keyname> <command> <method> <url> <header> <body> <notes> <description>")
		}
		if err := db.InsertKeyhackTemplate(subArgs[0], subArgs[1], subArgs[2], subArgs[3], subArgs[4], subArgs[5], subArgs[6], subArgs[7]); err != nil {
			return fmt.Errorf("failed to insert keyhack template: %v", err)
		}
		return nil

	case "domains":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: autoar db domains <list|delete> [options]")
		}
		action := subArgs[0]
		args := subArgs[1:]

		switch action {
		case "list":
			domains, err := db.ListDomains()
			if err != nil {
				return err
			}
			// Always print to stdout
			for _, d := range domains {
				fmt.Println(d)
			}
			// Also write to results file for Discord bot
			resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
			if resultsDir == "" {
				resultsDir = "new-results"
			}
			dbDir := filepath.Join(resultsDir, "db")
			if err := os.MkdirAll(dbDir, 0o755); err == nil {
				path := filepath.Join(dbDir, "domains.txt")
				if f, err := os.Create(path); err == nil {
					w := bufio.NewWriter(f)
					for _, d := range domains {
						fmt.Fprintln(w, d)
					}
					_ = w.Flush()
					_ = f.Close()
				}
			}
			return nil

		case "delete":
			var domain string
			for i := 0; i < len(args); i++ {
				switch args[i] {
				case "-d", "--domain":
					if i+1 < len(args) {
						domain = args[i+1]
						i++
					}
				}
			}
			if domain == "" {
				return fmt.Errorf("usage: autoar db domains delete -d <domain>")
			}
			if err := db.DeleteDomain(domain); err != nil {
				return err
			}
			fmt.Printf("[OK] Deleted domain and related data: %s\n", domain)
			return nil

		default:
			return fmt.Errorf("unknown db domains action: %s", action)
		}

	case "subdomains":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: autoar db subdomains <list|export> -d <domain> [-o file]")
		}
		action := subArgs[0]
		args := subArgs[1:]

		var domain, outFile string
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "-d", "--domain":
				if i+1 < len(args) {
					domain = args[i+1]
					i++
				}
			case "-o", "--output":
				if i+1 < len(args) {
					outFile = args[i+1]
					i++
				}
			}
		}
		if domain == "" {
			return fmt.Errorf("domain (-d) is required")
		}

		subs, err := db.ListSubdomains(domain)
		if err != nil {
			return err
		}

		switch action {
		case "list":
			// Print to stdout
			for _, s := range subs {
				fmt.Println(s)
			}
			// Also write to a standard results file for Discord bot
			resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
			if resultsDir == "" {
				resultsDir = "new-results"
			}
			subDir := filepath.Join(resultsDir, "db", "subdomains")
			if err := os.MkdirAll(subDir, 0o755); err == nil {
				path := filepath.Join(subDir, fmt.Sprintf("%s.txt", domain))
				if f, err := os.Create(path); err == nil {
					w := bufio.NewWriter(f)
					for _, s := range subs {
						fmt.Fprintln(w, s)
					}
					_ = w.Flush()
					_ = f.Close()
				}
			}
			return nil

		case "export":
			if outFile == "" {
				outFile = fmt.Sprintf("%s_subdomains.txt", domain)
			}
			f, err := os.Create(outFile)
			if err != nil {
				return fmt.Errorf("failed to create export file: %v", err)
			}
			defer f.Close()

			w := bufio.NewWriter(f)
			for _, s := range subs {
				fmt.Fprintln(w, s)
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("failed to write export file: %v", err)
			}
			fmt.Printf("[OK] Exported %d subdomains for %s to %s\n", len(subs), domain, outFile)
			return nil

		default:
			return fmt.Errorf("unknown db subdomains action: %s", action)
		}

	case "backup":
		uploadToR2 := false
		for i := 0; i < len(subArgs); i++ {
			switch subArgs[i] {
			case "--upload-r2", "-r2":
				uploadToR2 = true
			}
		}
		
		backupPath, r2URL, err := db.BackupDatabase(uploadToR2)
		if err != nil {
			return fmt.Errorf("failed to backup database: %v", err)
		}
		
		fmt.Printf("[OK] Database backup created: %s\n", backupPath)
		if r2URL != "" {
			fmt.Printf("[OK] Database backup uploaded to R2: %s\n", r2URL)
		}
		return nil

	default:
		return fmt.Errorf("unknown db command: %s", command)
	}
}

func main() {
	// Load .env file if it exists (before processing commands)
	if err := envloader.LoadEnv(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Failed to load .env file: %v\n", err)
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error

	switch cmd {
	// Go modules - direct calls
	case "depconfusion":
		err = handleDepconfusionCommand(args)
	case "github-wordlist":
		err = handleGitHubWordlist(args)

	case "subdomains":
		// Use Go subdomains module if action is "get"
		if len(args) > 0 && args[0] == "get" {
			err = handleSubdomainsGo(args[1:])
		} else {
			err = fmt.Errorf("unsupported subdomains action; use: autoar subdomains get -d <domain> [-t <threads>]")
		}

	case "livehosts":
		// Use Go livehosts module if action is "get"
		if len(args) > 0 && args[0] == "get" {
			err = handleLivehostsGo(args[1:])
		} else {
			err = fmt.Errorf("unsupported livehosts action; use: autoar livehosts get -d <domain> [-t <threads>] [-s|--silent]")
		}

	case "urls":
		// Use Go URLs module (no bash fallback)
		if len(args) > 0 && args[0] == "collect" {
			err = handleURLsGo(args[1:])
		} else {
			err = fmt.Errorf("unsupported urls action; use: autoar urls collect -d <domain> [-t <threads>] [--subdomain]")
		}

	case "dns":
		// DNS takeover and related scans - fully implemented in Go
		err = handleDNSCommand(args)

	case "cnames":
		err = handleCnamesCommand(args)

	case "fastlook":
		err = handleFastlookCommand(args)

	case "lite":
		err = handleLiteCommand(args)

	case "domain":
		err = handleDomainCommand(args)

	case "subdomain":
		err = handleSubdomainCommand(args)

	case "nuclei":
		err = handleNucleiCommand(args)

	case "reflection":
		err = handleReflectionCommand(args)

	case "dalfox":
		err = handleDalfoxCommand(args)

	case "tech":
		err = handleTechCommand(args)

	case "gf":
		err = handleGFCommand(args)

	case "sqlmap":
		err = handleSQLMapCommand(args)

	case "ports":
		err = handlePortsCommand(args)

	case "js":
		err = handleJSCommand(args)

	case "backup":
		err = handleBackupCommand(args)

	case "apkx":
		err = handleApkXCommand(args)

	case "check-tools":
		err = checktools.Run()

	case "setup":
		err = setup.Run()

	case "cleanup":
		err = utils.CleanupResultsDirectory()
		if err != nil {
			fmt.Printf("Error cleaning up results directory: %v\n", err)
		} else {
			fmt.Println("Successfully cleaned up results directory")
		}

	case "jwt":
		err = handleJWTCommand(args)

	case "db":
		// Database operations via Go module
		err = handleDBCommand(args)

	case "wpDepConf":
		// WordPress dependency confusion scan via Go module
		err = handleWPConfusion(args)

	case "github":
		err = handleGitHubCommand(args)

	case "keyhack":
		err = handleKeyhackCommand(args)

	case "misconfig":
		err = handleMisconfigCommand(args)

	case "aem":
		err = handleAEMCommand(args)

	case "zerodays", "0days":
		err = handleZerodaysCommand(args)

	case "monitor":
		err = handleMonitorCommand(args)

	case "s3":
		err = handleS3Command(args)

	case "scope":
		err = handleScopeCommand(args)

	case "ffuf":
		err = handleFFufCommand(args)

	// Bot/API commands
	case "bot":
		// Start Discord bot (from gobot module)
		fmt.Println("Starting Discord bot...")
		err = gobot.StartBot()

	case "api":
		// Start API server (from gobot module)
		fmt.Println("Starting REST API server...")
		err = gobot.StartAPI()

	case "asr":
		err = handleASRCommand(args)

	case "both":
		// Start both
		fmt.Println("Starting both bot and API...")
		err = gobot.StartBoth()

	// Help
	case "help", "--help", "-h":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func handleASRCommand(args []string) error {
	var domain, wordlist, resolvers string
	mode := 0 // 0 means not set
	threads := 50
	showHelp := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			showHelp = true
		case "-d", "--domain":
			if i+1 < len(args) {
				domain = args[i+1]
				i++
			}
		case "-mode", "--mode":
			if i+1 < len(args) {
				if m, err := strconv.Atoi(args[i+1]); err == nil {
					mode = m
				}
				i++
			}
		case "-t", "--threads":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil {
					threads = t
				}
				i++
			}
		case "-w", "--wordlist":
			if i+1 < len(args) {
				wordlist = args[i+1]
				i++
			}
		case "-r", "--resolvers":
			if i+1 < len(args) {
				resolvers = args[i+1]
				i++
			}
		}
	}

	if showHelp {
		printASRHelp()
		return nil
	}

	if domain == "" {
		return fmt.Errorf("domain is required (-d <domain>). Use 'autoar asr -h' for help")
	}

	// Interactive Mode Selection if not provided
	if mode == 0 {
		fmt.Println("\x1b[34m" + `Choose what you wanna do?
[1] Passive recon only
[2] Active recon only (Brute forcing, Permutations, Probing)
[3] Normal Recon [Passive + Active without Permutations]
[4] Quick Recon [Passive + TLS Probing + Scraping]
[5] Full recon [All Techniques]` + "\x1b[0m")
		fmt.Print("Enter your choice (1-5): ")
		var input string
		fmt.Scanln(&input)
		if m, err := strconv.Atoi(strings.TrimSpace(input)); err == nil && m >= 1 && m <= 5 {
			mode = m
		} else {
			mode = 5 // Default to Full Recon if invalid/empty
			fmt.Println("[!] Invalid choice, defaulting to Mode 5 (Full Recon)")
		}
	}

	opts := asrmod.Options{
		Domain:    domain,
		Mode:      mode,
		Threads:   threads,
		Wordlist:  wordlist,
		Resolvers: resolvers,
	}

	return asrmod.Run(context.Background(), opts)
}

func printASRHelp() {
	fmt.Println(`AutoAR ASR (High-Depth Reconnaissance)

Usage: autoar asr -d <domain> [options]

Options:
  -d, --domain <domain>      Target domain (required)
  -mode <1-5>                Reconnaissance mode (default: interactive if not set)
                               1: Passive recon only
                               2: Active recon only (Brute forcing, TLS, Permutations)
                               3: Normal Recon (Passive + Active without Permutations)
                               4: Quick Recon (Passive + TLS Probing + Scraping)
                               5: Full Recon (All Techniques)
  -t, --threads <number>     Number of workers/threads (default: 50)
  -w, --wordlist <path>      Custom wordlist for DNS bruteforcing
  -r, --resolvers <path>     Custom DNS resolvers file
  -h, --help                 Show this help message`)
}

