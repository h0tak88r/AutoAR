package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/backup"
	"github.com/h0tak88r/AutoAR/gomodules/checktools"
	"github.com/h0tak88r/AutoAR/gomodules/cnames"
	"github.com/h0tak88r/AutoAR/gomodules/dalfox"
	"github.com/h0tak88r/AutoAR/gomodules/db"
	"github.com/h0tak88r/AutoAR/gomodules/dns"
	"github.com/h0tak88r/AutoAR/gomodules/fastlook"
	"github.com/h0tak88r/AutoAR/gomodules/gf"
	"github.com/h0tak88r/AutoAR/gomodules/github-wordlist"
	"github.com/h0tak88r/AutoAR/gomodules/githubscan"
	"github.com/h0tak88r/AutoAR/gomodules/gobot"
	"github.com/h0tak88r/AutoAR/gomodules/jsscan"
	jwtmod "github.com/h0tak88r/AutoAR/gomodules/jwt"
	"github.com/h0tak88r/AutoAR/gomodules/livehosts"
	"github.com/h0tak88r/AutoAR/gomodules/misconfig"
	"github.com/h0tak88r/AutoAR/gomodules/monitor"
	"github.com/h0tak88r/AutoAR/gomodules/nuclei"
	"github.com/h0tak88r/AutoAR/gomodules/ports"
	"github.com/h0tak88r/AutoAR/gomodules/reflection"
	"github.com/h0tak88r/AutoAR/gomodules/sqlmap"
	"github.com/h0tak88r/AutoAR/gomodules/subdomains"
	"github.com/h0tak88r/AutoAR/gomodules/tech"
	"github.com/h0tak88r/AutoAR/gomodules/urls"
	"github.com/h0tak88r/AutoAR/gomodules/wp-confusion"
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
  urls collect        -d <domain>
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
  dns all             -d <domain>     (comprehensive scan)
  s3 scan             -b <bucket> [-r <region>]
  s3 enum             -b <root_domain>
  github scan         -r <owner/repo>
  github org          -o <org> [-m <max-repos>]
  github depconfusion -r <owner/repo>
  github experimental -r <owner/repo>
  github-wordlist scan -o <github_org> [-t <github_token>]
  backup scan            -d <domain> [-o <output_dir>] [-t <threads>] [-d <delay>]
  backup scan            -l <live_hosts_file> [-o <output_dir>] [-t <threads>] [-d <delay>]
  depconfusion scan <file>                    Scan local dependency file
  depconfusion github repo <owner/repo>       Scan GitHub repository
  depconfusion github org <org>               Scan GitHub organization
  depconfusion web <url> [url2] [url3]...     Scan web targets
  depconfusion web-file <file>                Scan targets from file
  misconfig scan <target> [service] [delay]   Scan for misconfigurations
  misconfig service <target> <service-id>     Scan specific service
  misconfig list                              List available services
  misconfig update                            Update templates
  keyhack list                                List all API key validation templates
  keyhack search <query>                      Search API key validation templates
  keyhack validate <provider> <api_key>       Generate validation command for API key
  keyhack add <keyname> <command> <desc> [notes] Add a new template
  jwt scan             --token <JWT_TOKEN> [OPTIONS]                Scan JWT token for vulnerabilities using jwt-hack

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

Utilities:
  check-tools
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
		default:
			// ignore unknown flags for now
		}
	}
	if domain == "" {
		return fmt.Errorf("domain (-d) is required; usage: cnames get -d <domain>")
	}
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
		return fmt.Errorf("domain (-d) is required; usage: fastlook run -d <domain>")
	}
	_, err := fastlook.RunFastlook(domain)
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

// handleBackupCommand parses:
//
//	autoar backup scan -d <domain> [-t <threads>] [--delay <ms>]
//	autoar backup scan -l <live_hosts_file> [-t <threads>] [--delay <ms>]
func handleBackupCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: backup scan -d <domain> | -l <live_hosts_file> [-t <threads>] [--delay <ms>]")
	}
	args = args[1:]

	opts := backup.Options{Threads: 100}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-d", "--domain":
			if i+1 < len(args) {
				opts.Domain = args[i+1]
				i++
			}
		case "-l", "--live-hosts":
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

// handleJWTCommand parses:
//
//	autoar jwt scan --token <JWT_TOKEN> [--skip-crack] [--skip-payloads] [-w wordlist] [--max-crack-attempts N]
//	autoar jwt scan <JWT_TOKEN> [--skip-crack] [--skip-payloads] [-w wordlist] [--max-crack-attempts N]
//
// Internally this is normalized to:
//
//	jwt-hack scan <JWT_TOKEN> [flags...]
func handleJWTCommand(args []string) error {
	if len(args) == 0 || args[0] != "scan" {
		return fmt.Errorf("usage: jwt scan --token <JWT_TOKEN> [--skip-crack] [--skip-payloads] [-w wordlist] [--max-crack-attempts N]")
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
			return fmt.Errorf("usage: misconfig scan <target> [--service <service-id>] [--delay <ms>]")
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

// handleMonitorCommand routes monitor updates subcommands
//
//	autoar monitor updates list
//	autoar monitor updates add -u <url> [--strategy <strategy>] [--pattern <pattern>]
//	autoar monitor updates remove -u <url>
//	autoar monitor updates start [--all] [-u <url>] [--interval <sec>]
//	autoar monitor updates stop [--all] [-u <url>]
func handleMonitorCommand(args []string) error {
	if len(args) < 2 || args[0] != "updates" {
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

	// Parse arguments: collect -d <domain> [-t <threads>]
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
		fmt.Println("Usage: urls collect -d <domain> [-t <threads>]")
		return fmt.Errorf("domain is required")
	}

	res, err := urls.CollectURLs(domain, threads)
	if err != nil {
		return err
	}

	fmt.Printf("[OK] Found %d total URLs; %d JavaScript URLs for %s\n", res.TotalURLs, res.JSURLs, res.Domain)
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
		return fmt.Errorf("usage: autoar dns <takeover|cname|ns|azure-aws|dnsreaper|all> -d <domain>")
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

	default:
		return fmt.Errorf("unknown db command: %s", command)
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error

	switch cmd {
	// Commands not yet migrated to Go (return error for now)
	case "s3",
		"depconfusion":
		err = fmt.Errorf("command '%s' is not yet implemented in Go. All bash modules have been removed.", cmd)

	// Go modules - direct calls
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
			err = fmt.Errorf("unsupported urls action; use: autoar urls collect -d <domain> [-t <threads>]")
		}

	case "dns":
		// DNS takeover and related scans - fully implemented in Go
		err = handleDNSCommand(args)

	case "cnames":
		err = handleCnamesCommand(args)

	case "fastlook":
		err = handleFastlookCommand(args)

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

	case "check-tools":
		err = checktools.Run()

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

	case "monitor":
		err = handleMonitorCommand(args)

	// Bot/API commands
	case "bot":
		// Start Discord bot (from gobot module)
		fmt.Println("Starting Discord bot...")
		err = gobot.StartBot()

	case "api":
		// Start API server (from gobot module)
		fmt.Println("Starting REST API server...")
		err = gobot.StartAPI()

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
