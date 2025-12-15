package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/h0tak88r/AutoAR/gomodules/db"
	"github.com/h0tak88r/AutoAR/gomodules/github-wordlist"
	"github.com/h0tak88r/AutoAR/gomodules/gobot"
	"github.com/h0tak88r/AutoAR/gomodules/subdomains"
	"github.com/h0tak88r/AutoAR/gomodules/wp-confusion"
)

var (
	rootDir     string
	modulesDir  string
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
  cleanup run         --domain <domain> [--keep]
  check-tools
  help

Special:
  bot                 Start Discord bot
  api                 Start REST API server
  both                Start both bot and API
`
	fmt.Print(usage)
}

func runBashModule(module string, args []string) error {
	scriptPath := filepath.Join(modulesDir, module+".sh")
	
	// Check if script exists
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		// Try /app/modules (Docker fallback)
		if altPath := filepath.Join("/app/modules", module+".sh"); altPath != scriptPath {
			if _, err2 := os.Stat(altPath); err2 == nil {
				scriptPath = altPath
				modulesDir = "/app/modules"
				rootDir = "/app"
			} else {
				return fmt.Errorf("module %s not found (tried: %s, %s)", module, scriptPath, altPath)
			}
		} else {
			return fmt.Errorf("module %s not found at %s", module, scriptPath)
		}
	}
	
	cmdArgs := append([]string{scriptPath}, args...)
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = rootDir
	
	// Set environment variables that bash modules might need
	cmd.Env = os.Environ()
	
	return cmd.Run()
}

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
	
	// Parse arguments similar to original: -u <url> | -l <list> -t | -p [-o <output>]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-u", "--url":
			if i+1 < len(args) {
				opts.URL = args[i+1]
				i++
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
	
	return wpconfusion.ScanWPConfusion(opts)
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
	
	if !silent {
		fmt.Printf("[OK] Found %d unique subdomains for %s\n", len(results), domain)
	}
	
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
		domainID, err := db.InsertOrGetDomain(subArgs[0])
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
		
		var subdomains []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				subdomains = append(subdomains, line)
			}
		}
		
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read file: %v", err)
		}
		
		if err := db.BatchInsertSubdomains(domain, subdomains, isLive); err != nil {
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
	// Bash modules - most commands
	case "livehosts", "cnames", "urls", "js", "s3", "domain",
		"cleanup", "check-tools", "lite", "reflection", "nuclei", "tech",
		"ports", "gf", "sqlmap", "dalfox", "dns", "github", "backup",
		"depconfusion", "misconfig", "fastlook", "keyhack", "jwt", "wpDepConf":
		err = runBashModule(cmd, args)
	
	// Special nested commands
	case "monitor":
		if len(args) < 1 {
			printUsage()
			os.Exit(1)
		}
		sub := args[0]
		subArgs := args[1:]
		if sub == "updates" {
			err = runBashModule("updates", subArgs)
		} else {
			printUsage()
			os.Exit(1)
		}
	
	// Go modules - direct calls
	case "github-wordlist":
		err = handleGitHubWordlist(args)
	
	case "subdomains":
		// Use Go subdomains module if action is "get"
		if len(args) > 0 && args[0] == "get" {
			err = handleSubdomainsGo(args[1:])
		} else {
			// Fallback to bash module for other actions
			err = runBashModule("subdomains", args)
		}
	
	case "db":
		// Database operations via Go module
		err = handleDBCommand(args)
	
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
