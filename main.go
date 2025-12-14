package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/h0tak88r/AutoAR/gomodules/github-wordlist"
	"github.com/h0tak88r/AutoAR/gomodules/gobot"
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
	
	autoarScript = filepath.Join(rootDir, "main.sh")
	
	// Fallback: if main.sh doesn't exist, use this binary
	if _, err := os.Stat(autoarScript); os.IsNotExist(err) {
		autoarScript = os.Args[0]
	}
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
	case "subdomains", "livehosts", "cnames", "urls", "js", "s3", "domain",
		"cleanup", "db", "check-tools", "lite", "reflection", "nuclei", "tech",
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
