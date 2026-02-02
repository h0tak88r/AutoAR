package dns

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// Paths and filenames used by the legacy bash dns_takeover.sh script.
const (
	findingsDirName = "vulnerabilities/dns-takeover"
)

// ensureSubdomains makes sure we have a fresh all-subs.txt for the domain
// and returns its path and the domain results directory.
func ensureSubdomains(domain string) (domainDir string, subsFile string, err error) {
	if domain == "" {
		return "", "", fmt.Errorf("domain is required")
	}

	resultsRoot := utils.GetResultsDir()
	domainDir = filepath.Join(resultsRoot, domain)
	subsDir := filepath.Join(domainDir, "subs")
	if err = utils.EnsureDir(subsDir); err != nil {
		return "", "", fmt.Errorf("failed to create subs dir: %w", err)
	}

	subsFile = filepath.Join(subsDir, "all-subs.txt")

	// Step 1: Check database first
	if os.Getenv("DB_HOST") != "" || os.Getenv("SAVE_TO_DB") == "true" {
		if err := db.Init(); err == nil {
			_ = db.InitSchema()
			count, err := db.CountSubdomains(domain)
			if err == nil && count > 0 {
				log.Printf("[INFO] Found %d subdomains in database for %s (dns module), using them", count, domain)
				// Load subdomains from database and write to file
				subs, err := db.ListSubdomains(domain)
				if err == nil && len(subs) > 0 {
					if err := writeLines(subsFile, subs); err != nil {
						log.Printf("[WARN] Failed to write subdomains from DB to file: %v", err)
					}
					return domainDir, subsFile, nil
				}
			}
		}
	}

	// Step 2: If we already have a reasonably-sized file, reuse it, but refresh if tiny.
	if info, statErr := os.Stat(subsFile); statErr == nil && info.Size() > 0 {
		count, cErr := countLines(subsFile)
		if cErr == nil && count >= 5 {
			log.Printf("[INFO] Using existing subdomains from %s (%d subdomains)", subsFile, count)
			return domainDir, subsFile, nil
		}
		log.Printf("[WARN] Only %d subdomains in %s, refreshing enumeration", count, subsFile)
	}

	// Step 3: Collect subdomains (not in database and no valid file)
	log.Printf("[INFO] Collecting subdomains for %s (dns module)", domain)
	subs, err := subdomains.EnumerateSubdomains(domain, 100)
	if err != nil {
		return "", "", fmt.Errorf("subdomain enumeration failed: %w", err)
	}
	if err := writeLines(subsFile, subs); err != nil {
		return "", "", fmt.Errorf("failed to write %s: %w", subsFile, err)
	}
	log.Printf("[OK] Found %d unique subdomains for %s", len(subs), domain)

	return domainDir, subsFile, nil
}

// TakeoverOptions for DNS takeover scan
type TakeoverOptions struct {
	Domain        string // Domain name
	Subdomain     string // Optional: single subdomain to scan (skips enumeration)
	LiveHostsFile string // Optional: path to live hosts file (skips enumeration)
}

// Takeover runs the comprehensive DNS takeover workflow (equivalent to `dns takeover` / `dns all`).
func Takeover(domain string) error {
	return TakeoverWithOptions(TakeoverOptions{Domain: domain})
}

// TakeoverWithOptions runs DNS takeover with options
func TakeoverWithOptions(opts TakeoverOptions) error {
	var domainDir, subsFile, outputDir string
	var err error
	
	// Determine output directory: use subdomain if provided, otherwise use root domain
	resultsRoot := utils.GetResultsDir()
	if opts.Subdomain != "" {
		// Save results under subdomain directory for consistency
		outputDir = filepath.Join(resultsRoot, opts.Subdomain)
	} else {
		// Use root domain directory
		outputDir = filepath.Join(resultsRoot, opts.Domain)
	}
	
	// If subdomain or live hosts file provided, use it directly without enumeration
	// Note: DNS scan processes root domain but saves results under subdomain directory
	if opts.Subdomain != "" {
		// Still use root domain directory for temporary files (subs/all-subs.txt)
		// but save results under subdomain directory
		tempDomainDir := filepath.Join(resultsRoot, opts.Domain)
		subsDir := filepath.Join(tempDomainDir, "subs")
		if err = utils.EnsureDir(subsDir); err != nil {
			return fmt.Errorf("failed to create subs dir: %w", err)
		}
		subsFile = filepath.Join(subsDir, "all-subs.txt")
		// Write single subdomain to file
		if err := writeLines(subsFile, []string{opts.Subdomain}); err != nil {
			return fmt.Errorf("failed to write subdomain file: %w", err)
		}
		log.Printf("[INFO] Using provided subdomain: %s (processing domain: %s, saving results to: %s)", opts.Subdomain, opts.Domain, outputDir)
	} else if opts.LiveHostsFile != "" {
		// Extract subdomains from live hosts file
		// Use root domain directory for temporary files
		tempDomainDir := filepath.Join(resultsRoot, opts.Domain)
		subsDir := filepath.Join(tempDomainDir, "subs")
		if err = utils.EnsureDir(subsDir); err != nil {
			return fmt.Errorf("failed to create subs dir: %w", err)
		}
		subsFile = filepath.Join(subsDir, "all-subs.txt")
		
		// Read live hosts and extract subdomains
		file, err := os.Open(opts.LiveHostsFile)
		if err != nil {
			return fmt.Errorf("failed to open live hosts file: %w", err)
		}
		defer file.Close()
		
		var subdomains []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			// Extract hostname from URL
			host := line
			if strings.HasPrefix(host, "http://") {
				host = strings.TrimPrefix(host, "http://")
			} else if strings.HasPrefix(host, "https://") {
				host = strings.TrimPrefix(host, "https://")
			}
			if idx := strings.Index(host, "/"); idx != -1 {
				host = host[:idx]
			}
			if host != "" {
				subdomains = append(subdomains, host)
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("failed to read live hosts file: %w", err)
		}
		if len(subdomains) == 0 {
			return fmt.Errorf("no subdomains found in live hosts file")
		}
		if err := writeLines(subsFile, subdomains); err != nil {
			return fmt.Errorf("failed to write subdomain file: %w", err)
		}
		log.Printf("[INFO] Using %d subdomain(s) from live hosts file (processing domain: %s, saving results to: %s)", len(subdomains), opts.Domain, outputDir)
	} else {
		// Standard enumeration - use root domain directory
		domainDir, subsFile, err = ensureSubdomains(opts.Domain)
		if err != nil {
			return err
		}
		outputDir = domainDir // Use domain directory for standard enumeration
	}
	
	// Use outputDir (subdomain directory if provided, otherwise root domain) for saving results
	findingsDir := filepath.Join(outputDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}

	// Initialise output files (compatible with legacy layout)
	// Note: Summary files removed - only raw results are generated
	files := []string{
		"nuclei-takeover-public.txt",
		"nuclei-takeover-custom.txt",
		"azure-takeover.txt",
		"aws-takeover.txt",
		"azure-aws-takeover.txt",
		"ns-takeover-raw.txt",
		"ns-takeover-vuln.txt",
		"ns-servers.txt",
		"ns-servers-vuln.txt",
		"dnsreaper-results.txt",
		"filtered-ns-takeover-vuln.txt",
		"dangling-ip.txt",
	}
	for _, name := range files {
		p := filepath.Join(findingsDir, name)
		if err := writeLines(p, nil); err != nil {
			return fmt.Errorf("failed to initialise %s: %w", p, err)
		}
	}

	log.Printf("[INFO] Starting comprehensive DNS takeover scan for %s", opts.Domain)

	// Use root domain directory for processing (temporary files), but save results to outputDir
	// When subdomain is provided, domainDir might not be set, so use root domain directory
	var processingDir string
	if opts.Subdomain != "" || opts.LiveHostsFile != "" {
		// When subdomain/live hosts file is provided, use root domain directory for processing
		processingDir = filepath.Join(resultsRoot, opts.Domain)
	} else {
		// Standard enumeration - use domainDir
		processingDir = domainDir
	}
	
	if err := runNucleiTakeover(processingDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] Nuclei takeover step failed: %v", err)
	}
	if err := runDNSReaper(processingDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] DNSReaper step failed: %v", err)
	}
	if err := checkAzureAWS(processingDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] Azure/AWS check failed: %v", err)
	}
	if err := runNSTakeover(processingDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] NS takeover step failed: %v", err)
	}
	if err := checkDanglingIPs(processingDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] Dangling IP check failed: %v", err)
	}

	// Summary file generation removed - only raw results are sent

	// Webhook sending removed - files are sent via utils.SendPhaseFiles from phase functions


	log.Printf("[OK] DNS takeover scan completed for %s (results in %s)", opts.Domain, findingsDir)
	return nil
}

// CNAME runs the CNAME-focused DNS takeover workflow.
func CNAME(domain string) error {
	domainDir, subsFile, err := ensureSubdomains(domain)
	if err != nil {
		return err
	}
	findingsDir := filepath.Join(domainDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}
	if err := runNucleiTakeover(domainDir, findingsDir, subsFile); err != nil {
		return err
	}
	if err := runDNSReaper(domainDir, findingsDir, subsFile); err != nil {
		return err
	}
	if err := checkAzureAWS(domainDir, findingsDir, subsFile); err != nil {
		return err
	}
	return nil
}

// NS runs the NS-focused DNS takeover workflow.
func NS(domain string) error {
	domainDir, subsFile, err := ensureSubdomains(domain)
	if err != nil {
		return err
	}
	findingsDir := filepath.Join(domainDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}
	return runNSTakeover(domainDir, findingsDir, subsFile)
}

// AzureAWS runs the Azure/AWS cloud takeover detection workflow.
func AzureAWS(domain string) error {
	domainDir, subsFile, err := ensureSubdomains(domain)
	if err != nil {
		return err
	}
	findingsDir := filepath.Join(domainDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}
	return checkAzureAWS(domainDir, findingsDir, subsFile)
}

// DNSReaper runs only the DNSReaper workflow.
func DNSReaper(domain string) error {
	domainDir, subsFile, err := ensureSubdomains(domain)
	if err != nil {
		return err
	}
	findingsDir := filepath.Join(domainDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}
	return runDNSReaper(domainDir, findingsDir, subsFile)
}

// DanglingIP runs only the dangling IP detection workflow.
func DanglingIP(domain string) error {
	domainDir, subsFile, err := ensureSubdomains(domain)
	if err != nil {
		return err
	}
	findingsDir := filepath.Join(domainDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}
	return checkDanglingIPs(domainDir, findingsDir, subsFile)
}

// ---- Implementation helpers (ported from modules/dns_takeover.sh) ----

func runNucleiTakeover(domainDir, findingsDir, subsFile string) error {
	if _, err := exec.LookPath("nuclei"); err != nil {
		log.Printf("[WARN] nuclei not found in PATH, skipping takeover templates")
		return nil
	}

	// discover public templates
	publicDirs := []string{
		"/app/nuclei-templates",
		"/app/nuclei-templates-backup",
		"nuclei-templates",
		"/usr/local/share/nuclei-templates",
		"/opt/nuclei-templates",
		"/root/nuclei-templates",
		"/home/autoar/nuclei-templates",
		"/home/autoar/.cache/nuclei/nuclei-templates",
	}
	var publicDir string
	for _, d := range publicDirs {
		if fi, err := os.Stat(filepath.Join(d, "http", "takeovers")); err == nil && fi.IsDir() {
			publicDir = d
			break
		}
	}

	if publicDir != "" {
		out := filepath.Join(findingsDir, "nuclei-takeover-public.txt")
		log.Printf("[INFO] Running Nuclei public takeover templates from %s", publicDir)
		cmd := exec.Command("nuclei", "-l", subsFile, "-t", filepath.Join(publicDir, "http", "takeovers"), "-o", out)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] Nuclei public takeover failed: %v", err)
		} else {
			count, _ := countLines(out)
			if count > 0 {
				log.Printf("[OK] Nuclei public takeover found %d candidates", count)
				// Send findings to webhook if configured
				webhookURL := os.Getenv("DISCORD_WEBHOOK")
				if webhookURL != "" {
					domain := filepath.Base(domainDir)
					if info, err := os.Stat(out); err == nil && info.Size() > 0 {
				utils.SendWebhookFileAsync(out, fmt.Sprintf("DNS Finding: CNAME takeover (Nuclei public) for %s (%d found)", domain, count))
				utils.SendWebhookLogAsync(fmt.Sprintf("Nuclei public takeover: %d candidates for %s", count, domain))
					}
				}
			}
		}
	} else {
		log.Printf("[WARN] No Nuclei public takeover templates directory found, skipping")
	}

	// custom templates (optional, same layout as bash script assumed)
	customDirs := []string{
		"/app/nuclei_templates",
		"/app/nuclei-templates-backup",
		"nuclei_templates",
		"/usr/local/share/nuclei_templates",
		"/opt/nuclei_templates",
		"/root/nuclei_templates",
		"/home/autoar/nuclei_templates",
		"/home/autoar/.cache/nuclei/nuclei-templates",
	}
	var customDir string
	for _, d := range customDirs {
		if fi, err := os.Stat(filepath.Join(d, "http", "takeovers")); err == nil && fi.IsDir() {
			customDir = d
			break
		}
	}
	if customDir != "" {
		out := filepath.Join(findingsDir, "nuclei-takeover-custom.txt")
		log.Printf("[INFO] Running Nuclei custom takeover templates from %s", customDir)
		cmd := exec.Command("nuclei", "-l", subsFile, "-t", filepath.Join(customDir, "http", "takeovers"), "-o", out)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] Nuclei custom takeover failed: %v", err)
		} else {
			count, _ := countLines(out)
			if count > 0 {
				log.Printf("[OK] Nuclei custom takeover found %d candidates", count)
				// Send findings to webhook if configured
				webhookURL := os.Getenv("DISCORD_WEBHOOK")
				if webhookURL != "" {
					domain := filepath.Base(domainDir)
					if info, err := os.Stat(out); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(out, fmt.Sprintf("DNS Finding: CNAME takeover (Nuclei custom) for %s (%d found)", domain, count))
					utils.SendWebhookLogAsync(fmt.Sprintf("Nuclei custom takeover: %d candidates for %s", count, domain))
					}
				}
			}
		}
	}

	return nil
}

func runDNSReaper(domainDir, findingsDir, subsFile string) error {
	// Only run DNSReaper if docker is available and usable
	if os.Getenv("AUTOAR_ENV") == "docker" {
		log.Printf("[WARN] DNSReaper in Docker requires access to Docker-in-Docker; skipping unless configured")
		return nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		log.Printf("[WARN] docker not found, skipping DNSReaper")
		return nil
	}
	if err := exec.Command("docker", "ps").Run(); err != nil {
		log.Printf("[WARN] cannot run docker ps (permissions?); skipping DNSReaper: %v", err)
		return nil
	}

	input := filepath.Join(findingsDir, "dnsreaper-input.txt")
	if err := copyFile(subsFile, input); err != nil {
		return fmt.Errorf("failed to prepare dnsreaper input: %w", err)
	}

	out := filepath.Join(findingsDir, "dnsreaper-results.txt")
	log.Printf("[INFO] Running DNSReaper against %s", input)
	cmd := exec.Command("docker", "run", "--rm", "-v", fmt.Sprintf("%s:/etc/dnsreaper", utils.GetRootDir()+":/etc/dnsreaper"))
	// Note: for simplicity we assume working directory is rootDir; the original script used `$(pwd)`
	cmd.Args = []string{"docker", "run", "--rm", "-v", fmt.Sprintf("%s:/etc/dnsreaper", utils.GetRootDir()), "punksecurity/dnsreaper", "file", "--filename", "/etc/dnsreaper/" + strings.TrimPrefix(input, utils.GetRootDir()+"/")}
	f, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("failed to create dnsreaper output: %w", err)
	}
	defer f.Close()
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[WARN] DNSReaper run failed: %v", err)
	} else {
		count, _ := countLines(out)
		if count > 0 {
			log.Printf("[OK] DNSReaper found %d candidates", count)
			// Send findings to webhook if configured
			webhookURL := os.Getenv("DISCORD_WEBHOOK")
			if webhookURL != "" {
				domain := filepath.Base(domainDir)
				if info, err := os.Stat(out); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(out, fmt.Sprintf("DNS Finding: DNSReaper results for %s (%d found)", domain, count))
					utils.SendWebhookLogAsync(fmt.Sprintf("DNSReaper: %d candidates for %s", count, domain))
				}
			}
		}
	}
	return nil
}

func checkAzureAWS(domainDir, findingsDir, subsFile string) error {
	azureOut := filepath.Join(findingsDir, "azure-takeover.txt")
	awsOut := filepath.Join(findingsDir, "aws-takeover.txt")
	comboOut := filepath.Join(findingsDir, "azure-aws-takeover.txt")
	if err := writeLines(azureOut, nil); err != nil {
		return err
	}
	if err := writeLines(awsOut, nil); err != nil {
		return err
	}
	if err := writeLines(comboOut, nil); err != nil {
		return err
	}

	fSubs, err := os.Open(subsFile)
	if err != nil {
		return err
	}
	defer fSubs.Close()

	subsScanner := bufio.NewScanner(fSubs)
	azureCount, awsCount, vulnCount := 0, 0, 0
	for subsScanner.Scan() {
		sub := strings.TrimSpace(subsScanner.Text())
		if sub == "" {
			continue
		}

		cname, status := lookupCNAMEStatus(sub)
		if cname == "" || status != "NXDOMAIN" {
			continue
		}

		// Azure
		if hasSuffix(cname, []string{".cloudapp.net", ".azurewebsites.net", ".cloudapp.azure.com", ".trafficmanager.net"}) {
			service := "Azure"
			line := fmt.Sprintf("[VULNERABLE] [SUBDOMAIN:%s] [CNAME:%s] [SERVICE:%s] [STATUS:%s]", sub, cname, service, status)
			appendLine(azureOut, line)
			appendLine(comboOut, line)
			azureCount++
			vulnCount++
			log.Printf("[VULN] Azure takeover candidate: %s -> %s", sub, cname)
		}

		if hasSuffix(cname, []string{".elasticbeanstalk.com", ".s3.amazonaws.com", ".elb.amazonaws.com"}) || strings.Contains(cname, ".execute-api.") {
			service := "AWS"
			line := fmt.Sprintf("[VULNERABLE] [SUBDOMAIN:%s] [CNAME:%s] [SERVICE:%s] [STATUS:%s]", sub, cname, service, status)
			appendLine(awsOut, line)
			appendLine(comboOut, line)
			awsCount++
			vulnCount++
			log.Printf("[VULN] AWS takeover candidate: %s -> %s", sub, cname)
		}
	}
	if err := subsScanner.Err(); err != nil {
		return err
	}

	// Append simple summary to combo file
	summary := []string{
		"=== AZURE & AWS SUBDOMAIN TAKEOVER DETECTION SUMMARY ===",
		"Scan Date: " + timeNowString(),
		fmt.Sprintf("Total Subdomains Checked: %d", mustCount(subsFile)),
		fmt.Sprintf("Azure Vulnerabilities Found: %d", azureCount),
		fmt.Sprintf("AWS Vulnerabilities Found: %d", awsCount),
		fmt.Sprintf("Total Vulnerabilities: %d", vulnCount),
	}
	if err := appendLines(comboOut, summary...); err != nil {
		return err
	}

	// Send findings to webhook if configured
	if azureCount > 0 || awsCount > 0 {
		log.Printf("[OK] Azure/AWS takeover: %d Azure, %d AWS candidates found", azureCount, awsCount)
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			// Extract domain from domainDir
			domain := filepath.Base(domainDir)
			if azureCount > 0 {
				azureFile := filepath.Join(findingsDir, "azure-takeover.txt")
				if info, err := os.Stat(azureFile); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(azureFile, fmt.Sprintf("DNS Finding: Azure takeover candidates for %s (%d found)", domain, azureCount))
				}
			}
			if awsCount > 0 {
				awsFile := filepath.Join(findingsDir, "aws-takeover.txt")
				if info, err := os.Stat(awsFile); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(awsFile, fmt.Sprintf("DNS Finding: AWS takeover candidates for %s (%d found)", domain, awsCount))
				}
			}
			if vulnCount > 0 {
				comboFile := filepath.Join(findingsDir, "azure-aws-takeover.txt")
				if info, err := os.Stat(comboFile); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(comboFile, fmt.Sprintf("DNS Finding: Azure/AWS takeover candidates for %s (%d total)", domain, vulnCount))
				}
			}
			utils.SendWebhookLogAsync(fmt.Sprintf("Azure/AWS takeover check: %d Azure, %d AWS candidates for %s", azureCount, awsCount, domain))
		}
	}

	return nil
}

func runNSTakeover(domainDir, findingsDir, subsFile string) error {
	// Read subdomains from file
	file, err := os.Open(subsFile)
	if err != nil {
		return fmt.Errorf("failed to open subdomains file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read subdomains file: %w", err)
	}

	if len(targets) == 0 {
		log.Printf("[WARN] No subdomains found, skipping NS takeover")
		return nil
	}

	// Initialize dnsx client
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		return fmt.Errorf("failed to create dnsx client: %w", err)
	}

	nsServers := filepath.Join(findingsDir, "ns-servers.txt")
	log.Printf("[INFO] Extracting NS records with dnsx (concurrent)")
	var nsRecords []string
	var nsMutex sync.Mutex

	// Use worker pool for concurrent DNS queries
	threads := 100
	if threads > len(targets) {
		threads = len(targets)
	}

	jobs := make(chan string, len(targets))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				result, err := dnsClient.QueryOne(target)
				if err != nil {
					continue
				}
				if result != nil && len(result.NS) > 0 {
					nsMutex.Lock()
					for _, ns := range result.NS {
						nsRecords = append(nsRecords, ns)
					}
					nsMutex.Unlock()
				}
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, target := range targets {
			jobs <- target
		}
	}()

	wg.Wait()
	if err := writeLinesToFile(nsServers, nsRecords); err != nil {
		log.Printf("[WARN] Failed to write NS servers: %v", err)
	}

	nsRaw := filepath.Join(findingsDir, "ns-takeover-raw.txt")
	var servfailTargets []string
	var servfailMutex sync.Mutex

	// Concurrent check for SERVFAIL targets
	jobs2 := make(chan string, len(targets))
	var wg2 sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			for target := range jobs2 {
				result, err := dnsClient.QueryOne(target)
				// Check for SERVFAIL or REFUSED errors
				if err != nil {
					errStr := strings.ToLower(err.Error())
					if strings.Contains(errStr, "servfail") || strings.Contains(errStr, "refused") {
						servfailMutex.Lock()
						servfailTargets = append(servfailTargets, target)
						servfailMutex.Unlock()
					}
				} else if result != nil && len(result.A) == 0 && len(result.AAAA) == 0 {
					// Empty result might indicate DNS issues
					servfailMutex.Lock()
					servfailTargets = append(servfailTargets, target)
					servfailMutex.Unlock()
				}
			}
		}()
	}
	go func() {
		defer close(jobs2)
		for _, target := range targets {
			jobs2 <- target
		}
	}()
	wg2.Wait()
	if err := writeLinesToFile(nsRaw, servfailTargets); err != nil {
		log.Printf("[WARN] Failed to write NS raw: %v", err)
	}

	nsVulnServers := filepath.Join(findingsDir, "ns-servers-vuln.txt")
	var vulnServers []string
	var vulnMutex sync.Mutex

	// Concurrent check for vulnerable NS servers
	if len(nsRecords) > 0 {
		jobs3 := make(chan string, len(nsRecords))
		var wg3 sync.WaitGroup
		nsThreads := threads
		if nsThreads > len(nsRecords) {
			nsThreads = len(nsRecords)
		}
		for i := 0; i < nsThreads; i++ {
			wg3.Add(1)
			go func() {
				defer wg3.Done()
				for ns := range jobs3 {
					_, err := dnsClient.QueryOne(ns)
					if err != nil {
						errStr := strings.ToLower(err.Error())
						if strings.Contains(errStr, "servfail") || strings.Contains(errStr, "refused") {
							vulnMutex.Lock()
							vulnServers = append(vulnServers, ns)
							vulnMutex.Unlock()
						}
					}
				}
			}()
		}
		go func() {
			defer close(jobs3)
			for _, ns := range nsRecords {
				jobs3 <- ns
			}
		}()
		wg3.Wait()
	}
	if err := writeLinesToFile(nsVulnServers, vulnServers); err != nil {
		log.Printf("[WARN] Failed to write NS vuln servers: %v", err)
	}

	nsRawCount, _ := countLines(nsRaw)
	nsSrvCount, _ := countLines(nsVulnServers)
	log.Printf("[INFO] NS takeover: %d subdomain errors, %d NS server errors", nsRawCount, nsSrvCount)

	// filter to interesting providers (using same regex list as bash script, simplified)
	nsFiltered := filepath.Join(findingsDir, "ns-takeover-vuln.txt")
	regex := "ns1-.*.azure-dns.com|ns2-.*.azure-dns.net|ns3-.*.azure-dns.org|ns4-.*.azure-dns.info|ns1\\.dnsimple\\.com|ns2\\.dnsimple\\.com|ns3\\.dnsimple\\.com|ns4\\.dnsimple\\.com|ns1\\.domain\\.com|ns2\\.domain\\.com|ns1\\.dreamhost\\.com|ns2\\.dreamhost\\.com|ns3\\.dreamhost\\.com|ns-cloud-.*.googledomains.com|ns5\\.he\\.net|ns4\\.he\\.net|ns3\\.he\\.net|ns2\\.he\\.net|ns1\\.he\\.net|ns1\\.linode\\.com|ns2\\.linode\\.com|ns1.*.name.com|ns2.*.name.com|ns3.*.name.com|ns4.*.name.com|ns1\\.domaindiscover\\.com|ns2\\.domaindiscover\\.com|yns1\\.yahoo\\.com|yns2\\.yahoo\\.com|ns1\\.reg\\.ru|ns2\\.reg\\.ru"
	if err := grepRegexToFile(regex, nsRaw, nsFiltered); err != nil {
		log.Printf("[WARN] regex filter on NS takeover failed: %v", err)
	}

	// Send findings to webhook if configured
	if nsRawCount > 0 || nsSrvCount > 0 {
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			// Extract domain from domainDir
			domain := filepath.Base(domainDir)
			if nsRawCount > 0 {
				nsRawFile := filepath.Join(findingsDir, "ns-takeover-raw.txt")
				if info, err := os.Stat(nsRawFile); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(nsRawFile, fmt.Sprintf("DNS Finding: NS takeover (subdomain errors) for %s (%d found)", domain, nsRawCount))
				}
			}
			if nsSrvCount > 0 {
				nsVulnFile := filepath.Join(findingsDir, "ns-servers-vuln.txt")
				if info, err := os.Stat(nsVulnFile); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(nsVulnFile, fmt.Sprintf("DNS Finding: NS takeover (server errors) for %s (%d found)", domain, nsSrvCount))
				}
			}
			nsVulnCount, _ := countLines(nsFiltered)
			if nsVulnCount > 0 {
				if info, err := os.Stat(nsFiltered); err == nil && info.Size() > 0 {
					utils.SendWebhookFileAsync(nsFiltered, fmt.Sprintf("DNS Finding: NS takeover (vulnerable providers) for %s (%d found)", domain, nsVulnCount))
				}
			}
			utils.SendWebhookLogAsync(fmt.Sprintf("NS takeover check: %d subdomain errors, %d NS server errors for %s", nsRawCount, nsSrvCount, domain))
		}
	}

	return nil
}

func checkDanglingIPs(domainDir, findingsDir, subsFile string) error {
	danglingOut := filepath.Join(findingsDir, "dangling-ip.txt")
	// Summary file removed - only raw results generated
	
	if err := writeLines(danglingOut, nil); err != nil {
		return err
	}

	// Read subdomains from file
	file, err := os.Open(subsFile)
	if err != nil {
		return fmt.Errorf("failed to open subdomains file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read subdomains file: %w", err)
	}

	if len(targets) == 0 {
		log.Printf("[WARN] No subdomains found, skipping dangling IP check")
		return nil
	}

	// Initialize dnsx client
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		return fmt.Errorf("failed to create dnsx client: %w", err)
	}

	log.Printf("[INFO] Checking for dangling IPs across %d subdomains", len(targets))

	// Track IPs and their associated subdomains
	ipToSubdomains := make(map[string][]string)
	ipStatus := make(map[string]string) // "active", "inactive", "unknown"
	
	var danglingCandidates []string
	totalIPs := 0
	checkedIPs := 0

	// Step 1: Collect all A and AAAA records
	for _, target := range targets {
		result, err := dnsClient.QueryOne(target)
		if err != nil {
			continue
		}

		// Collect IPv4 addresses
		if result != nil && len(result.A) > 0 {
			for _, ip := range result.A {
				ipToSubdomains[ip] = append(ipToSubdomains[ip], target)
				totalIPs++
			}
		}

		// Collect IPv6 addresses
		if result != nil && len(result.AAAA) > 0 {
			for _, ip := range result.AAAA {
				ipToSubdomains[ip] = append(ipToSubdomains[ip], target)
				totalIPs++
			}
		}
	}

	if totalIPs == 0 {
		log.Printf("[INFO] No IP addresses found in DNS records")
		return nil
	}

	log.Printf("[INFO] Found %d unique IP addresses, checking if they're active...", len(ipToSubdomains))

	// Step 2: Check if IPs are still active using httpx (if available)
	// We'll check a sample of subdomains pointing to each IP
	hasHttpx := false
	if _, err := exec.LookPath("httpx"); err == nil {
		hasHttpx = true
	}

	// Create a temporary file with IPs to check
	tempIPFile := filepath.Join(findingsDir, "dangling-ip-temp.txt")
	var ipList []string
	for ip := range ipToSubdomains {
		ipList = append(ipList, ip)
	}
	if err := writeLinesToFile(tempIPFile, ipList); err != nil {
		log.Printf("[WARN] Failed to create temp IP file: %v", err)
	} else {
		defer os.Remove(tempIPFile) // Clean up temp file
	}

	// Step 3: For each IP, check if it responds
	for ip, subdomains := range ipToSubdomains {
		checkedIPs++
		isActive := false
		status := "unknown"

		// Try to check if IP responds via HTTP/HTTPS
		if hasHttpx {
			// Check one of the subdomains pointing to this IP
			if len(subdomains) > 0 {
				testSubdomain := subdomains[0]
				// Use httpx to check if the subdomain responds
				cmd := exec.Command("httpx", "-u", fmt.Sprintf("http://%s", testSubdomain), "-silent", "-status-code", "-timeout", "5", "-no-color")
				output, err := cmd.CombinedOutput()
				if err == nil && len(output) > 0 {
					// If we get a status code, the IP is likely active
					outputStr := strings.TrimSpace(string(output))
					if strings.Contains(outputStr, "http://") || strings.Contains(outputStr, "https://") {
						isActive = true
						status = "active"
					}
				}
			}
		}

		// Also try direct IP check (some IPs might respond directly)
		if !isActive && hasHttpx {
			cmd := exec.Command("httpx", "-u", fmt.Sprintf("http://%s", ip), "-silent", "-status-code", "-timeout", "3", "-no-color")
			output, err := cmd.CombinedOutput()
			if err == nil && len(output) > 0 {
				outputStr := strings.TrimSpace(string(output))
				if strings.Contains(outputStr, "http://") || strings.Contains(outputStr, "https://") {
					isActive = true
					status = "active"
				}
			}
		}

		// If we couldn't verify with httpx, try a simple DNS reverse lookup
		if !isActive {
			// Check if IP has reverse DNS (PTR record)
			cmd := exec.Command("dig", "+short", "-x", ip)
			output, err := cmd.CombinedOutput()
			if err == nil {
				ptrRecord := strings.TrimSpace(string(output))
				if ptrRecord != "" && !strings.Contains(ptrRecord, "NXDOMAIN") {
					// Has PTR record, likely still in use
					status = "active"
					isActive = true
				} else {
					// No PTR record, might be dangling
					status = "inactive"
				}
			} else {
				status = "unknown"
			}
		}

		ipStatus[ip] = status

		// If IP appears inactive or unknown, it's a potential dangling IP candidate
		if status == "inactive" || (status == "unknown" && !isActive) {
			// Additional check: see if multiple subdomains point to this IP
			// If many subdomains point to an inactive IP, it's more likely dangling
			if len(subdomains) > 0 {
				line := fmt.Sprintf("[CANDIDATE] [IP:%s] [STATUS:%s] [SUBDOMAINS:%d] [EXAMPLES:%s]", 
					ip, status, len(subdomains), strings.Join(subdomains[:min(3, len(subdomains))], ","))
				if len(subdomains) > 3 {
					line += fmt.Sprintf(" (and %d more)", len(subdomains)-3)
				}
				appendLine(danglingOut, line)
				danglingCandidates = append(danglingCandidates, ip)
				log.Printf("[CANDIDATE] Potential dangling IP: %s (status: %s, %d subdomains)", ip, status, len(subdomains))
			}
		}
	}

	// Append dangling IPs to output file
	if err := appendLines(danglingOut, danglingCandidates...); err != nil {
		log.Printf("[WARN] Failed to write dangling IPs: %v", err)
	}
	// Summary file removed - only raw results generated

	log.Printf("[OK] Dangling IP check completed: %d candidates found out of %d IPs", len(danglingCandidates), len(ipToSubdomains))
	
	// Send findings to webhook if configured
	if len(danglingCandidates) > 0 {
		webhookURL := os.Getenv("DISCORD_WEBHOOK")
		if webhookURL != "" {
			// Extract domain from domainDir
			domain := filepath.Base(domainDir)
			danglingFile := filepath.Join(findingsDir, "dangling-ip.txt")
			// Summary file removed - only send raw results
			if info, err := os.Stat(danglingFile); err == nil && info.Size() > 0 {
				utils.SendWebhookFileAsync(danglingFile, fmt.Sprintf("DNS Finding: Dangling IP candidates for %s (%d found)", domain, len(danglingCandidates)))
			}
			utils.SendWebhookLogAsync(fmt.Sprintf("Dangling IP check: %d candidates found for %s", len(danglingCandidates), domain))
		}
	}
	
	return nil
}

func countStatus(statusMap map[string]string, status string) int {
	count := 0
	for _, s := range statusMap {
		if s == status {
			count++
		}
	}
	return count
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func writeSummary(domain, findingsDir, subsFile string) error {
	summary := filepath.Join(findingsDir, "dns-takeover-summary.txt")
	nPublic, _ := countLines(filepath.Join(findingsDir, "nuclei-takeover-public.txt"))
	nCustom, _ := countLines(filepath.Join(findingsDir, "nuclei-takeover-custom.txt"))
	dnsReaper, _ := countLines(filepath.Join(findingsDir, "dnsreaper-results.txt"))
	nAzure, _ := countLines(filepath.Join(findingsDir, "azure-takeover.txt"))
	nAWS, _ := countLines(filepath.Join(findingsDir, "aws-takeover.txt"))
	nNSRaw, _ := countLines(filepath.Join(findingsDir, "ns-takeover-raw.txt"))
	nNSSrv, _ := countLines(filepath.Join(findingsDir, "ns-servers-vuln.txt"))
	nNSVuln, _ := countLines(filepath.Join(findingsDir, "ns-takeover-vuln.txt"))
	nDanglingIP, _ := countLines(filepath.Join(findingsDir, "dangling-ip.txt"))

	lines := []string{
		"=== COMPREHENSIVE DNS TAKEOVER SCAN SUMMARY ===",
		"Scan Date: " + timeNowString(),
		"Target Domain: " + domain,
		fmt.Sprintf("Total Subdomains Scanned: %d", mustCount(subsFile)),
		"Tools Used: dnsx, nuclei, dnsreaper, dig, httpx",
		"",
		"=== FINDINGS SUMMARY ===",
		fmt.Sprintf("CNAME Takeover (Nuclei public): %d", nPublic),
		fmt.Sprintf("CNAME Takeover (Nuclei custom): %d", nCustom),
		fmt.Sprintf("DNSReaper Results: %d", dnsReaper),
		fmt.Sprintf("Azure Subdomain Takeover: %d", nAzure),
		fmt.Sprintf("AWS Subdomain Takeover: %d", nAWS),
		fmt.Sprintf("NS Takeover (Subdomain DNS Errors): %d", nNSRaw),
		fmt.Sprintf("NS Takeover (NS Server DNS Errors): %d", nNSSrv),
		fmt.Sprintf("NS Takeover (Vulnerable Providers): %d", nNSVuln),
		fmt.Sprintf("Dangling IP Candidates: %d", nDanglingIP),
		"",
		"=== NOTES ===",
		"- Review individual result files in the dns-takeover directory for details.",
		"- Always manually validate takeover conditions before reporting.",
		"- Dangling IP detection checks for IPs that may no longer be assigned to services.",
	}
	return writeLines(summary, lines)
}

// ---- small utilities ----

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	count := 0
	for s.Scan() {
		if strings.TrimSpace(s.Text()) != "" {
			count++
		}
	}
	return count, s.Err()
}

func mustCount(path string) int {
	c, err := countLines(path)
	if err != nil {
		return 0
	}
	return c
}

func writeLinesToFile(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if len(lines) == 0 {
		return nil
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if _, err := w.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

func appendLines(path string, lines ...string) error {
	for _, l := range lines {
		if err := appendLine(path, l); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func hasSuffix(s string, suffixes []string) bool {
	for _, suf := range suffixes {
		if strings.HasSuffix(strings.ToLower(s), strings.ToLower(suf)) {
			return true
		}
	}
	return false
}

func lookupCNAMEStatus(name string) (string, string) {
	// Use `dig` as in the legacy script
	if _, err := exec.LookPath("dig"); err != nil {
		return "", ""
	}

	// CNAME
	cmd := exec.Command("dig", "+short", "+noall", "+answer", name, "CNAME")
	b, err := cmd.CombinedOutput()
	if err != nil {
		return "", ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	cname := ""
	if len(lines) > 0 && strings.TrimSpace(lines[0]) != "" {
		fields := strings.Fields(lines[0])
		if len(fields) > 0 {
			cname = strings.TrimSpace(fields[len(fields)-1])
		}
	}

	// full status
	cmd = exec.Command("dig", "+noall", "+answer", name)
	b, err = cmd.CombinedOutput()
	if err != nil {
		return cname, "ERROR"
	}
	status := "UNKNOWN"
	out := string(b)
	if strings.Contains(out, "status: NXDOMAIN") {
		status = "NXDOMAIN"
	} else if strings.Contains(out, "status: NOERROR") {
		status = "NOERROR"
	} else if strings.Contains(out, "status: SERVFAIL") {
		status = "SERVFAIL"
	}
	return cname, status
}

func grepRegexToFile(pattern, src, dst string) error {
	if _, err := exec.LookPath("grep"); err != nil {
		return nil
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := exec.Command("grep", "-Ei", pattern, src)
	cmd.Stdout = f
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// grep returns non-zero when no matches; that's fine
		return nil
	}
	return nil
}

// sendDNSFindingsToWebhook sends DNS findings to Discord webhook if configured
func sendDNSFindingsToWebhook(domain, findingsDir string) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK")
	if webhookURL == "" {
		// No webhook configured, skip silently
		return
	}

	// Check for findings in key files
	findingsFiles := []struct {
		file        string
		description string
	}{
		{"dns-takeover-summary.txt", "DNS takeover summary"},
	}

	var foundFiles []string
	hasAnyFindings := false
	
	// Check all possible findings files
	allFindingsFiles := []string{
		"dangling-ip.txt", "nuclei-takeover-public.txt", "nuclei-takeover-custom.txt",
		"dnsreaper-results.txt", "azure-takeover.txt", "aws-takeover.txt",
		"ns-takeover-vuln.txt", "ns-takeover-raw.txt", "ns-servers-vuln.txt",
	}
	
	for _, f := range allFindingsFiles {
		filePath := filepath.Join(findingsDir, f)
		if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
			if count, err := countLines(filePath); err == nil && count > 0 {
				hasAnyFindings = true
				break
			}
		}
	}

	for _, ff := range findingsFiles {
		filePath := filepath.Join(findingsDir, ff.file)
		if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
			// Check if summary has actual findings (not just headers)
			data, err := os.ReadFile(filePath)
			if err == nil {
				content := string(data)
				// Check if summary indicates findings (look for counts > 0)
				if !strings.Contains(content, ": 0") || strings.Contains(content, ": 1") || strings.Contains(content, ": 2") {
					// Has findings, include it
					foundFiles = append(foundFiles, filePath)
				}
			}
		}
	}

	if len(foundFiles) > 0 {
		// Send summary file
		for _, filePath := range foundFiles {
			fileName := filepath.Base(filePath)
			description := fmt.Sprintf("DNS Scan Summary: %s for %s", fileName, domain)
			utils.SendWebhookFileAsync(filePath, description)
		}
	} else if !hasAnyFindings {
		// No findings at all, send completion message
		utils.SendWebhookLogAsync(fmt.Sprintf("DNS scan completed for %s with 0 findings", domain))
	}
}

func timeNowString() string {
	return time.Now().Format(time.RFC3339)
}
