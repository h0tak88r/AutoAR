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
	"time"

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

	// If we already have a reasonably-sized file, reuse it, but refresh if tiny.
	if info, statErr := os.Stat(subsFile); statErr == nil && info.Size() > 0 {
		count, cErr := countLines(subsFile)
		if cErr == nil && count >= 5 {
			log.Printf("[INFO] Using existing subdomains from %s (%d subdomains)", subsFile, count)
			return domainDir, subsFile, nil
		}
		log.Printf("[WARN] Only %d subdomains in %s, refreshing enumeration", count, subsFile)
	}

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

// Takeover runs the comprehensive DNS takeover workflow (equivalent to `dns takeover` / `dns all`).
func Takeover(domain string) error {
	domainDir, subsFile, err := ensureSubdomains(domain)
	if err != nil {
		return err
	}
	findingsDir := filepath.Join(domainDir, findingsDirName)
	if err := utils.EnsureDir(findingsDir); err != nil {
		return fmt.Errorf("failed to create findings dir: %w", err)
	}

	// Initialise output files (compatible with legacy layout)
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
		"dns-takeover-summary.txt",
		"dnsreaper-results.txt",
		"filtered-ns-takeover-vuln.txt",
	}
	for _, name := range files {
		p := filepath.Join(findingsDir, name)
		if err := writeLines(p, nil); err != nil {
			return fmt.Errorf("failed to initialise %s: %w", p, err)
		}
	}

	log.Printf("[INFO] Starting comprehensive DNS takeover scan for %s", domain)

	if err := runNucleiTakeover(domainDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] Nuclei takeover step failed: %v", err)
	}
	if err := runDNSReaper(domainDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] DNSReaper step failed: %v", err)
	}
	if err := checkAzureAWS(domainDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] Azure/AWS check failed: %v", err)
	}
	if err := runNSTakeover(domainDir, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] NS takeover step failed: %v", err)
	}

	if err := writeSummary(domain, findingsDir, subsFile); err != nil {
		log.Printf("[WARN] Failed to write DNS takeover summary: %v", err)
	}

	log.Printf("[OK] DNS takeover scan completed for %s (results in %s)", domain, findingsDir)
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
	log.Printf("[INFO] Extracting NS records with dnsx")
	var nsRecords []string
	for _, target := range targets {
		result, err := dnsClient.QueryOne(target)
		if err != nil {
			continue
		}
		if result != nil && len(result.NS) > 0 {
			for _, ns := range result.NS {
				nsRecords = append(nsRecords, ns)
			}
		}
	}
	if err := writeLinesToFile(nsServers, nsRecords); err != nil {
		log.Printf("[WARN] Failed to write NS servers: %v", err)
	}

	nsRaw := filepath.Join(findingsDir, "ns-takeover-raw.txt")
	var servfailTargets []string
	for _, target := range targets {
		result, err := dnsClient.QueryOne(target)
		// Check for SERVFAIL or REFUSED errors
		if err != nil {
			errStr := strings.ToLower(err.Error())
			if strings.Contains(errStr, "servfail") || strings.Contains(errStr, "refused") {
				servfailTargets = append(servfailTargets, target)
			}
		} else if result != nil && len(result.A) == 0 && len(result.AAAA) == 0 {
			// Empty result might indicate DNS issues
			servfailTargets = append(servfailTargets, target)
		}
	}
	if err := writeLinesToFile(nsRaw, servfailTargets); err != nil {
		log.Printf("[WARN] Failed to write NS raw: %v", err)
	}

	nsVulnServers := filepath.Join(findingsDir, "ns-servers-vuln.txt")
	var vulnServers []string
	for _, ns := range nsRecords {
		_, err := dnsClient.QueryOne(ns)
		if err != nil {
			errStr := strings.ToLower(err.Error())
			if strings.Contains(errStr, "servfail") || strings.Contains(errStr, "refused") {
				vulnServers = append(vulnServers, ns)
			}
		}
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

	return nil
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

	lines := []string{
		"=== COMPREHENSIVE DNS TAKEOVER SCAN SUMMARY ===",
		"Scan Date: " + timeNowString(),
		"Target Domain: " + domain,
		fmt.Sprintf("Total Subdomains Scanned: %d", mustCount(subsFile)),
		"Tools Used: dnsx, nuclei, dnsreaper, dig",
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
		"",
		"=== NOTES ===",
		"- Review individual result files in the dns-takeover directory for details.",
		"- Always manually validate takeover conditions before reporting.",
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

func timeNowString() string {
	return time.Now().Format(time.RFC3339)
}
