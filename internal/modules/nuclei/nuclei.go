package nuclei

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// ScanMode represents the nuclei scan mode
type ScanMode string

const (
	ModeFull            ScanMode = "full"
	ModeCVEs            ScanMode = "cves"
	ModePanels          ScanMode = "panels"
	ModeDefaultLogins   ScanMode = "default-logins"
	ModeVulnerabilities ScanMode = "vulnerabilities"
)

// Options holds nuclei scan options
type Options struct {
	Domain  string
	URL     string
	Mode    ScanMode
	Threads int
}

// Result holds nuclei scan results
type Result struct {
	TargetName  string
	Mode        ScanMode
	ResultFiles []string
}

// RunNuclei runs nuclei scan based on options
func RunNuclei(opts Options) (*Result, error) {
	if opts.Domain == "" && opts.URL == "" {
		return nil, fmt.Errorf("either domain (-d) or url (-u) must be provided")
	}
	if opts.Domain != "" && opts.URL != "" {
		return nil, fmt.Errorf("cannot use both -d and -u together")
	}
	if opts.Mode == "" {
		opts.Mode = ModeFull
	}
	if opts.Threads == 0 {
		opts.Threads = 100
	}

	// Validate mode
	validModes := map[ScanMode]bool{
		ModeFull: true, ModeCVEs: true, ModePanels: true,
		ModeDefaultLogins: true, ModeVulnerabilities: true,
	}
	if !validModes[opts.Mode] {
		return nil, fmt.Errorf("invalid mode: %s. Must be full, cves, panels, default-logins, or vulnerabilities", opts.Mode)
	}

	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, fmt.Errorf("nuclei is not installed or not in PATH")
	}

	root := utils.GetRootDir()
	resultsDir := utils.GetResultsDir()
	var targetFile, outputDir, targetName string

	// Handle URL mode (single URL, no subdomain enum)
	if opts.URL != "" {
		log.Printf("[INFO] Single URL mode: %s", opts.URL)
		targetName = opts.URL

		// Extract domain from URL for directory structure
		extractedDomain := extractDomainFromURL(opts.URL)
		domainDir := filepath.Join(resultsDir, extractedDomain)
		outputDir = filepath.Join(domainDir, "vulnerabilities")
		if err := utils.EnsureDir(outputDir); err != nil {
			return nil, fmt.Errorf("failed to create output dir: %w", err)
		}

		// Create temporary URL file
		targetFile = filepath.Join(domainDir, "temp-url.txt")
		if err := os.WriteFile(targetFile, []byte(opts.URL+"\n"), 0644); err != nil {
			return nil, fmt.Errorf("failed to create temp URL file: %w", err)
		}
		defer os.Remove(targetFile)

		log.Printf("[INFO] Running Nuclei in %s mode on single URL", opts.Mode)
		resultFiles, err := runNucleiScan(targetFile, outputDir, opts.Mode, opts.Threads, targetName, root)
		if err != nil {
			return nil, err
		}
		return &Result{TargetName: targetName, Mode: opts.Mode, ResultFiles: resultFiles}, nil
	}

	// Handle domain mode
	log.Printf("[INFO] Domain mode: %s", opts.Domain)
	targetName = opts.Domain
	domainDir := filepath.Join(resultsDir, opts.Domain)
	outputDir = filepath.Join(domainDir, "vulnerabilities")
	if err := utils.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Always perform subdomain enumeration and live-host detection for domain scans
	log.Printf("[INFO] Performing subdomain enumeration and live-host detection for %s", opts.Domain)
	subsDir := filepath.Join(domainDir, "subs")
	if err := utils.EnsureDir(subsDir); err != nil {
		return nil, fmt.Errorf("failed to create subs dir: %w", err)
	}

	// Ensure subdomains via Go module
	allSubsFile := filepath.Join(subsDir, "all-subs.txt")
	if _, err := os.Stat(allSubsFile); err != nil {
		log.Printf("[INFO] Enumerating subdomains for %s", opts.Domain)
		subs, err := subdomains.EnumerateSubdomains(opts.Domain, opts.Threads)
		if err != nil {
			log.Printf("[WARN] Subdomain enumeration failed: %v", err)
		} else {
			if err := writeLines(allSubsFile, subs); err != nil {
				log.Printf("[WARN] Failed to write subdomains: %v", err)
			} else {
				log.Printf("[OK] Found %d unique subdomains", len(subs))
			}
		}
	}

	// Use live hosts file from Step 1 (livehosts phase) if it exists
	// This avoids re-running livehosts collection which is already done in lite scan Step 1
	liveSubsFile := filepath.Join(subsDir, "live-subs.txt")
	if info, err := os.Stat(liveSubsFile); err != nil || info.Size() == 0 {
		// File doesn't exist or is empty, need to create it
		log.Printf("[INFO] Live hosts file not found or empty, filtering live hosts for %s", opts.Domain)
		_, err := livehosts.FilterLiveHosts(opts.Domain, opts.Threads, true)
		if err != nil {
			log.Printf("[WARN] Live host detection failed: %v", err)
		}
		// Re-check after creation
		if info, err := os.Stat(liveSubsFile); err != nil || info.Size() == 0 {
			return nil, fmt.Errorf("no live hosts found for %s", opts.Domain)
		}
		log.Printf("[INFO] Created live hosts file for %s", opts.Domain)
	} else {
		// File exists from Step 1, use it directly
		log.Printf("[INFO] Using existing live hosts file from Step 1 (size: %d bytes)", info.Size())
	}

	targetFile = liveSubsFile
	targetCount, _ := countLines(targetFile)
	log.Printf("[INFO] Running Nuclei in %s mode on %d live targets from %s", opts.Mode, targetCount, liveSubsFile)

	resultFiles, err := runNucleiScan(targetFile, outputDir, opts.Mode, opts.Threads, targetName, root)
	if err != nil {
		return nil, err
	}

	log.Printf("[OK] Nuclei scan completed successfully for %s (mode: %s)", targetName, opts.Mode)
	return &Result{TargetName: targetName, Mode: opts.Mode, ResultFiles: resultFiles}, nil
}

func runNucleiScan(targetFile, outputDir string, mode ScanMode, threads int, targetName, root string) ([]string, error) {
	if err := utils.EnsureDir(outputDir); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	var resultFiles []string

	switch mode {
	case ModeFull:
		files, err := runFullScan(targetFile, outputDir, threads, targetName, root)
		if err != nil {
			return nil, err
		}
		resultFiles = append(resultFiles, files...)
	case ModeCVEs:
		files, err := runCVEsScan(targetFile, outputDir, threads, targetName, root)
		if err != nil {
			return nil, err
		}
		resultFiles = append(resultFiles, files...)
	case ModePanels:
		files, err := runPanelsScan(targetFile, outputDir, threads, targetName, root)
		if err != nil {
			return nil, err
		}
		resultFiles = append(resultFiles, files...)
	case ModeDefaultLogins:
		files, err := runDefaultLoginsScan(targetFile, outputDir, threads, targetName, root)
		if err != nil {
			return nil, err
		}
		resultFiles = append(resultFiles, files...)
	case ModeVulnerabilities:
		files, err := runVulnerabilitiesScan(targetFile, outputDir, threads, targetName, root)
		if err != nil {
			return nil, err
		}
		resultFiles = append(resultFiles, files...)
	}

	return resultFiles, nil
}

func runFullScan(targetFile, outputDir string, threads int, targetName, root string) ([]string, error) {
	log.Printf("[INFO] === Running FULL scan mode ===")
	var resultFiles []string

	// 1. Custom templates (nuclei_templates/vulns)
	customDir := filepath.Join(root, "nuclei_templates", "vulns")
	if dirExists(customDir) {
		log.Printf("[INFO] Scanning with custom templates (nuclei_templates/vulns)...")
		customOut := filepath.Join(outputDir, "nuclei-custom-others.txt")
		if err := runNucleiCommand(targetFile, customDir, threads, customOut); err == nil {
			if count, _ := countLines(customOut); count > 0 {
				log.Printf("[OK] Found %d findings with custom templates", count)
				resultFiles = append(resultFiles, customOut)
			}
		}
	}

	// 2. Public HTTP templates
	publicDir := filepath.Join(root, "nuclei-templates", "http")
	if dirExists(publicDir) {
		log.Printf("[INFO] Scanning with public HTTP templates (nuclei-templates/http)...")
		publicOut := filepath.Join(outputDir, "nuclei-public-http.txt")
		if err := runNucleiCommand(targetFile, publicDir, threads, publicOut); err == nil {
			if count, _ := countLines(publicOut); count > 0 {
				log.Printf("[OK] Found %d findings with public HTTP templates", count)
				resultFiles = append(resultFiles, publicOut)
			}
		}
	}

	// 3. Also run CVEs and Panels scans in full mode
	if cveFiles, err := runCVEsScan(targetFile, outputDir, threads, targetName, root); err == nil {
		resultFiles = append(resultFiles, cveFiles...)
	}
	if panelFiles, err := runPanelsScan(targetFile, outputDir, threads, targetName, root); err == nil {
		resultFiles = append(resultFiles, panelFiles...)
	}

	return resultFiles, nil
}

func runCVEsScan(targetFile, outputDir string, threads int, targetName, root string) ([]string, error) {
	log.Printf("[INFO] === Running CVEs scan mode ===")
	var resultFiles []string

	// Custom CVE templates
	customDir := filepath.Join(root, "nuclei_templates", "cves")
	if dirExists(customDir) {
		log.Printf("[INFO] Scanning with custom CVE templates...")
		customOut := filepath.Join(outputDir, "nuclei-custom-cves.txt")
		if err := runNucleiCommand(targetFile, customDir, threads, customOut); err == nil {
			if count, _ := countLines(customOut); count > 0 {
				log.Printf("[OK] Found %d CVE findings with custom templates", count)
				resultFiles = append(resultFiles, customOut)
			}
		}
	}

	// Public CVE templates
	publicDir := filepath.Join(root, "nuclei-templates", "http", "cves")
	if dirExists(publicDir) {
		log.Printf("[INFO] Scanning with public CVE templates...")
		publicOut := filepath.Join(outputDir, "nuclei-public-cves.txt")
		if err := runNucleiCommand(targetFile, publicDir, threads, publicOut); err == nil {
			if count, _ := countLines(publicOut); count > 0 {
				log.Printf("[OK] Found %d CVE findings with public templates", count)
				resultFiles = append(resultFiles, publicOut)
			}
		}
	}

	return resultFiles, nil
}

func runPanelsScan(targetFile, outputDir string, threads int, targetName, root string) ([]string, error) {
	log.Printf("[INFO] === Running Panels Discovery scan mode ===")
	var resultFiles []string

	// Custom panels templates
	customDir := filepath.Join(root, "nuclei_templates", "panels")
	if dirExists(customDir) {
		log.Printf("[INFO] Scanning with custom panel templates...")
		customOut := filepath.Join(outputDir, "nuclei-custom-panels.txt")
		if err := runNucleiCommand(targetFile, customDir, threads, customOut); err == nil {
			if count, _ := countLines(customOut); count > 0 {
				log.Printf("[OK] Found %d panels with custom templates", count)
				resultFiles = append(resultFiles, customOut)
			}
		}
	}

	// Public exposed-panels templates
	publicDir := filepath.Join(root, "nuclei-templates", "http", "exposed-panels")
	if dirExists(publicDir) {
		log.Printf("[INFO] Scanning with public exposed panels templates...")
		publicOut := filepath.Join(outputDir, "nuclei-public-panels.txt")
		if err := runNucleiCommand(targetFile, publicDir, threads, publicOut); err == nil {
			if count, _ := countLines(publicOut); count > 0 {
				log.Printf("[OK] Found %d exposed panels with public templates", count)
				resultFiles = append(resultFiles, publicOut)
			}
		}
	}

	return resultFiles, nil
}

func runDefaultLoginsScan(targetFile, outputDir string, threads int, targetName, root string) ([]string, error) {
	log.Printf("[INFO] === Running Default Logins scan ===")
	var resultFiles []string

	// Custom default logins templates
	customDir := filepath.Join(root, "nuclei_templates", "default-logins")
	if dirExists(customDir) {
		log.Printf("[INFO] Scanning with custom default logins templates...")
		customOut := filepath.Join(outputDir, "nuclei-custom-default-logins.txt")
		if err := runNucleiCommand(targetFile, customDir, threads, customOut); err == nil {
			if count, _ := countLines(customOut); count > 0 {
				log.Printf("[OK] Found %d default login findings with custom templates", count)
				resultFiles = append(resultFiles, customOut)
			}
		}
	}

	// Public default logins templates
	publicDir := filepath.Join(root, "nuclei-templates", "http", "default-logins")
	if dirExists(publicDir) {
		log.Printf("[INFO] Scanning with public default logins templates...")
		publicOut := filepath.Join(outputDir, "nuclei-public-default-logins.txt")
		if err := runNucleiCommand(targetFile, publicDir, threads, publicOut); err == nil {
			if count, _ := countLines(publicOut); count > 0 {
				log.Printf("[OK] Found %d default login findings with public templates", count)
				resultFiles = append(resultFiles, publicOut)
			}
		}
	}

	return resultFiles, nil
}

func runVulnerabilitiesScan(targetFile, outputDir string, threads int, targetName, root string) ([]string, error) {
	log.Printf("[INFO] === Running Generic Vulnerabilities scan mode ===")
	var resultFiles []string

	// Custom vulnerability templates
	customDir := filepath.Join(root, "nuclei_templates", "vulns")
	if dirExists(customDir) {
		log.Printf("[INFO] Scanning with custom vulnerability templates...")
		customOut := filepath.Join(outputDir, "nuclei-custom-vulnerabilities.txt")
		if err := runNucleiCommand(targetFile, customDir, threads, customOut); err == nil {
			if count, _ := countLines(customOut); count > 0 {
				log.Printf("[OK] Found %d vulnerability findings with custom templates", count)
				resultFiles = append(resultFiles, customOut)
			}
		}
	}

	// Public vulnerability templates
	publicDir := filepath.Join(root, "nuclei-templates", "http", "vulnerabilities")
	if dirExists(publicDir) {
		log.Printf("[INFO] Scanning with public vulnerability templates...")
		publicOut := filepath.Join(outputDir, "nuclei-public-vulnerabilities.txt")
		if err := runNucleiCommand(targetFile, publicDir, threads, publicOut); err == nil {
			if count, _ := countLines(publicOut); count > 0 {
				log.Printf("[OK] Found %d vulnerability findings with public templates", count)
				resultFiles = append(resultFiles, publicOut)
			}
		}
	}

	// DAST vulnerability templates
	dastDir := filepath.Join(root, "nuclei-templates", "dast", "vulnerabilities")
	if dirExists(dastDir) {
		log.Printf("[INFO] Scanning with DAST vulnerability templates...")
		dastOut := filepath.Join(outputDir, "nuclei-dast-vulnerabilities.txt")
		if err := runNucleiCommand(targetFile, dastDir, threads, dastOut); err == nil {
			if count, _ := countLines(dastOut); count > 0 {
				log.Printf("[OK] Found %d vulnerability findings with DAST templates", count)
				resultFiles = append(resultFiles, dastOut)
			}
		}
	}

	return resultFiles, nil
}

func runNucleiCommand(targetFile, templateDir string, threads int, outputFile string) error {
	cmd := exec.Command("nuclei", "-l", targetFile, "-t", templateDir, "-c", fmt.Sprintf("%d", threads), "-silent", "-duc", "-o", outputFile)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func extractDomainFromURL(url string) string {
	// Simple extraction: remove http:// or https://, then take first part before /
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	if idx := strings.Index(url, "/"); idx > 0 {
		url = url[:idx]
	}
	return url
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func countLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	return os.WriteFile(path, []byte(data), 0644)
}
