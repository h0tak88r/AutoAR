package sqlmap

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Result holds sqlmap scan results
type Result struct {
	Domain     string
	Findings   int
	OutputFile string
}

// RunSQLMap runs sqlmap SQL injection scanner
func RunSQLMap(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads == 0 {
		threads = 100
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	inFile := filepath.Join(domainDir, "vulnerabilities", "sqli", "gf-results.txt")
	outFile := filepath.Join(domainDir, "vulnerabilities", "sqli", "sqlmap-results.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Ensure GF results exist
	if _, err := os.Stat(inFile); err != nil {
		log.Printf("[INFO] No SQLi candidates found, running GF scan first")
		if _, err := gf.ScanGF(domain); err != nil {
			return nil, fmt.Errorf("failed to run GF scan: %w", err)
		}
	}

	if info, err := os.Stat(inFile); err != nil || info.Size() == 0 {
		log.Printf("[WARN] No SQLi candidate file at %s", inFile)
		return &Result{Domain: domain, Findings: 0, OutputFile: outFile}, nil
	}

	// Clean URLs
	tempURLs := filepath.Join(domainDir, "vulnerabilities", "sqli", "clean_urls.txt")
	if err := cleanURLs(inFile, tempURLs); err != nil {
		return nil, fmt.Errorf("failed to clean URLs: %w", err)
	}
	defer os.Remove(tempURLs)

	if info, err := os.Stat(tempURLs); err != nil || info.Size() == 0 {
		log.Printf("[WARN] No valid URLs for sqlmap")
		return &Result{Domain: domain, Findings: 0, OutputFile: outFile}, nil
	}

	// Run sqlmap
	if _, err := exec.LookPath("interlace"); err == nil {
		log.Printf("[INFO] Running sqlmap with %d threads using interlace", threads)
		cmd := exec.Command("interlace", "-tL", tempURLs, "-threads", fmt.Sprintf("%d", threads), "-c", "sqlmap -u _target_ --batch --dbs --random-agent", "-o", outFile)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("[WARN] sqlmap scan failed: %v", err)
		}
	} else {
		log.Printf("[INFO] Running sqlmap in single-thread mode (interlace not found)")
		if err := runSQLMapSingleThread(tempURLs, outFile); err != nil {
			log.Printf("[WARN] sqlmap scan failed: %v", err)
		}
	}

	count, _ := countLines(outFile)
	log.Printf("[OK] SQLMap scan completed, found %d findings", count)

	return &Result{
		Domain:     domain,
		Findings:   count,
		OutputFile: outFile,
	}, nil
}

func cleanURLs(inFile, outFile string) error {
	in, err := os.Open(inFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer out.Close()

	urlRegex := regexp.MustCompile(`^https?://`)
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Remove non-printable chars and check if it's a valid URL
		cleaned := strings.Map(func(r rune) rune {
			if r >= 32 && r < 127 {
				return r
			}
			return -1
		}, line)
		if urlRegex.MatchString(cleaned) {
			if _, err := out.WriteString(cleaned + "\n"); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func runSQLMapSingleThread(urlsFile, outFile string) error {
	f, err := os.Open(urlsFile)
	if err != nil {
		return err
	}
	defer f.Close()

	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url == "" {
			continue
		}
		cmd := exec.Command("sqlmap", "-u", url, "--batch", "--random-agent", "--dbs")
		cmd.Stdout = out
		cmd.Stderr = os.Stderr
		_ = cmd.Run() // Continue on error
	}
	return scanner.Err()
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
