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
	"sync"

	"github.com/h0tak88r/AutoAR/internal/scanner/gf"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Result holds sqlmap scan results
type Result struct {
	Domain     string
	Findings   int
	OutputFile string
}

type sqlmapFinding struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Severity   string `json:"severity"`
	Module     string `json:"module"`
	Finding    string `json:"finding"`
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
	inFile := filepath.Join(domainDir, "vulnerabilities", "sqli", gf.ResultFileForPattern("sqli"))
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
		if scanID := utils.GetCurrentScanID(); scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "sql-detection", "sqlmap-results.json")
		}
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
		if scanID := utils.GetCurrentScanID(); scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "sql-detection", "sqlmap-results.json")
		}
		return &Result{Domain: domain, Findings: 0, OutputFile: outFile}, nil
	}

	// Run sqlmap via native Go concurrency (replaces interlace limitation)
	log.Printf("[INFO] Running sqlmap natively with %d threads", threads)
	structuredFindings, err := runSQLMapMultiThread(tempURLs, outFile, threads)
	if err != nil {
		log.Printf("[WARN] sqlmap scan failed: %v", err)
	}

	count, _ := countLines(outFile)
	log.Printf("[OK] SQLMap scan completed, found %d findings", count)

	if scanID := utils.GetCurrentScanID(); scanID != "" {
		if len(structuredFindings) > 0 {
			_ = utils.WriteJSONToScanDir(scanID, "sqlmap-results.json", structuredFindings)
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "sql-detection", "sqlmap-results.json")
		}
	}

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

func runSQLMapMultiThread(urlsFile, outFile string, workers int) ([]sqlmapFinding, error) {
	f, err := os.Open(urlsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	urls := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		u := strings.TrimSpace(scanner.Text())
		if u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return nil, nil
	}

	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	var outMutex sync.Mutex
	var findingsMutex sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string, len(urls))
	structuredFindings := make([]sqlmapFinding, 0, len(urls))

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				cmd := exec.Command("sqlmap", "-u", url, "--batch", "--random-agent", "--dbs")
				output, _ := cmd.CombinedOutput()
				outText := strings.ToLower(string(output))
				outMutex.Lock()
				_, _ = out.Write(output)
				outMutex.Unlock()
				if strings.Contains(outText, "is vulnerable") || strings.Contains(outText, "sql injection") || strings.Contains(outText, "injectable") {
					findingsMutex.Lock()
					structuredFindings = append(structuredFindings, sqlmapFinding{
						TemplateID: "SQL Injection",
						MatchedAt:  url,
						Severity:   "high",
						Module:     "sql-detection",
						Finding:    "Potential SQL injection vector detected by sqlmap",
					})
					findingsMutex.Unlock()
				}
			}
		}()
	}

	for _, url := range urls {
		jobs <- url
	}
	close(jobs)
	wg.Wait()

	return dedupeSQLMapFindings(structuredFindings), nil
}

func dedupeSQLMapFindings(in []sqlmapFinding) []sqlmapFinding {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]sqlmapFinding, 0, len(in))
	for _, f := range in {
		key := f.TemplateID + "|" + f.MatchedAt + "|" + f.Severity
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
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
