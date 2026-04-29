package dalfox

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/scanner/gf"
	"github.com/h0tak88r/AutoAR/internal/scanner/urls"
	dalfoxtool "github.com/h0tak88r/AutoAR/internal/tools/dalfox"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Result holds dalfox scan results
type Result struct {
	Domain     string
	Findings   int
	OutputFile string
}

// RunDalfox runs dalfox XSS scanner with automatic workflow:
// 1. Run urlfinder to collect URLs (if not already done)
// 2. Run gf to find XSS patterns (if not already done)
// 3. Run dalfox on the gf results
func RunDalfox(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads == 0 {
		threads = 100
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	urlsFile := filepath.Join(domainDir, "urls", "all-urls.txt")
	inFile := filepath.Join(domainDir, "vulnerabilities", "xss", gf.ResultFileForPattern("xss"))
	outFile := filepath.Join(domainDir, "dalfox-results.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Step 1: Ensure URLs exist (run urlfinder if needed)
	if info, err := os.Stat(urlsFile); err != nil || info.Size() == 0 {
		log.Printf("[INFO] No URLs found for %s, running urlfinder to collect URLs...", domain)
		urlRes, err := urls.CollectURLs(domain, threads, false)
		if err != nil {
			return nil, fmt.Errorf("failed to collect URLs: %w", err)
		}
		if urlRes == nil || urlRes.TotalURLs == 0 {
			if scanID := utils.GetCurrentScanID(); scanID != "" {
				_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-results.json")
			}
			return nil, fmt.Errorf("no URLs found for domain %s after urlfinder scan", domain)
		}
		log.Printf("[OK] Collected %d URLs for %s", urlRes.TotalURLs, domain)
	} else {
		log.Printf("[INFO] Found existing URLs file with %d bytes", info.Size())
	}

	// Step 2: Ensure GF results exist (run GF scan if needed)
	if info, err := os.Stat(inFile); err != nil || info.Size() == 0 {
		log.Printf("[INFO] No XSS candidates found, running GF scan to find XSS patterns...")
		gfRes, err := gf.ScanGF(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to run GF scan: %w", err)
		}
		if gfRes == nil {
			if scanID := utils.GetCurrentScanID(); scanID != "" {
				_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-results.json")
			}
			return nil, fmt.Errorf("GF scan returned no results for domain %s", domain)
		}
		// Check if XSS pattern file was created
		if info, err := os.Stat(inFile); err != nil || info.Size() == 0 {
			log.Printf("[WARN] GF scan completed but no XSS patterns found for %s", domain)
			if scanID := utils.GetCurrentScanID(); scanID != "" {
				_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-results.json")
			}
			return &Result{Domain: domain, Findings: 0, OutputFile: outFile}, nil
		}
		log.Printf("[OK] GF scan found XSS candidates, proceeding with dalfox...")
	} else {
		log.Printf("[INFO] Found existing GF results file with %d bytes", info.Size())
	}

	// Validate GF results file exists and has content
	if info, err := os.Stat(inFile); err != nil || info.Size() == 0 {
		log.Printf("[WARN] No XSS candidate file at %s", inFile)
		if scanID := utils.GetCurrentScanID(); scanID != "" {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-results.json")
		}
		return &Result{Domain: domain, Findings: 0, OutputFile: outFile}, nil
	}

	log.Printf("[INFO] Running dalfox (library mode) with %d threads", threads)
	results, err := dalfoxtool.ScanFile(inFile, dalfoxtool.Options{Threads: threads})
	if err != nil {
		return nil, fmt.Errorf("dalfox scan failed: %w", err)
	}

	// Persist results as JSONL for compatibility with file-based workflows.
	f, err := os.Create(outFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	for _, r := range results {
		if len(r.Raw) == 0 {
			continue
		}
		if _, err := f.Write(r.Raw); err != nil {
			log.Printf("[WARN] Failed to write dalfox result for %s: %v", r.Target, err)
			continue
		}
		if _, err := f.WriteString("\n"); err != nil {
			log.Printf("[WARN] Failed to write newline for %s: %v", r.Target, err)
		}
	}

	count := len(results)
	log.Printf("[OK] Dalfox scan completed, processed %d targets", count)

	if scanID := utils.GetCurrentScanID(); scanID != "" {
		if count > 0 {
			type dalfoxFinding struct {
				TemplateID string `json:"template-id"`
				MatchedAt  string `json:"matched-at"`
				Severity   string `json:"severity"`
				Type       string `json:"type,omitempty"`
				Parameter  string `json:"parameter,omitempty"`
				Payload    string `json:"payload,omitempty"`
				Module     string `json:"module"`
			}
			findings := make([]dalfoxFinding, 0, count)
			seen := make(map[string]struct{}, count)
			for _, r := range results {
				if len(r.Raw) == 0 {
					continue
				}
				var obj map[string]interface{}
				if err := json.Unmarshal(r.Raw, &obj); err != nil {
					continue
				}
				severity := strings.TrimSpace(fmt.Sprint(obj["severity"]))
				if severity == "" || severity == "<nil>" {
					severity = "high"
				}
				fType := strings.TrimSpace(fmt.Sprint(obj["type"]))
				if fType == "" || fType == "<nil>" {
					fType = "xss"
				}
				param := strings.TrimSpace(fmt.Sprint(obj["param"]))
				if param == "" || param == "<nil>" {
					param = strings.TrimSpace(fmt.Sprint(obj["parameter"]))
				}
				payload := strings.TrimSpace(fmt.Sprint(obj["payload"]))
				findingLabel := fmt.Sprintf("XSS (%s)", strings.ToUpper(fType))
				key := findingLabel + "|" + r.Target + "|" + param + "|" + payload
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, dalfoxFinding{
					TemplateID: findingLabel,
					MatchedAt:  r.Target,
					Severity:   severity,
					Type:       fType,
					Parameter:  param,
					Payload:    payload,
					Module:     "xss-detection",
				})
			}
			if len(findings) > 0 {
				if err := utils.WriteJSONToScanDir(scanID, "dalfox-results.json", findings); err != nil {
					log.Printf("[WARN] Failed to write dalfox JSON: %v", err)
				}
			} else {
				_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-results.json")
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "xss-detection", "dalfox-results.json")
		}
	}

	return &Result{
		Domain:     domain,
		Findings:   count,
		OutputFile: outFile,
	}, nil
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
