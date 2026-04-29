package ports

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	naabutool "github.com/h0tak88r/AutoAR/internal/tools/naabu"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Result holds port scan results
type Result struct {
	Domain     string
	Ports      int
	OutputFile string
}

type PortFinding struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Service    string `json:"service"`
	Status     string `json:"status"`
	Severity   string `json:"severity"`
	Finding    string `json:"finding"`
	Module     string `json:"module"`
	MatchedAt  string `json:"matched-at"`
	TemplateID string `json:"template-id"`
}

// ScanPorts runs port scanning using naabu
func ScanPorts(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads == 0 {
		threads = 100
	}

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	subsDir := filepath.Join(domainDir, "subs")
	subsFile := filepath.Join(subsDir, "live-subs.txt")
	outFile := filepath.Join(domainDir, "ports", "ports.txt")

	if err := utils.EnsureDir(filepath.Dir(outFile)); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// Get live hosts file (checks file first, then database)
	liveHostsFile, err := livehosts.GetLiveHostsFile(domain)
	if err != nil {
		log.Printf("[WARN] Failed to get live hosts file for %s: %v, attempting to create it", domain, err)
		// Fallback: try to create it by running livehosts
		_, err2 := livehosts.FilterLiveHosts(domain, threads, false)
		if err2 != nil {
			return nil, fmt.Errorf("failed to get live hosts for %s: %w", domain, err2)
		}
		liveHostsFile = subsFile
	}

	if liveHostsFile != subsFile {
		// File was created from database, update subsFile path
		subsFile = liveHostsFile
	}

	if _, err := os.Stat(subsFile); err != nil {
		return nil, fmt.Errorf("live hosts file not found: %s", subsFile)
	}

	log.Printf("[INFO] Running naabu port scan with %d threads (library mode)", threads)
	count, records, err := naabutool.ScanFromFile(subsFile, threads, outFile)
	if err != nil {
		log.Printf("[WARN] Naabu scan failed: %v", err)
		count = 0
	}
	log.Printf("[OK] Port scan completed, found %d open ports", count)

	// Write JSON results to scan directory (local-first)
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		findings := make([]PortFinding, 0, len(records))
		for _, rec := range records {
			findings = append(findings, PortFinding{
				Host:       rec.Host,
				Port:       rec.Port,
				Protocol:   rec.Protocol,
				Service:    "unknown",
				Status:     "open",
				Severity:   "info",
				Finding:    fmt.Sprintf("Open Port %d (%s)", rec.Port, rec.Protocol),
				Module:     "port-scan",
				MatchedAt:  rec.Host,
				TemplateID: fmt.Sprintf("port/%d", rec.Port),
			})
		}
		if len(findings) > 0 {
			if err := utils.WriteJSONToScanDir(scanID, "ports.json", findings); err != nil {
				log.Printf("[WARN] Failed to write ports JSON: %v", err)
			}
		} else {
			_ = utils.WriteNoFindingsJSON(scanID, domain, "ports", "ports.json")
		}
	}

	// Send result files to Discord webhook if configured (only when not running under bot)
	// When running under bot (AUTOAR_CURRENT_SCAN_ID is set), the bot handles R2 upload and zip link
	if utils.GetCurrentScanID() == "" {
		utils.SendPhaseFiles("ports", domain, []string{outFile})
	}

	return &Result{
		Domain:     domain,
		Ports:      count,
		OutputFile: outFile,
	}, nil
}
