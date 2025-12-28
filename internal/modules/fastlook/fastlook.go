package fastlook

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/v3/internal/modules/utils"
)

// Result holds a simple summary of a fastlook run.
type Result struct {
	Domain     string
	Subdomains int
	LiveHosts  int
	TotalURLs  int
	JSURLs     int
	ResultsDir string
}

// RunFastlook reproduces the behaviour of modules/fastlook.sh using Go modules only.
// Optimized version with increased concurrency and real-time file sending.
// Steps:
// 1) Filter live hosts (includes subdomain enumeration if needed, with 200 threads)
// 2) Collect URLs and JS URLs (with 200 threads, skip subdomain enum since livehosts already did it)
func RunFastlook(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	log.Printf("[INFO] Starting Fast Look (Optimized) for %s", domain)

	resultsDir := utils.GetResultsDir()
	res := &Result{
		Domain:     domain,
		ResultsDir: resultsDir,
	}

	// Step 1: Live host filtering (includes subdomain enumeration internally, optimized with 200 threads)
	log.Printf("[INFO] [1/2] Filtering live hosts for %s (threads: 200)", domain)
	startTime := time.Now()
	
	liveRes, err := livehosts.FilterLiveHosts(domain, 200, true) // Increased from 100 to 200
	duration := time.Since(startTime)
	
	if err != nil {
		log.Printf("[WARN] Live host filtering failed for %s: %v", domain, err)
	} else {
		if liveRes != nil {
			res.Subdomains = liveRes.TotalSubs
			res.LiveHosts = liveRes.LiveSubs
		}
		log.Printf("[OK] Live host filtering completed in %s: %d live hosts out of %d subdomains", duration, res.LiveHosts, res.Subdomains)
		
		// Send phase 1 files in real-time
		sendFastlookPhaseFiles("livehosts", domain)
	}

	// Step 2: URL/JS collection (skip subdomain enum since livehosts already did it, optimized with 200 threads)
	log.Printf("[INFO] [2/2] Collecting URLs and JS URLs for %s (threads: 200, skip subdomain enum)", domain)
	startTime = time.Now()
	
	urlRes, err := urls.CollectURLs(domain, 200, false) // Increased from 100 to 200
	duration = time.Since(startTime)
	
	if err != nil {
		log.Printf("[WARN] URL collection failed for %s: %v", domain, err)
	} else {
		if urlRes != nil {
			res.TotalURLs = urlRes.TotalURLs
			res.JSURLs = urlRes.JSURLs
		}
		log.Printf("[OK] URL collection completed in %s: %d URLs, %d JS URLs", duration, res.TotalURLs, res.JSURLs)
		
		// Send phase 2 files in real-time
		sendFastlookPhaseFiles("urls", domain)
	}

	log.Printf("[OK] Fast Look completed for %s", domain)
	return res, nil
}

// sendFastlookPhaseFiles sends result files for a specific fastlook phase to Discord
func sendFastlookPhaseFiles(phaseName, domain string) {
	// Small delay to ensure files are written (reduced for real-time sending)
	time.Sleep(500 * time.Millisecond)
	
	resultsDir := utils.GetResultsDir()
	var filePaths []string
	
	switch phaseName {
	case "livehosts":
		filePaths = []string{
			filepath.Join(resultsDir, domain, "subs", "all-subs.txt"),
			filepath.Join(resultsDir, domain, "subs", "live-subs.txt"),
		}
	case "urls":
		filePaths = []string{
			filepath.Join(resultsDir, domain, "urls", "all-urls.txt"),
			filepath.Join(resultsDir, domain, "urls", "js-urls.txt"),
		}
	}
	
	if len(filePaths) > 0 {
		// Retry logic to find files
		maxRetries := 5
		retryDelay := 1 * time.Second
		var existingFiles []string
		
		for attempt := 1; attempt <= maxRetries; attempt++ {
			existingFiles = []string{}
			for _, filePath := range filePaths {
				if info, err := os.Stat(filePath); err == nil && info.Size() > 0 {
					existingFiles = append(existingFiles, filePath)
				}
			}
			if len(existingFiles) > 0 {
				break
			}
			if attempt < maxRetries {
				time.Sleep(retryDelay)
			}
		}
		
		if len(existingFiles) > 0 {
			log.Printf("[DEBUG] [FASTLOOK] Sending %d file(s) for phase %s", len(existingFiles), phaseName)
			
			// SendPhaseFiles will send minimal webhook message (phase name) and files
			if err := utils.SendPhaseFiles(phaseName, domain, existingFiles); err != nil {
				log.Printf("[DEBUG] [FASTLOOK] Failed to send files for phase %s: %v", phaseName, err)
			}
		}
	}
}
