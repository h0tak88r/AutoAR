package fastlook

import (
	"fmt"
	"log"

	"github.com/h0tak88r/AutoAR/gomodules/livehosts"
	"github.com/h0tak88r/AutoAR/gomodules/subdomains"
	"github.com/h0tak88r/AutoAR/gomodules/urls"
	"github.com/h0tak88r/AutoAR/gomodules/utils"
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
// Steps:
// 1) Enumerate subdomains (if needed)
// 2) Filter live hosts (via livehosts module)
// 3) Collect URLs and JS URLs (via urls module)
func RunFastlook(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	log.Printf("[INFO] Starting Fast Look for %s", domain)

	// Step 1: Subdomain enumeration (idempotent; livehosts/urls also ensure this)
	log.Printf("[INFO] [1/3] Ensuring subdomains for %s", domain)
	subs, err := subdomains.EnumerateSubdomains(domain, 100)
	if err != nil {
		log.Printf("[WARN] Subdomain enumeration failed for %s: %v", domain, err)
	}

	// Step 2: Live host filtering
	log.Printf("[INFO] [2/3] Filtering live hosts for %s", domain)
	liveRes, err := livehosts.FilterLiveHosts(domain, 100, true)
	if err != nil {
		log.Printf("[WARN] Live host filtering failed for %s: %v", domain, err)
	}

	// Step 3: URL/JS collection
	log.Printf("[INFO] [3/3] Collecting URLs and JS URLs for %s", domain)
	urlRes, err := urls.CollectURLs(domain, 100)
	if err != nil {
		log.Printf("[WARN] URL collection failed for %s: %v", domain, err)
	}

	resultsDir := utils.GetResultsDir()

	res := &Result{
		Domain:     domain,
		Subdomains: len(subs),
		ResultsDir: resultsDir,
	}
	if liveRes != nil {
		res.LiveHosts = liveRes.LiveSubs
	}
	if urlRes != nil {
		res.TotalURLs = urlRes.TotalURLs
		res.JSURLs = urlRes.JSURLs
	}

	log.Printf("[OK] Fast Look completed for %s", domain)
	return res, nil
}
