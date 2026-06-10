package recon

import (
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/cnames"
	"github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/h0tak88r/AutoAR/internal/scanner/tech"
	"github.com/h0tak88r/AutoAR/internal/scanner/urls"
)

// Result holds the summary of a full recon run.
type Result struct {
	Domain     string
	Subdomains int
	LiveHosts  int
	CNAMEs     int
	TechHosts  int
	TotalURLs  int
	JSURLs     int
	Duration   time.Duration
}

// RunFullRecon runs subdomains, livehosts, tech, cnames and URL collection in a
// single pipeline. The URL phase produces urls/all-urls.txt, which downstream
// scanners (gf, sqlmap, …) consume — this is what the retired fastlook module did.
func RunFullRecon(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads <= 0 {
		threads = 100
	}

	start := time.Now()
	res := &Result{Domain: domain}

	logger.GetLogger().Infof("[RECON] Starting unified asset discovery for %s", domain)

	// Phase 1: Subdomains
	logger.GetLogger().Infof("[RECON] [1/5] Enumerating subdomains...")
	subs, err := subdomains.EnumerateSubdomains(domain, threads)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] Subdomain enumeration failed: %v", err)
	} else {
		res.Subdomains = len(subs)
		logger.GetLogger().Infof("[RECON] [OK] Found %d subdomains", res.Subdomains)
	}

	// Phase 2: Live Hosts
	logger.GetLogger().Infof("[RECON] [2/5] Identifying live hosts...")
	lhRes, err := livehosts.FilterLiveHosts(domain, threads, false) // skip enum since we just did it
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] Live host filtering failed: %v", err)
	} else if lhRes != nil {
		res.LiveHosts = lhRes.LiveSubs
		logger.GetLogger().Infof("[RECON] [OK] Found %d live hosts", res.LiveHosts)
	}

	// Phase 3: Tech Detection
	logger.GetLogger().Infof("[RECON] [3/5] Detecting technologies...")
	techRes, err := tech.DetectTech(domain, threads)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] Tech detection failed: %v", err)
	} else if techRes != nil {
		res.TechHosts = techRes.Hosts
		logger.GetLogger().Infof("[RECON] [OK] Detected technologies for %d hosts", res.TechHosts)
	}

	// Phase 4: CNAME Collection
	logger.GetLogger().Infof("[RECON] [4/5] Collecting CNAME records...")
	cnameRes, err := cnames.CollectCNAMEs(domain)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] CNAME collection failed: %v", err)
	} else if cnameRes != nil {
		res.CNAMEs = cnameRes.Records
		logger.GetLogger().Infof("[RECON] [OK] Collected %d CNAME records", res.CNAMEs)
	}

	// Phase 5: URL Collection — produces urls/all-urls.txt and urls/js-urls.txt.
	// skipSubdomainEnum=false reuses the subs/live-subs already gathered above.
	logger.GetLogger().Infof("[RECON] [5/5] Collecting URLs...")
	urlRes, err := urls.CollectURLs(domain, threads, false)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] URL collection failed: %v", err)
	} else if urlRes != nil {
		res.TotalURLs = urlRes.TotalURLs
		res.JSURLs = urlRes.JSURLs
		logger.GetLogger().Infof("[RECON] [OK] Collected %d URLs (%d JS)", res.TotalURLs, res.JSURLs)
	}

	res.Duration = time.Since(start)
	logger.GetLogger().Infof("[RECON] Unified asset discovery completed in %v", res.Duration)

	return res, nil
}
