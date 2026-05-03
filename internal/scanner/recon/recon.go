package recon

import (
	"fmt"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/cnames"
	"github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	"github.com/h0tak88r/AutoAR/internal/scanner/subdomains"
	"github.com/h0tak88r/AutoAR/internal/scanner/tech"
)

// Result holds the summary of a full recon run.
type Result struct {
	Domain     string
	Subdomains int
	LiveHosts  int
	CNAMEs     int
	TechHosts  int
	Duration   time.Duration
}

// RunFullRecon runs subdomains, livehosts, tech and cnames in a single pipeline.
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
	logger.GetLogger().Infof("[RECON] [1/4] Enumerating subdomains...")
	subs, err := subdomains.EnumerateSubdomains(domain, threads)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] Subdomain enumeration failed: %v", err)
	} else {
		res.Subdomains = len(subs)
		logger.GetLogger().Infof("[RECON] [OK] Found %d subdomains", res.Subdomains)
	}

	// Phase 2: Live Hosts
	logger.GetLogger().Infof("[RECON] [2/4] Identifying live hosts...")
	lhRes, err := livehosts.FilterLiveHosts(domain, threads, false) // skip enum since we just did it
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] Live host filtering failed: %v", err)
	} else if lhRes != nil {
		res.LiveHosts = lhRes.LiveSubs
		logger.GetLogger().Infof("[RECON] [OK] Found %d live hosts", res.LiveHosts)
	}

	// Phase 3: Tech Detection
	logger.GetLogger().Infof("[RECON] [3/4] Detecting technologies...")
	techRes, err := tech.DetectTech(domain, threads)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] Tech detection failed: %v", err)
	} else if techRes != nil {
		res.TechHosts = techRes.Hosts
		logger.GetLogger().Infof("[RECON] [OK] Detected technologies for %d hosts", res.TechHosts)
	}

	// Phase 4: CNAME Collection
	logger.GetLogger().Infof("[RECON] [4/4] Collecting CNAME records...")
	cnameRes, err := cnames.CollectCNAMEs(domain)
	if err != nil {
		logger.GetLogger().Infof("[RECON] [WARN] CNAME collection failed: %v", err)
	} else if cnameRes != nil {
		res.CNAMEs = cnameRes.Records
		logger.GetLogger().Infof("[RECON] [OK] Collected %d CNAME records", res.CNAMEs)
	}

	res.Duration = time.Since(start)
	logger.GetLogger().Infof("[RECON] Unified asset discovery completed in %v", res.Duration)

	return res, nil
}
