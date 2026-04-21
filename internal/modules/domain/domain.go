package domain

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	aemmod "github.com/h0tak88r/AutoAR/internal/modules/aem"
	"github.com/h0tak88r/AutoAR/internal/modules/backup"
	"github.com/h0tak88r/AutoAR/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/internal/modules/depconfusion"
	"github.com/h0tak88r/AutoAR/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/internal/modules/envloader"
	"github.com/h0tak88r/AutoAR/internal/modules/ffuf"
	"github.com/h0tak88r/AutoAR/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/internal/modules/jsscan"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/misconfig"
	"github.com/h0tak88r/AutoAR/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/internal/modules/reflection"
	"github.com/h0tak88r/AutoAR/internal/modules/s3"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
	wpconfusion "github.com/h0tak88r/AutoAR/internal/modules/wp-confusion"
)

// Result holds domain scan results
type Result struct {
	Domain string
}

// ScanOptions holds options for domain scan
type ScanOptions struct {
	Domain   string
	SkipFFuf bool
}

// RunDomain runs the full domain scan workflow with ALL features
func RunDomain(opts ScanOptions) (*Result, error) {
	domain := opts.Domain
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	_ = envloader.LoadEnv()

	// Initialize metrics
	metrics := utils.InitMetrics()
	metrics.IncrementActiveScans()
	defer metrics.DecrementActiveScans()

	// Check if shutting down
	shutdownMgr := utils.GetShutdownManager()
	if shutdownMgr.IsShuttingDown() {
		return nil, fmt.Errorf("shutdown in progress")
	}
	shutdownMgr.IncrementActiveScans()
	defer shutdownMgr.DecrementActiveScans()

	resultsDir := utils.GetResultsDir()
	domainDir := filepath.Join(resultsDir, domain)
	_ = os.MkdirAll(domainDir, 0755)

	liveHostsFile := filepath.Join(domainDir, "subs", "live-subs.txt")

	totalSteps := 18
	if opts.SkipFFuf {
		totalSteps = 17
	}
	var currentStep int32

	getNextStep := func() int {
		return int(atomic.AddInt32(&currentStep, 1))
	}

	// Phase 1: Reconnaissance
	if err := utils.RunWorkflowPhase("subdomains", getNextStep(), totalSteps, "Subdomain enumeration", domain, 0, func() error {
		subs, err := subdomains.EnumerateSubdomains(domain, 150)
		if err != nil {
			return err
		}
		subsDir := filepath.Join(domainDir, "subs")
		_ = os.MkdirAll(subsDir, 0755)
		return utils.WriteLines(filepath.Join(subsDir, "all-subs.txt"), subs)
	}); err != nil {
		log.Printf("[WARN] Subdomain enumeration failed: %v", err)
	}

	// Phase 2: Host Discovery
	var wgPhase2 sync.WaitGroup
	wgPhase2.Add(2)
	go func() {
		defer wgPhase2.Done()
		_ = utils.RunWorkflowPhase("cnames", getNextStep(), totalSteps, "CNAME collection", domain, 0, func() error {
			_, err := cnames.CollectCNAMEsWithOptions(cnames.Options{Domain: domain, Threads: 150, Timeout: 5 * time.Minute})
			return err
		})
	}()
	go func() {
		defer wgPhase2.Done()
		_ = utils.RunWorkflowPhase("livehosts", getNextStep(), totalSteps, "Live host filtering", domain, 0, func() error {
			_, err := livehosts.FilterLiveHosts(domain, 150, true)
			return err
		})
	}()
	wgPhase2.Wait()

	// Phase 3: Vulnerability Discovery
	var wgPhase3 sync.WaitGroup
	phases3 := []struct {
		key, desc string
		fn        func() error
		timeout   int
	}{
		{"tech", "Technology detection", func() error { _, err := tech.DetectTech(domain, 150); return err }, 0},
		{"ports", "Port scanning", func() error { _, err := ports.ScanPorts(domain, 150); return err }, 0},
		{"urls", "URL collection", func() error { _, err := urls.CollectURLs(domain, 150, false); return err }, 0},
		{"jsscan", "JavaScript scan", func() error { _, err := jsscan.Run(jsscan.Options{Domain: domain, Threads: 150}); return err }, 0},
		{"dns", "DNS takeover scan", func() error { return dns.Takeover(domain) }, 0},
		{"aem", "AEM webapp discovery and scan", func() error {
			lh := ""; if _, err := os.Stat(liveHostsFile); err == nil { lh = liveHostsFile }
			_, err := aemmod.Run(aemmod.Options{Domain: domain, LiveHostsFile: lh, Threads: 50})
			return err
		}, 0},
		{"wp_confusion", "WordPress confusion scan", func() error {
			return wpconfusion.ScanWPConfusion(wpconfusion.ScanOptions{URL: "https://" + domain, Plugins: true, Theme: true, Output: filepath.Join(domainDir, "wp-confusion", "wp-confusion-results.txt")})
		}, 0},
		{"depconfusion", "Dependency confusion scan", func() error {
			lh := liveHostsFile; if _, err := os.Stat(lh); err != nil {
				lh = filepath.Join(os.TempDir(), domain+"_targets.txt")
				_ = os.WriteFile(lh, []byte("https://"+domain+"\n"), 0644); defer os.Remove(lh)
			}
			return depconfusion.Run(depconfusion.Options{Mode: "web", Domain: domain, TargetFile: lh, Workers: 10})
		}, 0},
		{"s3", "S3 bucket enumeration", func() error { return s3.Run(s3.Options{Action: "enum", Root: domain}) }, 0},
		{"backup", "Backup file discovery", func() error {
			lh := ""; if _, err := os.Stat(liveHostsFile); err == nil { lh = liveHostsFile }
			_, err := backup.Run(backup.Options{Domain: domain, LiveHostsFile: lh, Threads: 150, Method: "all"})
			return err
		}, 0},
		{"misconfig", "Cloud misconfiguration scan", func() error {
			lh := ""; if _, err := os.Stat(liveHostsFile); err == nil { lh = liveHostsFile }
			return misconfig.Run(misconfig.Options{Target: domain, Action: "scan", Threads: 150, LiveHostsFile: lh})
		}, 1800},
	}

	for _, p := range phases3 {
		wgPhase3.Add(1)
		go func(phase struct {
			key, desc string
			fn        func() error
			timeout   int
		}) {
			defer wgPhase3.Done()
			_ = utils.RunWorkflowPhase(phase.key, getNextStep(), totalSteps, phase.desc, domain, phase.timeout, phase.fn)
		}(p)
	}
	wgPhase3.Wait()

	// Phase 4: Final Heavy Scanning
	var wgPhase4 sync.WaitGroup
	wgPhase4.Add(3)
	if !opts.SkipFFuf { wgPhase4.Add(1) }

	go func() { defer wgPhase4.Done(); _ = utils.RunWorkflowPhase("reflection", getNextStep(), totalSteps, "Reflection scan", domain, 0, func() error { _, err := reflection.ScanReflection(domain); return err }) }()
	go func() { defer wgPhase4.Done(); _ = utils.RunWorkflowPhase("gf", getNextStep(), totalSteps, "GF pattern matching", domain, 0, func() error { _, err := gf.ScanGFWithOptions(gf.Options{Domain: domain, SkipCheck: true}); return err }) }()
	go func() { defer wgPhase4.Done(); _ = utils.RunWorkflowPhase("nuclei", getNextStep(), totalSteps, "Nuclei scan", domain, 0, func() error { _, err := nuclei.RunNuclei(nuclei.Options{Domain: domain, Mode: nuclei.ModeFull, Threads: 120}); return err }) }()
	if !opts.SkipFFuf {
		go func() { defer wgPhase4.Done(); _ = utils.RunWorkflowPhase("ffuf", getNextStep(), totalSteps, "FFuf fuzzing", domain, 0, func() error { _, err := ffuf.RunFFuf(ffuf.Options{Domain: domain, Threads: 40, Bypass403: true}); return err }) }()
	}
	wgPhase4.Wait()

	// Cleanup
	_ = os.RemoveAll(filepath.Join(resultsDir, "aem"))
	metrics.IncrementCompletedScans()
	return &Result{Domain: domain}, nil
}
