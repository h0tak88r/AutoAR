package lite

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/h0tak88r/AutoAR/internal/scanner/backup"
	"github.com/h0tak88r/AutoAR/internal/scanner/cf1016"
	"github.com/h0tak88r/AutoAR/internal/scanner/cnames"
	"github.com/h0tak88r/AutoAR/internal/scanner/dns"
	"github.com/h0tak88r/AutoAR/internal/scanner/exposure"
	"github.com/h0tak88r/AutoAR/internal/scanner/jsscan"
	"github.com/h0tak88r/AutoAR/internal/scanner/livehosts"
	"github.com/h0tak88r/AutoAR/internal/scanner/misconfig"
	"github.com/h0tak88r/AutoAR/internal/scanner/nuclei"
	"github.com/h0tak88r/AutoAR/internal/scanner/reflection"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// Options holds lite scan options
type Options struct {
	Domain              string
	SkipJS              bool
	PhaseTimeoutDefault int // seconds
	Timeouts            map[string]int
}

// Result holds lite scan results
type Result struct {
	Domain string
	Steps  int
}

// RunLite runs the lite scan workflow
func RunLite(opts Options) (*Result, error) {
	if opts.Domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	if opts.PhaseTimeoutDefault == 0 {
		opts.PhaseTimeoutDefault = 3600 // 1 hour default
	}

	if opts.Timeouts == nil {
		opts.Timeouts = make(map[string]int)
	}

	phases := []string{"livehosts", "reflection", "js", "cnames", "backup", "dns", "cf1016", "exposure", "misconfig", "nuclei"}
	for _, phase := range phases {
		if opts.Timeouts[phase] == 0 {
			opts.Timeouts[phase] = opts.PhaseTimeoutDefault
		}
	}

	totalSteps := 10
	if opts.SkipJS {
		totalSteps = 9
	}

	log.Printf("[INFO] Starting Lite Scan for %s (%d steps)", opts.Domain, totalSteps)
	step := 1

	// Step 1: Live host filtering
	_ = utils.RunWorkflowPhase("livehosts", step, totalSteps, "Live host filtering", opts.Domain, opts.Timeouts["livehosts"], func() error {
		_, err := livehosts.FilterLiveHosts(opts.Domain, 150, true)
		return err
	})
	step++

	// Step 2: Reflection scanning
	_ = utils.RunWorkflowPhase("reflection", step, totalSteps, "Reflection scanning", opts.Domain, opts.Timeouts["reflection"], func() error {
		_, err := reflection.ScanReflectionWithOptions(reflection.Options{
			Domain:     opts.Domain,
			Threads:    50,
			Timeout:    time.Duration(opts.Timeouts["reflection"]) * time.Second,
			URLThreads: 150,
		})
		return err
	})
	step++

	// Step 3: JS scan
	if !opts.SkipJS {
		_ = utils.RunWorkflowPhase("js", step, totalSteps, "JavaScript scanning", opts.Domain, opts.Timeouts["js"], func() error {
			_, err := jsscan.Run(jsscan.Options{Domain: opts.Domain, Threads: 150})
			return err
		})
		step++
	}

	// Step 4: CNAME
	_ = utils.RunWorkflowPhase("cnames", step, totalSteps, "CNAME collection", opts.Domain, opts.Timeouts["cnames"], func() error {
		_, err := cnames.CollectCNAMEsWithOptions(cnames.Options{Domain: opts.Domain, Threads: 100, Timeout: time.Duration(opts.Timeouts["cnames"]) * time.Second})
		return err
	})
	step++

	// Step 5: Backup
	liveHostsFile := filepath.Join(utils.GetResultsDir(), opts.Domain, "subs", "live-subs.txt")
	_ = utils.RunWorkflowPhase("backup", step, totalSteps, "Backup scan", opts.Domain, opts.Timeouts["backup"], func() error {
		lh := ""
		if _, err := os.Stat(liveHostsFile); err == nil { lh = liveHostsFile }
		_, err := backup.Run(backup.Options{Domain: opts.Domain, LiveHostsFile: lh, Threads: 150, Method: "regular"})
		return err
	})
	step++

	// Step 6: DNS
	_ = utils.RunWorkflowPhase("dns", step, totalSteps, "DNS takeover", opts.Domain, opts.Timeouts["dns"], func() error {
		return dns.Takeover(opts.Domain)
	})
	step++

	// Step 7: CF1016
	_ = utils.RunWorkflowPhase("cf1016", step, totalSteps, "Cloudflare 1016", opts.Domain, opts.Timeouts["cf1016"], func() error {
		_, err := cf1016.Run(cf1016.Options{Domain: opts.Domain, Threads: 100, Timeout: 10 * time.Second})
		return err
	})
	step++

	// Step 8: Exposure
	_ = utils.RunWorkflowPhase("exposure", step, totalSteps, "Exposure scan", opts.Domain, opts.Timeouts["exposure"], func() error {
		_, err := exposure.Run(exposure.Options{Domain: opts.Domain, Threads: 50, Timeout: 8 * time.Second})
		return err
	})
	step++

	// Step 9: Misconfig
	_ = utils.RunWorkflowPhase("misconfig", step, totalSteps, "Misconfiguration scan", opts.Domain, opts.Timeouts["misconfig"], func() error {
		return misconfig.Run(misconfig.Options{Target: opts.Domain, Action: "scan", Threads: 150, Timeout: opts.Timeouts["misconfig"]})
	})
	step++

	// Step 10: Nuclei
	_ = utils.RunWorkflowPhase("nuclei", step, totalSteps, "Nuclei scan", opts.Domain, opts.Timeouts["nuclei"], func() error {
		_, err := nuclei.RunNuclei(nuclei.Options{Domain: opts.Domain, Mode: nuclei.ModeFull, Threads: 120})
		return err
	})

	return &Result{Domain: opts.Domain, Steps: totalSteps}, nil
}
