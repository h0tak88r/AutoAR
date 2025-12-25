package domain

import (
	"fmt"
	"log"

	"github.com/h0tak88r/AutoAR/internal/modules/cnames"
	"github.com/h0tak88r/AutoAR/internal/modules/dalfox"
	"github.com/h0tak88r/AutoAR/internal/modules/dns"
	"github.com/h0tak88r/AutoAR/internal/modules/gf"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/nuclei"
	"github.com/h0tak88r/AutoAR/internal/modules/ports"
	"github.com/h0tak88r/AutoAR/internal/modules/reflection"
	"github.com/h0tak88r/AutoAR/internal/modules/sqlmap"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/tech"
	"github.com/h0tak88r/AutoAR/internal/modules/urls"
)

// Result holds domain scan results
type Result struct {
	Domain string
}

// RunDomain runs the full domain scan workflow
func RunDomain(domain string) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	log.Printf("[INFO] Starting full domain scan for %s", domain)

	// Stepwise pipeline with soft-fail behavior
	steps := []struct {
		name string
		fn   func() error
	}{
		{"subdomains", func() error {
			_, err := subdomains.EnumerateSubdomains(domain, 100)
			return err
		}},
		{"cnames", func() error {
			_, err := cnames.CollectCNAMEs(domain)
			return err
		}},
		{"livehosts", func() error {
			_, err := livehosts.FilterLiveHosts(domain, 100, true)
			return err
		}},
		{"tech", func() error {
			_, err := tech.DetectTech(domain, 100)
			return err
		}},
		{"urls", func() error {
			_, err := urls.CollectURLs(domain, 100, false)
			return err
		}},
		{"js_scan", func() error {
			// Call via autoar command
			return fmt.Errorf("js_scan not yet ported to Go, skipping")
		}},
		{"reflection", func() error {
			_, err := reflection.ScanReflection(domain)
			return err
		}},
		{"gf", func() error {
			_, err := gf.ScanGF(domain)
			return err
		}},
		{"sqlmap", func() error {
			_, err := sqlmap.RunSQLMap(domain, 100)
			return err
		}},
		{"dalfox", func() error {
			_, err := dalfox.RunDalfox(domain, 100)
			return err
		}},
		{"ports", func() error {
			_, err := ports.ScanPorts(domain, 100)
			return err
		}},
		{"nuclei", func() error {
			_, err := nuclei.RunNuclei(nuclei.Options{Domain: domain, Mode: nuclei.ModeFull, Threads: 100})
			return err
		}},
		{"dns", func() error {
			return dns.Takeover(domain)
		}},
	}

	for _, step := range steps {
		log.Printf("[INFO] Running %s for %s", step.name, domain)
		if err := step.fn(); err != nil {
			log.Printf("[WARN] %s step failed for %s: %v", step.name, domain, err)
		}
	}

	log.Printf("[OK] Full domain scan completed for %s", domain)
	return &Result{Domain: domain}, nil
}
