package asr

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/h0tak88r/AutoAR/internal/modules/asr/internal/crawl"
	"github.com/h0tak88r/AutoAR/internal/modules/asr/internal/dns_asr"
	"github.com/h0tak88r/AutoAR/internal/modules/asr/internal/http_asr"
	"github.com/h0tak88r/AutoAR/internal/modules/asr/internal/passive"
	"github.com/h0tak88r/AutoAR/internal/modules/asr/internal/permutations"
	"github.com/h0tak88r/AutoAR/internal/modules/asr/internal/tls"
	"github.com/h0tak88r/AutoAR/internal/modules/subdomains"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// RunMode1: Passive Recon Only
func RunMode1(ctx context.Context, opts Options) error {
	opts.Progress("Running Mode 1: Passive Recon Only")
	subs, err := subdomains.EnumerateSubdomains(opts.Domain, opts.Threads)
	if err != nil {
		return err
	}
	opts.Progress(fmt.Sprintf("Found %d passive subdomains", len(subs)))
	
	resultsRoot := utils.GetResultsDir()
	domainDir := filepath.Join(resultsRoot, opts.Domain)
	os.MkdirAll(domainDir, 0755)
	
	return utils.WriteLines(filepath.Join(domainDir, "all_subs_passive.txt"), subs)
}

// RunMode2: DNS Bruteforce + TLS Probing + Permutations
func RunMode2(ctx context.Context, opts Options) error {
	opts.Progress("Running Mode 2: DNS Bruteforce + TLS Probing + Permutations")
	
	resultsRoot := utils.GetResultsDir()
	domainDir := filepath.Join(resultsRoot, opts.Domain)
	os.MkdirAll(domainDir, 0755)

	var allSubdomains []string

	// 1. TLS Probing
	opts.Progress("Starting TLS probing")
	tlsClient, _ := tls.NewClient(opts.Threads)
	tlsSubs, err := tlsClient.Probe(ctx, opts.Domain)
	if err == nil {
		opts.Progress(fmt.Sprintf("Found %d subdomains via TLS", len(tlsSubs)))
		allSubdomains = append(allSubdomains, tlsSubs...)
	}

	// 2. DNS Bruteforce
	if opts.Wordlist != "" {
		opts.Progress("Starting DNS bruteforce (using puredns)")
		dnsClient, _ := dns_asr.NewClientWithResolverFile(opts.Resolvers, opts.Threads)
		bruteSubs, _ := dnsClient.BruteforceWithWordlistFile(ctx, opts.Domain, opts.Wordlist, opts.Threads)
		opts.Progress(fmt.Sprintf("Found %d subdomains via DNS bruteforce", len(bruteSubs)))
		allSubdomains = append(allSubdomains, bruteSubs...)
	}

	// 3. Permutations
	opts.Progress("Starting permutations")
	gen := permutations.NewGenerator([]string{"dev", "staging", "prod", "api", "test"})
	permSubs := gen.Generate(allSubdomains, opts.Domain)
	opts.Progress(fmt.Sprintf("Generated %d permutations", len(permSubs)))
	allSubdomains = append(allSubdomains, permSubs...)

	allSubdomains = deduplicate(allSubdomains)
	return utils.WriteLines(filepath.Join(domainDir, "asr_results_mode2.txt"), allSubdomains)
}

// RunMode3: Passive + TLS + DNS Bruteforce + HTTP Check + Scraping
func RunMode3(ctx context.Context, opts Options) error {
	opts.Progress("Running Mode 3: Passive + TLS + DNS Bruteforce + HTTP Check + Scraping")
	
	resultsRoot := utils.GetResultsDir()
	domainDir := filepath.Join(resultsRoot, opts.Domain)
	os.MkdirAll(domainDir, 0755)

	var allSubdomains []string

	// 1. Passive Recon
	opts.Progress("Starting passive reconnaissance")
	passiveRunner, _ := passive.NewRunner(opts.Threads)
	passSubs, _ := passiveRunner.Enumerate(ctx, opts.Domain)
	opts.Progress(fmt.Sprintf("Found %d subdomains via passive sources", len(passSubs)))
	allSubdomains = append(allSubdomains, passSubs...)

	// 2. TLS Probing
	opts.Progress("Starting TLS probing")
	tlsClient, _ := tls.NewClient(opts.Threads)
	tlsSubs, _ := tlsClient.Probe(ctx, opts.Domain)
	opts.Progress(fmt.Sprintf("Found %d subdomains via TLS certificate probing", len(tlsSubs)))
	allSubdomains = append(allSubdomains, tlsSubs...)

	// 3. DNS Bruteforce
	if opts.Wordlist != "" {
		opts.Progress("Starting DNS bruteforce (using puredns)")
		dnsClient, _ := dns_asr.NewClientWithResolverFile(opts.Resolvers, opts.Threads)
		bruteSubs, _ := dnsClient.BruteforceWithWordlistFile(ctx, opts.Domain, opts.Wordlist, opts.Threads)
		opts.Progress(fmt.Sprintf("Found %d subdomains via DNS bruteforce", len(bruteSubs)))
		allSubdomains = append(allSubdomains, bruteSubs...)
	}

	// Deduplicate before resolving
	allSubdomains = deduplicate(allSubdomains)
	dnsClient, _ := dns_asr.NewClientWithResolverFile(opts.Resolvers, opts.Threads)
	allSubdomains, _ = dnsClient.Resolve(ctx, allSubdomains, opts.Threads)
	utils.WriteLines(filepath.Join(domainDir, "all_subs_resolved.txt"), allSubdomains)

	// 4. HTTP Check
	opts.Progress("Checking for live HTTP hosts")
	httpClient, _ := http_asr.NewClient(opts.Threads)
	liveHosts, _ := httpClient.CheckLive(ctx, allSubdomains, opts.Threads)
	opts.Progress(fmt.Sprintf("Found %d live hosts", len(liveHosts)))
	utils.WriteLines(filepath.Join(domainDir, "filtered_hosts.txt"), liveHosts)

	// 5. Scraping
	opts.Progress("Starting web scraping for additional subdomains")
	scraper := crawl.NewScraper()
	var scrapedSubs []string
	for _, host := range liveHosts {
		subs, _ := scraper.Extract(ctx, host, opts.Domain)
		scrapedSubs = append(scrapedSubs, subs...)
	}
	opts.Progress(fmt.Sprintf("Found %d additional subdomains via scraping", len(scrapedSubs)))
	allSubdomains = append(allSubdomains, scrapedSubs...)
	allSubdomains = deduplicate(allSubdomains)

	return utils.WriteLines(filepath.Join(domainDir, "asr_results_mode3.txt"), allSubdomains)
}

// RunMode4: Passive + TLS + HTTP Check + Scraping (No DNS Bruteforce)
func RunMode4(ctx context.Context, opts Options) error {
	opts.Progress("Running Mode 4: Passive + TLS + HTTP Check + Scraping (No DNS Bruteforce)")
	
	resultsRoot := utils.GetResultsDir()
	domainDir := filepath.Join(resultsRoot, opts.Domain)
	os.MkdirAll(domainDir, 0755)

	var allSubdomains []string

	// 1. Passive Recon
	opts.Progress("Starting passive reconnaissance")
	passiveRunner, _ := passive.NewRunner(opts.Threads)
	passSubs, _ := passiveRunner.Enumerate(ctx, opts.Domain)
	opts.Progress(fmt.Sprintf("Found %d subdomains via passive sources", len(passSubs)))
	allSubdomains = append(allSubdomains, passSubs...)

	// 2. TLS Probing
	opts.Progress("Starting TLS probing")
	tlsClient, _ := tls.NewClient(opts.Threads)
	tlsSubs, _ := tlsClient.Probe(ctx, opts.Domain)
	opts.Progress(fmt.Sprintf("Found %d subdomains via TLS certificate probing", len(tlsSubs)))
	allSubdomains = append(allSubdomains, tlsSubs...)

	allSubdomains = deduplicate(allSubdomains)
	
	// 3. HTTP Check
	opts.Progress("Checking for live HTTP hosts")
	httpClient, _ := http_asr.NewClient(opts.Threads)
	liveHosts, _ := httpClient.CheckLive(ctx, allSubdomains, opts.Threads)
	opts.Progress(fmt.Sprintf("Found %d live hosts", len(liveHosts)))
	utils.WriteLines(filepath.Join(domainDir, "filtered_hosts.txt"), liveHosts)

	// 4. Scraping
	opts.Progress("Starting web scraping for additional subdomains")
	scraper := crawl.NewScraper()
	var scrapedSubs []string
	for _, host := range liveHosts {
		subs, _ := scraper.Extract(ctx, host, opts.Domain)
		scrapedSubs = append(scrapedSubs, subs...)
	}
	opts.Progress(fmt.Sprintf("Found %d additional subdomains via scraping", len(scrapedSubs)))
	allSubdomains = append(allSubdomains, scrapedSubs...)
	allSubdomains = deduplicate(allSubdomains)

	return utils.WriteLines(filepath.Join(domainDir, "asr_results_mode4.txt"), allSubdomains)
}

// RunMode5: Full Recon
func RunMode5(ctx context.Context, opts Options) error {
	opts.Progress("Running Mode 5: Full Recon")
	
	resultsRoot := utils.GetResultsDir()
	domainDir := filepath.Join(resultsRoot, opts.Domain)
	os.MkdirAll(domainDir, 0755)

	var allSubdomains []string

	// 1. Passive Recon
	opts.Progress("Starting passive reconnaissance")
	passiveRunner, _ := passive.NewRunner(opts.Threads)
	passSubs, _ := passiveRunner.Enumerate(ctx, opts.Domain)
	opts.Progress(fmt.Sprintf("Found %d subdomains via passive sources", len(passSubs)))
	allSubdomains = append(allSubdomains, passSubs...)

	// 2. TLS Probing
	opts.Progress("Starting TLS probing")
	tlsClient, _ := tls.NewClient(opts.Threads)
	tlsSubs, _ := tlsClient.Probe(ctx, opts.Domain)
	opts.Progress(fmt.Sprintf("Found %d subdomains via TLS certificate probing", len(tlsSubs)))
	allSubdomains = append(allSubdomains, tlsSubs...)

	// 3. DNS Bruteforce
	if opts.Wordlist != "" {
		opts.Progress("Starting DNS bruteforce (using puredns)")
		dnsClient, _ := dns_asr.NewClientWithResolverFile(opts.Resolvers, opts.Threads)
		bruteSubs, _ := dnsClient.BruteforceWithWordlistFile(ctx, opts.Domain, opts.Wordlist, opts.Threads)
		opts.Progress(fmt.Sprintf("Found %d subdomains via DNS bruteforce", len(bruteSubs)))
		allSubdomains = append(allSubdomains, bruteSubs...)
	}

	// 4. Permutations
	opts.Progress("Starting permutations")
	gen := permutations.NewGenerator([]string{"dev", "staging", "prod", "api", "test"})
	permSubs := gen.Generate(allSubdomains, opts.Domain)
	opts.Progress(fmt.Sprintf("Generated %d permutations", len(permSubs)))
	allSubdomains = append(allSubdomains, permSubs...)

	// Deduplicate before resolving
	allSubdomains = deduplicate(allSubdomains)
	dnsClient, _ := dns_asr.NewClientWithResolverFile(opts.Resolvers, opts.Threads)
	allSubdomains, _ = dnsClient.Resolve(ctx, allSubdomains, opts.Threads)
	utils.WriteLines(filepath.Join(domainDir, "all_subs_resolved.txt"), allSubdomains)

	// 5. HTTP Check
	opts.Progress("Checking for live HTTP hosts")
	httpClient, _ := http_asr.NewClient(opts.Threads)
	liveHosts, _ := httpClient.CheckLive(ctx, allSubdomains, opts.Threads)
	opts.Progress(fmt.Sprintf("Found %d live hosts", len(liveHosts)))
	utils.WriteLines(filepath.Join(domainDir, "filtered_hosts.txt"), liveHosts)

	// 6. Scraping
	opts.Progress("Starting web scraping for additional subdomains")
	scraper := crawl.NewScraper()
	var scrapedSubs []string
	for _, host := range liveHosts {
		subs, _ := scraper.Extract(ctx, host, opts.Domain)
		scrapedSubs = append(scrapedSubs, subs...)
	}
	opts.Progress(fmt.Sprintf("Found %d additional subdomains via scraping", len(scrapedSubs)))
	allSubdomains = append(allSubdomains, scrapedSubs...)
	allSubdomains = deduplicate(allSubdomains)

	return utils.WriteLines(filepath.Join(domainDir, "asr_results_mode5.txt"), allSubdomains)
}
