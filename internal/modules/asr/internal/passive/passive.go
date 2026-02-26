package passive

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// Runner is a wrapper around subfinder's runner
type Runner struct {
	subfinder *runner.Runner
}

// NewRunner creates a new subfinder runner
func NewRunner(threads int) (*Runner, error) {
	options := &runner.Options{
		Threads:            threads,
		Timeout:            30,
		MaxEnumerationTime: 10,
	}

	subfinderRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, err
	}

	return &Runner{
		subfinder: subfinderRunner,
	}, nil
}

// Enumerate performs passive subdomain enumeration for a domain
func (r *Runner) Enumerate(ctx context.Context, domain string) ([]string, error) {
	var allSubs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Sources to run
	type source interface {
		Enumerate(context.Context, string) ([]string, error)
	}

	sources := []source{
		NewAlienVaultSource(),
		NewAnubisSource(),
		NewHackerTargetSource(),
		NewWaybackSource(),
		NewRapidDNSSource(),
	}

	// 1. Subfinder (High priority, separate call)
	wg.Add(1)
	go func() {
		defer wg.Done()
		output := &bytes.Buffer{}
		err := r.subfinder.EnumerateSingleDomain(domain, []io.Writer{output})
		if err == nil {
			scanner := bytes.NewBuffer(output.Bytes())
			for {
				line, err := scanner.ReadString('\n')
				if err != nil {
					break
				}
				sub := strings.TrimSpace(line)
				if sub != "" {
					mu.Lock()
					allSubs = append(allSubs, sub)
					mu.Unlock()
				}
			}
		}
	}()

	// 2. Custom Sources
	for _, s := range sources {
		wg.Add(1)
		go func(src source) {
			defer wg.Done()
			subs, err := src.Enumerate(ctx, domain)
			if err == nil {
				mu.Lock()
				allSubs = append(allSubs, subs...)
				mu.Unlock()
			}
		}(s)
	}

	// 3. SecurityTrails (if key exists)
	apiKey := os.Getenv("SECURITYTRAILS_API_KEY")
	if apiKey == "" {
		apiKey = "AE4qcaLV9GUPqxWHa-WDKfFu7C0PIYD1"
	}
	if apiKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := NewSecurityTrailsSource(apiKey)
			subs, err := st.Enumerate(ctx, domain)
			if err == nil {
				mu.Lock()
				allSubs = append(allSubs, subs...)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Deduplicate
	unique := make(map[string]bool)
	var finalResults []string
	for _, s := range allSubs {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !unique[s] {
			unique[s] = true
			finalResults = append(finalResults, s)
		}
	}

	return finalResults, nil
}


