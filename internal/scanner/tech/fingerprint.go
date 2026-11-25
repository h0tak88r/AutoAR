package tech

import (
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/httpx/runner"
)

// Fingerprint is what one HTTP probe learned about a host.
type Fingerprint struct {
	Input      string // the target exactly as passed in
	URL        string
	StatusCode int
	Title      string
	Server     string
	Techs      []string
}

// FingerprintOptions tunes a probe batch.
type FingerprintOptions struct {
	Threads   int // default 50
	RateLimit int // requests per second, default 150
	Timeout   int // seconds per request, default 8
}

// FingerprintHosts probes targets once each (same-host redirects followed)
// and reports tech stack, title and server header. Hosts that do not answer
// are simply absent from the result.
func FingerprintHosts(targets []string, o FingerprintOptions) ([]Fingerprint, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if o.Threads <= 0 {
		o.Threads = 50
	}
	if o.RateLimit <= 0 {
		o.RateLimit = 150
	}
	if o.Timeout <= 0 {
		o.Timeout = 8
	}
	var (
		mu  sync.Mutex
		out []Fingerprint
	)
	options := runner.Options{
		InputTargetHost:     targets,
		Threads:             o.Threads,
		RateLimit:           o.RateLimit,
		Timeout:             o.Timeout,
		Retries:             0,
		TechDetect:          true,
		ExtractTitle:        true,
		StatusCode:          true,
		OutputServerHeader:  true,
		FollowHostRedirects: true,
		MaxRedirects:        3,
		NoColor:             true,
		Silent:              true,
		DisableStdout:       true,
		OnResult: func(r runner.Result) {
			if r.Err != nil || r.Failed || r.URL == "" {
				return
			}
			fp := Fingerprint{
				Input: strings.TrimSpace(r.Input), URL: r.URL, StatusCode: r.StatusCode,
				Title: strings.TrimSpace(r.Title), Server: strings.TrimSpace(r.WebServer),
				Techs: append([]string(nil), r.Technologies...),
			}
			mu.Lock()
			out = append(out, fp)
			mu.Unlock()
		},
	}
	if err := options.ValidateOptions(); err != nil {
		return nil, fmt.Errorf("httpx options: %w", err)
	}
	r, err := runner.New(&options)
	if err != nil {
		return nil, fmt.Errorf("httpx runner: %w", err)
	}
	defer r.Close()
	r.RunEnumeration()
	return out, nil
}
