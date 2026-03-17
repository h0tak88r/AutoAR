// Package gospider provides an embeddable spidering wrapper around the external
// gospider binary.  It invokes the binary as a subprocess and parses the URL
// lines from its output, returning them as a deduplicated []string.
// If the binary is not installed, Run returns an empty result without error.
package gospider

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
)

// Options controls the spider run.
type Options struct {
	Sites      []string // URLs to spider
	Depth      int      // recursion depth (default 2)
	Concurrent int      // concurrent requests per site (default 5)
	Threads    int      // parallel sites (default 5)
	Timeout    int      // per-request timeout seconds (default 10)
	Robots     bool     // follow robots.txt hints (default true)
	JS         bool     // linkfinder in JS files (default true)
}

// Result holds discovered URLs.
type Result struct {
	URLs []string
}

// urlPattern extracts raw URLs from gospider output lines like:
//
//	[url] - [code-200] - https://target.com/path
//	[href] - https://target.com/path
var urlPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

// Run spiders the given sites and returns all discovered URLs.
// If the gospider binary is not available it logs a warning and returns an empty result.
func Run(opts Options) (*Result, error) {
	if len(opts.Sites) == 0 {
		return &Result{}, nil
	}

	// Defaults
	if opts.Depth == 0 {
		opts.Depth = 2
	}
	if opts.Concurrent == 0 {
		opts.Concurrent = 5
	}
	if opts.Threads == 0 {
		opts.Threads = 5
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10
	}

	binaryPath, err := exec.LookPath("gospider")
	if err != nil {
		log.Printf("[gospider] binary not found in PATH – skipping spidering")
		return &Result{}, nil
	}

	seen := make(map[string]bool)
	var collected []string

	add := func(u string) {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u != "" && !seen[u] {
			seen[u] = true
			collected = append(collected, u)
		}
	}

	for _, site := range opts.Sites {
		if !strings.HasPrefix(site, "http") {
			site = "https://" + site
		}

		args := []string{
			"-s", site,
			"-d", fmt.Sprintf("%d", opts.Depth),
			"-c", fmt.Sprintf("%d", opts.Concurrent),
			"-t", fmt.Sprintf("%d", opts.Threads),
			"-m", fmt.Sprintf("%d", opts.Timeout),
			"-q", // quiet — one URL per line on stdout
		}
		if opts.Robots {
			args = append(args, "--robots")
		}
		if opts.JS {
			args = append(args, "--js")
		}

		cmd := exec.Command(binaryPath, args...)
		var out bytes.Buffer
		cmd.Stdout = &out

		log.Printf("[gospider] Crawling %s (depth=%d concurrent=%d)", site, opts.Depth, opts.Concurrent)
		if runErr := cmd.Run(); runErr != nil {
			// exit 1 is normal when no URLs found
			log.Printf("[gospider] %s finished with: %v", site, runErr)
		}

		sc := bufio.NewScanner(&out)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "http") {
				add(line)
				continue
			}
			// Non-quiet fallback: extract URLs from formatted lines
			for _, match := range urlPattern.FindAllString(line, -1) {
				add(match)
			}
		}
	}

	log.Printf("[gospider] Collected %d unique URLs across %d site(s)", len(collected), len(opts.Sites))
	return &Result{URLs: collected}, nil
}
