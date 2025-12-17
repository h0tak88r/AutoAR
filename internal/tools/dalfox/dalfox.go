package dalfox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	dalfoxlib "github.com/hahwul/dalfox/v2/lib"
)

// Options controls how the embedded dalfox engine runs.
type Options struct {
	Threads       int
	OnlyDiscovery bool
}

// Result represents a single dalfox scan result for one target URL.
type Result struct {
	Target string          `json:"target"`
	Raw    json.RawMessage `json:"raw"`
}

// ScanFile reads target URLs from the given file (one per line), runs
// dalfox scans against them, and returns a slice of results. The caller
// is responsible for persisting Raw somewhere (e.g. JSONL file).
func ScanFile(path string, opts Options) ([]Result, error) {
	if opts.Threads <= 0 {
		opts.Threads = 50
	}

	targets, err := readLines(path)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found in %s", path)
	}

	targetCh := make(chan string, len(targets))
	resultsCh := make(chan Result, len(targets))
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for url := range targetCh {
			url = strings.TrimSpace(url)
			if url == "" {
				continue
			}

			opt := dalfoxlib.Options{
				OnlyDiscovery: opts.OnlyDiscovery,
			}

			res, err := dalfoxlib.NewScan(dalfoxlib.Target{
				URL:     url,
				Method:  "GET",
				Options: opt,
			})
			if err != nil {
				continue
			}

			b, err := json.Marshal(res)
			if err != nil {
				continue
			}

			resultsCh <- Result{Target: url, Raw: b}
		}
	}

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go worker()
	}

	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)

	wg.Wait()
	close(resultsCh)

	var out []Result
	for r := range resultsCh {
		out = append(out, r)
	}

	return out, nil
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}
