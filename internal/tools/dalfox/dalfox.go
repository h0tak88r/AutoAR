package dalfox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
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
	Target    string          `json:"target"`
	Raw       json.RawMessage `json:"raw"`
	Severity  string          `json:"severity,omitempty"`
	Type      string          `json:"type,omitempty"`
	Parameter string          `json:"parameter,omitempty"`
	Payload   string          `json:"payload,omitempty"`
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
			var raw map[string]any
			_ = json.Unmarshal(b, &raw)
			severity := strings.TrimSpace(fmt.Sprint(raw["severity"]))
			if severity == "" || severity == "<nil>" {
				severity = "high"
			}
			fType := strings.TrimSpace(fmt.Sprint(raw["type"]))
			if fType == "" || fType == "<nil>" {
				fType = "xss"
			}
			param := strings.TrimSpace(fmt.Sprint(raw["param"]))
			if param == "" || param == "<nil>" {
				param = strings.TrimSpace(fmt.Sprint(raw["parameter"]))
			}
			payload := strings.TrimSpace(fmt.Sprint(raw["payload"]))

			resultsCh <- Result{
				Target:    url,
				Raw:       b,
				Severity:  severity,
				Type:      fType,
				Parameter: param,
				Payload:   payload,
			}
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
	seen := make(map[string]struct{})
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Deduplicate by endpoint+param-names before handing to dalfox workers.
		k := normaliseURL(line)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// normaliseURL strips query parameter values, keeping only sorted param names.
// https://x.com/p?a=1&b=2 and https://x.com/p?a=foo&b=bar → same key.
func normaliseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		u2, _ := url.Parse(raw)
		if u2 != nil {
			u2.RawQuery = ""
			u2.Fragment = ""
			return u2.String()
		}
		return raw
	}
	q := u.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	normQ := make(url.Values, len(names))
	for _, k := range names {
		normQ[k] = []string{""}
	}
	u.RawQuery = normQ.Encode()
	u.Fragment = ""
	return u.String()
}
