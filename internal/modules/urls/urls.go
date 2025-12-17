package urls

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	jsfindertool "github.com/h0tak88r/AutoAR/internal/tools/jsfinder"
	urlfindertool "github.com/h0tak88r/AutoAR/internal/tools/urlfinder"
	"github.com/h0tak88r/AutoAR/internal/modules/livehosts"
	"github.com/h0tak88r/AutoAR/internal/modules/utils"
)

// Result summarizes URL collection for a domain.
type Result struct {
	Domain    string
	Threads   int
	TotalURLs int
	JSURLs    int
	AllFile   string
	JSFile    string
}

// CollectURLs ensures live hosts exist for a domain and then collects URLs and JS URLs
// using external tools (urlfinder and jsfinder), mirroring modules/urls.sh behaviour.
func CollectURLs(domain string, threads int) (*Result, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}
	if threads <= 0 {
		threads = 100
	}

	// Initialize directory structure
	domainDir, err := utils.DomainDirInit(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to init domain dir: %v", err)
	}

	subsDir := filepath.Join(domainDir, "subs")
	urlsDir := filepath.Join(domainDir, "urls")
	if err := utils.EnsureDir(urlsDir); err != nil {
		return nil, fmt.Errorf("failed to ensure urls dir: %v", err)
	}

	// Ensure live hosts exist using Go livehosts module (silent to avoid duplicate Discord output)
	liveRes, err := livehosts.FilterLiveHosts(domain, threads, true)
	if err != nil {
		log.Printf("[WARN] livehosts filtering failed for %s: %v", domain, err)
	}

	liveFile := filepath.Join(subsDir, "live-subs.txt")
	if liveRes != nil && liveRes.LiveSubsFile != "" {
		liveFile = liveRes.LiveSubsFile
	}

	// Prepare output files
	allFile := filepath.Join(urlsDir, "all-urls.txt")
	jsFile := filepath.Join(urlsDir, "js-urls.txt")
	_ = writeLines(allFile, nil)
	_ = writeLines(jsFile, nil)

	// 1) Collect URLs with embedded urlfinder library
	log.Printf("[INFO] Collecting URLs with embedded urlfinder for %s", domain)
	if _, err := urlfindertool.FindURLsToFile(domain, allFile, urlfindertool.Options{AllSources: true}); err != nil {
		log.Printf("[WARN] urlfinder library failed for %s: %v", domain, err)
	}

	// 2) Collect JS URLs with embedded jsfinder over live hosts
	if fi, err := os.Stat(liveFile); err == nil && fi.Size() > 0 {
		log.Printf("[INFO] Running embedded jsfinder on live hosts for %s", domain)
		liveURLs, err := readLines(liveFile)
		if err != nil {
			log.Printf("[WARN] Failed to read live hosts file for jsfinder: %v", err)
		} else {
			jsMatches, err := jsfindertool.Extract(liveURLs, jsfindertool.ExtractOptions{
				Concurrency: threads,
				Silent:      true,
			})
			if err != nil {
				log.Printf("[WARN] jsfinder library failed for %s: %v", domain, err)
			} else if len(jsMatches) > 0 {
				if err := writeLines(jsFile, jsMatches); err != nil {
					log.Printf("[WARN] Failed to write jsfinder results: %v", err)
				}
			}
		}
	}

	// 3) Merge JS URLs from all-urls.txt into js-urls.txt and deduplicate
	allURLs, _ := readLines(allFile)
	jsURLs, _ := readLines(jsFile)
	for _, u := range allURLs {
		if strings.Contains(strings.ToLower(u), ".js") {
			jsURLs = append(jsURLs, u)
		}
	}

	jsURLs = uniqueStrings(jsURLs)
	_ = writeLines(jsFile, jsURLs)

	// 4) Merge js-urls.txt back into all-urls.txt and deduplicate
	allURLs = uniqueStrings(append(allURLs, jsURLs...))
	_ = writeLines(allFile, allURLs)

	total := len(allURLs)
	jsCount := len(jsURLs)
	log.Printf("[OK] Found %d total URLs; %d JavaScript URLs for %s", total, jsCount, domain)

	return &Result{
		Domain:    domain,
		Threads:   threads,
		TotalURLs: total,
		JSURLs:    jsCount,
		AllFile:   allFile,
		JSFile:    jsFile,
	}, nil
}

// helpers

// readLines reads non-empty lines from a file.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
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

// writeLines writes lines to a file (one per line). If lines is nil, creates/empties the file.
func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if len(lines) == 0 {
		return nil
	}

	w := bufio.NewWriter(file)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// uniqueStrings returns a deduplicated slice preserving order.
func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
