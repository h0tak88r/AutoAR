package jsfinder

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ExtractOptions controls how the JS finder runs.
type ExtractOptions struct {
	Concurrency int
	Silent      bool
}

// Extract takes a list of page URLs and returns all discovered JavaScript
// URLs, roughly mirroring the behaviour of the original jsfinder CLI.
func Extract(urls []string, opt ExtractOptions) ([]string, error) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 20
	}

	// Buffered channel for results
	results := make(chan string, 1024)
	sem := make(chan struct{}, opt.Concurrency)

	var wg sync.WaitGroup

	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}

		wg.Add(1)
		go func(pageURL string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				Timeout: 7 * time.Second,
			}

			req, err := http.NewRequest("GET", pageURL, nil)
			if err != nil {
				if !opt.Silent {
					fmt.Fprintf(os.Stderr, "[jsfinder] error creating request for %s: %v\n", pageURL, err)
				}
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				if !opt.Silent {
					fmt.Fprintf(os.Stderr, "[jsfinder] error getting response from %s: %v\n", pageURL, err)
				}
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				if !opt.Silent {
					fmt.Fprintf(os.Stderr, "[jsfinder] non-200 from %s: %d\n", pageURL, resp.StatusCode)
				}
				return
			}

			bodyBytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				if !opt.Silent {
					fmt.Fprintf(os.Stderr, "[jsfinder] error reading body from %s: %v\n", pageURL, err)
				}
				return
			}
			bodyString := string(bodyBytes)

			re := regexp.MustCompile(`(?i)(?:src|srcdoc|formaction|dynsrc|standby|ng-include|ui-sref|href|data-main|data|onclick|onload|style|srcdoc|formaction|iframe|object|background|input|button|action|dynsrc|srcset|manifest|code|archive|classid|cite|codebase|longdesc|lowsrc|usemap|standby|ng-click|ng-src|ng-inlude|ui-sref|require|createElement|appendChild|innerHTML|getScript|XMLHttpRequest|fetch|import|onerror|WebSocket|ServiceWorker|SharedWorker|importScripts|eval)\s*=\s*["']([^"']*\.js(\?[^"']*)?)["']`)

			matches := re.FindAllStringSubmatch(bodyString, -1)
			if len(matches) == 0 {
				return
			}

			for _, match := range matches {
				jsURL := match[1]
				normalized := normalizeJSURL(pageURL, jsURL)
				if normalized != "" {
					results <- normalized
				}
			}
		}(u)
	}

	// Close results when all workers are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and deduplicate
	seen := make(map[string]struct{})
	var out []string
	for js := range results {
		js = strings.TrimSpace(js)
		if js == "" {
			continue
		}
		if _, ok := seen[js]; ok {
			continue
		}
		seen[js] = struct{}{}
		out = append(out, js)
	}

	return out, nil
}

// ExtractFromFile is a small helper that reads page URLs from a file
// and returns discovered JS URLs.
func ExtractFromFile(path string, opt ExtractOptions) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var urls []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return Extract(urls, opt)
}

// normalizeJSURL mirrors the URL normalisation logic from the original
// jsfinder CLI, but returns the JS URL as a string instead of writing
// directly to a file.
func normalizeJSURL(pageURL, jsURL string) string {
	jsURL = strings.TrimSpace(jsURL)
	if jsURL == "" {
		return ""
	}

	url := strings.TrimSpace(pageURL)
	if url == "" {
		return ""
	}

	if strings.HasSuffix(jsURL, ".js") || strings.Contains(jsURL, ".js?") {
		if strings.HasPrefix(jsURL, "/") {
			if strings.Contains(url, ".com") || strings.Contains(url, ".net") || strings.Contains(url, ".org") {
				if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
					url = "https://" + strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
				}
				if strings.Contains(jsURL, ".com") || strings.Contains(jsURL, ".net") || strings.Contains(jsURL, ".org") {
					if strings.HasPrefix(jsURL, "//") {
						return fmt.Sprintf("https:%s", jsURL)
					}
					return fmt.Sprintf("https://%s", strings.TrimPrefix(jsURL, "/"))
				}
				if strings.HasPrefix(jsURL, "/") {
					return fmt.Sprintf("%s%s", url, jsURL)
				}
				if strings.HasPrefix(jsURL, "https://") || strings.HasPrefix(jsURL, "http://") {
					return jsURL
				}
				if strings.HasPrefix(jsURL, "//") {
					return fmt.Sprintf("https:%s", jsURL)
				}
				return fmt.Sprintf("https://%s", jsURL)
			}
			return fmt.Sprintf("%s/%s", url, jsURL)
		}
		if strings.HasPrefix(jsURL, "https://") || strings.HasPrefix(jsURL, "http://") {
			return jsURL
		}
		if strings.Contains(jsURL, ".com") || strings.Contains(jsURL, ".net") || strings.Contains(jsURL, ".org") {
			if strings.Contains(jsURL, ".com/") {
				return fmt.Sprintf("https://%s%s", jsURL[:strings.Index(jsURL, ".com")+4], jsURL[strings.Index(jsURL, ".com")+4:])
			}
			if strings.Contains(jsURL, ".net/") {
				return fmt.Sprintf("https://%s%s", jsURL[:strings.Index(jsURL, ".net")+4], jsURL[strings.Index(jsURL, ".net")+4:])
			}
			if strings.Contains(jsURL, ".org/") {
				return fmt.Sprintf("https://%s%s", jsURL[:strings.Index(jsURL, ".org")+4], jsURL[strings.Index(jsURL, ".org")+4:])
			}
			return fmt.Sprintf("https://%s/%s", jsURL[:strings.Index(jsURL, ".")+4], jsURL[strings.Index(jsURL, ".")+4:])
		}
		return fmt.Sprintf("%s/%s", url, jsURL)
	}

	// Non-JS URLs fall back to a simple join.
	return fmt.Sprintf("%s/%s", url, jsURL)
}
