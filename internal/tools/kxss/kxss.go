package kxss

import (
	"bufio"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Result represents a single reflection finding for a URL parameter.
type Result struct {
	URL   string
	Param string
	Chars []string
}

// ScanURLs runs the kxss reflection logic against the provided URLs.
// It returns a slice of Result objects similar to the original CLI output.
func ScanURLs(urls []string) ([]Result, error) {
	// Reuse the same HTTP client settings as the original tool.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	httpClient := &http.Client{
		Transport: transport,
	}

	// Match original redirect behaviour (do not follow redirects).
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	var results []Result

	for _, raw := range urls {
		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}

		reflected, err := checkReflectedWithClient(httpClient, u)
		if err != nil {
			continue
		}
		if len(reflected) == 0 {
			continue
		}

		for _, param := range reflected {
			// Initial append check with fixed suffix, same as original tool.
			ok, err := checkAppendWithClient(httpClient, u, param, "iy3j4h234hjb23234")
			if err != nil || !ok {
				continue
			}

			chars := []string{}
			for _, ch := range []string{"\"", "'", "<", ">", "$", "|", "(", ")", "`", ":", ";", "{", "}"} {
				okChar, err := checkAppendWithClient(httpClient, u, param, "aprefix"+ch+"asuffix")
				if err != nil {
					continue
				}
				if okChar {
					chars = append(chars, ch)
				}
			}

			if len(chars) > 0 {
				results = append(results, Result{
					URL:   u,
					Param: param,
					Chars: chars,
				})
			}
		}
	}

	return results, nil
}

// ScanFile is a helper that reads URLs from a file (one per line) and
// returns reflection results.
func ScanFile(path string) ([]Result, error) {
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

	return ScanURLs(urls)
}

// --- Internal helpers adapted from original kxss main.go ---

func checkReflectedWithClient(client *http.Client, targetURL string) ([]string, error) {
	out := make([]string, 0)

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return out, err
	}

	// Same UA as original tool
	req.Header.Add("User-Agent", "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return out, err
	}
	if resp.Body == nil {
		return out, err
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return out, err
	}

	// Skip redirects
	if strings.HasPrefix(resp.Status, "3") {
		return out, nil
	}

	// Only HTML-like responses
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "html") {
		return out, nil
	}

	body := string(b)

	u, err := url.Parse(targetURL)
	if err != nil {
		return out, err
	}

	for key, vv := range u.Query() {
		for _, v := range vv {
			if !strings.Contains(body, v) {
				continue
			}
			out = append(out, key)
		}
	}

	return out, nil
}

func checkAppendWithClient(client *http.Client, targetURL, param, suffix string) (bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false, err
	}

	qs := u.Query()
	val := qs.Get(param)
	qs.Set(param, val+suffix)
	u.RawQuery = qs.Encode()

	reflected, err := checkReflectedWithClient(client, u.String())
	if err != nil {
		return false, err
	}

	for _, r := range reflected {
		if r == param {
			return true, nil
		}
	}

	return false, nil
}
