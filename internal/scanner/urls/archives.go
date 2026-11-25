package urls

// Shared plumbing for the archive URL sources (Wayback, Common Crawl, OTX,
// URLScan, VirusTotal).
//
// The Internet Archive answers Go's default User-Agent ("Go-http-client/1.1")
// with 429/498 while serving the same query to any other client, so every
// Wayback lookup AutoAR made came back empty. Archive requests now carry an
// honest AutoAR User-Agent, retry once on throttling, and keep whatever lines
// arrived when a large CDX listing is cut off by the deadline.

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/version"
)

var archiveUA = "Mozilla/5.0 (compatible; AutoAR/" + version.Version + "; +https://github.com/h0tak88r/AutoAR)"

// Overridable in tests.
var (
	waybackBase     = "https://web.archive.org"
	commonCrawlBase = "https://index.commoncrawl.org"
	otxBase         = "https://otx.alienvault.com"
	urlscanBase     = "https://urlscan.io"
	archiveBackoff  = []time.Duration{3 * time.Second, 10 * time.Second}
)

// uaTransport sets the archive User-Agent on requests that have none.
type uaTransport struct{ base http.RoundTripper }

func (t uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", archiveUA)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

// archiveClient is an HTTP client for archive APIs with the given deadline.
func archiveClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: uaTransport{}}
}

// archiveRetryable reports a throttled or briefly unavailable source.
func archiveRetryable(code int) bool {
	switch code {
	case http.StatusTooManyRequests, 498, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// archiveDo sends req, retrying throttled responses with backoff. The caller
// closes the body of a non-nil response.
func archiveDo(client *http.Client, req *http.Request, source string) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if !archiveRetryable(resp.StatusCode) || attempt >= len(archiveBackoff) {
			return resp, nil
		}
		resp.Body.Close()
		logger.GetLogger().Infof("[INFO] %s returned %d, retrying in %s", source, resp.StatusCode, archiveBackoff[attempt])
		time.Sleep(archiveBackoff[attempt])
	}
}

// archiveGet is archiveDo for a plain GET.
func archiveGet(client *http.Client, url, source string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return archiveDo(client, req, source)
}

// readLinesPartial reads non-empty trimmed lines until EOF or an error, and
// returns what it read either way (a CDX listing cut off by the deadline
// still holds thousands of good URLs).
func readLinesPartial(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []string
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

var (
	ccIndexMu   sync.Mutex
	ccIndexName string
	ccIndexAt   time.Time
)

// ccFallbackIndex is used when the collection list cannot be read.
const ccFallbackIndex = "CC-MAIN-2026-39"

// latestCommonCrawlIndex returns the newest Common Crawl CDX index id (looked
// up once a day; the old code queried a fixed 2023 index).
func latestCommonCrawlIndex(client *http.Client) string {
	ccIndexMu.Lock()
	defer ccIndexMu.Unlock()
	if ccIndexName != "" && time.Since(ccIndexAt) < 24*time.Hour {
		return ccIndexName
	}
	name := ccFallbackIndex
	if resp, err := archiveGet(client, commonCrawlBase+"/collinfo.json", "Common Crawl index list"); err == nil {
		var list []struct {
			ID string `json:"id"`
		}
		if resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list) == nil && len(list) > 0 && list[0].ID != "" {
			name = list[0].ID // newest first
		}
		resp.Body.Close()
	}
	ccIndexName, ccIndexAt = name, time.Now()
	return name
}

// URL-collection cache stamp. A urls/ directory is reused only when this
// version of the collector filled it within urlsCacheTTL: collections made
// while every archive source was silently failing (no stamp) are redone once.
const (
	urlsCacheVersion = 2
	urlsCacheTTL     = 24 * time.Hour
	urlsStampFile    = ".collected"
)

type urlsStamp struct {
	Version int   `json:"version"`
	At      int64 `json:"at"`
}

func writeURLsStamp(urlsDir string) {
	b, _ := json.Marshal(urlsStamp{Version: urlsCacheVersion, At: time.Now().Unix()})
	_ = os.WriteFile(filepath.Join(urlsDir, urlsStampFile), b, 0o644)
}

// URLsCacheFresh reports whether urlsDir holds a collection this collector
// version made less than urlsCacheTTL ago.
func URLsCacheFresh(urlsDir string) bool {
	b, err := os.ReadFile(filepath.Join(urlsDir, urlsStampFile))
	if err != nil {
		return false
	}
	var s urlsStamp
	if json.Unmarshal(b, &s) != nil || s.Version != urlsCacheVersion {
		return false
	}
	return time.Since(time.Unix(s.At, 0)) < urlsCacheTTL
}

// IsJSURL reports whether u is a JavaScript file: its path (query and
// fragment ignored) ends in .js or .mjs. Substring checks also took .json,
// .jsp and /js/ paths.
func IsJSURL(u string) bool {
	low := strings.ToLower(strings.TrimSpace(u))
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return false
	}
	if i := strings.IndexAny(low, "?#"); i >= 0 {
		low = low[:i]
	}
	return strings.HasSuffix(low, ".js") || strings.HasSuffix(low, ".mjs")
}

// Common Crawl's index servers are often overloaded (504 for every query);
// after one failure the source is skipped for a while instead of costing
// every scan its retries.
var (
	ccDownMu    sync.Mutex
	ccDownUntil time.Time
	ccDownFor   = 30 * time.Minute
)

func commonCrawlDown() bool {
	ccDownMu.Lock()
	defer ccDownMu.Unlock()
	return time.Now().Before(ccDownUntil)
}

func markCommonCrawlDown() {
	ccDownMu.Lock()
	ccDownUntil = time.Now().Add(ccDownFor)
	ccDownMu.Unlock()
}
