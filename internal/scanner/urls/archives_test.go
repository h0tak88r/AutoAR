package urls

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeArchive behaves like the Internet Archive: Go's default User-Agent gets
// 429, anything else gets the listing.
func fakeArchive(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.UserAgent(), "Go-http-client") {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	oW, oC, oO, oB := waybackBase, commonCrawlBase, otxBase, archiveBackoff
	t.Cleanup(func() { waybackBase, commonCrawlBase, otxBase, archiveBackoff = oW, oC, oO, oB })
	waybackBase, commonCrawlBase, otxBase = srv.URL, srv.URL, srv.URL
	archiveBackoff = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}
	ccIndexMu.Lock()
	ccIndexName = ""
	ccIndexMu.Unlock()
}

// The bug: every Wayback lookup sent Go's default User-Agent and got 429/498,
// so host and root URL collection came back nearly empty.
func TestWaybackSendsArchiveUserAgent(t *testing.T) {
	var gotUA, gotQuery string
	fakeArchive(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotQuery = r.UserAgent(), r.URL.Query().Get("url")
		fmt.Fprint(w, "https://www.acme.com/\nhttps://www.acme.com/static/app.js\n\nhttps://www.acme.com/global.js\n")
	})
	got := collectWaybackURLs(archiveClient(5*time.Second), "www.acme.com", true)
	if len(got) != 3 || got[1] != "https://www.acme.com/static/app.js" {
		t.Fatalf("urls: %v", got)
	}
	if !strings.Contains(gotUA, "AutoAR/") || gotQuery != "www.acme.com/*" {
		t.Fatalf("ua %q query %q", gotUA, gotQuery)
	}
	collectWaybackURLs(archiveClient(5*time.Second), "acme.com", false)
	if gotQuery != "*.acme.com/*" {
		t.Fatalf("root query %q", gotQuery)
	}
	// A client that kept Go's User-Agent is exactly what failed before.
	if got := collectWaybackURLs(&http.Client{Timeout: 5 * time.Second}, "www.acme.com", true); len(got) != 0 {
		t.Fatalf("fake archive should refuse the Go UA, got %v", got)
	}
}

func TestArchiveRetriesThrottling(t *testing.T) {
	var calls int32
	fakeArchive(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(498)
			return
		}
		fmt.Fprint(w, "https://a.acme.com/x.js\n")
	})
	if got := collectWaybackURLs(archiveClient(5*time.Second), "a.acme.com", true); len(got) != 1 || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("got %v after %d calls", got, calls)
	}
}

// A root-domain CDX listing that outlives the deadline keeps what arrived
// (it used to be dropped whole: 38,000 lines for awaze.com).
func TestWaybackKeepsPartialListing(t *testing.T) {
	fakeArchive(t, func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "https://acme.com/p%d.js\n", i)
		}
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})
	got := collectWaybackURLs(archiveClient(300*time.Millisecond), "acme.com", false)
	if len(got) != 3 {
		t.Fatalf("partial listing: %v", got)
	}
}

func TestCommonCrawlUsesNewestIndex(t *testing.T) {
	var path string
	fakeArchive(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collinfo.json" {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "CC-MAIN-2026-40"}, {"id": "CC-MAIN-2026-33"}})
			return
		}
		path = r.URL.Path
		fmt.Fprint(w, `{"url":"https://www.acme.com/main.js"}`+"\n"+`{"url":"https://www.acme.com/"}`+"\n")
	})
	got := collectCommonCrawlURLs(archiveClient(5*time.Second), "www.acme.com", true)
	if path != "/CC-MAIN-2026-40-index" || len(got) != 2 {
		t.Fatalf("path %q urls %v", path, got)
	}
}

func TestOTXHostnameEndpointForHosts(t *testing.T) {
	var path string
	fakeArchive(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		fmt.Fprint(w, `{"url_list":[{"url":"https://www.acme.com/a.js"}]}`)
	})
	if got := collectOTXURLs(archiveClient(5*time.Second), "www.acme.com", true); len(got) != 1 || path != "/api/v1/indicators/hostname/www.acme.com/url_list" {
		t.Fatalf("host: %q %v", path, got)
	}
	collectOTXURLs(archiveClient(5*time.Second), "acme.com", false)
	if path != "/api/v1/indicators/domain/acme.com/url_list" {
		t.Fatalf("domain: %q", path)
	}
}

// A collection made while the sources were failing has no stamp: it is
// redone once instead of being reused forever.
func TestURLsCacheStamp(t *testing.T) {
	dir := t.TempDir()
	if URLsCacheFresh(dir) {
		t.Fatal("no stamp must not be fresh")
	}
	writeURLsStamp(dir)
	if !URLsCacheFresh(dir) {
		t.Fatal("fresh stamp rejected")
	}
	old, _ := json.Marshal(urlsStamp{Version: urlsCacheVersion, At: time.Now().Add(-urlsCacheTTL - time.Minute).Unix()})
	_ = os.WriteFile(filepath.Join(dir, urlsStampFile), old, 0o644)
	if URLsCacheFresh(dir) {
		t.Fatal("stale stamp accepted")
	}
	prev, _ := json.Marshal(urlsStamp{Version: urlsCacheVersion - 1, At: time.Now().Unix()})
	_ = os.WriteFile(filepath.Join(dir, urlsStampFile), prev, 0o644)
	if URLsCacheFresh(dir) {
		t.Fatal("older collector version accepted")
	}
}

func TestIsJSURL(t *testing.T) {
	for u, want := range map[string]bool{
		"https://a.com/x.js": true, "https://a.com/x.js?v=1": true, "http://a.com/x.mjs#f": true,
		"https://a.com/x.json": false, "https://a.com/x.jsp": false, "https://a.com/js/": false,
		"https://a.com/wp-json/v2": false, "/rel/x.js": false,
	} {
		if IsJSURL(u) != want {
			t.Errorf("IsJSURL(%q) != %v", u, want)
		}
	}
}

// One Common Crawl failure parks the source instead of costing every scan
// its retries.
func TestCommonCrawlBreaker(t *testing.T) {
	var calls int32
	fakeArchive(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/collinfo.json" {
			_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "CC-MAIN-2026-40"}})
			return
		}
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusGatewayTimeout)
	})
	ccDownMu.Lock()
	ccDownUntil = time.Time{}
	ccDownMu.Unlock()
	t.Cleanup(func() { ccDownMu.Lock(); ccDownUntil = time.Time{}; ccDownMu.Unlock() })
	c := archiveClient(5 * time.Second)
	collectCommonCrawlURLs(c, "www.acme.com", true)
	first := atomic.LoadInt32(&calls)
	collectCommonCrawlURLs(c, "api.acme.com", true)
	if first != 3 || atomic.LoadInt32(&calls) != first {
		t.Fatalf("calls: first scan %d (want 1 + 2 retries), second scan added %d", first, atomic.LoadInt32(&calls)-first)
	}
}
