package jsendpoints

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestDownloadFileRefusesNonPublic: target-supplied URLs (host list entries,
// <script src>) pointing at metadata/internal/loopback addresses must be
// refused before any request is made.
func TestDownloadFileRefusesNonPublic(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(`<script src="/app.js"></script>`))
	}))
	defer srv.Close()

	client := newFetchClient()
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/app.js",
		"file:///etc/passwd",
		srv.URL + "/",
	} {
		if _, err := downloadFile(client, u, maxJSBytes); err == nil {
			t.Errorf("downloadFile(%q) succeeded; want SSRF refusal", u)
		}
	}
	if eps, _ := CollectEndpointsForHosts([]string{srv.URL}, 2); len(eps) != 0 {
		t.Errorf("CollectEndpointsForHosts on a loopback host returned %v", eps)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("loopback server received %d request(s); want 0", n)
	}
}

func TestExtractEndpoints(t *testing.T) {
	js := `fetch("/api/v1/users");axios.get('/internal/admin/list');var a="/static/x.png";`
	got := map[string]bool{}
	for _, ep := range extractEndpoints(js, "https://t.example/app.js") {
		got[ep] = true
	}
	if !got["/api/v1/users"] || !got["/internal/admin/list"] {
		t.Fatalf("missing endpoints: %v", got)
	}
	if got["/static/x.png"] {
		t.Fatalf("noise not filtered: %v", got)
	}
}
