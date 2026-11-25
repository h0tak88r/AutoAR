package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func getDashboardUI(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ui", serveDashboardUI)
	r.GET("/ui/*filepath", serveDashboardUI)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", target, w.Code)
	}
	return w
}

func TestDashboardSecurityHeaders(t *testing.T) {
	w := getDashboardUI(t, "/ui")
	h := w.Header()
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
		"X-Frame-Options":        "SAMEORIGIN",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, d := range []string{"connect-src 'self'", "img-src 'self' data: blob:", "object-src 'none'", "base-uri 'self'", "frame-ancestors 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, d) {
			t.Errorf("dashboard CSP missing %q: %s", d, csp)
		}
	}
	if strings.Contains(csp, "cdn.jsdelivr.net") || strings.Contains(csp, "connect-src 'self' https:") || strings.Contains(csp, "sandbox") {
		t.Errorf("dashboard CSP is too loose: %s", csp)
	}
}

func TestDashboardCSPPerTool(t *testing.T) {
	apk := getDashboardUI(t, "/ui/apkauditor/").Header().Get("Content-Security-Policy")
	if !strings.Contains(apk, "sandbox allow-scripts") || strings.Contains(apk, "allow-same-origin") {
		t.Errorf("APK auditor page must be sandboxed without allow-same-origin: %s", apk)
	}
	if !strings.Contains(apk, "https://fonts.googleapis.com") {
		t.Errorf("APK auditor CSP must allow Google Fonts: %s", apk)
	}
	// The worker script is not a document; it must not carry the sandbox flag.
	if wk := getDashboardUI(t, "/ui/apkauditor/src/analyzer.worker.js").Header().Get("Content-Security-Policy"); strings.Contains(wk, "sandbox") {
		t.Errorf("worker script CSP should not include sandbox: %s", wk)
	}
	if lab := getDashboardUI(t, "/ui/securitylab/").Header().Get("Content-Security-Policy"); !strings.Contains(lab, "connect-src 'self' https: http:") || strings.Contains(lab, "sandbox") {
		t.Errorf("Security Lab CSP: %s", lab)
	}
}

func TestDashboardVendoredLibsServed(t *testing.T) {
	for _, p := range []string{"/ui/vendor/marked-15.0.12.min.js", "/ui/vendor/purify-3.4.16.min.js"} {
		w := getDashboardUI(t, p)
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
			t.Errorf("%s Content-Type = %q", p, ct)
		}
		if w.Body.Len() < 10000 {
			t.Errorf("%s body too small (%d bytes)", p, w.Body.Len())
		}
	}
}
