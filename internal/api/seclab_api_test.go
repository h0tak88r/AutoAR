package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMCPSeclabTools(t *testing.T) {
	// ssrf_payloads with a tag filter.
	res := mcpCallTool("ssrf_payloads", map[string]any{"tag": "CORS", "limit": float64(5)})
	if ie, _ := res["isError"].(bool); ie {
		t.Fatalf("ssrf_payloads errored: %s", mcpToolText(t, res))
	}
	var ssrf struct {
		Count    int `json:"count"`
		Payloads []struct {
			Tags  []string `json:"tags"`
			Group string   `json:"group"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &ssrf); err != nil {
		t.Fatalf("ssrf output not JSON: %v", err)
	}
	if ssrf.Count == 0 || ssrf.Count > 5 {
		t.Fatalf("ssrf count=%d", ssrf.Count)
	}

	// xss_payloads filtered by tag + event.
	res = mcpCallTool("xss_payloads", map[string]any{"tag": "svg", "event": "onload", "limit": float64(4)})
	var xss struct {
		Count    int `json:"count"`
		Payloads []struct {
			Tag   string `json:"tag"`
			Event string `json:"event"`
		} `json:"payloads"`
	}
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &xss); err != nil {
		t.Fatalf("xss output not JSON: %v", err)
	}
	if xss.Count == 0 {
		t.Fatal("no xss payloads")
	}
	for _, p := range xss.Payloads {
		if !strings.EqualFold(p.Tag, "svg") {
			t.Fatalf("xss tag leak: %q", p.Tag)
		}
	}

	// takeover_fingerprints dns-only.
	res = mcpCallTool("takeover_fingerprints", map[string]any{"type": "dns", "limit": float64(10)})
	var tko struct {
		Count        int              `json:"count"`
		Fingerprints []map[string]any `json:"fingerprints"`
	}
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &tko); err != nil {
		t.Fatalf("takeover output not JSON: %v", err)
	}
	if tko.Count == 0 {
		t.Fatal("no takeover fingerprints")
	}
	for _, f := range tko.Fingerprints {
		if f["kind"] != "dns" {
			t.Fatalf("takeover kind leak: %v", f["kind"])
		}
	}
}

func TestSeclabEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/seclab/:name", apiSeclabHandler)

	for _, name := range []string{"ssrf", "xss", "takeover-subdomain", "takeover-dns"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/seclab/"+name, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", name, w.Code)
		}
		var v any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatalf("%s: body not JSON: %v", name, err)
		}
	}
	// Unknown dataset -> 404 with the available list.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/seclab/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown dataset status %d", w.Code)
	}
}
