package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func mcpToolText(t *testing.T, res map[string]any) string {
	t.Helper()
	content, ok := res["content"].([]map[string]any)
	if !ok || len(content) == 0 {
		t.Fatalf("no content in tool result: %#v", res)
	}
	return content[0]["text"].(string)
}

func TestMCPReconDorks(t *testing.T) {
	res := mcpCallTool("recon_dorks", map[string]any{"target": "example.com", "severity": "critical"})
	if ie, _ := res["isError"].(bool); ie {
		t.Fatalf("recon_dorks errored: %s", mcpToolText(t, res))
	}
	var out struct {
		Count int `json:"count"`
		Dorks []struct {
			Severity string `json:"severity"`
			Query    string `json:"query"`
			URL      string `json:"url"`
		} `json:"dorks"`
	}
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &out); err != nil {
		t.Fatalf("tool output not JSON: %v", err)
	}
	if out.Count == 0 || len(out.Dorks) == 0 {
		t.Fatal("no critical dorks returned")
	}
	for _, d := range out.Dorks {
		if d.Severity != "critical" {
			t.Fatalf("severity filter leaked: %q", d.Severity)
		}
		if strings.Contains(d.Query, "{T}") || strings.Contains(d.URL, "{T}") {
			t.Fatalf("placeholder not substituted: query=%q url=%q", d.Query, d.URL)
		}
		if !strings.HasPrefix(d.URL, "http") {
			t.Fatalf("dork url is not a URL: %q", d.URL)
		}
	}
}

func TestDorksEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/dorks", apiDorksHandler)

	// Default: severity-grouped legacy shape for the page.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dorks", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var grouped map[string][]struct {
		Title string `json:"title"`
		Query string `json:"query"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &grouped); err != nil {
		t.Fatalf("grouped body not JSON: %v", err)
	}
	if len(grouped["critical"]) == 0 {
		t.Fatal("no critical dorks in grouped response")
	}

	// Full: filtered + target-substituted with built URLs.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/dorks?format=full&target=acme.com&platform=shodan", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("full status %d", w.Code)
	}
	var full struct {
		Count int `json:"count"`
		Dorks []struct {
			Platforms []string `json:"platforms"`
			URL       string   `json:"url"`
		} `json:"dorks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
		t.Fatalf("full body not JSON: %v", err)
	}
	if full.Count == 0 {
		t.Fatal("no shodan dorks returned")
	}
	for _, d := range full.Dorks {
		if strings.Contains(d.URL, "{T}") {
			t.Fatalf("unsubstituted url: %q", d.URL)
		}
	}
}
