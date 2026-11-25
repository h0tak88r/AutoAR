package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// TestDashboardStatsHidesMonitorDataFromViewers: Monitor is admin-only, so the
// dashboard must not leak its change details / counts to other roles, and the
// subdomain totals come from the aggregate query.
func TestDashboardStatsHidesMonitorDataFromViewers(t *testing.T) {
	withTestSQLite(t)
	gin.SetMode(gin.TestMode)
	resetCache := func() {
		domainCountsCacheMu.Lock()
		domainCountsCache, domainCountsCachedAt = nil, time.Time{} // force a fresh aggregate
		domainCountsCacheMu.Unlock()
	}
	resetCache()
	t.Cleanup(resetCache)
	if _, err := db.InsertOrGetDomain("example.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.BatchInsertSubdomains("example.com", []string{"a.example.com", "b.example.com"}, false); err != nil {
		t.Fatal(err)
	}

	get := func(role string) map[string]any {
		r := gin.New()
		r.GET("/stats", func(c *gin.Context) { c.Set("auth_role", role); apiDashboardStats(c) })
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("role %q: status %d", role, w.Code)
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	viewer := get("viewer")
	for _, k := range []string{"recent_changes", "monitor_targets", "running_monitors"} {
		if _, ok := viewer[k]; ok {
			t.Errorf("viewer response leaks %q", k)
		}
	}
	if viewer["domains"] != float64(1) || viewer["subdomains"] != float64(2) {
		t.Errorf("viewer counts = domains %v subdomains %v, want 1 / 2", viewer["domains"], viewer["subdomains"])
	}
	admin := get("admin")
	for _, k := range []string{"recent_changes", "monitor_targets", "running_monitors"} {
		if _, ok := admin[k]; !ok {
			t.Errorf("admin response is missing %q", k)
		}
	}
}
