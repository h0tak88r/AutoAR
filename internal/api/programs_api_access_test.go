package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// C12: GET /api/scope/programs must not let a viewer force the ~20-minute
// upstream rebuild, and must not show viewers the account owner's H1 stats
// or account labels.
func TestListProgramsViewerCannotRefreshAndIsRedacted(t *testing.T) {
	setupWatchTestDB(t)
	saveProgramsCache(programsCachePayload{
		Programs: []ProgramSummary{{Platform: "h1", Handle: "acme", Name: "Acme",
			Stats:   ProgramStats{ReportsForUser: 7, BountyEarnedForUser: 12345},
			Sources: []string{"owner-account"}}},
		GeneratedAt: time.Now(),
	})
	programsForcedRefreshMu.Lock()
	programsForcedRefreshAt = time.Time{}
	programsForcedRefreshMu.Unlock()

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/scope/programs", func(c *gin.Context) { c.Set("auth_role", "viewer"); c.Next() }, apiListPrograms)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/scope/programs?refresh=true&sort=bounty", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Programs []ProgramSummary `json:"programs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Programs) != 1 {
		t.Fatalf("bad body %s (%v)", w.Body.String(), err)
	}
	p := resp.Programs[0]
	if p.Stats.ReportsForUser != 0 || p.Stats.BountyEarnedForUser != 0 || len(p.Sources) != 0 {
		t.Fatalf("viewer saw private stats/sources: %+v", p)
	}
	programsForcedRefreshMu.Lock()
	forced := !programsForcedRefreshAt.IsZero()
	programsForcedRefreshMu.Unlock()
	if forced {
		t.Fatal("a viewer's ?refresh=true must not trigger a forced rebuild")
	}
}

func TestForcedProgramsRefreshIsRateLimited(t *testing.T) {
	programsForcedRefreshMu.Lock()
	programsForcedRefreshAt = time.Time{}
	programsForcedRefreshMu.Unlock()
	if !allowForcedProgramsRefresh() {
		t.Fatal("first forced refresh must be allowed")
	}
	if allowForcedProgramsRefresh() {
		t.Fatal("a second forced refresh within the min gap must be refused")
	}
}
