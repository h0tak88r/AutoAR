package api

import (
	"strings"
	"testing"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// B5: the race/nuclei scope tag matches exact hosts and wildcards (never a
// registrable root), lets out-of-scope entries win, and says "⏸ program
// paused" for programs not accepting submissions.
func TestRaceScopeTagHostLevelAndPaused(t *testing.T) {
	setupWatchTestDB(t)
	if err := db.ReplaceCatalogSource("h1", []db.CatalogSourceProgram{
		{Program: db.CatalogProgram{Handle: "acme", Company: "Acme"}, Domains: []db.CatalogDomain{
			{Domain: "app.acme.com", InScope: true},
			{Domain: "status.acme.com", InScope: false},
		}},
		{Program: db.CatalogProgram{Handle: "wild", Company: "Wild"}, Domains: []db.CatalogDomain{
			{Domain: "*.wild.io", InScope: true},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"app.acme.com":    "🟢 IN SCOPE — h1 `acme`",
		"status.acme.com": "🔴 catalog OOS — h1 `acme`",
		"x.acme.com":      "⚪ no program match",
		"api.wild.io":     "🟢 IN SCOPE — h1 `wild`",
	}
	for host, want := range cases {
		if got := raceScopeTag(raceProgramsForHost(host)); got != want {
			t.Errorf("tag(%s) = %q, want %q", host, got, want)
		}
	}
	// Pause the program via the watch's pause map.
	programWatchPauseDiff([]ProgramSummary{{Platform: "h1", Handle: "acme", SubmissionState: "open"}}, time.Now())
	programWatchPauseDiff([]ProgramSummary{{Platform: "h1", Handle: "acme", SubmissionState: "paused"}}, time.Now())
	if got := raceScopeTag(raceProgramsForHost("app.acme.com")); !strings.HasPrefix(got, "⏸ program paused — h1 `acme`") {
		t.Errorf("paused program tag = %q", got)
	}
}
