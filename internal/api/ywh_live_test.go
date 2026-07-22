package api

import (
	"os"
	"testing"
)

// Live smoke test — only runs when YWH_TEST_TOKEN is set. Confirms the native
// YWH fetcher returns programs against the real API.
func TestFetchYWHProgramsLive(t *testing.T) {
	tok := os.Getenv("YWH_TEST_TOKEN")
	if tok == "" {
		t.Skip("set YWH_TEST_TOKEN to run")
	}
	progs, err := fetchYWHProgramsWithToken(tok, true, false)
	if err != nil {
		t.Fatalf("fetch err: %v", err)
	}
	t.Logf("fetched %d YWH bounty programs", len(progs))
	if len(progs) == 0 {
		t.Fatalf("expected >0 programs")
	}
	for i := 0; i < len(progs) && i < 3; i++ {
		t.Logf("  [%d] handle=%s url=%s scopes=%d", i, progs[i].Handle, progs[i].URL, progs[i].ScopeTargets)
	}
}
