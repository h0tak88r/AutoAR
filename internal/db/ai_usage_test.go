package db

import (
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAIUsageSQLite(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "usage.db"))
	aiUsageContract(t)
}

// Postgres is what prod runs: SUM(bigint) is numeric there and GROUP BY
// expressions must match exactly, so the same contract runs against a real
// server when AUTOAR_TEST_PG_URL is set.
func TestAIUsagePostgres(t *testing.T) {
	url := os.Getenv("AUTOAR_TEST_PG_URL")
	if url == "" {
		t.Skip("AUTOAR_TEST_PG_URL not set")
	}
	t.Setenv("DB_TYPE", "postgresql")
	t.Setenv("DB_HOST", url)
	aiUsageContract(t)
	if c, err := aiUsageDB(); err == nil {
		_ = c.exec(`DROP TABLE IF EXISTS ai_usage`)
	}
}

func aiUsageContract(t *testing.T) {
	t.Helper()
	t.Setenv("AUTOAR_SILENT", "true")
	SetDB(nil)
	t.Cleanup(func() { SetDB(nil) })
	if c, err := aiUsageDB(); err == nil {
		_ = c.exec(`DELETE FROM ai_usage`)
	} else {
		t.Fatalf("db: %v", err)
	}
	tz := int64(3 * 3600) // Cairo summer
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	rows := []AIUsageRow{
		// 2026-10-17 01:30 local (22:30Z on the 16th): counts toward the 17th locally.
		{TS: time.Date(2026, 10, 16, 22, 30, 0, 0, time.UTC).Unix(), Provider: "deepseek", Model: "deepseek-flash", Feature: "triage",
			PromptTokens: 1000, CacheHitTokens: 600, CompletionTokens: 200, OK: true, CostUSD: 0.01, Priced: true},
		{TS: time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC).Unix(), Provider: "deepseek", Model: "deepseek-flash", Feature: "agent",
			PromptTokens: 500, CompletionTokens: 100, OK: true, CostUSD: 0.02, Priced: true},
		{TS: time.Date(2026, 10, 17, 9, 5, 0, 0, time.UTC).Unix(), Provider: "deepseek", Model: "deepseek-flash", Feature: "agent",
			OK: false, Error: "429"},
		{TS: time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC).Unix(), Provider: "zai", Model: "glm-4.5-air", Feature: "report",
			PromptTokens: 50, CompletionTokens: 5, OK: true},
	}
	for _, r := range rows {
		if err := InsertAIUsage(r); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	all, err := AIUsageSince(0)
	if err != nil {
		t.Fatal(err)
	}
	if all.Calls != 4 || all.Errors != 1 || all.PromptTokens != 1550 || all.CacheHitTokens != 600 ||
		all.CompletionTokens != 305 || math.Abs(all.CostUSD-0.03) > 1e-9 || all.UnpricedCalls != 1 {
		t.Fatalf("all-time totals wrong: %+v", all)
	}

	days, err := AIUsageDaily(10, tz, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) != 10 || days[9].Day != "2026-10-17" || days[0].Day != "2026-10-08" {
		t.Fatalf("day range wrong: first %s last %s (%d)", days[0].Day, days[len(days)-1].Day, len(days))
	}
	if d := days[9]; d.Calls != 3 || math.Abs(d.CostUSD-0.03) > 1e-9 {
		t.Errorf("local 2026-10-17 should hold the 22:30Z call too: %+v", d)
	}
	if d := days[2]; d.Day != "2026-10-10" || d.Calls != 1 {
		t.Errorf("2026-10-10 bucket: %+v", d)
	}
	if days[5].Calls != 0 {
		t.Errorf("empty days must be zero-filled, got %+v", days[5])
	}

	by, err := AIUsageBy("feature", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(by) != 3 || by[0].Key != "agent" || by[0].Calls != 2 || by[0].Errors != 1 {
		t.Fatalf("by feature (cost desc): %+v", by)
	}
	if _, err := AIUsageBy("provider; DROP TABLE ai_usage", 0); err == nil {
		t.Fatal("unknown dimension must be refused, not interpolated")
	}

	first, err := AIUsageFirstTS()
	if err != nil || first != rows[3].TS {
		t.Fatalf("first ts = %d (%v), want %d", first, err, rows[3].TS)
	}
}
