package db

// AI usage metering: one row per model call (brain.Usage), written by the
// API layer's usage sink. Cost is frozen at write time from the list price in
// force for that call, so a later price change never rewrites history.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var aiUsageSchemaPG = []string{
	`CREATE TABLE IF NOT EXISTS ai_usage (
		id BIGSERIAL PRIMARY KEY,
		ts BIGINT NOT NULL,
		provider TEXT NOT NULL DEFAULT '',
		model TEXT NOT NULL DEFAULT '',
		feature TEXT NOT NULL DEFAULT '',
		prompt_tokens BIGINT NOT NULL DEFAULT 0,
		cache_hit_tokens BIGINT NOT NULL DEFAULT 0,
		completion_tokens BIGINT NOT NULL DEFAULT 0,
		reasoning_tokens BIGINT NOT NULL DEFAULT 0,
		latency_ms BIGINT NOT NULL DEFAULT 0,
		ok INTEGER NOT NULL DEFAULT 1,
		error TEXT NOT NULL DEFAULT '',
		cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
		priced INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ai_usage_ts ON ai_usage(ts)`,
}

var aiUsageSchemaSQLite = []string{
	`CREATE TABLE IF NOT EXISTS ai_usage (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts BIGINT NOT NULL,
		provider TEXT NOT NULL DEFAULT '',
		model TEXT NOT NULL DEFAULT '',
		feature TEXT NOT NULL DEFAULT '',
		prompt_tokens BIGINT NOT NULL DEFAULT 0,
		cache_hit_tokens BIGINT NOT NULL DEFAULT 0,
		completion_tokens BIGINT NOT NULL DEFAULT 0,
		reasoning_tokens BIGINT NOT NULL DEFAULT 0,
		latency_ms BIGINT NOT NULL DEFAULT 0,
		ok INTEGER NOT NULL DEFAULT 1,
		error TEXT NOT NULL DEFAULT '',
		cost_usd REAL NOT NULL DEFAULT 0,
		priced INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_ai_usage_ts ON ai_usage(ts)`,
}

var (
	aiUsageMu      sync.Mutex
	aiUsageReadyOn DB
)

func aiUsageDB() (triageConn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	var c triageConn
	schema := aiUsageSchemaPG
	switch d := dbInstance.(type) {
	case *PostgresDB:
		c = pgTriage{p: d}
	case *SQLiteDB:
		c, schema = sqliteTriage{s: d}, aiUsageSchemaSQLite
	default:
		return nil, errors.New("ai usage: unsupported backend")
	}
	aiUsageMu.Lock()
	defer aiUsageMu.Unlock()
	if aiUsageReadyOn != dbInstance {
		for _, q := range schema {
			if err := c.exec(q); err != nil {
				return nil, fmt.Errorf("ai usage schema: %w", err)
			}
		}
		aiUsageReadyOn = dbInstance
	}
	return c, nil
}

// AIUsageRow is one metered model call.
type AIUsageRow struct {
	TS               int64
	Provider         string
	Model            string
	Feature          string
	PromptTokens     int64
	CacheHitTokens   int64
	CompletionTokens int64
	ReasoningTokens  int64
	LatencyMS        int64
	OK               bool
	Error            string
	CostUSD          float64
	Priced           bool
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// InsertAIUsage stores one call.
func InsertAIUsage(r AIUsageRow) error {
	c, err := aiUsageDB()
	if err != nil {
		return err
	}
	return c.exec(`INSERT INTO ai_usage (ts, provider, model, feature, prompt_tokens, cache_hit_tokens,
		completion_tokens, reasoning_tokens, latency_ms, ok, error, cost_usd, priced)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.TS, r.Provider, r.Model, r.Feature, r.PromptTokens, r.CacheHitTokens, r.CompletionTokens,
		r.ReasoningTokens, r.LatencyMS, b2i(r.OK), r.Error, r.CostUSD, b2i(r.Priced))
}

// AIUsageTotals aggregates calls over a window.
type AIUsageTotals struct {
	Calls            int64   `json:"calls"`
	Errors           int64   `json:"errors"`
	PromptTokens     int64   `json:"prompt_tokens"`
	CacheHitTokens   int64   `json:"cache_hit_tokens"`
	CompletionTokens int64   `json:"completion_tokens"`
	CostUSD          float64 `json:"cost_usd"`
	UnpricedCalls    int64   `json:"unpriced_calls"` // successful calls with no price (cost understated)
}

// Portable aggregate columns: CAST keeps PG's SUM(bigint)=numeric scannable.
const aiUsageAgg = `COUNT(*),
	CAST(COALESCE(SUM(CASE WHEN ok = 0 THEN 1 ELSE 0 END),0) AS BIGINT),
	CAST(COALESCE(SUM(prompt_tokens),0) AS BIGINT),
	CAST(COALESCE(SUM(cache_hit_tokens),0) AS BIGINT),
	CAST(COALESCE(SUM(completion_tokens),0) AS BIGINT),
	CAST(COALESCE(SUM(cost_usd),0) AS DOUBLE PRECISION),
	CAST(COALESCE(SUM(CASE WHEN priced = 0 AND ok = 1 THEN 1 ELSE 0 END),0) AS BIGINT)`

func scanTotals(r rowScanner, t *AIUsageTotals) error {
	return r.Scan(&t.Calls, &t.Errors, &t.PromptTokens, &t.CacheHitTokens, &t.CompletionTokens, &t.CostUSD, &t.UnpricedCalls)
}

// AIUsageSince totals every call at or after since (unix seconds; 0 = all).
func AIUsageSince(since int64) (AIUsageTotals, error) {
	var t AIUsageTotals
	c, err := aiUsageDB()
	if err != nil {
		return t, err
	}
	err = c.query(`SELECT `+aiUsageAgg+` FROM ai_usage WHERE ts >= ?`, func(r rowScanner) error {
		return scanTotals(r, &t)
	}, since)
	return t, err
}

// AIUsageGroup is a breakdown row (by feature or model).
type AIUsageGroup struct {
	Key string `json:"key"`
	AIUsageTotals
}

// AIUsageBy breaks totals since `since` down by "feature" or "model".
func AIUsageBy(dim string, since int64) ([]AIUsageGroup, error) {
	col := map[string]string{"feature": "feature", "model": "model"}[dim]
	if col == "" {
		return nil, fmt.Errorf("ai usage: unknown dimension %q", dim)
	}
	c, err := aiUsageDB()
	if err != nil {
		return nil, err
	}
	out := []AIUsageGroup{}
	err = c.query(`SELECT `+col+`, `+aiUsageAgg+` FROM ai_usage WHERE ts >= ? GROUP BY `+col+` ORDER BY 7 DESC, 2 DESC`,
		func(r rowScanner) error {
			var g AIUsageGroup
			if err := r.Scan(&g.Key, &g.Calls, &g.Errors, &g.PromptTokens, &g.CacheHitTokens, &g.CompletionTokens, &g.CostUSD, &g.UnpricedCalls); err != nil {
				return err
			}
			out = append(out, g)
			return nil
		}, since)
	return out, err
}

// AIUsageDay is one calendar day in the caller's timezone.
type AIUsageDay struct {
	Day string `json:"day"` // YYYY-MM-DD
	AIUsageTotals
}

// AIUsageDaily returns `days` consecutive days ending today, zero-filled.
// tzOffsetSec is the caller's offset east of UTC (Cairo summer = +10800).
func AIUsageDaily(days int, tzOffsetSec int64, now time.Time) ([]AIUsageDay, error) {
	if days < 1 || days > 366 {
		return nil, fmt.Errorf("ai usage: days out of range")
	}
	c, err := aiUsageDB()
	if err != nil {
		return nil, err
	}
	today := (now.Unix() + tzOffsetSec) / 86400
	first := today - int64(days) + 1
	since := first*86400 - tzOffsetSec
	byDay := map[int64]AIUsageTotals{}
	// The offset is an int64 we computed, inlined so SELECT and GROUP BY
	// share one expression (PG rejects two placeholders as "different").
	dayExpr := fmt.Sprintf("((ts + %d) / 86400)", tzOffsetSec)
	err = c.query(`SELECT `+dayExpr+`, `+aiUsageAgg+` FROM ai_usage WHERE ts >= ? GROUP BY 1`,
		func(r rowScanner) error {
			var d int64
			var t AIUsageTotals
			if err := r.Scan(&d, &t.Calls, &t.Errors, &t.PromptTokens, &t.CacheHitTokens, &t.CompletionTokens, &t.CostUSD, &t.UnpricedCalls); err != nil {
				return err
			}
			byDay[d] = t
			return nil
		}, since)
	if err != nil {
		return nil, err
	}
	out := make([]AIUsageDay, 0, days)
	for d := first; d <= today; d++ {
		out = append(out, AIUsageDay{Day: time.Unix(d*86400, 0).UTC().Format("2006-01-02"), AIUsageTotals: byDay[d]})
	}
	return out, nil
}

// AIUsageFirstTS is when metering recorded its first call (0 = none yet).
func AIUsageFirstTS() (int64, error) {
	c, err := aiUsageDB()
	if err != nil {
		return 0, err
	}
	var ts int64
	err = c.query(`SELECT CAST(COALESCE(MIN(ts),0) AS BIGINT) FROM ai_usage`, func(r rowScanner) error {
		return r.Scan(&ts)
	})
	if err != nil && strings.Contains(err.Error(), "no rows") {
		return 0, nil
	}
	return ts, err
}
