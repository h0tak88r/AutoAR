package brain

import (
	"math"
	"testing"
	"time"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-12 }

func TestDeepSeekPeakWindow(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct {
		when string
		peak bool
	}{
		{"2026-10-16T00:59:59Z", false}, // Fri, just before 01:00
		{"2026-10-16T01:00:00Z", true},
		{"2026-10-16T03:59:59Z", true},
		{"2026-10-16T04:00:00Z", false}, // gap 04-06
		{"2026-10-16T06:00:00Z", true},
		{"2026-10-16T09:59:59Z", true},
		{"2026-10-16T10:00:00Z", false},
		{"2026-10-17T07:00:00Z", false}, // Saturday
		{"2026-10-18T02:00:00Z", false}, // Sunday
		{"2026-10-16T09:30:00+03:00", true}, // 06:30Z: offsets are normalised to UTC
	}
	for _, c := range cases {
		if got := DeepSeekPeakAt(at(c.when)); got != c.peak {
			t.Errorf("%s: peak=%v, want %v", c.when, got, c.peak)
		}
	}
}

func TestDeepSeekCostSplitsCacheAndHalvesOffPeak(t *testing.T) {
	peak := time.Date(2026, 10, 16, 7, 0, 0, 0, time.UTC) // Fri 07:00Z
	off := time.Date(2026, 10, 17, 7, 0, 0, 0, time.UTC)  // Sat
	u := Usage{Provider: "deepseek", Model: "deepseek-flash", Time: peak,
		PromptTokens: 1_000_000, CacheHitTokens: 400_000, CompletionTokens: 500_000}
	// 400k hit * 0.006 + 600k miss * 0.30 + 500k out * 1.20 = 0.0024 + 0.18 + 0.6
	usd, ok := cost(u)
	if !ok || !near(usd, 0.7824) {
		t.Fatalf("peak cost = %v (%v), want 0.7824", usd, ok)
	}
	u.Time = off
	if usd, _ := cost(u); !near(usd, 0.3912) {
		t.Fatalf("off-peak cost = %v, want half of peak 0.3912", usd)
	}
	// A cache-hit count above the prompt total must not produce negative misses.
	u.CacheHitTokens = 2_000_000
	if usd, _ := cost(u); usd < 0 {
		t.Fatalf("negative cost %v", usd)
	}
}

func TestCostUnpricedAndProviderReported(t *testing.T) {
	if _, ok := cost(Usage{Provider: "deepseek", Model: "deepseek-chat", PromptTokens: 10}); ok {
		t.Error("a model with no list price must stay unpriced, not guessed")
	}
	if _, ok := cost(Usage{Provider: "zai", Model: "glm-4.5-air", PromptTokens: 10}); ok {
		t.Error("non-DeepSeek providers have no list price")
	}
	if usd, ok := cost(Usage{Provider: "openrouter", CostUSD: 0.0123, Priced: true}); !ok || usd != 0.0123 {
		t.Errorf("provider-reported cost must win, got %v %v", usd, ok)
	}
}

func TestUsageFieldsParsesEachWireFormat(t *testing.T) {
	var u Usage
	Provider{ID: "deepseek"}.usageFields([]byte(`{"choices":[],"usage":{"prompt_tokens":1200,"completion_tokens":300,
		"prompt_cache_hit_tokens":800,"prompt_cache_miss_tokens":400,"completion_tokens_details":{"reasoning_tokens":120}}}`), &u)
	if u.PromptTokens != 1200 || u.CacheHitTokens != 800 || u.CompletionTokens != 300 || u.ReasoningTokens != 120 {
		t.Errorf("deepseek usage parsed as %+v", u)
	}

	u = Usage{}
	Provider{ID: "openrouter"}.usageFields([]byte(`{"usage":{"prompt_tokens":50,"completion_tokens":5,"cost":0.0004,
		"prompt_tokens_details":{"cached_tokens":20}}}`), &u)
	if u.CacheHitTokens != 20 || !u.Priced || u.CostUSD != 0.0004 {
		t.Errorf("openai-style usage parsed as %+v", u)
	}

	u = Usage{}
	Provider{ID: "gemini", gemini: true}.usageFields([]byte(`{"usageMetadata":{"promptTokenCount":90,
		"candidatesTokenCount":10,"cachedContentTokenCount":30,"thoughtsTokenCount":40}}`), &u)
	if u.PromptTokens != 90 || u.CacheHitTokens != 30 || u.CompletionTokens != 50 || u.ReasoningTokens != 40 {
		t.Errorf("gemini usage parsed as %+v (thinking tokens bill as output)", u)
	}

	u = Usage{}
	Provider{ID: "deepseek"}.usageFields([]byte(`not json`), &u)
	if u.PromptTokens != 0 || u.Priced {
		t.Errorf("garbage reply must leave zero usage, got %+v", u)
	}
}

func TestEmitUsageFillsFeatureAndCost(t *testing.T) {
	got := make(chan Usage, 1)
	SetUsageSink(func(u Usage) { got <- u })
	defer SetUsageSink(func(Usage) {})
	emitUsage(Usage{Provider: "deepseek", Model: "deepseek-flash", Time: time.Date(2026, 10, 17, 7, 0, 0, 0, time.UTC),
		PromptTokens: 1_000_000, OK: true})
	select {
	case u := <-got:
		if u.Feature != "other" {
			t.Errorf("unlabelled call should be 'other', got %q", u.Feature)
		}
		if !u.Priced || !near(u.CostUSD, 0.15) { // off-peak cache-miss input
			t.Errorf("cost = %v priced=%v, want 0.15", u.CostUSD, u.Priced)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sink never called")
	}
}
