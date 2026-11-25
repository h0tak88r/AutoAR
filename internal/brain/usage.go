package brain

// Metering: every model call made through Provider.Chat reports one Usage
// event to the registered sink (the API layer stores it). Token counts come
// from the provider's own usage block, never from estimating prompt length.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Usage is one model call as the provider billed it.
type Usage struct {
	Time             time.Time
	Provider         string
	Model            string
	Feature          string // triage | agent | report | validate | monitor | test | other
	PromptTokens     int    // all input tokens, cache hits included
	CacheHitTokens   int    // input tokens served from the provider's prompt cache
	CompletionTokens int    // all output tokens, reasoning included
	ReasoningTokens  int
	LatencyMS        int64
	OK               bool
	Error            string
	CostUSD          float64 // 0 when unpriced
	Priced           bool    // CostUSD came from a list price or the provider itself
}

var usageSink atomic.Value // func(Usage)

// SetUsageSink registers where Usage events go. The sink runs on its own
// goroutine so storage never adds latency to (or fails) a model call.
func SetUsageSink(fn func(Usage)) { usageSink.Store(fn) }

func emitUsage(u Usage) {
	fn, _ := usageSink.Load().(func(Usage))
	if fn == nil {
		return
	}
	if u.Feature == "" {
		u.Feature = "other"
	}
	u.CostUSD, u.Priced = cost(u)
	go func() {
		defer func() { _ = recover() }()
		fn(u)
	}()
}

// usageFields pulls token counts and any provider-reported cost out of a raw
// reply. Missing fields stay zero; a reply without a usage block is still a
// call (it is recorded with zero tokens).
func (p Provider) usageFields(raw []byte, u *Usage) {
	if p.gemini {
		var r struct {
			UsageMetadata struct {
				PromptTokenCount        int `json:"promptTokenCount"`
				CandidatesTokenCount    int `json:"candidatesTokenCount"`
				CachedContentTokenCount int `json:"cachedContentTokenCount"`
				ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
			} `json:"usageMetadata"`
		}
		if json.Unmarshal(raw, &r) == nil {
			m := r.UsageMetadata
			u.PromptTokens = m.PromptTokenCount
			u.CacheHitTokens = m.CachedContentTokenCount
			// Gemini bills thinking tokens as output but reports them apart.
			u.CompletionTokens = m.CandidatesTokenCount + m.ThoughtsTokenCount
			u.ReasoningTokens = m.ThoughtsTokenCount
		}
		return
	}
	var r struct {
		Usage struct {
			PromptTokens         int     `json:"prompt_tokens"`
			CompletionTokens     int     `json:"completion_tokens"`
			PromptCacheHitTokens int     `json:"prompt_cache_hit_tokens"` // DeepSeek
			Cost                 float64 `json:"cost"`                    // OpenRouter
			PromptTokensDetails  struct {
				CachedTokens int `json:"cached_tokens"` // OpenAI-style
			} `json:"prompt_tokens_details"`
			CompletionTokensDetails struct {
				ReasoningTokens int `json:"reasoning_tokens"`
			} `json:"completion_tokens_details"`
		} `json:"usage"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return
	}
	u.PromptTokens = r.Usage.PromptTokens
	u.CompletionTokens = r.Usage.CompletionTokens
	u.CacheHitTokens = max(r.Usage.PromptCacheHitTokens, r.Usage.PromptTokensDetails.CachedTokens)
	u.ReasoningTokens = r.Usage.CompletionTokensDetails.ReasoningTokens
	if r.Usage.Cost > 0 {
		u.CostUSD, u.Priced = r.Usage.Cost, true
	}
}

// Price is a list price in USD per 1M tokens.
type Price struct {
	CacheHit  float64 `json:"cache_hit"`
	CacheMiss float64 `json:"cache_miss"`
	Output    float64 `json:"output"`
}

// PricingSource is where the DeepSeek list prices below were read.
const (
	PricingSource  = "https://api-docs.deepseek.com/quick_start/pricing"
	PricingChecked = "2026-10-17"
)

// deepseekPeak holds DeepSeek's PEAK list prices; off-peak is exactly half.
// The retired v4-flash names are still accepted and billed at Flash price.
var deepseekPeak = map[string]Price{
	"deepseek-flash":               {CacheHit: 0.006, CacheMiss: 0.30, Output: 1.20},
	"deepseek-v4-flash":            {CacheHit: 0.006, CacheMiss: 0.30, Output: 1.20},
	"deepseek-v4-flash-vision-exp": {CacheHit: 0.006, CacheMiss: 0.30, Output: 1.20},
	"deepseek-v4-pro":              {CacheHit: 0.044, CacheMiss: 1.32, Output: 3.96},
}

// DeepSeekPeakAt reports whether t falls in DeepSeek's peak window:
// 01:00-04:00 and 06:00-10:00 UTC, Monday to Friday. Chinese public holidays
// are also off-peak; they are not modelled, so a holiday call is priced at
// peak (the estimate errs high, never low).
func DeepSeekPeakAt(t time.Time) bool {
	t = t.UTC()
	if wd := t.Weekday(); wd == time.Saturday || wd == time.Sunday {
		return false
	}
	h := t.Hour()
	return (h >= 1 && h < 4) || (h >= 6 && h < 10)
}

// DeepSeekPrice returns the list price that applies to model at time t.
func DeepSeekPrice(model string, t time.Time) (Price, bool) {
	p, ok := deepseekPeak[strings.ToLower(strings.TrimSpace(model))]
	if !ok {
		return Price{}, false
	}
	if !DeepSeekPeakAt(t) {
		p = Price{CacheHit: p.CacheHit / 2, CacheMiss: p.CacheMiss / 2, Output: p.Output / 2}
	}
	return p, true
}

// cost prices one call. A provider-reported cost (OpenRouter) wins; DeepSeek
// models use the list price for the call's time; anything else is unpriced.
func cost(u Usage) (float64, bool) {
	if u.Priced {
		return u.CostUSD, true
	}
	if u.Provider != "deepseek" {
		return 0, false
	}
	p, ok := DeepSeekPrice(u.Model, u.Time)
	if !ok {
		return 0, false
	}
	hit := min(u.CacheHitTokens, u.PromptTokens)
	miss := u.PromptTokens - hit
	usd := (float64(hit)*p.CacheHit + float64(miss)*p.CacheMiss + float64(u.CompletionTokens)*p.Output) / 1e6
	return usd, true
}

// Balance is the provider account's remaining credit.
type Balance struct {
	Available bool          `json:"available"`
	Infos     []BalanceInfo `json:"infos"`
}

// BalanceInfo is one currency's balance, as decimal strings from the provider.
type BalanceInfo struct {
	Currency string `json:"currency"`
	Total    string `json:"total"`
	Granted  string `json:"granted"`
	ToppedUp string `json:"topped_up"`
}

// ErrNoBalanceAPI means the provider has no balance endpoint we support.
var ErrNoBalanceAPI = errors.New("provider has no balance API")

// Balance reads the account balance (DeepSeek GET /user/balance).
func (p Provider) Balance(ctx context.Context) (*Balance, error) {
	if p.ID != "deepseek" {
		return nil, ErrNoBalanceAPI
	}
	key := p.Key()
	if key == "" {
		return nil, fmt.Errorf("%w: %s has no API key", errNotConfigured, p.Name)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.deepseek.com/user/balance", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, scrubKey(err, key)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, statusError(resp.StatusCode, raw)
	}
	var r struct {
		IsAvailable  bool `json:"is_available"`
		BalanceInfos []struct {
			Currency        string `json:"currency"`
			TotalBalance    string `json:"total_balance"`
			GrantedBalance  string `json:"granted_balance"`
			ToppedUpBalance string `json:"topped_up_balance"`
		} `json:"balance_infos"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("unreadable balance response: %w", err)
	}
	b := &Balance{Available: r.IsAvailable}
	for _, i := range r.BalanceInfos {
		b.Infos = append(b.Infos, BalanceInfo{Currency: i.Currency, Total: i.TotalBalance, Granted: i.GrantedBalance, ToppedUp: i.ToppedUpBalance})
	}
	return b, nil
}
