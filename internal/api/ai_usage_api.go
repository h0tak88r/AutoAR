package api

// AI spend analytics for the Overview page: what every model call cost,
// metered from the provider's own token counts (see brain/usage.go), plus the
// live account balance where the provider exposes one (DeepSeek).

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
)

func init() {
	brain.SetUsageSink(func(u brain.Usage) {
		err := db.InsertAIUsage(db.AIUsageRow{
			TS: u.Time.Unix(), Provider: u.Provider, Model: u.Model, Feature: u.Feature,
			PromptTokens: int64(u.PromptTokens), CacheHitTokens: int64(u.CacheHitTokens),
			CompletionTokens: int64(u.CompletionTokens), ReasoningTokens: int64(u.ReasoningTokens),
			LatencyMS: u.LatencyMS, OK: u.OK, Error: u.Error, CostUSD: u.CostUSD, Priced: u.Priced,
		})
		if err != nil {
			log.Printf("[ai-usage] record failed: %v", err)
		}
	})
}

// Balance lookups are cached briefly: the Overview refreshes often and the
// number only moves when calls are billed.
var balanceCache struct {
	sync.Mutex
	provider string
	at       time.Time
	val      *brain.Balance
	err      string
}

func cachedBalance(ctx context.Context, p brain.Provider) (*brain.Balance, string) {
	balanceCache.Lock()
	defer balanceCache.Unlock()
	if balanceCache.provider == p.ID && time.Since(balanceCache.at) < 60*time.Second {
		return balanceCache.val, balanceCache.err
	}
	b, err := p.Balance(ctx)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	balanceCache.provider, balanceCache.at, balanceCache.val, balanceCache.err = p.ID, time.Now(), b, msg
	return b, msg
}

// apiAIUsage (GET /api/ai/usage?tz=<JS getTimezoneOffset minutes>).
func apiAIUsage(c *gin.Context) {
	// JS getTimezoneOffset is minutes WEST of UTC (Cairo summer = -180).
	tzMin, _ := strconv.Atoi(c.DefaultQuery("tz", "0"))
	if tzMin < -14*60 || tzMin > 14*60 {
		tzMin = 0
	}
	tz := int64(-tzMin) * 60
	now := time.Now()
	todayStart := ((now.Unix()+tz)/86400)*86400 - tz

	windows := map[string]int64{
		"today": todayStart,
		"7d":    now.Add(-7 * 24 * time.Hour).Unix(),
		"30d":   now.Add(-30 * 24 * time.Hour).Unix(),
		"all":   0,
	}
	totals := gin.H{}
	for k, since := range windows {
		t, err := db.AIUsageSince(since)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		totals[k] = t
	}
	daily, err := db.AIUsageDaily(30, tz, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	byFeature, _ := db.AIUsageBy("feature", windows["30d"])
	byModel, _ := db.AIUsageBy("model", windows["30d"])
	first, _ := db.AIUsageFirstTS()

	p := brain.Active()
	resp := gin.H{
		"provider":       gin.H{"id": p.ID, "name": p.Name, "model": p.Model(), "configured": p.Configured()},
		"totals":         totals,
		"daily":          daily,
		"by_feature":     byFeature,
		"by_model":       byModel,
		"tracking_since": first,
	}
	if p.ID == "deepseek" {
		pricing := gin.H{"source": brain.PricingSource, "checked": brain.PricingChecked, "peak_now": brain.DeepSeekPeakAt(now)}
		if price, ok := brain.DeepSeekPrice(p.Model(), now); ok {
			pricing["model"] = p.Model()
			pricing["now"] = price
		}
		resp["pricing"] = pricing
	}
	if p.Configured() {
		b, errMsg := cachedBalance(c.Request.Context(), p)
		resp["balance"], resp["balance_error"] = b, errMsg
	}
	c.JSON(http.StatusOK, resp)
}
