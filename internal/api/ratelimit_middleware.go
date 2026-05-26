package api

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

func RateLimitMiddleware() gin.HandlerFunc {
	rate := 100
	burst := 200
	if v := strings.TrimSpace(os.Getenv("API_RATE_LIMIT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			rate = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("API_RATE_BURST")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			burst = n
		}
	}

	limiter := utils.InitAPIRateLimiter(rate, burst)

	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}

		clientIP := c.ClientIP()
		if clientIP == "127.0.0.1" || clientIP == "::1" {
			c.Next()
			return
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		if err := limiter.Wait(ctx); err != nil {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		c.Next()
	}
}
