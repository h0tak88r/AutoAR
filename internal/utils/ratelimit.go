package utils

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	rate       int           // tokens per second
	burst      int           // max tokens in bucket
	tokens     int           // current tokens
	lastRefill time.Time     // last refill time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
// rate: number of operations per second
// burst: maximum burst size
func NewRateLimiter(rate, burst int) *RateLimiter {
	return &RateLimiter{
		rate:       rate,
		burst:      burst,
		tokens:     burst,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	for {
		if rl.TryAcquire() {
			return nil
		}

		// Calculate wait time
		waitTime := rl.getWaitTime()
		
		select {
		case <-time.After(waitTime):
			continue
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// TryAcquire attempts to acquire a token without blocking
func (rl *RateLimiter) TryAcquire() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.refill()

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}

	return false
}

// refill adds tokens based on elapsed time
func (rl *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)
	
	// Calculate tokens to add
	tokensToAdd := int(elapsed.Seconds() * float64(rl.rate))
	
	if tokensToAdd > 0 {
		rl.tokens += tokensToAdd
		if rl.tokens > rl.burst {
			rl.tokens = rl.burst
		}
		rl.lastRefill = now
	}
}

// getWaitTime calculates how long to wait for next token
func (rl *RateLimiter) getWaitTime() time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if rl.tokens > 0 {
		return 0
	}

	// Wait for one token to be available
	return time.Second / time.Duration(rl.rate)
}

// APIRateLimiter is a global rate limiter for HTTP API requests.
var (
	APIRateLimiter  *RateLimiter
	rateLimiterOnce sync.Once
)

// InitAPIRateLimiter initializes the API rate limiter.
// rate: requests per second, burst: max burst size.
func InitAPIRateLimiter(rate, burst int) *RateLimiter {
	rateLimiterOnce.Do(func() {
		APIRateLimiter = NewRateLimiter(rate, burst)
	})
	return APIRateLimiter
}

// GetAPIRateLimiter returns the API rate limiter.
func GetAPIRateLimiter() *RateLimiter {
	if APIRateLimiter == nil {
		return InitAPIRateLimiter(100, 200)
	}
	return APIRateLimiter
}
