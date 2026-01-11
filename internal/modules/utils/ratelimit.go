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

// DiscordRateLimiter is a global rate limiter for Discord API calls
var (
	DiscordRateLimiter *RateLimiter
	rateLimiterOnce    sync.Once
)

// InitDiscordRateLimiter initializes the Discord rate limiter
// Default: 5 files per second (Discord limit is 50/sec, we use 10% for safety)
func InitDiscordRateLimiter(filesPerSecond int) *RateLimiter {
	rateLimiterOnce.Do(func() {
		if filesPerSecond <= 0 {
			filesPerSecond = 5 // Default
		}
		DiscordRateLimiter = NewRateLimiter(filesPerSecond, filesPerSecond*2)
	})
	return DiscordRateLimiter
}

// GetDiscordRateLimiter returns the Discord rate limiter
func GetDiscordRateLimiter() *RateLimiter {
	if DiscordRateLimiter == nil {
		return InitDiscordRateLimiter(5)
	}
	return DiscordRateLimiter
}
