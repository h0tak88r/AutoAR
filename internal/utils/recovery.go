package utils

import (
	"context"
	"time"
)

// RecoveryStrategy defines how to handle errors
type RecoveryStrategy struct {
	MaxRetries    int
	RetryDelay    time.Duration
	SkipOnFailure bool
	NotifyUser    bool
}

// DefaultRecovery returns default recovery strategy
func DefaultRecovery() RecoveryStrategy {
	return RecoveryStrategy{
		MaxRetries:    3,
		RetryDelay:    2 * time.Second,
		SkipOnFailure: true,
		NotifyUser:    true,
	}
}

// ExecuteWithRecovery executes function with error recovery
func ExecuteWithRecovery(ctx context.Context, strategy RecoveryStrategy, fn func() error) error {
	var lastErr error
	
	for attempt := 1; attempt <= strategy.MaxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Check if retryable
		if !IsRetryable(err) {
			GetLogger().WithError(err).Warn("[RECOVERY] error not retryable")
			break
		}
		
		// Check if should retry
		if attempt < strategy.MaxRetries {
			GetLogger().WithError(err).Warnf("[RECOVERY] attempt %d/%d failed, retrying in %v",
				attempt, strategy.MaxRetries, strategy.RetryDelay)
			
			select {
			case <-time.After(strategy.RetryDelay):
				// Exponential backoff
				strategy.RetryDelay *= 2
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	
	// All retries failed
	if strategy.SkipOnFailure {
		GetLogger().WithError(lastErr).Warnf("[RECOVERY] skipping after %d failed attempts", strategy.MaxRetries)
		return nil // Skip and continue
	}
	
	return lastErr
}
