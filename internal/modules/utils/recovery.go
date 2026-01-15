package utils

import (
	"context"
	"log"
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
			log.Printf("[RECOVERY] Error not retryable: %v", err)
			break
		}
		
		// Check if should retry
		if attempt < strategy.MaxRetries {
			log.Printf("[RECOVERY] Attempt %d/%d failed: %v. Retrying in %v...", 
				attempt, strategy.MaxRetries, err, strategy.RetryDelay)
			
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
		log.Printf("[RECOVERY] Skipping after %d failed attempts: %v", strategy.MaxRetries, lastErr)
		return nil // Skip and continue
	}
	
	return lastErr
}
