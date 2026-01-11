package utils

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ConcurrentFileUploader handles concurrent file uploads with rate limiting
type ConcurrentFileUploader struct {
	maxConcurrent int
	semaphore     chan struct{}
}

// NewConcurrentFileUploader creates a new concurrent file uploader
func NewConcurrentFileUploader(maxConcurrent int) *ConcurrentFileUploader {
	if maxConcurrent <= 0 {
		maxConcurrent = 3 // Default to 3 concurrent uploads
	}
	return &ConcurrentFileUploader{
		maxConcurrent: maxConcurrent,
		semaphore:     make(chan struct{}, maxConcurrent),
	}
}

// UploadResult contains the result of a file upload
type UploadResult struct {
	FilePath string
	Success  bool
	Error    error
}

// UploadFiles uploads multiple files concurrently
func (u *ConcurrentFileUploader) UploadFiles(
	ctx context.Context,
	files []string,
	uploadFunc func(string) error,
) []UploadResult {
	var wg sync.WaitGroup
	results := make([]UploadResult, len(files))
	
	for i, file := range files {
		wg.Add(1)
		go func(index int, filePath string) {
			defer wg.Done()
			
			// Acquire semaphore (blocks if max concurrent reached)
			select {
			case u.semaphore <- struct{}{}:
				defer func() { <-u.semaphore }() // Release semaphore
			case <-ctx.Done():
				results[index] = UploadResult{
					FilePath: filePath,
					Success:  false,
					Error:    ctx.Err(),
				}
				return
			}
			
			// Perform upload
			err := uploadFunc(filePath)
			results[index] = UploadResult{
				FilePath: filePath,
				Success:  err == nil,
				Error:    err,
			}
		}(i, file)
	}
	
	wg.Wait()
	return results
}

// RetryConfig holds retry configuration
type RetryConfig struct {
	MaxAttempts int
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
	}
}

// RetryWithBackoff retries a function with exponential backoff
func RetryWithBackoff(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	delay := config.InitialDelay
	
	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		// Try the operation
		err := fn()
		if err == nil {
			return nil // Success
		}
		
		lastErr = err
		
		// Don't sleep after last attempt
		if attempt == config.MaxAttempts {
			break
		}
		
		// Log retry attempt
		log.Printf("[RETRY] Attempt %d/%d failed: %v. Retrying in %v...", 
			attempt, config.MaxAttempts, err, delay)
		
		// Wait with context cancellation support
		select {
		case <-time.After(delay):
			// Calculate next delay with exponential backoff
			delay = time.Duration(float64(delay) * config.Multiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		}
	}
	
	return fmt.Errorf("failed after %d attempts: %w", config.MaxAttempts, lastErr)
}
