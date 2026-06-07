package utils

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()
	if cfg.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", cfg.MaxAttempts)
	}
	if cfg.InitialDelay != 1*time.Second {
		t.Errorf("InitialDelay = %v, want 1s", cfg.InitialDelay)
	}
	if cfg.MaxDelay != 30*time.Second {
		t.Errorf("MaxDelay = %v, want 30s", cfg.MaxDelay)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("Multiplier = %f, want 2.0", cfg.Multiplier)
	}
}

func TestNewConcurrentFileUploader(t *testing.T) {
	u := NewConcurrentFileUploader(5)
	if u.maxConcurrent != 5 {
		t.Errorf("maxConcurrent = %d, want 5", u.maxConcurrent)
	}
	if cap(u.semaphore) != 5 {
		t.Errorf("semaphore cap = %d, want 5", cap(u.semaphore))
	}

	// Zero or negative should default to 3
	u2 := NewConcurrentFileUploader(0)
	if u2.maxConcurrent != 3 {
		t.Errorf("maxConcurrent = %d, want 3 (default)", u2.maxConcurrent)
	}

	u3 := NewConcurrentFileUploader(-1)
	if u3.maxConcurrent != 3 {
		t.Errorf("maxConcurrent = %d, want 3 (default)", u3.maxConcurrent)
	}
}

func TestRetryWithBackoffSuccess(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:  2,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	fn := func() error {
		attempts++
		return nil
	}

	err := RetryWithBackoff(context.Background(), cfg, fn)
	if err != nil {
		t.Errorf("RetryWithBackoff() = %v, want nil", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (should succeed on first try)", attempts)
	}
}

func TestRetryWithBackoffAllFailures(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Multiplier:   2.0,
	}

	attempts := 0
	testErr := errors.New("always fails")
	fn := func() error {
		attempts++
		return testErr
	}

	err := RetryWithBackoff(context.Background(), cfg, fn)
	if err == nil {
		t.Fatal("RetryWithBackoff() should return an error")
	}
	if !errors.Is(err, testErr) {
		t.Errorf("RetryWithBackoff() = %v, want %v", err, testErr)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestRetryWithBackoffContextCancel(t *testing.T) {
	cfg := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	fn := func() error {
		attempts++
		cancel() // Cancel after first attempt
		return errors.New("fail")
	}

	err := RetryWithBackoff(ctx, cfg, fn)
	if err == nil {
		t.Fatal("RetryWithBackoff() should return an error when context is cancelled")
	}
}

func TestConcurrentFileUploaderUpload(t *testing.T) {
	uploader := NewConcurrentFileUploader(2)
	files := []string{"a.txt", "b.txt", "c.txt"}

	var mu sync.Mutex
	concurrent := 0
	maxConcurrent := 0

	uploadFunc := func(path string) error {
		mu.Lock()
		concurrent++
		if concurrent > maxConcurrent {
			maxConcurrent = concurrent
		}
		mu.Unlock()

		time.Sleep(5 * time.Millisecond)

		mu.Lock()
		concurrent--
		mu.Unlock()
		return nil
	}

	results := uploader.UploadFiles(context.Background(), files, uploadFunc)

	if len(results) != 3 {
		t.Fatalf("len(results) = %d, want 3", len(results))
	}
	for _, r := range results {
		if !r.Success {
			t.Errorf("upload of %s failed: %v", r.FilePath, r.Error)
		}
	}
	if maxConcurrent > 2 {
		t.Errorf("maxConcurrent = %d, want at most 2", maxConcurrent)
	}
}

func TestConcurrentFileUploaderContextCancel(t *testing.T) {
	uploader := NewConcurrentFileUploader(1)
	ctx, cancel := context.WithCancel(context.Background())

	// Block the single semaphore slot
	uploader.semaphore <- struct{}{}

	files := []string{"blocked.txt"}
	done := make(chan struct{})
	go func() {
		uploader.UploadFiles(ctx, files, func(path string) error {
			return nil
		})
		close(done)
	}()

	cancel()        // Cancel while the goroutine is waiting for semaphore
	<-uploader.semaphore // Release the slot so UploadFiles can observe cancellation

	select {
	case <-done:
		// Success — UploadFiles returned after cancellation
	case <-time.After(500 * time.Millisecond):
		t.Error("UploadFiles did not return within 500ms after context cancellation")
	}
}
