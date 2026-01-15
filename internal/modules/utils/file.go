package utils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteLines writes lines to a file (one per line)
// Creates parent directories if they don't exist
func WriteLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	return os.WriteFile(path, []byte(data), 0644)
}

// ReadLines reads lines from a file
func ReadLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	// Remove empty last line if present
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines, nil
}

// WaitForFile waits for a file to exist and have non-zero size
// pollingInterval defaults to 500ms if 0
// timeout defaults to 30 seconds if 0
func WaitForFile(ctx context.Context, path string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	
	pollInterval := 500 * time.Millisecond
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	
	// Create context with timeout if not already set
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for file %s: %w", path, ctx.Err())
		case <-ticker.C:
			info, err := os.Stat(path)
			if err == nil && info.Size() > 0 {
				// File exists and has content
				return nil
			}
		}
	}
}
