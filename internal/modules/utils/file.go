package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
)

// WriteLines writes lines to a file (one per line)
// Creates parent directories if they don't exist.
// After writing, if R2 storage is enabled and the file is non-empty,
// it automatically uploads the file and prints the public URL.
func WriteLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		return err
	}

	// Auto-upload to R2 if enabled and file is non-empty
	if len(lines) > 0 && r2storage.IsEnabled() {
		go uploadResultAsync(path)
	}

	return nil
}

// uploadResultAsync uploads a result file to R2 in the background.
// The R2 key strips the leading "/" and uses the full local path as key.
func uploadResultAsync(path string) {
	// Derive R2 key from the path:
	// Strip absolute prefix up to "new-results" so the key is e.g.
	//   new-results/example.com/subs/subdomains.txt
	r2Key := path
	if idx := strings.Index(path, "new-results/"); idx >= 0 {
		r2Key = path[idx:]
	} else {
		r2Key = strings.TrimPrefix(r2Key, "/")
	}
	r2storage.UploadResultFileAndLog(path, r2Key)
	log.Printf("[R2] ✅ Auto-uploaded result file: %s", path)
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
