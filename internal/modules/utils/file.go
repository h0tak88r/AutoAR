package utils

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/h0tak88r/AutoAR/internal/modules/db"
	"github.com/h0tak88r/AutoAR/internal/modules/r2storage"
)

// WriteLines writes lines to a file (one per line)
// Creates parent directories if they don't exist.
// After writing, if R2 storage is enabled and the file is non-empty,
// it automatically uploads the file and prints the public URL.
func WriteLines(path string, lines []string) error {
	_, err := WriteResultText(path, lines)
	return err
}

// WriteFile writes raw bytes to a file.
// After writing, if R2 storage is enabled and the file is non-empty,
// it automatically uploads the file to R2 using the same key rules as WriteLines.
func WriteFile(path string, data []byte) error {
	_, err := WriteResultBytes(path, data)
	return err
}

// WriteResultText writes text lines and returns indexed artifact metadata.
func WriteResultText(path string, lines []string) (*db.ScanArtifact, error) {
	data := strings.Join(lines, "\n")
	if len(lines) > 0 {
		data += "\n"
	}
	lineCount := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			lineCount++
		}
	}
	return writeAndIndexResult(path, []byte(data), lineCount, "text/plain; charset=utf-8")
}

// AppendResultLine appends a single text line and indexes the resulting artifact.
func AppendResultLine(path, line string) (*db.ScanArtifact, error) {
	existing, _ := os.ReadFile(path) // best effort
	appendData := []byte(line)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		appendData = append([]byte("\n"), appendData...)
	}
	appendData = append(appendData, '\n')
	merged := append(existing, appendData...)
	return WriteResultBytes(path, merged)
}

// WriteResultBytes writes bytes and returns indexed artifact metadata.
func WriteResultBytes(path string, data []byte) (*db.ScanArtifact, error) {
	contentType := detectContentType(path, data)
	lineCount := 0
	if isTextContent(contentType, data) {
		lineCount = countNonEmptyLines(data)
	}
	return writeAndIndexResult(path, data, lineCount, contentType)
}

// IndexExistingResultFile uploads and indexes an already-written result file.
// Useful for tool outputs that were produced outside WriteResult* wrappers.
func IndexExistingResultFile(scanID, path string) (*db.ScanArtifact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() || info.Size() == 0 {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	contentType := detectContentType(path, data)
	lineCount := 0
	if isTextContent(contentType, data) {
		lineCount = countNonEmptyLines(data)
	}

	artifact := &db.ScanArtifact{
		ScanID:      strings.TrimSpace(scanID),
		FileName:    filepath.Base(path),
		LocalPath:   path,
		SizeBytes:   info.Size(),
		LineCount:   lineCount,
		ContentType: contentType,
		CreatedAt:   info.ModTime().UTC(),
	}
	if r2storage.IsEnabled() {
		artifact.R2Key = toR2Key(path)
		artifact.PublicURL = r2storage.UploadResultFileAndLog(path, artifact.R2Key)
	}
	if artifact.ScanID != "" && artifact.PublicURL != "" {
		if err := db.AppendScanArtifact(artifact); err != nil {
			return nil, err
		}
	}
	return artifact, nil
}

func writeAndIndexResult(path string, data []byte, lineCount int, contentType string) (*db.ScanArtifact, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return nil, err
	}

	info, _ := os.Stat(path)
	size := int64(len(data))
	modified := time.Now().UTC()
	if info != nil {
		size = info.Size()
		modified = info.ModTime().UTC()
	}

	scanID := strings.TrimSpace(os.Getenv("AUTOAR_CURRENT_SCAN_ID"))
	artifact := &db.ScanArtifact{
		ScanID:      scanID,
		FileName:    filepath.Base(path),
		LocalPath:   path,
		SizeBytes:   size,
		LineCount:   lineCount,
		ContentType: contentType,
		CreatedAt:   modified,
	}

	if len(data) > 0 && r2storage.IsEnabled() {
		artifact.R2Key = toR2Key(path)
		artifact.PublicURL = r2storage.UploadResultFileAndLog(path, artifact.R2Key)
	}

	// Persist artifact index for scan UI when scan id and uploaded URL are available.
	if scanID != "" && artifact.PublicURL != "" {
		if err := db.AppendScanArtifact(artifact); err != nil {
			log.Printf("[R2] failed to index artifact for scan %s: %v", scanID, err)
		}
	}

	return artifact, nil
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

func toR2Key(path string) string {
	r2Key := path
	if idx := strings.Index(path, "new-results/"); idx >= 0 {
		r2Key = path[idx:]
	} else {
		r2Key = strings.TrimPrefix(r2Key, "/")
	}
	return r2Key
}

func detectContentType(path string, data []byte) string {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != "" {
		if byExt := mime.TypeByExtension(ext); byExt != "" {
			return byExt
		}
	}
	if len(data) == 0 {
		return "application/octet-stream"
	}
	sniff := data
	if len(sniff) > 512 {
		sniff = sniff[:512]
	}
	return http.DetectContentType(sniff)
}

func isTextContent(contentType string, data []byte) bool {
	if strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") || strings.Contains(contentType, "yaml") {
		return true
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	return utf8.Valid(data)
}

func countNonEmptyLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	lines := strings.Split(string(data), "\n")
	n := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
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
