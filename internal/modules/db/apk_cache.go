package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// APKCacheEntry represents a cached APK scan result
type APKCacheEntry struct {
	Hash           string    `json:"hash"`
	Filename       string    `json:"filename"`
	FindingsTable  string    `json:"findings_table"` // Markdown content of findings table
	HTMLReportURL  string    `json:"html_report_url"`
	JSONResultsURL string    `json:"json_results_url"`
	OriginalAPKURL string    `json:"original_apk_url"`
	MITMPatchedURL string    `json:"mitm_patched_url"`
	CreatedAt      time.Time `json:"created_at"`
}

// HashAPKFile calculates SHA256 hash of an APK file
func HashAPKFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetAPKCache retrieves cached APK scan results by hash
func GetAPKCache(hash string) (*APKCacheEntry, error) {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return nil, err
		}
	}

	// Cast to SQLiteDB to access db field
	sqliteDB, ok := dbInstance.(*SQLiteDB)
	if !ok {
		return nil, fmt.Errorf("APK cache only supported with SQLite")
	}

	var entry APKCacheEntry
	var dataJSON string
	var createdAt string

	query := `SELECT hash, data, created_at FROM apk_cache WHERE hash = ? LIMIT 1`
	
	row := sqliteDB.db.QueryRow(query, hash)
	if err := row.Scan(&entry.Hash, &dataJSON, &createdAt); err != nil {
		return nil, err // Not found or error
	}

	// Parse JSON data
	if err := json.Unmarshal([]byte(dataJSON), &entry); err != nil {
		return nil, fmt.Errorf("failed to parse cache data: %w", err)
	}

	// Parse timestamp
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		entry.CreatedAt = t
	}

	log.Printf("[CACHE] Found cached APK: hash=%s, filename=%s, age=%s", 
		hash[:16], entry.Filename, time.Since(entry.CreatedAt).Round(time.Second))

	return &entry, nil
}

// SaveAPKCache saves APK scan results to cache
func SaveAPKCache(entry *APKCacheEntry) error {
	if dbInstance == nil {
		if err := Init(); err != nil {
			return err
		}
	}

	// Cast to SQLiteDB to access db field
	sqliteDB, ok := dbInstance.(*SQLiteDB)
	if !ok {
		return fmt.Errorf("APK cache only supported with SQLite")
	}

	// Serialize entry to JSON
	dataJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to serialize cache entry: %w", err)
	}

	query := `
		INSERT INTO apk_cache (hash, data, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(hash) DO UPDATE SET
			data = excluded.data,
			created_at = excluded.created_at
	`

	if _, err := sqliteDB.db.Exec(query, entry.Hash, string(dataJSON), entry.CreatedAt.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("failed to save APK cache: %w", err)
	}

	log.Printf("[CACHE] Saved APK to cache: hash=%s, filename=%s", entry.Hash[:16], entry.Filename)
	return nil
}
