package utils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
)

// GetResultsDir returns the results directory path
// Normalizes absolute paths at root (like /new-results) to relative paths when not in Docker
func GetResultsDir() string {
	dir := os.Getenv("AUTOAR_RESULTS_DIR")
	if dir == "" {
		return "new-results"
	}

	// Normalize absolute paths at root when not in Docker
	if filepath.IsAbs(dir) && !strings.HasPrefix(dir, "/app") {
		// Check if we're in Docker
		isDocker := false
		if _, err := os.Stat("/app"); err == nil {
			if err := os.MkdirAll("/app", 0755); err == nil {
				testPath := "/app/.test-write"
				if f, err := os.Create(testPath); err == nil {
					f.Close()
					os.Remove(testPath)
					isDocker = true
				}
			}
		}
		
		// If not in Docker and path is absolute (like /new-results), convert to relative
		if !isDocker {
			if cwd, err := os.Getwd(); err == nil {
				return filepath.Join(cwd, "new-results")
	}
	return "new-results"
		}
	}

	return dir
}

// ResultsDir returns the results directory for a specific domain
func ResultsDir(domain string) string {
	return filepath.Join(GetResultsDir(), domain)
}

// EnsureDir creates a directory if it doesn't exist
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// DomainDirInit creates and returns the domain results directory structure
func DomainDirInit(domain string) (string, error) {
	dir := ResultsDir(domain)
	subsDir := filepath.Join(dir, "subs")
	urlsDir := filepath.Join(dir, "urls")
	vulnsDir := filepath.Join(dir, "vulnerabilities", "js")
	
	if err := EnsureDir(subsDir); err != nil {
		return "", err
	}
	if err := EnsureDir(urlsDir); err != nil {
		return "", err
	}
	if err := EnsureDir(vulnsDir); err != nil {
		return "", err
	}
	
	return dir, nil
}

// CleanupDomainResults removes domain results directory (Docker mode only)
func CleanupDomainResults(domain string, force bool) error {
	if os.Getenv("AUTOAR_ENV") != "docker" && !force {
		return nil
	}
	
	dir := ResultsDir(domain)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	
	return os.RemoveAll(dir)
}

// IsDiscordBotAvailable checks if Discord bot is available
func IsDiscordBotAvailable() bool {
	env := os.Getenv("AUTOAR_ENV")
	token := os.Getenv("DISCORD_BOT_TOKEN")
	return env == "docker" && token != ""
}

// DetectEnvironment detects if running in Docker or local
func DetectEnvironment() string {
	if _, err := os.Stat("/app/main.sh"); err == nil {
		return "docker"
	}
	return "local"
}

// GetRootDir returns the AutoAR root directory
func GetRootDir() string {
	if env := DetectEnvironment(); env == "docker" {
		return "/app"
	}
	
	// Try to find from current working directory
	if cwd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(cwd, "modules")); err == nil {
			return cwd
		}
	}
	
	// Try executable directory
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(exeDir, "modules")); err == nil {
			return exeDir
		}
	}
	
	return "."
}

// URLSlug creates a URL slug (hash)
func URLSlug(url string) string {
	// Simple implementation - in production, use crypto/sha1
	return strings.ReplaceAll(url, "/", "_")
}

// CleanupResultsDirectory removes all contents of the results directory
// It removes all files and subdirectories but keeps the results directory itself
func CleanupResultsDirectory() error {
	resultsDir := GetResultsDir()
	
	// Check if directory exists
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		// Directory doesn't exist, nothing to clean
		return nil
	}
	
	// Read all entries in the directory
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		return fmt.Errorf("failed to read results directory: %w", err)
	}
	
	// Remove each entry
	for _, entry := range entries {
		entryPath := filepath.Join(resultsDir, entry.Name())
		if err := os.RemoveAll(entryPath); err != nil {
			return fmt.Errorf("failed to remove %s: %w", entryPath, err)
		}
	}
	
	return nil
}

// UploadResultsToR2 uploads domain results to R2 and optionally removes local files
// domain: the domain name (e.g., "example.com")
// removeLocal: if true, removes local files after successful upload
// Returns map of local file path -> R2 URL, or error
func UploadResultsToR2(domain string, removeLocal bool) (map[string]string, error) {
	if !r2storage.IsEnabled() {
		return nil, fmt.Errorf("R2 storage is not enabled")
	}

	resultsPath := ResultsDir(domain)
	
	// Check if directory exists
	if _, err := os.Stat(resultsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("results directory does not exist: %s", resultsPath)
	}

	log.Printf("[R2] 📤 Uploading results for %s to R2...", domain)
	urls, err := r2storage.UploadResultsDirectory(domain, resultsPath, removeLocal)
	if err != nil {
		return nil, fmt.Errorf("failed to upload results to R2: %w", err)
	}

	log.Printf("[R2] ✅ Successfully uploaded %d files for %s to R2", len(urls), domain)
	return urls, nil
}

// ShouldUseR2ForResults checks if R2 should be used as primary storage for results
// This is determined by the USE_R2_STORAGE environment variable
func ShouldUseR2ForResults() bool {
	return r2storage.IsEnabled() && os.Getenv("USE_R2_STORAGE") == "true"
}
