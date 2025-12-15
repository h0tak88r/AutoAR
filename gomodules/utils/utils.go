package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GetResultsDir returns the results directory path
func GetResultsDir() string {
	if dir := os.Getenv("AUTOAR_RESULTS_DIR"); dir != "" {
		return dir
	}
	return "new-results"
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
