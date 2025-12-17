package downloader

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// IPAToolDownloader handles iOS app downloads using ipatool.
// This is vendored from the apkX project so that AutoAR can
// re-use the same workflow.
type IPAToolDownloader struct {
	OutputDir string
}

// IPAToolApp represents an iOS app from ipatool.
type IPAToolApp struct {
	BundleID    string `json:"bundleId"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Size        int64  `json:"size"`
	Price       string `json:"price"`
	Description string `json:"description"`
	Developer   string `json:"developer"`
	Category    string `json:"category"`
	IconURL     string `json:"iconUrl"`
}

// NewIPAToolDownloader creates a new iOS app downloader.
func NewIPAToolDownloader(outputDir string) *IPAToolDownloader {
	return &IPAToolDownloader{
		OutputDir: outputDir,
	}
}

// DownloadApp downloads an iOS app by bundle ID using ipatool.
func (d *IPAToolDownloader) DownloadApp(bundleID, version string) (string, error) {
	// Check if ipatool is available
	if _, err := exec.LookPath("ipatool"); err != nil {
		return "", fmt.Errorf("ipatool not found in PATH: %v", err)
	}

	// Check if we're authenticated, if not, try to authenticate
	if err := d.ensureAuthenticated(); err != nil {
		return "", fmt.Errorf("authentication failed: %v", err)
	}

	// Ensure output directory exists
	if err := os.MkdirAll(d.OutputDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %v", err)
	}

	// Build ipatool command with correct syntax
	args := []string{"download"}

	// Add bundle ID using the correct flag
	args = append(args, "--bundle-identifier", bundleID)

	// Add version if specified
	if version != "" {
		args = append(args, "--external-version-id", version)
	}

	// Add output directory
	args = append(args, "--output", d.OutputDir)

	// Add purchase flag to obtain license if needed
	args = append(args, "--purchase")

	// Add keychain passphrase - use environment variable or default
	keychainPassphrase := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE")
	if keychainPassphrase == "" {
		// Default passphrase used by original apkX
		keychainPassphrase = "sallam@88"
	}

	args = append(args, "--keychain-passphrase", keychainPassphrase)
	args = append(args, "--non-interactive")

	fmt.Printf("Downloading iOS app: %s (version: %s)\n", bundleID, version)
	fmt.Printf("Command: ipatool %s\n", strings.Join(args, " "))

	// Execute ipatool command
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("ipatool command failed with output: %s\n", string(output))
		return "", fmt.Errorf("ipatool download failed: %v, output: %s", err, string(output))
	}

	fmt.Printf("ipatool output: %s\n", string(output))

	// Find the downloaded IPA file
	ipaPath, err := d.findDownloadedIPA(bundleID)
	if err != nil {
		return "", fmt.Errorf("failed to find downloaded IPA: %v", err)
	}

	fmt.Printf("iOS app downloaded successfully: %s\n", ipaPath)
	return ipaPath, nil
}

// SearchApp searches for iOS apps by name using ipatool.
func (d *IPAToolDownloader) SearchApp(query string, limit int) ([]IPAToolApp, error) {
	// Check if ipatool is available
	if _, err := exec.LookPath("ipatool"); err != nil {
		return nil, fmt.Errorf("ipatool not found in PATH: %v", err)
	}

	// Build search command with correct syntax
	args := []string{"search", query}
	if limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", limit))
	}

	// Add keychain passphrase for authentication
	keychainPassphrase := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE")
	if keychainPassphrase == "" {
		keychainPassphrase = "sallam@88"
	}
	args = append(args, "--keychain-passphrase", keychainPassphrase)
	args = append(args, "--non-interactive")

	// Execute ipatool search command
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ipatool search failed: %v, output: %s", err, string(output))
	}

	// Parse JSON output
	var apps []IPAToolApp
	if err := json.Unmarshal(output, &apps); err != nil {
		return nil, fmt.Errorf("failed to parse search results: %v", err)
	}

	return apps, nil
}

// GetAppInfo gets detailed information about an iOS app.
func (d *IPAToolDownloader) GetAppInfo(bundleID string) (*IPAToolApp, error) {
	// Check if ipatool is available
	if _, err := exec.LookPath("ipatool"); err != nil {
		return nil, fmt.Errorf("ipatool not found in PATH: %v", err)
	}

	// Build info command with correct syntax
	args := []string{"info", bundleID}

	// Add keychain passphrase for authentication
	keychainPassphrase := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE")
	if keychainPassphrase == "" {
		keychainPassphrase = "sallam@88"
	}
	args = append(args, "--keychain-passphrase", keychainPassphrase)
	args = append(args, "--non-interactive")

	// Execute ipatool info command
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ipatool info failed: %v, output: %s", err, string(output))
	}

	// Parse JSON output
	var app IPAToolApp
	if err := json.Unmarshal(output, &app); err != nil {
		return nil, fmt.Errorf("failed to parse app info: %v", err)
	}

	return &app, nil
}

// findDownloadedIPA finds the most recently downloaded IPA file for the bundle.
func (d *IPAToolDownloader) findDownloadedIPA(bundleID string) (string, error) {
	entries, err := os.ReadDir(d.OutputDir)
	if err != nil {
		return "", err
	}

	var latestFile string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() {
			fileName := strings.ToLower(entry.Name())
			if strings.HasSuffix(fileName, ".ipa") {
				if strings.Contains(entry.Name(), bundleID) ||
					strings.Contains(entry.Name(), strings.ReplaceAll(bundleID, ".", "_")) ||
					strings.HasPrefix(entry.Name(), bundleID+"_") {

					info, err := entry.Info()
					if err != nil {
						continue
					}

					if info.ModTime().After(latestTime) {
						latestTime = info.ModTime()
						latestFile = filepath.Join(d.OutputDir, entry.Name())
					}
				}
			}
		}
	}

	if latestFile == "" {
		// Fallback: most recent .ipa
		for _, entry := range entries {
			if !entry.IsDir() {
				fileName := strings.ToLower(entry.Name())
				if strings.HasSuffix(fileName, ".ipa") {
					info, err := entry.Info()
					if err != nil {
						continue
					}

					if info.ModTime().After(latestTime) {
						latestTime = info.ModTime()
						latestFile = filepath.Join(d.OutputDir, entry.Name())
					}
				}
			}
		}
	}

	if latestFile == "" {
		return "", fmt.Errorf("no IPA file found for bundle ID %s", bundleID)
	}

	return latestFile, nil
}

// ensureAuthenticated checks if ipatool is authenticated and attempts to authenticate if needed.
func (d *IPAToolDownloader) ensureAuthenticated() error {
	keychainPassphrase := os.Getenv("IPATOOL_KEYCHAIN_PASSPHRASE")
	if keychainPassphrase == "" {
		keychainPassphrase = "sallam@88"
	}

	// Try to get account info to check if we're authenticated.
	args := []string{"auth", "info", "--keychain-passphrase", keychainPassphrase, "--non-interactive"}
	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()

	if err == nil && len(output) > 0 {
		fmt.Printf("Already authenticated with App Store\n")
		return nil
	}

	// If not authenticated, try to authenticate using environment variables.
	return d.authenticateWithEnvVars(keychainPassphrase)
}

// authenticateWithEnvVars attempts to authenticate using environment variables.
func (d *IPAToolDownloader) authenticateWithEnvVars(keychainPassphrase string) error {
	email := os.Getenv("IPATOOL_EMAIL")
	password := os.Getenv("IPATOOL_PASSWORD")

	if email == "" || password == "" {
		return fmt.Errorf("ipatool authentication requires IPATOOL_EMAIL and IPATOOL_PASSWORD environment variables. Please set these in your environment")
	}

	fmt.Printf("Attempting to authenticate with Apple ID: %s\n", email)

	args := []string{"auth", "login", "--email", email, "--password", password}
	args = append(args, "--keychain-passphrase", keychainPassphrase)
	args = append(args, "--non-interactive")

	cmd := exec.Command("ipatool", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("ipatool authentication failed: %v, output: %s", err, string(output))
	}

	fmt.Printf("Successfully authenticated with Apple ID\n")
	return nil
}

