package downloader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Colors copied from utils to keep it self-contained
const (
	ColorEnd     = "\033[0m"
	ColorBlue    = "\033[34m"
	ColorGreen   = "\033[32m"
	ColorRed     = "\033[31m"
	ColorYellow  = "\033[33m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorHeader  = "\033[1;30m"
	ColorWarning = "\033[1;33m"
	ColorBold    = "\033[1m"
)

type ApkeepDownloader struct {
	BinaryPath string
	OutputDir  string
}

type DownloadConfig struct {
	PackageName   string
	Version       string
	Source        string // "apk-pure", "google-play", "f-droid", "huawei-app-gallery"
	Email         string // For Google Play
	AAS           string // For Google Play
	OAuthToken    string // For Google Play
	AcceptTOS     bool   // For Google Play
	SleepDuration int    // Sleep between requests
	Parallel      int    // Parallel downloads
}

func NewApkeepDownloader(outputDir string) (*ApkeepDownloader, error) {
	path, err := exec.LookPath("apkeep")
	if err != nil {
		// Try local bin
		if _, err := os.Stat("bin/apkeep"); err == nil {
			path, _ = filepath.Abs("bin/apkeep")
		} else {
			return nil, fmt.Errorf("apkeep not found in PATH or ./bin. Please install it: curl -L https://github.com/EFForg/apkeep/releases/download/0.18.0/apkeep-x86_64-unknown-linux-gnu -o /usr/local/bin/apkeep && chmod +x /usr/local/bin/apkeep")
		}
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	return &ApkeepDownloader{
		BinaryPath: path,
		OutputDir:  outputDir,
	}, nil
}

func (a *ApkeepDownloader) DownloadAPK(config DownloadConfig) (string, error) {
	// Build apkeep command
	args := []string{}

	// Add package name with optional version
	appID := config.PackageName
	if config.Version != "" {
		appID = fmt.Sprintf("%s@%s", config.PackageName, config.Version)
	}
	args = append(args, "-a", appID)

	// Add download source
	if config.Source != "" {
		args = append(args, "-d", config.Source)
	}

	// Add Google Play specific options
	if config.Source == "google-play" {
		if config.Email != "" {
			args = append(args, "-e", config.Email)
		}
		if config.AAS != "" {
			args = append(args, "-t", config.AAS)
		}
		if config.OAuthToken != "" {
			args = append(args, "--oauth-token", config.OAuthToken)
		}
		if config.AcceptTOS {
			args = append(args, "--accept-tos")
		}
	}

	// Add sleep duration
	if config.SleepDuration > 0 {
		args = append(args, "-s", fmt.Sprintf("%d", config.SleepDuration))
	}

	// Add parallel downloads
	if config.Parallel > 0 {
		args = append(args, "-r", fmt.Sprintf("%d", config.Parallel))
	}

	// Add output directory
	args = append(args, a.OutputDir)

	fmt.Printf("%s** Downloading APK: %s from %s...%s\n",
		ColorBlue, config.PackageName, config.Source, ColorEnd)

	// Execute apkeep command
	cmd := exec.Command(a.BinaryPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("apkeep download failed: %v", err)
	}

	// Find the downloaded APK file
	apkPath, err := a.findDownloadedAPK(config.PackageName)
	if err != nil {
		return "", fmt.Errorf("failed to find downloaded APK: %v", err)
	}

	fmt.Printf("%s** APK downloaded successfully: %s%s\n",
		ColorGreen, apkPath, ColorEnd)

	return apkPath, nil
}

func (a *ApkeepDownloader) ListVersions(packageName, source string) ([]string, error) {
	args := []string{
		"-l",              // List versions
		"-a", packageName, // Package name
		"-d", source, // Source
		a.OutputDir, // Output directory (required but not used for listing)
	}

	cmd := exec.Command(a.BinaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %v", err)
	}

	// Parse output to extract versions
	lines := strings.Split(string(output), "\n")
	var versions []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "Downloading") && !strings.Contains(line, "Usage:") {
			versions = append(versions, line)
		}
	}

	return versions, nil
}

func (a *ApkeepDownloader) findDownloadedAPK(packageName string) (string, error) {
	// Look for APK files in the output directory
	entries, err := os.ReadDir(a.OutputDir)
	if err != nil {
		return "", err
	}

	// Find the most recently created APK file
	var latestAPK string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".apk") {
			// Check if this APK is related to our package
			if strings.Contains(entry.Name(), packageName) ||
				strings.Contains(entry.Name(), strings.ReplaceAll(packageName, ".", "_")) {

				info, err := entry.Info()
				if err != nil {
					continue
				}

				if info.ModTime().After(latestTime) {
					latestTime = info.ModTime()
					latestAPK = filepath.Join(a.OutputDir, entry.Name())
				}
			}
		}
	}

	if latestAPK == "" {
		return "", fmt.Errorf("no APK file found for package %s", packageName)
	}

	return latestAPK, nil
}

func (a *ApkeepDownloader) DownloadMultipleAPKs(packages []string, config DownloadConfig) ([]string, error) {
	var downloadedAPKs []string

	for _, packageName := range packages {
		config.PackageName = packageName
		apkPath, err := a.DownloadAPK(config)
		if err != nil {
			fmt.Printf("%sWarning: Failed to download %s: %v%s\n",
				ColorWarning, packageName, err, ColorEnd)
			continue
		}
		downloadedAPKs = append(downloadedAPKs, apkPath)
	}

	return downloadedAPKs, nil
}

// GetDefaultConfig returns a default configuration for apkeep
func GetDefaultConfig() DownloadConfig {
	return DownloadConfig{
		Source:        "apk-pure", // Default to APKPure (no credentials needed)
		SleepDuration: 1000,       // 1 second sleep between requests
		Parallel:      1,          // Single download at a time
	}
}

// GetGooglePlayConfig returns a configuration for Google Play Store
func GetGooglePlayConfig(email, aasToken string) DownloadConfig {
	return DownloadConfig{
		Source:        "google-play",
		Email:         email,
		AAS:           aasToken,
		AcceptTOS:     true,
		SleepDuration: 2000, // 2 seconds sleep for Google Play
		Parallel:      1,
	}
}

// NewDownloadConfig creates a new DownloadConfig with default values
func NewDownloadConfig(packageName, version, source string) DownloadConfig {
	return DownloadConfig{
		PackageName:   packageName,
		Version:       version,
		Source:        source,
		SleepDuration: 1000,
		Parallel:      1,
	}
}
