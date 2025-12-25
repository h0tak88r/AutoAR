package downloader

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/utils"
)

// ApkeepDownloader wraps the apkeep CLI to download Android APKs by package.
// This is vendored from the apkX project so that AutoAR can reuse the same
// behavior.
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
	SleepDuration int    // Sleep between requests (ms)
	Parallel      int    // Parallel downloads
}

func NewApkeepDownloader(outputDir string) (*ApkeepDownloader, error) {
	path, err := exec.LookPath("apkeep")
	if err != nil {
		return nil, fmt.Errorf("apkeep not found in PATH. Please install it: cargo install apkeep")
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	return &ApkeepDownloader{
		BinaryPath: path,
		OutputDir:  outputDir,
	}, nil
}

// DownloadAPK downloads a single APK using apkeep.
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
		utils.ColorBlue, config.PackageName, config.Source, utils.ColorEnd)

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
		utils.ColorGreen, apkPath, utils.ColorEnd)

	return apkPath, nil
}

// findDownloadedAPK finds the newest APK file related to the package.
func (a *ApkeepDownloader) findDownloadedAPK(packageName string) (string, error) {
	entries, err := os.ReadDir(a.OutputDir)
	if err != nil {
		return "", err
	}

	var latestAPK string
	var latestTime time.Time

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".apk") {
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

// GetDefaultConfig returns a default configuration for apkeep.
func GetDefaultConfig() DownloadConfig {
	return DownloadConfig{
		Source:        "apk-pure", // Default to APKPure (no credentials needed)
		SleepDuration: 1000,
		Parallel:      1,
	}
}

