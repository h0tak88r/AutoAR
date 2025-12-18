package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ApkPureClient implements APK download from ApkPure using their API endpoint
// (same approach as apkeep Rust tool) instead of scraping HTML.
type ApkPureClient struct {
	apiURL     string
	httpClient *http.Client
	// Regex to extract download URL from API response: (X?APKJ)..(https://...)
	downloadURLRegex *regexp.Regexp
}

// NewApkPureClient creates a new client using the ApkPure API endpoint
// (same as apkeep Rust tool) to avoid HTML scraping and 403 errors.
func NewApkPureClient() (*ApkPureClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	
	// Regex pattern from apkeep: matches (X?APKJ)..(https://...)
	// In Rust, ".." means exactly two characters, in Go we use ".{2}"
	downloadRegex, err := regexp.Compile(`(X?APKJ).{2}(https?://(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile download URL regex: %w", err)
	}
	
	return &ApkPureClient{
		apiURL: "https://api.pureapk.com/m/v3/cms/app_version?hl=en-US&package_name=",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Jar:     jar,
		},
		downloadURLRegex: downloadRegex,
	}, nil
}

// DownloadAPKByPackage uses the ApkPure API to get the download URL for the given
// package name, then downloads and saves the APK into destDir.
// It returns the absolute path to the downloaded APK.
func (c *ApkPureClient) DownloadAPKByPackage(ctx context.Context, packageName, destDir string) (string, error) {
	if strings.TrimSpace(packageName) == "" {
		return "", fmt.Errorf("package name is required")
	}

	if destDir == "" {
		destDir = os.TempDir()
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create dest dir: %w", err)
	}

	// Call the API endpoint (same as apkeep)
	apiURL := c.apiURL + packageName
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create API request: %w", err)
	}

	// Set API headers (same as apkeep)
	req.Header.Set("x-cv", "3172501")
	req.Header.Set("x-sv", "29")
	req.Header.Set("x-abis", "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64")
	req.Header.Set("x-gp", "1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected API status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read API response: %w", err)
	}

	// Extract download URL using regex (same pattern as apkeep)
	matches := c.downloadURLRegex.FindStringSubmatch(string(body))
	if len(matches) < 3 {
		return "", fmt.Errorf("could not find download URL in API response for package %q", packageName)
	}

	apkType := matches[1] // "APK" or "XAPKJ"
	downloadURL := matches[2]

	// Determine file extension
	ext := "apk"
	if apkType == "XAPKJ" {
		ext = "xapk"
	}

	// Build a safe filename based on package name.
	base := strings.ReplaceAll(packageName, ".", "_")
	if base == "" {
		base = "app"
	}
	outPath := filepath.Join(destDir, base+"."+ext)

	// Download the APK
	dlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create download request: %w", err)
	}

	dlResp, err := c.httpClient.Do(dlReq)
	if err != nil {
		return "", fmt.Errorf("download request failed: %w", err)
	}
	defer dlResp.Body.Close()

	if dlResp.StatusCode < 200 || dlResp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status downloading APK: %s", dlResp.Status)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, dlResp.Body); err != nil {
		return "", fmt.Errorf("failed to write APK: %w", err)
	}

	return outPath, nil
}


