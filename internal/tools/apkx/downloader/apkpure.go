package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// ApkPureClient implements a minimal subset of the original Python ApkPure
// helper: search by package name, resolve the detail page, and follow the
// fast-download link to obtain the final APK download URL.
type ApkPureClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewApkPureClient creates a new client with sane defaults.
func NewApkPureClient() *ApkPureClient {
	return &ApkPureClient{
		baseURL: "https://apkpure.com",
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// DownloadAPKByPackage searches ApkPure for the given package name,
// resolves the download URL, and saves the APK into destDir.
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

	detailPath, err := c.findDetailPath(ctx, packageName)
	if err != nil {
		return "", err
	}

	downloadURL, ext, err := c.resolveDownloadURL(ctx, detailPath)
	if err != nil {
		return "", err
	}

	// Build a safe filename based on package name.
	base := strings.ReplaceAll(packageName, ".", "_")
	if base == "" {
		base = "app"
	}
	if ext == "" {
		ext = "apk"
	}

	outPath := filepath.Join(destDir, base+"."+ext)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "AutoAR-apkx/1.0 (+https://github.com/h0tak88r/AutoAR)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected status downloading APK: %s", resp.Status)
	}

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", fmt.Errorf("failed to write APK: %w", err)
	}

	return outPath, nil
}

// findDetailPath performs a search on ApkPure and returns the first
// detail page URL that looks like it matches the given package name.
func (c *ApkPureClient) findDetailPath(ctx context.Context, pkg string) (string, error) {
	searchURL := c.baseURL + "/search?q=" + url.QueryEscape(pkg)

	doc, err := c.fetchDocument(ctx, searchURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch search results: %w", err)
	}

	var candidate string

	doc.Find("div#search-res dl.search-dl").EachWithBreak(func(i int, s *goquery.Selection) bool {
		a := s.Find("dt a").First()
		if a.Length() == 0 {
			return true // continue
		}
		href, ok := a.Attr("href")
		if !ok {
			return true
		}

		// Prefer results where the href contains the package name.
		if strings.Contains(strings.ToLower(href), strings.ToLower(pkg)) {
			candidate = href
			return false // break
		}

		// Fallback: remember the first result if nothing else matches.
		if candidate == "" {
			candidate = href
		}

		return true
	})

	if candidate == "" {
		return "", fmt.Errorf("no search results found on ApkPure for %q", pkg)
	}

	return candidate, nil
}

// resolveDownloadURL follows the ApkPure detail page and fast-download page
// to obtain the final download URL and file extension.
func (c *ApkPureClient) resolveDownloadURL(ctx context.Context, detailPath string) (string, string, error) {
	detailURL := detailPath
	if !strings.HasPrefix(detailURL, "http://") && !strings.HasPrefix(detailURL, "https://") {
		detailURL = c.baseURL + detailPath
	}

	doc, err := c.fetchDocument(ctx, detailURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch detail page: %w", err)
	}

	box := doc.Find("div.box").First()
	if box.Length() == 0 {
		return "", "", fmt.Errorf("could not find app detail box on page")
	}

	nyDown := box.Find("div.ny-down").First()
	if nyDown.Length() == 0 {
		return "", "", fmt.Errorf("could not find download button on detail page")
	}

	a := nyDown.Find("a.da").First()
	href, ok := a.Attr("href")
	if !ok || href == "" {
		return "", "", fmt.Errorf("download link missing href")
	}

	dlPageURL := href
	if !strings.HasPrefix(dlPageURL, "http://") && !strings.HasPrefix(dlPageURL, "https://") {
		dlPageURL = c.baseURL + href
	}

	// Fetch the fast-download page and extract the final link.
	doc2, err := c.fetchDocument(ctx, dlPageURL)
	if err != nil {
		return "", "", fmt.Errorf("failed to fetch fast-download page: %w", err)
	}

	fast := doc2.Find("div.fast-download-box").First()
	if fast.Length() == 0 {
		return "", "", fmt.Errorf("could not find fast-download box")
	}

	link := fast.Find("a#download_link").First()
	finalURL, ok := link.Attr("href")
	if !ok || finalURL == "" {
		return "", "", fmt.Errorf("download_link anchor missing href")
	}

	title, _ := link.Attr("title")
	ext := ""
	if title != "" {
		parts := strings.Fields(title)
		if len(parts) > 0 {
			last := parts[len(parts)-1]
			ext = strings.TrimPrefix(last, ".")
		}
	}

	if !strings.HasPrefix(finalURL, "http://") && !strings.HasPrefix(finalURL, "https://") {
		finalURL = c.baseURL + finalURL
	}

	return finalURL, ext, nil
}

func (c *ApkPureClient) fetchDocument(ctx context.Context, urlStr string) (*goquery.Document, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "AutoAR-apkx/1.0 (+https://github.com/h0tak88r/AutoAR)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %s fetching %s", resp.Status, urlStr)
	}

	return goquery.NewDocumentFromReader(resp.Body)
}

