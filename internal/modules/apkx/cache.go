package apkx

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/h0tak88r/AutoAR/v3/internal/modules/r2storage"
)

// CacheInfo stores package and version information for caching
type CacheInfo struct {
	PackageName    string `json:"package_name"`
	Version        string `json:"version"`
	VersionCode    string `json:"version_code,omitempty"`
	MITMPatchedAPK string `json:"mitm_patched_apk,omitempty"` // Path to MITM patched APK if exists
}

// getCacheKey generates a cache key from package and version
func getCacheKey(packageName, version string) string {
	// Sanitize for filesystem use
	safePkg := strings.ReplaceAll(packageName, ".", "_")
	safeVer := strings.ReplaceAll(version, ".", "_")
	safeVer = strings.ReplaceAll(safeVer, " ", "_")
	return fmt.Sprintf("%s_%s", safePkg, safeVer)
}

// getCachePath returns the local cache path for a package+version
func getCachePath(packageName, version string) string {
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}
	cacheKey := getCacheKey(packageName, version)
	return filepath.Join(resultsDir, "apkx", "cache", cacheKey)
}

// getR2CachePath returns the R2 cache path for a package+version
func getR2CachePath(packageName, version string) string {
	cacheKey := getCacheKey(packageName, version)
	return fmt.Sprintf("apkx/cache/%s", cacheKey)
}

// CheckCache checks if cached results exist for a package+version
// Returns cache path (local or R2 URL) and true if found, empty string and false if not
// Checks R2 first (since local cache may be cleaned up), then local cache
// If version is "latest", searches for any cached version of the package
func CheckCache(packageName, version string) (string, bool) {
	if packageName == "" || version == "" {
		return "", false
	}

	// Check R2 cache FIRST (since local cache may be cleaned up by /cleanup command)
	if r2storage.IsEnabled() {
		// If version is "latest", search for any cached version
		if version == "latest" {
			foundVersion, found := findAnyCachedVersionInR2(packageName)
			if found {
				log.Printf("[CACHE] [ + ]Found R2 cached results for %s v%s (was looking for 'latest')", packageName, foundVersion)
				r2CachePrefix := getR2CachePath(packageName, foundVersion)
				return "r2:" + r2CachePrefix, true
			}
			// Also try checking with the exact "latest" version in case it was saved that way
			r2CachePrefix := getR2CachePath(packageName, "latest")
			r2ResultsKey := r2CachePrefix + "/results.json"
			exists, err := r2storage.FileExists(r2ResultsKey)
			if err == nil && exists {
				log.Printf("[CACHE] [ + ]Found R2 cached results for %s vlatest", packageName)
				return "r2:" + r2CachePrefix, true
			}
		} else {
			// Check specific version
			r2CachePrefix := getR2CachePath(packageName, version)
			r2ResultsKey := r2CachePrefix + "/results.json"
			exists, err := r2storage.FileExists(r2ResultsKey)
			if err == nil && exists {
				log.Printf("[CACHE] [ + ]Found R2 cached results for %s v%s", packageName, version)
				return "r2:" + r2CachePrefix, true // Return with r2: prefix to indicate R2 location
			}
		}
	}

	// Check local cache second
	// If version is "latest", search for any cached version locally
	if version == "latest" {
		foundVersion, found := findAnyCachedVersionLocal(packageName)
		if found {
			log.Printf("[CACHE] [ + ]Found local cached results for %s v%s (was looking for 'latest')", packageName, foundVersion)
			localCachePath := getCachePath(packageName, foundVersion)
			return localCachePath, true
		}
	} else {
		localCachePath := getCachePath(packageName, version)
		resultsJson := filepath.Join(localCachePath, "results.json")
		if _, err := os.Stat(resultsJson); err == nil {
			log.Printf("[CACHE] [ + ]Found local cached results for %s v%s", packageName, version)
			return localCachePath, true
		}
	}

	// Check for existing scan result directory (from before caching was implemented)
	// Look for {resultsDir}/apkx/{package_name}/results.json
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}
	// Convert package name to directory name (dots to underscores, like com.example.app -> com_example_app)
	packageDirName := strings.ReplaceAll(packageName, ".", "_")
	existingScanPath := filepath.Join(resultsDir, "apkx", packageDirName)
	existingResultsJson := filepath.Join(existingScanPath, "results.json")
	if _, err := os.Stat(existingResultsJson); err == nil {
		log.Printf("[CACHE] 📦 Found existing scan result for %s, migrating to cache...", packageName)
		// Try to extract version from existing manifest
		manifestPath := filepath.Join(existingScanPath, "AndroidManifest.xml")
		extractedVersion := version
		if _, err := os.Stat(manifestPath); err == nil {
			content, readErr := os.ReadFile(manifestPath)
			if readErr == nil {
				manifestContent := string(content)
				versionRegex := regexp.MustCompile(`android:versionName\s*=\s*["']([^"']+)["']`)
				if matches := versionRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
					extractedVersion = matches[1]
				} else {
					versionCodeRegex := regexp.MustCompile(`android:versionCode\s*=\s*["']([^"']+)["']`)
					if matches := versionCodeRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
						extractedVersion = "v" + matches[1]
					}
				}
			}
		}
		if extractedVersion == "" || extractedVersion == "unknown" {
			extractedVersion = "latest"
		}
		
		// Create a Result object from existing scan
		existingResult := &Result{
			ReportDir: existingScanPath,
			LogFile:   existingResultsJson,
			Duration:  0, // Unknown duration
		}
		
		// Check for MITM patched APK
		mitmFiles, _ := filepath.Glob(filepath.Join(existingScanPath, "*-mitm-patched*.apk"))
		if len(mitmFiles) > 0 {
			existingResult.MITMPatchedAPK = mitmFiles[0]
		}
		
		// Save to cache
		if err := SaveToCache(packageName, extractedVersion, "", existingResult); err == nil {
			log.Printf("[CACHE] [ + ]Migrated existing scan to cache: %s v%s", packageName, extractedVersion)
			// Return the new cache path
			newCachePath := getCachePath(packageName, extractedVersion)
			return newCachePath, true
		} else {
			log.Printf("[CACHE] ⚠️  Failed to migrate existing scan to cache: %v", err)
		}
	}

	return "", false
}

// findAnyCachedVersionInR2 searches R2 for any cached version of a package
// Returns the version found and true if found, empty string and false if not
func findAnyCachedVersionInR2(packageName string) (string, bool) {
	if !r2storage.IsEnabled() {
		return "", false
	}

	// Search for any cache entry for this package
	// R2 cache path format: apkx/cache/{package}_{version}/results.json
	packagePrefix := fmt.Sprintf("apkx/cache/%s_", strings.ReplaceAll(packageName, ".", "_"))
	
	// Use R2's ListObjects to find all cache entries for this package
	// We need to access the R2 client directly, so we'll use a helper function
	foundVersion, err := r2storage.FindCachedVersion(packagePrefix)
	if err == nil && foundVersion != "" {
		return foundVersion, true
	}
	
	return "", false
}

// findAnyCachedVersionLocal searches local cache for any cached version of a package
// Returns the version found and true if found, empty string and false if not
func findAnyCachedVersionLocal(packageName string) (string, bool) {
	resultsDir := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsDir == "" {
		resultsDir = "new-results"
	}
	
	cacheDir := filepath.Join(resultsDir, "apkx", "cache")
	packagePrefix := strings.ReplaceAll(packageName, ".", "_") + "_"
	
	// List all cache directories
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", false
	}
	
	// Find any directory that starts with the package prefix
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), packagePrefix) {
			// Extract version from directory name
			// Format: {package}_{version}
			version := strings.TrimPrefix(entry.Name(), packagePrefix)
			// Check if results.json exists
			resultsJson := filepath.Join(cacheDir, entry.Name(), "results.json")
			if _, err := os.Stat(resultsJson); err == nil {
				return version, true
			}
		}
	}
	
	return "", false
}

// LoadCachedResult loads a cached result from local filesystem
func LoadCachedResult(cachePath string) (*Result, error) {
	resultsJson := filepath.Join(cachePath, "results.json")
	if _, err := os.Stat(resultsJson); os.IsNotExist(err) {
		return nil, fmt.Errorf("cached results not found: %s", resultsJson)
	}

	// Read cache info to get MITM patched APK path
	cacheInfoFile := filepath.Join(cachePath, "cache_info.json")
	var cacheInfo CacheInfo
	mitmPatchedAPK := ""
	if data, err := os.ReadFile(cacheInfoFile); err == nil {
		json.Unmarshal(data, &cacheInfo)
		// Check if MITM patched APK exists
		if cacheInfo.MITMPatchedAPK != "" {
			// Check if file exists (might be in cache or original location)
			if _, statErr := os.Stat(cacheInfo.MITMPatchedAPK); statErr == nil {
				mitmPatchedAPK = cacheInfo.MITMPatchedAPK
			} else {
				// Try in cache directory
				cachedMitmPath := filepath.Join(cachePath, filepath.Base(cacheInfo.MITMPatchedAPK))
				if _, statErr := os.Stat(cachedMitmPath); statErr == nil {
					mitmPatchedAPK = cachedMitmPath
				}
			}
		}
	}

	// Create Result from cache
	result := &Result{
		ReportDir:     cachePath,
		LogFile:       resultsJson,
		Duration:      0, // Cached results don't have duration
		MITMPatchedAPK: mitmPatchedAPK,
		FromCache:     true, // Mark as cached result
	}

	return result, nil
}

// SaveToCache saves scan results to cache for future use
func SaveToCache(packageName, version, versionCode string, result *Result) error {
	if packageName == "" || version == "" || result == nil {
		return fmt.Errorf("invalid cache parameters")
	}

	cachePath := getCachePath(packageName, version)
	if err := os.MkdirAll(cachePath, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Save cache info
	cacheInfo := CacheInfo{
		PackageName:    packageName,
		Version:        version,
		VersionCode:    versionCode,
		MITMPatchedAPK: result.MITMPatchedAPK, // Save MITM patched APK path if exists
	}
	cacheInfoData, err := json.MarshalIndent(cacheInfo, "", "  ")
	if err == nil {
		cacheInfoFile := filepath.Join(cachePath, "cache_info.json")
		os.WriteFile(cacheInfoFile, cacheInfoData, 0644)
	}

	// Copy results.json to cache
	if result.LogFile != "" {
		if data, err := os.ReadFile(result.LogFile); err == nil {
			cachedResultsJson := filepath.Join(cachePath, "results.json")
			os.WriteFile(cachedResultsJson, data, 0644)
		}
	}

	// Copy other important files
	if result.ReportDir != "" {
		// Copy findings-table.md if exists
		tablePath := filepath.Join(result.ReportDir, "findings-table.md")
		if _, err := os.Stat(tablePath); err == nil {
			if data, err := os.ReadFile(tablePath); err == nil {
				cachedTablePath := filepath.Join(cachePath, "findings-table.md")
				os.WriteFile(cachedTablePath, data, 0644)
			}
		}

		// Copy AndroidManifest.xml if exists
		manifestPaths := []string{
			filepath.Join(result.ReportDir, "AndroidManifest.xml"),
			filepath.Join(result.ReportDir, "resources", "AndroidManifest.xml"),
		}
		for _, manifestPath := range manifestPaths {
			if _, err := os.Stat(manifestPath); err == nil {
				if data, err := os.ReadFile(manifestPath); err == nil {
					cachedManifestPath := filepath.Join(cachePath, "AndroidManifest.xml")
					os.WriteFile(cachedManifestPath, data, 0644)
				}
				break
			}
		}

		// Copy MITM patched APK to cache if it exists
		if result.MITMPatchedAPK != "" {
			if _, err := os.Stat(result.MITMPatchedAPK); err == nil {
				// Copy to cache directory
				cachedMitmPath := filepath.Join(cachePath, filepath.Base(result.MITMPatchedAPK))
				if data, err := os.ReadFile(result.MITMPatchedAPK); err == nil {
					os.WriteFile(cachedMitmPath, data, 0644)
					// Update cache info with cached path
					cacheInfo.MITMPatchedAPK = cachedMitmPath
					// Re-save cache info
					cacheInfoData, _ := json.MarshalIndent(cacheInfo, "", "  ")
					os.WriteFile(filepath.Join(cachePath, "cache_info.json"), cacheInfoData, 0644)
				}
			}
		}
	}

	log.Printf("[CACHE] 💾 Saved results to cache: %s", cachePath)

	// Upload to R2 if enabled (skip timestamp for cache - we want predictable paths)
	if r2storage.IsEnabled() {
		r2CachePrefix := getR2CachePath(packageName, version)
		log.Printf("[CACHE] 📤 Uploading cache to R2: %s", r2CachePrefix)
		_, err := r2storage.UploadDirectory(cachePath, r2CachePrefix, true)
		if err != nil {
			log.Printf("[CACHE] ⚠️  Failed to upload cache to R2: %v", err)
		} else {
			log.Printf("[CACHE] [ + ]Cache uploaded to R2")
		}
	}

	return nil
}

// ExtractVersionFromAPK extracts version from APK file quickly without full decompilation
// This is used to check cache before doing expensive scan
// Tries aapt/aapt2 first (fastest), then falls back to minimal apktool decode
func ExtractVersionFromAPK(apkPath string) (packageName, version, versionCode string, err error) {
	// Try aapt dump badging first (fastest method)
	if pkg, ver, code := extractVersionWithAAPT(apkPath); pkg != "" {
		return pkg, ver, code, nil
	}

	// Fallback: Try minimal apktool decode to extract manifest
	return extractVersionWithApktool(apkPath)
}

// extractVersionWithAAPT uses aapt/aapt2 to quickly extract version info
func extractVersionWithAAPT(apkPath string) (packageName, version, versionCode string) {
	// Try aapt2 first (newer)
	for _, tool := range []string{"aapt2", "aapt"} {
		cmd := exec.Command(tool, "dump", "badging", apkPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// Log debug info but continue to next tool
			log.Printf("[DEBUG] %s failed: %v", tool, err)
			continue
		}

		outputStr := string(output)
		
		// Extract package name: package: name='com.example.app'
		pkgRegex := regexp.MustCompile(`package:\s*name=['"]([^'"]+)['"]`)
		if matches := pkgRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
			packageName = matches[1]
		}

		// Extract version name: versionName='1.0.0'
		verRegex := regexp.MustCompile(`versionName=['"]([^'"]+)['"]`)
		if matches := verRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
			version = matches[1]
		}

		// Extract version code: versionCode='123'
		codeRegex := regexp.MustCompile(`versionCode=['"](\d+)['"]`)
		if matches := codeRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
			versionCode = matches[1]
		}

		if packageName != "" && (version != "" || versionCode != "") {
			if version == "" && versionCode != "" {
				version = "v" + versionCode
			}
			return packageName, version, versionCode
		}
	}

	return "", "", ""
}

// extractVersionWithApktool does a minimal apktool decode to extract manifest
func extractVersionWithApktool(apkPath string) (packageName, version, versionCode string, err error) {
	// Find apktool
	apktoolPath := "/usr/local/bin/apktool.jar"
	if _, err := os.Stat(apktoolPath); os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("apktool not found for version extraction")
	}

	// Find java
	javaPath, err := exec.LookPath("java")
	if err != nil {
		return "", "", "", fmt.Errorf("java not found")
	}

	// Create temp directory for minimal decode
	tmpDir, err := os.MkdirTemp("", "apkx-version-*")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Decode APK (this is still expensive but necessary if aapt not available)
	cmd := exec.Command(javaPath, "-jar", apktoolPath, "d", apkPath, "-o", tmpDir, "-f", "-s") // -s = no sources, faster
	_, err = cmd.CombinedOutput()
	if err != nil {
		return "", "", "", fmt.Errorf("apktool decode failed: %w", err)
	}

	// Look for AndroidManifest.xml in decoded output
	manifestPaths := []string{
		filepath.Join(tmpDir, "AndroidManifest.xml"),
		filepath.Join(tmpDir, "resources", "AndroidManifest.xml"),
	}

	var manifestPath string
	for _, path := range manifestPaths {
		if _, err := os.Stat(path); err == nil {
			manifestPath = path
			break
		}
	}

	if manifestPath == "" {
		return "", "", "", fmt.Errorf("AndroidManifest.xml not found after decode")
	}

	// Read and parse manifest
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to read manifest: %w", err)
	}

	manifestContent := string(content)

	// Extract package name
	packageRegex := regexp.MustCompile(`package\s*=\s*["']([^"']+)["']`)
	if matches := packageRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		packageName = matches[1]
	}

	// Extract version name
	versionRegex := regexp.MustCompile(`android:versionName\s*=\s*["']([^"']+)["']`)
	if matches := versionRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		version = matches[1]
	}

	// Extract version code
	versionCodeRegex := regexp.MustCompile(`android:versionCode\s*=\s*["']([^"']+)["']`)
	if matches := versionCodeRegex.FindStringSubmatch(manifestContent); len(matches) > 1 {
		versionCode = matches[1]
	}

	// If version name not found, use version code
	if version == "" && versionCode != "" {
		version = "v" + versionCode
	}

	if packageName == "" {
		return "", "", "", fmt.Errorf("failed to extract package name")
	}

	return packageName, version, versionCode, nil
}

