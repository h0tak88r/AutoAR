package analyzer

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/decompiler"
	"github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/reporter"
	"github.com/h0tak88r/AutoAR/v3/internal/tools/apkx/utils"
	"gopkg.in/yaml.v3"
)

//go:embed regexes.yaml
var patternsFS embed.FS

type Config struct {
	APKPath        string
	OutputDir      string
	PatternsPath   string
	Workers        int
	WebhookURL     string
	TaskHijackOnly bool
	HTMLOutput     bool
	JanusScan      bool
}

type APKScanner struct {
	config    *Config
	patterns  map[string][]string
	tempDir   string
	results   map[string][]string
	resultsMu sync.Mutex
	apkPkg    string
	cacheDir  string
	mu        sync.Mutex
	analyzers []AnalyzerInterface
}

type AnalyzerInterface interface {
	Analyze(decompileDir string) ([]string, error)
	SetAPKPath(apkPath string)
}

type Pattern struct {
	Name       string   `yaml:"name"`
	Regex      string   `yaml:"regex,omitempty"`
	Regexes    []string `yaml:"regexes,omitempty"`
	Confidence string   `yaml:"confidence"`
}

type PatternsConfig struct {
	Patterns []Pattern `yaml:"patterns"`
}

func NewAPKScanner(config *Config) *APKScanner {
	analyzers := []AnalyzerInterface{}

	return &APKScanner{
		config:    config,
		results:   make(map[string][]string),
		analyzers: analyzers,
	}
}

func (s *APKScanner) Run() error {
	// Validate APK file
	if err := s.validateAPK(); err != nil {
		return err
	}

	// Try to use cached decompiled APK or decompile new one
	if err := s.decompileAPK(); err != nil {
		return fmt.Errorf("failed to decompile APK: %v", err)
	}

	// Load patterns
	patterns, err := s.loadPatterns()
	if err != nil {
		return fmt.Errorf("failed to load patterns: %v", err)
	}

	// Process files concurrently
	results := make(map[string][]string)
	resultsMu := sync.Mutex{}
	var wg sync.WaitGroup

	// Collect all files first, with size filtering to prevent processing huge files
	var filesToProcess []string
	const maxFileSize = 10 * 1024 * 1024 // 10MB limit
	err = filepath.Walk(s.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && isRelevantFile(path) {
			// Skip files larger than 10MB (likely binary, not useful for pattern matching)
			if info.Size() <= maxFileSize {
				filesToProcess = append(filesToProcess, path)
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to collect files: %v", err)
	}

	// Limit total files processed to prevent runaway scans (configurable via env)
	maxFiles := 20000 // Default limit
	if envMaxFiles := os.Getenv("APKX_MAX_FILES"); envMaxFiles != "" {
		if m, err := strconv.Atoi(envMaxFiles); err == nil && m > 0 {
			maxFiles = m
		}
	}
	
	if len(filesToProcess) > maxFiles {
		fmt.Printf("%sWarning: Found %d files, limiting to %d to prevent resource exhaustion%s\n", 
			utils.ColorWarning, len(filesToProcess), maxFiles, utils.ColorEnd)
		filesToProcess = filesToProcess[:maxFiles]
	}

	fmt.Printf("%sAnalyzing %d files...%s\n", utils.ColorBlue, len(filesToProcess), utils.ColorEnd)

	// Use config.Workers if set, otherwise use a conservative default based on file count
	maxWorkers := s.config.Workers
	if maxWorkers <= 0 {
		// Adaptive concurrency: fewer workers for large file sets to prevent OOM
		if len(filesToProcess) > 10000 {
			maxWorkers = 4 // Very conservative for huge APKs
		} else if len(filesToProcess) > 5000 {
			maxWorkers = 6
		} else if len(filesToProcess) > 1000 {
			maxWorkers = 8
		} else {
			maxWorkers = 10 // Original default for smaller APKs
		}
	}
	
	// Cap at reasonable maximum to prevent resource exhaustion
	if maxWorkers > 20 {
		maxWorkers = 20
	}

	// Process files in batches to control concurrency
	semaphore := make(chan struct{}, maxWorkers)
	
	// Progress tracking with throttling (log every 100 files or 5 seconds)
	processedCount := 0
	lastLogTime := time.Now()
	progressMu := sync.Mutex{}
	
	fmt.Printf("%sUsing %d concurrent workers for processing...%s\n", utils.ColorBlue, maxWorkers, utils.ColorEnd)

	for _, path := range filesToProcess {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			matches := s.processFile(filePath, patterns)
			if len(matches) > 0 {
				resultsMu.Lock()
				for pattern, found := range matches {
					if len(found) > 0 {
						results[pattern] = append(results[pattern], found...)
					}
				}
				resultsMu.Unlock()
			}
			
			// Throttled progress logging
			progressMu.Lock()
			processedCount++
			now := time.Now()
			if processedCount%100 == 0 || now.Sub(lastLogTime) >= 5*time.Second {
				fmt.Printf("%sProgress: %d of %d (%.0f%%)%s\n", 
					utils.ColorBlue, processedCount, len(filesToProcess), 
					float64(processedCount)/float64(len(filesToProcess))*100, utils.ColorEnd)
				lastLogTime = now
			}
			progressMu.Unlock()
		}(path)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	
	// Final progress message
	fmt.Printf("%sCompleted analysis of %d files%s\n", utils.ColorGreen, len(filesToProcess), utils.ColorEnd)

	// Special handling for AndroidManifest.xml - detect exported components
	manifestPath := filepath.Join(s.tempDir, "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); err == nil {
		s.detectExportedComponents(manifestPath, results, &resultsMu)
	} else {
		// Try alternative locations for AndroidManifest.xml
		altPaths := []string{
			filepath.Join(s.tempDir, "resources", "AndroidManifest.xml"),
			filepath.Join(s.tempDir, "sources", "AndroidManifest.xml"),
			filepath.Join(s.tempDir, "res", "AndroidManifest.xml"),
		}

		for _, altPath := range altPaths {
			if _, err := os.Stat(altPath); err == nil {
				s.detectExportedComponents(altPath, results, &resultsMu)
				break
			}
		}
	}

	// Built-in Janus vulnerability detection (pure Go, no external tools)
	if s.config.JanusScan {
		if finding := s.detectJanusVulnerabilityPure(); finding != "" {
			results["JanusVulnerability"] = []string{finding}
		}
	}

	// Save results
	return s.saveResults(results)
}

func (s *APKScanner) validateAPK() error {
	if _, err := os.Stat(s.config.APKPath); os.IsNotExist(err) {
		return fmt.Errorf("APK file does not exist: %s", s.config.APKPath)
	}
	s.apkPkg = filepath.Base(s.config.APKPath)
	return nil
}

func (s *APKScanner) loadPatterns() (map[string][]string, error) {
	var data []byte
	var err error

	if s.config.PatternsPath != "" {
		data, err = os.ReadFile(s.config.PatternsPath)
	if err != nil {
			return nil, fmt.Errorf("failed to read patterns file %s: %v", s.config.PatternsPath, err)
		}
	} else {
		data, err = patternsFS.ReadFile("regexes.yaml")
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded patterns: %v", err)
		}
	}

	var config PatternsConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse patterns YAML: %v", err)
	}

	// Validate and compile patterns
	s.patterns = make(map[string][]string)

	// Process patterns from single config
	for _, pattern := range config.Patterns {
		// Skip empty patterns
		if pattern.Name == "" || (pattern.Regex == "" && len(pattern.Regexes) == 0) {
			continue
		}

		var regexes []string
		if pattern.Regex != "" {
			regexes = []string{pattern.Regex}
		} else {
			regexes = pattern.Regexes
		}

		// Validate each regex
		validRegexes := make([]string, 0)
		for _, regex := range regexes {
			if _, err := regexp.Compile(regex); err != nil {
				fmt.Printf("%sWarning: Invalid regex pattern for '%s': %v%s\n",
					utils.ColorWarning, pattern.Name, err, utils.ColorEnd)
				continue
			}
			validRegexes = append(validRegexes, regex)
		}

		if len(validRegexes) > 0 {
			s.patterns[pattern.Name] = validRegexes
		}
	}

	if len(s.patterns) == 0 {
		return nil, fmt.Errorf("no valid patterns found in patterns file")
	}

	fmt.Printf("%s** Loaded %d patterns%s\n",
		utils.ColorBlue, len(s.patterns), utils.ColorEnd)
	return s.patterns, nil
}

func (s *APKScanner) processFile(path string, patterns map[string][]string) map[string][]string {
	// Check file size before reading - skip files larger than 10MB to prevent OOM
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	
	// Skip files larger than 10MB (they're likely binary and not useful for pattern matching)
	const maxFileSize = 10 * 1024 * 1024 // 10MB
	if info.Size() > maxFileSize {
		return nil
	}
	
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	contentStr := string(content)
	matches := make(map[string][]string)
	seen := make(map[string]bool)

	// Get relative path for better output
	relPath := path
	if strings.Contains(path, s.tempDir) {
		if rel, err := filepath.Rel(s.tempDir, path); err == nil {
			relPath = rel
		}
	}

	for patternName, regexes := range patterns {
		for _, regex := range regexes {
			re, err := regexp.Compile(regex)
			if err != nil {
				continue
			}

			// Find all matches with some surrounding context
			allIndexes := re.FindAllStringIndex(contentStr, -1)
			if allIndexes == nil {
				continue
			}

			for _, idx := range allIndexes {
				match := contentStr[idx[0]:idx[1]]
				match = strings.TrimSpace(match)

				if match == "" || seen[match] {
					continue
				}

				// Skip common false positives
				if isCommonFalsePositive(match) {
					continue
				}

				// Get some context around the match
				start := max(0, idx[0]-100)
				end := min(len(contentStr), idx[1]+100)
				context := contentStr[start:end]
				context = strings.ReplaceAll(context, "\n", " ")
				context = strings.TrimSpace(context)

				// Special handling for security vulnerability patterns
				var result string
				if patternName == "InsecureStorage" || patternName == "CertificatePinning" || patternName == "DebugMode" {
					// For security vulnerabilities, provide more detailed context
					lines := strings.Split(contentStr, "\n")
					lineNum := 1
					for i, line := range lines {
						if strings.Contains(line, match) {
							lineNum = i + 1
							break
						}
					}
					result = fmt.Sprintf("%s:%d: %s (Context: %s)", relPath, lineNum, match, context)
				} else {
					result = fmt.Sprintf("%s: %s (Context: ...%s...)", relPath, match, context)
				}
				matches[patternName] = append(matches[patternName], result)
				seen[match] = true
			}
		}
	}

	return matches
}

func isCommonFalsePositive(match string) bool {
	falsePositives := []string{
		"http://schemas.android.com/apk/res/android",
		"http://schemas.android.com/apk/res-auto",
		"http://schemas.android.com/aapt",
		"android.permission.",
		"android:name=",
		"android:label=",
		"android:value=",
		"android.intent.",
		"com.android.",
		"androidx.",
	}

	for _, fp := range falsePositives {
		if strings.Contains(match, fp) {
			return true
		}
	}

	return false
}

func (s *APKScanner) getCacheDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".apkx", "cache")
}

func (s *APKScanner) getApkHash() (string, error) {
	f, err := os.Open(s.config.APKPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (s *APKScanner) decompileAPK() error {
	// Setup cache directory in user's home
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	s.cacheDir = filepath.Join(homeDir, ".apkx", "cache")
	if err := os.MkdirAll(s.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %v", err)
	}

	// Calculate APK hash for cache key
	hash, err := s.getApkHash()
	if err != nil {
		return fmt.Errorf("failed to calculate APK hash: %v", err)
	}

	// Check if cached version exists
	cachedDir := filepath.Join(s.cacheDir, hash)
	if _, err := os.Stat(cachedDir); err == nil {
		fmt.Printf("%s** Found cached decompiled APK, skipping decompilation...%s\n",
			utils.ColorBlue, utils.ColorEnd)
		s.tempDir = cachedDir
		return nil
	}

	// If not cached, create temporary directory for decompilation
	tempDir, err := os.MkdirTemp("", "apkx-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Initialize decompiler
	decompiler, err := decompiler.NewJadx()
	if err != nil {
		os.RemoveAll(tempDir)
		return fmt.Errorf("failed to initialize jadx: %v", err)
	}

	// Decompile APK
	fmt.Printf("%s** Decompiling APK (this may take a while)...%s\n",
		utils.ColorBlue, utils.ColorEnd)
	if err := decompiler.Decompile(s.config.APKPath, tempDir, ""); err != nil {
		// Check if we have any decompiled files before giving up
		if _, statErr := os.Stat(filepath.Join(tempDir, "sources")); statErr == nil {
			fmt.Printf("%s** Some decompilation errors occurred, but continuing with available files...%s\n",
				utils.ColorWarning, utils.ColorEnd)
		} else {
			os.RemoveAll(tempDir)
			return fmt.Errorf("failed to decompile APK: %v", err)
		}
	}

	// Move successful decompilation to cache
	if err := os.Rename(tempDir, cachedDir); err != nil {
		// If moving fails, try copying
		if copyErr := copyDir(tempDir, cachedDir); copyErr != nil {
			os.RemoveAll(tempDir)
			return fmt.Errorf("failed to cache decompiled APK: %v", copyErr)
		}
		os.RemoveAll(tempDir)
	}

	s.tempDir = cachedDir
	return nil
}

// Helper function to copy directory recursively
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {

		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// Helper function to copy a single file
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Close()
}

func (s *APKScanner) sendToDiscord(jsonPath, htmlPath string) error {
	if s.config.WebhookURL == "" {
		return nil
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add JSON file
	jsonFile, err := os.Open(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to open JSON file: %v", err)
	}
	defer jsonFile.Close()

	jsonPart, err := writer.CreateFormFile("file1", filepath.Base(jsonPath))
	if err != nil {
		return fmt.Errorf("failed to create JSON form file: %v", err)
	}

	_, err = io.Copy(jsonPart, jsonFile)
	if err != nil {
		return fmt.Errorf("failed to copy JSON file content: %v", err)
	}

	// Add HTML file
	htmlFile, err := os.Open(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to open HTML file: %v", err)
	}
	defer htmlFile.Close()

	htmlPart, err := writer.CreateFormFile("file2", filepath.Base(htmlPath))
	if err != nil {
		return fmt.Errorf("failed to create HTML form file: %v", err)
	}

	_, err = io.Copy(htmlPart, htmlFile)
	if err != nil {
		return fmt.Errorf("failed to copy HTML file content: %v", err)
	}

	// Add message field
	_ = writer.WriteField("content", fmt.Sprintf("APK Analysis Results for: %s\n\n📄 JSON Report: %s\n🌐 HTML Report: %s",
		s.apkPkg, filepath.Base(jsonPath), filepath.Base(htmlPath)))

	writer.Close()

	// Create and send request
	req, err := http.NewRequest("POST", s.config.WebhookURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("webhook request failed with status: %d", resp.StatusCode)
	}

	fmt.Printf("%sResults sent to Discord webhook successfully%s\n",
		utils.ColorGreen, utils.ColorEnd)
	return nil
}

func (s *APKScanner) saveResults(results map[string][]string) error {
	// Create statistics map for different finding types
	stats := make(map[string]int)

	// Count findings by category
	for category, matches := range results {
		if len(matches) > 0 {
			stats[category] = len(matches)
		}
	}

	// Print only the summary to terminal
	fmt.Printf("\n%s=== APK Analysis Summary ===%s\n", utils.ColorGreen, utils.ColorEnd)
	if len(stats) == 0 {
		fmt.Printf("%sNo sensitive information found.%s\n", utils.ColorYellow, utils.ColorEnd)
	} else {
		fmt.Printf("%sFound sensitive information in %d categories:%s\n",
			utils.ColorBlue, len(stats), utils.ColorEnd)

		for category, count := range stats {
			fmt.Printf("  • %s: %d findings\n", category, count)
		}
	}

	// Save detailed results to JSON file
	if s.config.OutputDir != "" {
		jsonData, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results to JSON: %v", err)
		}

		jsonPath := filepath.Join(s.config.OutputDir, "results.json")
		if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write results to file: %v", err)
		}
		fmt.Printf("\n%sDetailed results saved to: %s%s%s\n",
			utils.ColorBlue, utils.ColorGreen, jsonPath, utils.ColorEnd)

		// Generate HTML report if requested
		if s.config.HTMLOutput {
			if err := s.generateHTMLReport(results, jsonPath); err != nil {
				fmt.Printf("%sWarning: Failed to generate HTML report: %v%s\n",
					utils.ColorYellow, err, utils.ColorEnd)
			}
		}

		// After saving the file, send to Discord if webhook is configured
		if s.config.WebhookURL != "" {
			htmlPath := filepath.Join(s.config.OutputDir, "security-report.html")
			if err := s.sendToDiscord(jsonPath, htmlPath); err != nil {
				fmt.Printf("%sWarning: Failed to send results to Discord: %v%s\n",
					utils.ColorYellow, err, utils.ColorEnd)
			}
		}
	}

	return nil
}

func (s *APKScanner) generateHTMLReport(results map[string][]string, jsonPath string) error {
	// Extract package information from AndroidManifest.xml
	packageName, version := reporter.ExtractPackageInfo(s.tempDir)

	// Extract minSdkVersion from apktool.yml
	minSdkVersion := reporter.ExtractMinSdkVersion(s.tempDir)

	// Prepare HTML report data
	reportData := reporter.HTMLReportData{
		APKName:       filepath.Base(s.config.APKPath),
		PackageName:   packageName,
		Version:       version,
		MinSdkVersion: minSdkVersion,
		ScanTime:      time.Now().Format("2006-01-02 15:04:05"),
		TotalFindings: s.countTotalFindings(results),
		Categories:    s.prepareCategoriesData(results),
		Summary:       s.prepareSummaryData(results),
	}

	// Copy important decompiled files to report directory
	s.copyDecompiledFiles()

	// Generate HTML report (optional, kept for backward compatibility)
	// Note: The Discord bot now generates a markdown table instead
	if s.config.HTMLOutput {
		htmlContent, err := reporter.GenerateHTMLReport(reportData)
		if err != nil {
			return fmt.Errorf("failed to generate HTML report: %v", err)
		}

		htmlPath := filepath.Join(s.config.OutputDir, "security-report.html")
		if err := ioutil.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
			return fmt.Errorf("failed to write HTML report: %v", err)
		}

		fmt.Printf("%sHTML report generated: %s%s%s\n",
			utils.ColorBlue, utils.ColorGreen, htmlPath, utils.ColorEnd)
	}
	return nil
}

func (s *APKScanner) countTotalFindings(results map[string][]string) int {
	total := 0
	for _, findings := range results {
		total += len(findings)
	}
	return total
}

// copyDecompiledFiles copies important decompiled files to the report directory
func (s *APKScanner) copyDecompiledFiles() {
	// Files to copy from decompiled directory to report directory
	filesToCopy := []string{
		"AndroidManifest.xml",
		"sources/AndroidManifest.xml",
		"resources/AndroidManifest.xml",
		"res/AndroidManifest.xml",
		"resources/com.jbl.oneapp.apk/AndroidManifest.xml", // Specific case for some APKs
		"apktool.yml",
		"h5/apktool.yml", // Alternative location
	}

	for _, fileName := range filesToCopy {
		srcPath := filepath.Join(s.tempDir, fileName)
		dstPath := filepath.Join(s.config.OutputDir, filepath.Base(fileName))

		// Check if source file exists
		if _, err := os.Stat(srcPath); err == nil {
			// Copy the file
			if err := copyFile(srcPath, dstPath); err != nil {
				fmt.Printf("%sWarning: Failed to copy %s: %v%s\n",
					utils.ColorWarning, fileName, err, utils.ColorEnd)
			} else {
				fmt.Printf("%sCopied %s to report directory%s\n",
					utils.ColorGreen, fileName, utils.ColorEnd)
			}
		}
	}
}

func (s *APKScanner) prepareCategoriesData(results map[string][]string) map[string]reporter.CategoryData {
	categories := make(map[string]reporter.CategoryData)

	for category, findings := range results {
		if len(findings) == 0 {
			continue
		}

		var findingData []reporter.FindingData
		for _, finding := range findings {
			// Parse finding string to extract file, match, and context
			// Format: "file: match (Context: ...context...)"
			parts := strings.Split(finding, ": ")
			if len(parts) >= 2 {
				file := parts[0]
				remaining := strings.Join(parts[1:], ": ")
				match := remaining
				context := ""

				// Extract context if present
				if strings.Contains(remaining, " (Context: ") {
					contextStart := strings.Index(remaining, " (Context: ")
					context = remaining[contextStart+11 : len(remaining)-1]
					match = remaining[:contextStart]
				}

				// Clean up the context - remove extra whitespace and newlines
				context = strings.TrimSpace(context)

				// Replace common patterns with better formatting
				context = strings.ReplaceAll(context, "❯ Description:", "\n❯ Description:")
				context = strings.ReplaceAll(context, "❯ Impact:", "\n❯ Impact:")
				context = strings.ReplaceAll(context, "❯ Recommendation:", "\n❯ Recommendation:")
				context = strings.ReplaceAll(context, "❯ Files:", "\n❯ Files:")
				context = strings.ReplaceAll(context, "• ", "\n• ")
				context = strings.ReplaceAll(context, "│ ", "\n│ ")

				// Clean up extra whitespace
				context = strings.ReplaceAll(context, "\n ", "\n")
				context = strings.ReplaceAll(context, "\n\n", "\n")
				context = strings.TrimSpace(context)

				findingData = append(findingData, reporter.FindingData{
					File:    file,
					Match:   strings.TrimSpace(match),
					Context: context,
				})
			}
		}

		categories[category] = reporter.CategoryData{
			Name:     category,
			Count:    len(findings),
			Findings: findingData,
		}
	}

	return categories
}

func (s *APKScanner) detectExportedComponents(manifestPath string, results map[string][]string, resultsMu *sync.Mutex) {
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return
	}

	manifestContent := string(content)

	// Detect exported activities
	exportedActivities := s.detectExportedActivities(manifestContent)
	if len(exportedActivities) > 0 {
		resultsMu.Lock()
		results["ExportedActivities"] = exportedActivities
		resultsMu.Unlock()
	}

	// Detect exported services
	exportedServices := s.detectExportedServices(manifestContent)
	if len(exportedServices) > 0 {
		resultsMu.Lock()
		results["ExportedServices"] = exportedServices
		resultsMu.Unlock()
	}

	// Detect exported broadcast receivers
	exportedReceivers := s.detectExportedBroadcastReceivers(manifestContent)
	if len(exportedReceivers) > 0 {
		resultsMu.Lock()
		results["ExportedBroadcastReceivers"] = exportedReceivers
		resultsMu.Unlock()
	}

	// Detect exported content providers
	exportedProviders := s.detectExportedContentProviders(manifestContent)
	if len(exportedProviders) > 0 {
		resultsMu.Lock()
		results["ExportedContentProviders"] = exportedProviders
		resultsMu.Unlock()
	}

	// Detect webviews
	webviews := s.detectWebViews(manifestContent)
	if len(webviews) > 0 {
		resultsMu.Lock()
		results["WebViews"] = webviews
		resultsMu.Unlock()
	}

	// Detect deep links
	deepLinks := s.detectDeepLinks(manifestContent)
	if len(deepLinks) > 0 {
		resultsMu.Lock()
		results["DeepLinks"] = deepLinks
		resultsMu.Unlock()
	}

	// Detect custom URL schemes
	customSchemes := s.detectCustomURLSchemes(manifestContent)
	if len(customSchemes) > 0 {
		resultsMu.Lock()
		results["CustomURLSchemes"] = customSchemes
		resultsMu.Unlock()
	}

	// Detect file provider exports
	fileProviders := s.detectFileProviderExports(manifestContent)
	if len(fileProviders) > 0 {
		resultsMu.Lock()
		results["FileProviderExports"] = fileProviders
		resultsMu.Unlock()
	}

	// Detect task hijacking vulnerabilities
	taskHijacking := s.detectTaskHijacking(manifestContent)
	if len(taskHijacking) > 0 {
		resultsMu.Lock()
		results["taskAffinity"] = taskHijacking
		resultsMu.Unlock()
	}

	// Detect single task launch mode
	singleTask := s.detectSingleTaskLaunchMode(manifestContent)
	if len(singleTask) > 0 {
		resultsMu.Lock()
		results["SingleTaskLaunchMode"] = singleTask
		resultsMu.Unlock()
	}
}

func (s *APKScanner) detectExportedActivities(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<activity[^>]*?android:name="([^"]+)".*?android:exported="true"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			activityName := match[1]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, activityName, "activity")
			result := fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", activityName, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectExportedServices(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<service[^>]*?android:name="([^"]+)".*?android:exported="true"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			serviceName := match[1]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, serviceName, "service")
			result := fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", serviceName, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectExportedBroadcastReceivers(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<receiver[^>]*?android:name="([^"]+)".*?android:exported="true"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			receiverName := match[1]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, receiverName, "receiver")
			result := fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", receiverName, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectExportedContentProviders(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<provider[^>]*?android:name="([^"]+)".*?android:exported="true"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			providerName := match[1]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, providerName, "provider")
			result := fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", providerName, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectWebViews(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<activity[^>]*?android:name="([^"]+)".*?<intent-filter[^>]*?<action[^>]*?android:name="android\.intent\.action\.VIEW"[^>]*?<category[^>]*?android:name="android\.intent\.category\.BROWSABLE"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			activityName := match[1]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, activityName, "activity")
			result := fmt.Sprintf("AndroidManifest.xml: %s (Context: %s)", activityName, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectDeepLinks(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<activity[^>]*?android:name="([^"]+)".*?<intent-filter[^>]*?<action[^>]*?android:name="android\.intent\.action\.VIEW"[^>]*?<category[^>]*?android:name="android\.intent\.category\.DEFAULT"[^>]*?<data[^>]*?android:scheme="([^"]+)"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 2 {
			activityName := match[1]
			scheme := match[2]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, activityName, "activity")
			result := fmt.Sprintf("AndroidManifest.xml: %s -> %s:// (Context: %s)", activityName, scheme, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectCustomURLSchemes(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<data[^>]*?android:scheme="([^"]+)"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			scheme := match[1]
			result := fmt.Sprintf("AndroidManifest.xml: Custom scheme '%s://'", scheme)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectFileProviderExports(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<provider[^>]*?android:name="([^"]+)".*?android:exported="true".*?android:authorities="([^"]+)"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 2 {
			providerName := match[1]
			authority := match[2]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, providerName, "provider")
			result := fmt.Sprintf("AndroidManifest.xml: %s (Authority: %s) (Context: %s)", providerName, authority, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectTaskHijacking(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<activity[^>]*?android:name="([^"]+)".*?android:taskAffinity="([^"]+)"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 2 {
			activityName := match[1]
			taskAffinity := match[2]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, activityName, "activity")
			result := fmt.Sprintf("AndroidManifest.xml: %s (TaskAffinity: %s) (Context: %s)", activityName, taskAffinity, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) detectSingleTaskLaunchMode(manifestContent string) []string {
	// Use the regex pattern from regexes.yaml
	pattern := `(?s)<activity[^>]*?android:name="([^"]+)".*?android:launchMode="singleTask"`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllStringSubmatch(manifestContent, -1)
	var results []string

	for _, match := range matches {
		if len(match) > 1 {
			activityName := match[1]
			// Get some context around the match
			context := s.getComponentContext(manifestContent, activityName, "activity")
			result := fmt.Sprintf("AndroidManifest.xml: %s (LaunchMode: singleTask) (Context: %s)", activityName, context)
			results = append(results, result)
		}
	}

	return results
}

func (s *APKScanner) getComponentContext(manifestContent, componentName, componentType string) string {
	lines := strings.Split(manifestContent, "\n")

	// Find the line containing the component name and android:name
	for i, line := range lines {
		if strings.Contains(line, componentName) && strings.Contains(line, "android:name=") {
			// Look backwards to find the opening tag (it might be on a previous line)
			openingTagLine := i
			for j := i; j >= 0 && j >= i-5; j-- {
				if strings.Contains(lines[j], "<"+componentType) {
					openingTagLine = j
					break
				}
			}

			// Get context around the component (3 lines before opening tag and 3 lines after component name)
			start := max(0, openingTagLine-3)
			end := min(len(lines), i+4)
			context := lines[start:end]

			// Clean up the context
			contextStr := strings.Join(context, " ")
			contextStr = strings.ReplaceAll(contextStr, "\n", " ")
			contextStr = strings.ReplaceAll(contextStr, "\t", " ")
			contextStr = strings.ReplaceAll(contextStr, "  ", " ")
			contextStr = strings.TrimSpace(contextStr)

			// Limit context length
			if len(contextStr) > 200 {
				contextStr = contextStr[:200] + "..."
			}

			return contextStr
		}
	}

	return "Context not found"
}

func (s *APKScanner) prepareSummaryData(results map[string][]string) reporter.SummaryData {
	// Count files processed (this is an approximation)
	totalFiles := 0
	filepath.Walk(s.tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isRelevantFile(path) {
			totalFiles++
		}
		return nil
	})

	// Count patterns loaded
	totalPatterns := len(s.patterns)

	// Count vulnerabilities and risk levels
	vulnerabilities := 0
	highRisk := 0
	mediumRisk := 0
	lowRisk := 0

	for category, findings := range results {
		if len(findings) == 0 {
			continue
		}

		vulnerabilities += len(findings)

		// Determine risk level based on category name
		categoryLower := strings.ToLower(category)
		if strings.Contains(categoryLower, "high") || strings.Contains(categoryLower, "critical") {
			highRisk += len(findings)
		} else if strings.Contains(categoryLower, "medium") {
			mediumRisk += len(findings)
		} else {
			lowRisk += len(findings)
		}
	}

	return reporter.SummaryData{
		TotalFiles:      totalFiles,
		TotalPatterns:   totalPatterns,
		Vulnerabilities: vulnerabilities,
		HighRisk:        highRisk,
	}
}

// Helper function to filter relevant files
func isRelevantFile(filename string) bool {
	// Always include AndroidManifest.xml regardless of location
	if strings.HasSuffix(filename, "AndroidManifest.xml") {
		return true
	}

	// Skip common resource and library files
	skipPaths := []string{
		"/res/anim/",
		"/res/color/",
		"/res/drawable/",
		"/res/layout/",
		"/res/menu/",
		"/res/mipmap/",
		"/res/xml/",
		"/resources/",
		"/META-INF/",
		"/kotlin/",
		"/okhttp3/",
		"/okio/",
	}

	for _, skip := range skipPaths {
		if strings.Contains(filename, skip) {
			return false
		}
	}

	// Focus on files that typically contain sensitive information
	relevantExts := []string{
		".java",       // Java source
		".kt",         // Kotlin source
		".xml",        // Configuration files
		".txt",        // Text files
		".json",       // JSON data
		".yaml",       // YAML data
		".yml",        // YAML data
		".properties", // Properties files
		".conf",       // Configuration files
		".config",     // Configuration files
		".plist",      // iOS/macOS property lists
		".db",         // Databases
		".sql",        // SQL files
		".env",        // Environment files
		".ini",        // INI configuration
		".html",       // HTML files
		".js",         // JavaScript files
		".php",        // PHP files
		".py",         // Python files
	}

	ext := strings.ToLower(filepath.Ext(filename))
	for _, relevantExt := range relevantExts {
		if ext == relevantExt {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// detectJanusVulnerabilityPure inspects the APK for presence of V1/V2/V3 schemes
// without verifying cryptographic signatures. It returns a one-line finding string.
func (s *APKScanner) detectJanusVulnerabilityPure() string {
	v1, v2, v3 := detectSigningSchemes(s.config.APKPath)
	if !v1 {
		return ""
	}
	var vuln, sev string
	if v2 || v3 {
		vuln = "Potentially Vulnerable"
		sev = "MEDIUM"
	} else {
		vuln = "Highly Vulnerable"
		sev = "HIGH"
	}
	return fmt.Sprintf("[%s] Janus Vulnerability: %s (V1:%t V2:%t V3:%t)", sev, vuln, v1, v2, v3)
}

// detectSigningSchemes checks:
// - V1: META-INF/*.RSA|*.DSA|*.EC entries
// - V2/V3: APK Signing Block IDs (0x7109871a for v2, 0xf05368c0 for v3)
func detectSigningSchemes(apkPath string) (v1, v2, v3 bool) {
	// V1 detection via META-INF
	if zr, err := zip.OpenReader(apkPath); err == nil {
		for _, f := range zr.File {
			name := strings.ToUpper(f.Name)
			if strings.HasPrefix(name, "META-INF/") &&
				(strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC")) {
				v1 = true
				break
			}
		}
		zr.Close()
	}

	// V2/V3 detection via APK Signing Block
	if v2Found, v3Found := detectV2V3BySigningBlock(apkPath); v2Found || v3Found {
		v2, v3 = v2Found, v3Found
	}
	return
}

// detectV2V3BySigningBlock parses the APK Signing Block located immediately
// before the ZIP Central Directory. It scans the ID-value pairs for known IDs.
func detectV2V3BySigningBlock(apkPath string) (bool, bool) {
	const (
		eocdSig       = 0x06054b50
		maxEOCDSearch = 0x10000 // 64 KiB
	)

	f, err := os.Open(apkPath)
	if err != nil {
		return false, false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return false, false
	}
	fileSize := fi.Size()
	readStart := fileSize - maxEOCDSearch
	if readStart < 0 {
		readStart = 0
	}
	bufSize := fileSize - readStart
	buf := make([]byte, bufSize)
	if _, err := f.ReadAt(buf, readStart); err != nil {
		return false, false
	}

	// Find EOCD
	var eocdOffset int64 = -1
	for i := len(buf) - 22; i >= 0; i-- { // min EOCD size is 22 bytes
		if binary.LittleEndian.Uint32(buf[i:]) == eocdSig {
			eocdOffset = readStart + int64(i)
			break
		}
	}
	if eocdOffset < 0 {
		return false, false
	}

	// Central directory offset at EOCD+16 (uint32 LE)
	cdOffset := int64(binary.LittleEndian.Uint32(buf[(eocdOffset-readStart)+16:]))

	// The APK Signing Block ends right before the central dir. Its structure:
	// [size (8 LE)] [pairs ...] [size (8 LE)] [magic (16 bytes)]
	// We need to read 24 bytes before cdOffset to get tail size+magic then hop back.
	tail := make([]byte, 24)
	if _, err := f.ReadAt(tail, cdOffset-24); err != nil {
		return false, false
	}
	// Verify magic "APK Sig Block 42"
	magic := tail[8:24]
	if string(magic) != "APK Sig Block 42" {
		return false, false
	}
	blockSize := int64(binary.LittleEndian.Uint64(tail[:8]))
	// The size counts everything except the first 8 bytes; total block = 8 + size
	totalBlockSize := 8 + blockSize
	startOfBlock := cdOffset - totalBlockSize
	if startOfBlock < 0 {
		return false, false
	}

	block := make([]byte, totalBlockSize)
	if _, err := f.ReadAt(block, startOfBlock); err != nil {
		return false, false
	}

	// Skip first 8 bytes (leading size)
	p := int64(8)
	end := totalBlockSize - 24 // before [size][magic]
	var hasV2, hasV3 bool
	for p < end {
		if p+8 > end {
			break
		}
		pairLen := int64(binary.LittleEndian.Uint64(block[p:]))
		p += 8
		if pairLen <= 4 || p+pairLen > end {
			break
		}
		id := binary.LittleEndian.Uint32(block[p:])
		switch id {
		case 0x7109871a: // V2 ID
			hasV2 = true
		case 0xf05368c0: // V3 ID
			hasV3 = true
		}
		p += pairLen
		if hasV2 && hasV3 {
			break
		}
	}
	return hasV2, hasV3
}
