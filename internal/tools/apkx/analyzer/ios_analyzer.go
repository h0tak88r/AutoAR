package analyzer

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// IOSAnalyzer handles iOS app analysis similar to MobSF
type IOSAnalyzer struct {
	config    *Config
	patterns  map[string][]string
	results   map[string][]IOSPatternMatch
	resultsMu sync.Mutex
	tempDir   string
}

// IOSAppInfo contains basic information about the iOS app
type IOSAppInfo struct {
	BundleID      string   `json:"bundle_id"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	BuildNumber   string   `json:"build_number"`
	MinimumOS     string   `json:"minimum_os"`
	Architectures []string `json:"architectures"`
	Size          int64    `json:"size"`
	SigningInfo   string   `json:"signing_info"`
}

type IOSBinaryInfo struct {
	ExecutableName string   `json:"executable_name"`
	ExecutablePath string   `json:"executable_path"`
	Architectures  []string `json:"architectures"`
	BinaryType     string   `json:"binary_type"`
	Libraries      []string `json:"libraries"`
	Symbols        []string `json:"symbols"`
}

// IOSVulnerability represents a security vulnerability found in the iOS app
type IOSVulnerability struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Context     string `json:"context,omitempty"`
}

// IOSPatternMatch represents a pattern match with structured information
type IOSPatternMatch struct {
	File    string `json:"file"`
	Keyword string `json:"keyword"`
	Context string `json:"context"`
}

// NewIOSAnalyzer creates a new iOS analyzer
func NewIOSAnalyzer(config *Config) *IOSAnalyzer {
	return &IOSAnalyzer{
		config:   config,
		patterns: make(map[string][]string),
		results:  make(map[string][]IOSPatternMatch),
	}
}

// AnalyzeIPA performs comprehensive analysis on an iOS app
func (a *IOSAnalyzer) AnalyzeIPA(ipaPath string) error {
	fmt.Printf("Starting iOS app analysis: %s\n", filepath.Base(ipaPath))

	// Validate IPA file first
	if err := a.validateIPAFile(ipaPath); err != nil {
		return fmt.Errorf("IPA file validation failed: %v", err)
	}

	// Load patterns
	if err := a.loadPatterns(); err != nil {
		return fmt.Errorf("failed to load patterns: %v", err)
	}

	// Extract IPA
	extractDir, err := a.extractIPA(ipaPath)
	if err != nil {
		return fmt.Errorf("failed to extract IPA: %v", err)
	}
	defer os.RemoveAll(extractDir)

	// Analyze app info
	appInfo, err := a.analyzeAppInfo(extractDir)
	if err != nil {
		fmt.Printf("Warning: failed to analyze app info: %v\n", err)
	}

	// Analyze binary
	var binaryInfo *IOSBinaryInfo
	appBundlePath, err := a.findAppBundle(extractDir)
	if err != nil {
		fmt.Printf("Warning: failed to find app bundle: %v\n", err)
		binaryInfo = &IOSBinaryInfo{}
	} else {
		binaryInfo, err = a.analyzeBinary(appBundlePath)
		if err != nil {
			fmt.Printf("Warning: Binary analysis failed: %v\n", err)
			binaryInfo = &IOSBinaryInfo{}
		}
	}

	// Perform static analysis
	if err := a.performStaticAnalysis(extractDir); err != nil {
		return fmt.Errorf("static analysis failed: %v", err)
	}

	// Perform security analysis
	vulnerabilities, err := a.performSecurityAnalysis(extractDir)
	if err != nil {
		fmt.Printf("Warning: security analysis failed: %v\n", err)
	}

	// Copy important files to report directory
	a.copyIOSFiles(extractDir)

	// Generate reports
	if err := a.generateReports(ipaPath, appInfo, binaryInfo, vulnerabilities); err != nil {
		return fmt.Errorf("failed to generate reports: %v", err)
	}

	fmt.Printf("iOS app analysis completed successfully\n")
	return nil
}

// extractIPA extracts the IPA file to a temporary directory
func (a *IOSAnalyzer) extractIPA(ipaPath string) (string, error) {
	// Validate file exists and is readable
	if _, err := os.Stat(ipaPath); err != nil {
		return "", fmt.Errorf("IPA file not found or not accessible: %v", err)
	}

	// Check file size
	fileInfo, err := os.Stat(ipaPath)
	if err != nil {
		return "", fmt.Errorf("cannot stat IPA file: %v", err)
	}

	if fileInfo.Size() == 0 {
		return "", fmt.Errorf("IPA file is empty")
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "apkx-ios-")
	if err != nil {
		return "", err
	}

	// Open IPA file as zip
	reader, err := zip.OpenReader(ipaPath)
	if err != nil {
		os.RemoveAll(tempDir)
		// Provide more specific error information
		if strings.Contains(err.Error(), "not a valid zip file") {
			return "", fmt.Errorf("IPA file is not a valid ZIP archive. This might be a corrupted file or not an IPA file at all. Original error: %v", err)
		}
		return "", fmt.Errorf("failed to open IPA file as ZIP: %v", err)
	}
	defer reader.Close()

	// Extract all files
	for _, file := range reader.File {
		path := filepath.Join(tempDir, file.Name)

		// Skip if it's a directory
		if file.FileInfo().IsDir() {
			os.MkdirAll(path, file.FileInfo().Mode())
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return "", err
		}

		// Extract file
		rc, err := file.Open()
		if err != nil {
			return "", err
		}

		outFile, err := os.Create(path)
		if err != nil {
			rc.Close()
			return "", err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return "", err
		}
	}

	// Find the Payload directory (standard IPA structure)
	payloadDir, err := a.findPayloadDirectory(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", fmt.Errorf("failed to find Payload directory: %v", err)
	}

	return payloadDir, nil
}

// validateIPAFile validates that the file is a proper IPA file
func (a *IOSAnalyzer) validateIPAFile(ipaPath string) error {
	// Check if file exists
	if _, err := os.Stat(ipaPath); err != nil {
		return fmt.Errorf("file not found: %v", err)
	}

	// Check file extension
	if !strings.HasSuffix(strings.ToLower(ipaPath), ".ipa") {
		return fmt.Errorf("file does not have .ipa extension")
	}

	// Check file size
	fileInfo, err := os.Stat(ipaPath)
	if err != nil {
		return fmt.Errorf("cannot stat file: %v", err)
	}

	if fileInfo.Size() == 0 {
		return fmt.Errorf("file is empty")
	}

	// Check if file is a valid ZIP archive by trying to open it
	reader, err := zip.OpenReader(ipaPath)
	if err != nil {
		if strings.Contains(err.Error(), "not a valid zip file") {
			return fmt.Errorf("file is not a valid ZIP archive (IPA files are ZIP archives). This might be a corrupted file or not an IPA file at all")
		}
		return fmt.Errorf("cannot open file as ZIP archive: %v", err)
	}
	defer reader.Close()

	// Check if it has the expected IPA structure (Payload directory)
	hasPayload := false
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "Payload/") {
			hasPayload = true
			break
		}
	}

	if !hasPayload {
		return fmt.Errorf("file does not contain a Payload directory, which is required for IPA files")
	}

	return nil
}

// findPayloadDirectory finds the Payload directory in the extracted IPA
func (a *IOSAnalyzer) findPayloadDirectory(extractDir string) (string, error) {
	// Look for Payload directory (case-insensitive)
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return "", err
	}

	for _, entry := range entries {
		if strings.ToLower(entry.Name()) == "payload" && entry.IsDir() {
			return filepath.Join(extractDir, entry.Name()), nil
		}
	}

	return "", fmt.Errorf("Payload directory not found in IPA")
}

// analyzeAppInfo extracts basic information about the iOS app
func (a *IOSAnalyzer) analyzeAppInfo(extractDir string) (*IOSAppInfo, error) {
	info := &IOSAppInfo{}

	// Find the .app bundle
	appBundlePath, err := a.findAppBundle(extractDir)
	if err != nil {
		return nil, err
	}

	// Read Info.plist
	infoPlistPath := filepath.Join(appBundlePath, "Info.plist")
	if _, err := os.Stat(infoPlistPath); err == nil {
		// Parse Info.plist using improved parser
		plistData, err := a.parsePlistFile(infoPlistPath)
		if err == nil {
			// Extract basic info from parsed plist
			if val, ok := plistData["CFBundleIdentifier"]; ok {
				info.BundleID = fmt.Sprintf("%v", val)
			}
			if val, ok := plistData["CFBundleName"]; ok {
				info.Name = fmt.Sprintf("%v", val)
			}
			if val, ok := plistData["CFBundleShortVersionString"]; ok {
				info.Version = fmt.Sprintf("%v", val)
			}
			if val, ok := plistData["CFBundleVersion"]; ok {
				info.BuildNumber = fmt.Sprintf("%v", val)
			}
			if val, ok := plistData["MinimumOSVersion"]; ok {
				info.MinimumOS = fmt.Sprintf("%v", val)
			}
		} else {
			// Fallback to regex parsing
			content, err := os.ReadFile(infoPlistPath)
			if err == nil {
				info.BundleID = a.extractFromPlist(content, "CFBundleIdentifier")
				info.Name = a.extractFromPlist(content, "CFBundleName")
				info.Version = a.extractFromPlist(content, "CFBundleShortVersionString")
				info.BuildNumber = a.extractFromPlist(content, "CFBundleVersion")
				info.MinimumOS = a.extractFromPlist(content, "MinimumOSVersion")
			}
		}
	}

	// Get file size
	if stat, err := os.Stat(appBundlePath); err == nil {
		info.Size = stat.Size()
	}

	// Get architectures
	info.Architectures = a.getArchitectures(appBundlePath)

	return info, nil
}

// findAppBundle finds the .app bundle inside the extracted IPA
func (a *IOSAnalyzer) findAppBundle(extractDir string) (string, error) {
	var appBundlePath string

	err := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() && strings.HasSuffix(path, ".app") {
			appBundlePath = path
			return filepath.SkipDir // Stop walking once we find the app bundle
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	if appBundlePath == "" {
		return "", fmt.Errorf("no .app bundle found in IPA")
	}

	return appBundlePath, nil
}

// extractFromPlist extracts a value from plist content using regex
func (a *IOSAnalyzer) extractFromPlist(content []byte, key string) string {
	// This is a simplified approach - in production, use a proper plist parser
	pattern := fmt.Sprintf(`<key>%s</key>\s*<string>([^<]+)</string>`, key)
	re := regexp.MustCompile(pattern)
	matches := re.FindSubmatch(content)
	if len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

// parsePlistFile parses a plist file and returns a map of key-value pairs
func (a *IOSAnalyzer) parsePlistFile(plistPath string) (map[string]interface{}, error) {
	content, err := os.ReadFile(plistPath)
	if err != nil {
		return nil, err
	}

	// Try to parse as XML plist first
	if strings.Contains(string(content), "<?xml") {
		return a.parseXMLPlist(content)
	}

	// Try to parse as binary plist (simplified)
	return a.parseBinaryPlist(content)
}

// parseXMLPlist parses XML plist format
func (a *IOSAnalyzer) parseXMLPlist(content []byte) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// Extract key-value pairs using regex (simplified approach)
	keyPattern := regexp.MustCompile(`<key>([^<]+)</key>\s*<([^>]+)>([^<]*)</[^>]+>`)
	matches := keyPattern.FindAllSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			key := string(match[1])
			valueType := string(match[2])
			value := string(match[3])

			// Convert value based on type
			switch valueType {
			case "string":
				result[key] = value
			case "integer":
				if intVal, err := strconv.Atoi(value); err == nil {
					result[key] = intVal
				} else {
					result[key] = value
				}
			case "true":
				result[key] = true
			case "false":
				result[key] = false
			default:
				result[key] = value
			}
		}
	}

	return result, nil
}

// parseBinaryPlist parses binary plist format (simplified)
func (a *IOSAnalyzer) parseBinaryPlist(content []byte) (map[string]interface{}, error) {
	// Convert binary plist to XML first, then parse
	xmlContent := a.convertPlistToText(content, "")

	// Parse the XML content
	return a.parseXMLPlist([]byte(xmlContent))
}

// extractKeyValuePairsFromBinaryPlist extracts key-value pairs from binary plist
func (a *IOSAnalyzer) extractKeyValuePairsFromBinaryPlist(plistContent []byte) map[string]string {
	pairs := make(map[string]string)

	// Simple extraction of readable strings
	content := string(plistContent)

	// Look for specific patterns in the binary plist content
	// Extract bundle identifier
	if bundleID := a.extractBundleIdentifier(content); bundleID != "" {
		pairs["CFBundleIdentifier"] = bundleID
	}

	// Extract app name
	if appName := a.extractAppName(content); appName != "" {
		pairs["CFBundleName"] = appName
	}

	// Extract version
	if version := a.extractVersion(content); version != "" {
		pairs["CFBundleShortVersionString"] = version
	}

	// Extract build number
	if buildNumber := a.extractBuildNumber(content); buildNumber != "" {
		pairs["CFBundleVersion"] = buildNumber
	}

	// Extract minimum OS version
	if minOS := a.extractMinimumOSVersion(content); minOS != "" {
		pairs["MinimumOSVersion"] = minOS
	}

	return pairs
}

// extractBundleIdentifier extracts the bundle identifier from binary plist
func (a *IOSAnalyzer) extractBundleIdentifier(content string) string {
	// Look for com. patterns in the content
	re := regexp.MustCompile(`com\.[a-zA-Z0-9.-]+`)
	matches := re.FindAllString(content, -1)

	for _, match := range matches {
		// Filter out common false positives and look for the actual bundle ID
		if !strings.Contains(match, "apple.com") &&
			!strings.Contains(match, "compilers") &&
			!strings.Contains(match, "T") &&
			!strings.Contains(match, "\\") &&
			!strings.Contains(match, "S6.0TAPPLS2.0") &&
			len(match) > 10 {
			// This looks like a real bundle identifier
			return match
		}
	}

	return ""
}

// extractAppName extracts the app name from binary plist
func (a *IOSAnalyzer) extractAppName(content string) string {
	// Look for app names that don't contain special characters
	re := regexp.MustCompile(`[A-Za-z][A-Za-z0-9_-]{2,}`)
	matches := re.FindAllString(content, -1)

	for _, match := range matches {
		// Filter out common false positives and look for app names
		if !strings.Contains(match, "CFBundle") &&
			!strings.Contains(match, "UI") &&
			!strings.Contains(match, "NS") &&
			!strings.Contains(match, "DT") &&
			!strings.Contains(match, "Build") &&
			!strings.Contains(match, "Version") &&
			!strings.Contains(match, "Platform") &&
			!strings.Contains(match, "T") &&
			!strings.Contains(match, "\\") &&
			!strings.Contains(match, "S6.0TAPPLS2.0") &&
			!strings.Contains(match, "compilers") &&
			len(match) > 3 {
			// This looks like an app name
			return match
		}
	}

	return ""
}

// extractVersion extracts the version from binary plist
func (a *IOSAnalyzer) extractVersion(content string) string {
	// Look for version patterns like 1.0, 2.1.3, etc.
	re := regexp.MustCompile(`[0-9]+\.[0-9]+(?:\.[0-9]+)?`)
	matches := re.FindAllString(content, -1)

	for _, match := range matches {
		// Filter out build numbers and other numeric patterns
		if len(match) <= 10 && !strings.Contains(match, "T") {
			return match
		}
	}

	return ""
}

// extractBuildNumber extracts the build number from binary plist
func (a *IOSAnalyzer) extractBuildNumber(content string) string {
	// Look for build number patterns
	re := regexp.MustCompile(`[0-9]{3,}`)
	matches := re.FindAllString(content, -1)

	for _, match := range matches {
		// Filter out very long numbers and common false positives
		if len(match) >= 3 && len(match) <= 6 && !strings.Contains(match, "T") {
			return match
		}
	}

	return ""
}

// extractMinimumOSVersion extracts the minimum OS version from binary plist
func (a *IOSAnalyzer) extractMinimumOSVersion(content string) string {
	// Look for iOS version patterns
	re := regexp.MustCompile(`[0-9]+\.[0-9]+`)
	matches := re.FindAllString(content, -1)

	for _, match := range matches {
		// Look for reasonable iOS version numbers
		if len(match) <= 5 && !strings.Contains(match, "T") {
			// Check if it's a reasonable iOS version (8.0 to 20.0)
			if parts := strings.Split(match, "."); len(parts) == 2 {
				if major, err := strconv.Atoi(parts[0]); err == nil {
					if major >= 8 && major <= 20 {
						return match
					}
				}
			}
		}
	}

	return ""
}

// extractValueAfterKey extracts a value that appears after a key in binary plist
func (a *IOSAnalyzer) extractValueAfterKey(searchArea, key string) string {
	// Look for common value patterns after the key
	patterns := []string{
		`com\.[a-zA-Z0-9.-]+`,         // Bundle identifiers
		`[0-9]+\.[0-9]+(?:\.[0-9]+)?`, // Version numbers
		`[a-zA-Z0-9_-]{3,}`,           // General strings
		`iPhoneOS|iPadOS|iOS`,         // OS names
		`arm64|armv7|armv7s|x86_64`,   // Architectures
		`[A-Za-z0-9_-]{2,}\.app`,      // App names
		`[A-Za-z0-9_-]{2,}\.dylib`,    // Library names
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(searchArea, 1)
		if len(matches) > 0 {
			value := matches[0]
			// Filter out very short or common values
			if len(value) > 2 && !a.isCommonPlistKey(value) {
				return value
			}
		}
	}

	// If no pattern matches, try to extract any readable string
	// Look for strings that start with letters and contain alphanumeric characters
	re := regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9._-]{2,}`)
	matches := re.FindAllString(searchArea, 1)
	if len(matches) > 0 {
		value := matches[0]
		// Filter out common plist keys and very short values
		if len(value) > 3 && !a.isCommonPlistKey(value) && !strings.HasPrefix(value, "CFBundle") && !strings.HasPrefix(value, "UI") && !strings.HasPrefix(value, "NS") {
			return value
		}
	}

	return ""
}

// isCommonPlistKey checks if a string is a common plist key (not a value)
func (a *IOSAnalyzer) isCommonPlistKey(str string) bool {
	commonKeys := []string{
		"CFBundleInfoDictionaryVersion", "CFBundleName", "CFBundlePackageType",
		"CFBundleSupportedPlatforms", "BuildMachineOSBuild", "CFBundleDevelopmentRegion",
		"CFBundleExecutable", "NSManagedObjectModel", "VersionHashes", "CurrentVersionName",
		"NSBundle", "NSPrincipalClass", "NSAppTransportSecurity", "CFBundleVersion",
		"CFBundleShortVersionString", "MinimumOSVersion", "UIRequiredDeviceCapabilities",
		"UISupportedInterfaceOrientations", "UIMainStoryboardFile", "UILaunchStoryboardName",
		"LSRequiresIPhoneOS", "UIDeviceFamily", "CFBundleURLTypes", "CFBundleURLSchemes",
		"CFBundleURLName", "NSAllowsArbitraryLoads", "NSCameraUsageDescription",
		"NSLocationUsageDescription", "NSMicrophoneUsageDescription", "NSPhotoLibraryUsageDescription",
		"NSContactsUsageDescription", "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysUsageDescription",
		"CFBundleIcons", "CFBundleIconFiles", "CFBundleIconName", "CFBundlePrimaryIcon",
		"UILaunchImages", "UILaunchImageName", "UILaunchImageOrientation", "UILaunchImageSize",
		"UIInterfaceOrientationPortrait", "UIInterfaceOrientationPortraitUpsideDown",
		"UIInterfaceOrientationLandscapeLeft", "UIInterfaceOrientationLandscapeRight",
		"CFBundleDevelopmentRegion", "CFBundleInfoDictionaryVersion", "DTPlatformBuild",
		"DTPlatformName", "DTPlatformVersion", "DTSDKBuild", "DTSDKName", "DTXcode",
		"DTXcodeBuild", "BuildMachineOSBuild", "CFBundleSignature",
	}

	for _, key := range commonKeys {
		if strings.Contains(str, key) {
			return true
		}
	}

	return false
}

// getArchitectures returns the architectures supported by the app
func (a *IOSAnalyzer) getArchitectures(appBundlePath string) []string {
	// Look for binary files and check their architectures
	var architectures []string

	// Find the main executable
	infoPlistPath := filepath.Join(appBundlePath, "Info.plist")
	if content, err := os.ReadFile(infoPlistPath); err == nil {
		executableName := a.extractFromPlist(content, "CFBundleExecutable")
		if executableName != "" {
			executablePath := filepath.Join(appBundlePath, executableName)
			if _, err := os.Stat(executablePath); err == nil {
				// Use file command to get architecture info
				architectures = a.getBinaryArchitectures(executablePath)
			}
		}
	}

	if len(architectures) == 0 {
		architectures = []string{"unknown"}
	}

	return architectures
}

// analyzeBinary performs Mach-O binary analysis similar to MobSF
func (a *IOSAnalyzer) analyzeBinary(appBundlePath string) (*IOSBinaryInfo, error) {
	info := &IOSBinaryInfo{}

	// Find the main executable
	infoPlistPath := filepath.Join(appBundlePath, "Info.plist")
	content, err := os.ReadFile(infoPlistPath)
	if err != nil {
		return info, err
	}

	executableName := a.extractFromPlist(content, "CFBundleExecutable")
	if executableName == "" {
		// Try to find any executable in the bundle
		entries, err := os.ReadDir(appBundlePath)
		if err != nil {
			return info, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				// Check if file is executable by trying to stat it
				filePath := filepath.Join(appBundlePath, entry.Name())
				if stat, err := os.Stat(filePath); err == nil && stat.Mode()&0111 != 0 {
					executableName = entry.Name()
					break
				}
			}
		}
	}

	if executableName == "" {
		return info, fmt.Errorf("no executable found in app bundle")
	}

	executablePath := filepath.Join(appBundlePath, executableName)
	if _, err := os.Stat(executablePath); err != nil {
		return info, err
	}

	// Get binary information using file command
	info.Architectures = a.getBinaryArchitectures(executablePath)
	info.ExecutableName = executableName
	info.ExecutablePath = executablePath

	// Get binary type (Objective-C vs Swift)
	info.BinaryType = a.detectBinaryType(executablePath)

	// Get libraries and frameworks
	info.Libraries = a.getBinaryLibraries(executablePath)

	// Get symbols (simplified)
	info.Symbols = a.getBinarySymbols(executablePath)

	return info, nil
}

// detectBinaryType detects if the binary is Objective-C or Swift
func (a *IOSAnalyzer) detectBinaryType(executablePath string) string {
	// Use otool to check for Swift libraries
	cmd := exec.Command("otool", "-L", executablePath)
	output, err := cmd.Output()
	if err != nil {
		return "Unknown"
	}

	// Check for Swift runtime libraries
	if strings.Contains(string(output), "libswiftCore.dylib") {
		return "Swift"
	}
	return "Objective-C"
}

// getBinaryLibraries gets the libraries linked by the binary
func (a *IOSAnalyzer) getBinaryLibraries(executablePath string) []string {
	cmd := exec.Command("otool", "-L", executablePath)
	output, err := cmd.Output()
	if err != nil {
		return []string{}
	}

	var libraries []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ".dylib") || strings.Contains(line, ".framework") {
			// Extract library name
			parts := strings.Fields(line)
			if len(parts) > 0 {
				lib := parts[0]
				if strings.Contains(lib, "/") {
					lib = filepath.Base(lib)
				}
				libraries = append(libraries, lib)
			}
		}
	}

	return libraries
}

// getBinarySymbols gets symbols from the binary (simplified)
func (a *IOSAnalyzer) getBinarySymbols(executablePath string) []string {
	cmd := exec.Command("nm", "-u", executablePath)
	output, err := cmd.Output()
	if err != nil {
		return []string{}
	}

	var symbols []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "U ") {
			symbols = append(symbols, line)
		}
	}

	return symbols
}

// getBinaryArchitectures uses the file command to determine binary architectures
func (a *IOSAnalyzer) getBinaryArchitectures(binaryPath string) []string {
	// This would require executing the 'file' command
	// For now, return a placeholder
	return []string{"arm64", "armv7"}
}

// performStaticAnalysis performs static analysis on the extracted app
func (a *IOSAnalyzer) performStaticAnalysis(extractDir string) error {
	fmt.Println("Performing static analysis...")

	// Collect all files to process (similar to APK scanner approach)
	var filesToProcess []string
	err := filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files that can't be accessed
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Use proper file filtering like APK scanner
		if !a.isRelevantFile(path) {
			return nil
		}

		filesToProcess = append(filesToProcess, path)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %v", err)
	}

	fmt.Printf("Analyzing %d relevant files...\n", len(filesToProcess))

	// Process files concurrently using the same approach as APK scanner
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.config.Workers)

	for _, filePath := range filesToProcess {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			matches := a.processFile(path, a.patterns)
			if len(matches) > 0 {
				a.resultsMu.Lock()
				for patternName, patternMatches := range matches {
					a.results[patternName] = append(a.results[patternName], patternMatches...)
				}
				a.resultsMu.Unlock()
			}
		}(filePath)
	}

	wg.Wait()
	return nil
}

// processFile processes a single file with patterns (similar to APK scanner)
func (a *IOSAnalyzer) processFile(path string, patterns map[string][]string) map[string][]IOSPatternMatch {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Convert binary plist to text if needed
	contentStr := a.convertPlistToText(content, path)

	matches := make(map[string][]IOSPatternMatch)
	seen := make(map[string]bool)

	// Get relative path for better output
	relPath := path
	if strings.Contains(path, a.tempDir) {
		if rel, err := filepath.Rel(a.tempDir, path); err == nil {
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
				if a.isCommonFalsePositive(match) {
					continue
				}

				// Get some context around the match (more context for better display)
				start := max(0, idx[0]-200)
				end := min(len(contentStr), idx[1]+200)
				context := contentStr[start:end]

				// Clean up context but preserve line breaks for code blocks
				context = strings.TrimSpace(context)

				// Create a structured pattern match
				patternMatch := IOSPatternMatch{
					File:    relPath,
					Keyword: match,
					Context: context,
				}
				matches[patternName] = append(matches[patternName], patternMatch)
				seen[match] = true
			}
		}
	}

	return matches
}

// convertPlistToText converts binary plist to text format for pattern matching
func (a *IOSAnalyzer) convertPlistToText(content []byte, filePath string) string {
	// Check if it's a binary plist
	if len(content) > 8 && string(content[:8]) == "bplist00" {
		// Try to convert binary plist to XML using plutil command
		tempFile, err := os.CreateTemp("", "apkx-plist-*")
		if err != nil {
			return string(content) // Fallback to original content
		}
		defer os.Remove(tempFile.Name())
		defer tempFile.Close()

		// Write binary plist to temp file
		if _, err := tempFile.Write(content); err != nil {
			return string(content)
		}
		tempFile.Close()

		// Convert using plutil
		cmd := exec.Command("plutil", "-convert", "xml1", "-o", "-", tempFile.Name())
		output, err := cmd.Output()
		if err != nil {
			// If plutil fails, try to extract readable strings from binary plist
			return a.extractStringsFromBinaryPlist(content)
		}

		return string(output)
	}

	// If it's already text, return as is
	return string(content)
}

// extractStringsFromBinaryPlist extracts readable strings from binary plist
func (a *IOSAnalyzer) extractStringsFromBinaryPlist(content []byte) string {
	// Simple string extraction from binary plist
	// This is a basic implementation - in production you might want to use a proper plist library
	var result strings.Builder

	// Look for ASCII strings in the binary data
	i := 0
	for i < len(content) {
		// Skip non-printable characters
		if content[i] < 32 || content[i] > 126 {
			i++
			continue
		}

		// Find start of potential string
		start := i
		for i < len(content) && content[i] >= 32 && content[i] <= 126 {
			i++
		}

		// If we found a string of reasonable length, add it
		if i-start > 3 {
			str := string(content[start:i])
			// Filter out very common plist keys that are not useful for pattern matching
			if !a.isCommonPlistKey(str) {
				result.WriteString(str)
				result.WriteString("\n")
			}
		}
	}

	return result.String()
}

// isCommonFalsePositive checks if a match is a common false positive
func (a *IOSAnalyzer) isCommonFalsePositive(match string) bool {
	// Common false positives for iOS
	falsePositives := []string{
		"http://www.apple.com/DTDs/PropertyList-1.0.dtd",
		"com.apple.developer",
		"NSAppTransportSecurity",
		"CFBundleIdentifier",
		"CFBundleName",
		"CFBundleVersion",
		"CFBundleShortVersionString",
		"MinimumOSVersion",
		"UIRequiredDeviceCapabilities",
		"UISupportedInterfaceOrientations",
		"UISupportedInterfaceOrientations~ipad",
		"UISupportedInterfaceOrientations~iphone",
		"UISupportedInterfaceOrientations~ipod",
		"UISupportedInterfaceOrientations~ipodtouch",
		"UISupportedInterfaceOrientations~iphone6",
		"UISupportedInterfaceOrientations~iphone6plus",
		"UISupportedInterfaceOrientations~iphone6s",
		"UISupportedInterfaceOrientations~iphone6splus",
		"UISupportedInterfaceOrientations~iphone7",
		"UISupportedInterfaceOrientations~iphone7plus",
		"UISupportedInterfaceOrientations~iphone8",
		"UISupportedInterfaceOrientations~iphone8plus",
		"UISupportedInterfaceOrientations~iphonex",
		"UISupportedInterfaceOrientations~iphonexs",
		"UISupportedInterfaceOrientations~iphonexsmax",
		"UISupportedInterfaceOrientations~iphonexr",
		"UISupportedInterfaceOrientations~iphone11",
		"UISupportedInterfaceOrientations~iphone11pro",
		"UISupportedInterfaceOrientations~iphone11promax",
		"UISupportedInterfaceOrientations~iphone12",
		"UISupportedInterfaceOrientations~iphone12mini",
		"UISupportedInterfaceOrientations~iphone12pro",
		"UISupportedInterfaceOrientations~iphone12promax",
		"UISupportedInterfaceOrientations~iphone13",
		"UISupportedInterfaceOrientations~iphone13mini",
		"UISupportedInterfaceOrientations~iphone13pro",
		"UISupportedInterfaceOrientations~iphone13promax",
		"UISupportedInterfaceOrientations~iphone14",
		"UISupportedInterfaceOrientations~iphone14plus",
		"UISupportedInterfaceOrientations~iphone14pro",
		"UISupportedInterfaceOrientations~iphone14promax",
		"UISupportedInterfaceOrientations~iphone15",
		"UISupportedInterfaceOrientations~iphone15plus",
		"UISupportedInterfaceOrientations~iphone15pro",
		"UISupportedInterfaceOrientations~iphone15promax",
	}

	for _, fp := range falsePositives {
		if strings.Contains(match, fp) {
			return true
		}
	}

	return false
}

// isBinaryFile checks if a file is likely binary
func (a *IOSAnalyzer) isBinaryFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := []string{".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf", ".zip", ".tar", ".gz"}

	for _, binaryExt := range binaryExts {
		if ext == binaryExt {
			return true
		}
	}

	return false
}

// isRelevantFile checks if a file is relevant for analysis (similar to APK scanner)
func (a *IOSAnalyzer) isRelevantFile(filename string) bool {
	// Always include Info.plist regardless of location
	if strings.HasSuffix(filename, "Info.plist") {
		return true
	}

	// Skip iOS-specific static directories and files that developers can't edit
	skipPaths := []string{
		// iOS system frameworks and libraries
		"/Frameworks/",
		"/System/Library/",
		"/usr/lib/",
		"/usr/share/",
		"/usr/bin/",
		"/bin/",
		"/sbin/",
		"/var/",
		"/etc/",
		"/tmp/",

		// iOS app bundle static content
		"/Base.lproj/",
		"/en.lproj/",
		"/es.lproj/",
		"/fr.lproj/",
		"/de.lproj/",
		"/it.lproj/",
		"/pt.lproj/",
		"/ru.lproj/",
		"/ja.lproj/",
		"/ko.lproj/",
		"/zh.lproj/",
		"/zh-Hans.lproj/",
		"/zh-Hant.lproj/",

		// iOS resources that are typically static
		"/Resources/",
		"/Assets.car",
		"/CodeResources",
		"/embedded.mobileprovision",
		"/_CodeSignature/",
		"/SC_Info/",

		// Third-party frameworks (usually static)
		"/Alamofire.framework/",
		"/AFNetworking.framework/",
		"/SDWebImage.framework/",
		"/Realm.framework/",
		"/Firebase.framework/",
		"/GoogleMaps.framework/",
		"/Bolts.framework/",
		"/FBSDKCoreKit.framework/",
		"/FBSDKLoginKit.framework/",
		"/FBSDKShareKit.framework/",
		"/TwitterKit.framework/",
		"/Fabric.framework/",
		"/Crashlytics.framework/",
		"/Answers.framework/",
		"/Branch.framework/",
		"/AppsFlyer.framework/",
		"/Adjust.framework/",
		"/Amplitude.framework/",
		"/Mixpanel.framework/",
		"/Segment.framework/",
		"/Intercom.framework/",
		"/Zendesk.framework/",
		"/Stripe.framework/",
		"/PayPal.framework/",
		"/Braintree.framework/",
		"/Square.framework/",
		"/OneSignal.framework/",
		"/Pushwoosh.framework/",
		"/UrbanAirship.framework/",
		"/Leanplum.framework/",
		"/Localytics.framework/",
		"/Flurry.framework/",
		"/AppDynamics.framework/",
		"/NewRelic.framework/",
		"/HockeyApp.framework/",
		"/TestFlight.framework/",
		"/AppCenter.framework/",
		"/Sentry.framework/",
		"/Bugsnag.framework/",
		"/Instabug.framework/",
		"/Rollbar.framework/",
		"/Raygun.framework/",
		"/Crittercism.framework/",
		"/Apteligent.framework/",
		"/Crashlytics.framework/",
		"/Fabric.framework/",
		"/Answers.framework/",
		"/MoEngage.framework/",
		"/CleverTap.framework/",
		"/Apptimize.framework/",
		"/Optimizely.framework/",
		"/Apptentive.framework/",
		"/Helpshift.framework/",
		"/Zendesk.framework/",
		"/Freshdesk.framework/",
		"/Intercom.framework/",
		"/Drift.framework/",
		"/Crisp.framework/",
		"/Tawk.framework/",
		"/LiveChat.framework/",
		"/Olark.framework/",
		"/Zopim.framework/",
		"/UserVoice.framework/",
		"/Uservoice.framework/",
		"/GetSatisfaction.framework/",
		"/Usabilla.framework/",
		"/Apptentive.framework/",
		"/Helpshift.framework/",
		"/Zendesk.framework/",
		"/Freshdesk.framework/",
		"/Intercom.framework/",
		"/Drift.framework/",
		"/Crisp.framework/",
		"/Tawk.framework/",
		"/LiveChat.framework/",
		"/Olark.framework/",
		"/Zopim.framework/",
		"/UserVoice.framework/",
		"/Uservoice.framework/",
		"/GetSatisfaction.framework/",
		"/Usabilla.framework/",

		// Common static file patterns
		".nib",
		".storyboardc",
		".car",
		".mom",
		".momd",
		".cdb",
		".sqlite",
		".db",
		".strings",
		".lproj",
		".bundle",
		".framework",
		".dylib",
		".a",
		".o",
		".so",
		".dylib",
		".tbd",
		".dSYM",
		".appex",
		".xctest",
		".xctestbundle",
		".xcconfig",
		".xccheckout",
		".xcworkspace",
		".xcuserdata",
		".xcscmblueprint",
		".xcuserstate",
		".xcarchive",
		".ipa",
		".app",
		".dmg",
		".pkg",
		".mpkg",
		".dmg",
		".iso",
		".img",
		".toast",
		".udif",
		".sparseimage",
		".sparsebundle",
		".dmgpart",
		".partimage",
		".raw",
		".img",
		".iso",
		".bin",
		".cue",
		".mdf",
		".mds",
		".nrg",
		".ccd",
		".sub",
		".img",
		".bin",
		".cue",
		".mdf",
		".mds",
		".nrg",
		".ccd",
		".sub",
		".img",
		".bin",
		".cue",
		".mdf",
		".mds",
		".nrg",
		".ccd",
		".sub",
	}

	// Check if file should be skipped based on path
	for _, skip := range skipPaths {
		if strings.Contains(filename, skip) {
			return false
		}
	}

	// Focus on files that typically contain sensitive information
	relevantExts := []string{
		".swift",      // Swift source
		".m",          // Objective-C source
		".mm",         // Objective-C++ source
		".h",          // Header files
		".plist",      // Property lists
		".xml",        // Configuration files
		".txt",        // Text files
		".json",       // JSON data
		".yaml",       // YAML data
		".yml",        // YAML data
		".properties", // Properties files
		".conf",       // Configuration files
		".config",     // Configuration files
		".db",         // Databases
		".sql",        // SQL files
		".env",        // Environment files
		".ini",        // INI configuration
		".html",       // HTML files
		".js",         // JavaScript files
		".php",        // PHP files
		".py",         // Python files
		".rb",         // Ruby files
		".go",         // Go files
		".rs",         // Rust files
		".cpp",        // C++ files
		".c",          // C files
		".hpp",        // C++ header files
		".hxx",        // C++ header files
		".cc",         // C++ files
		".cxx",        // C++ files
		".cs",         // C# files
		".java",       // Java files
		".kt",         // Kotlin files
		".scala",      // Scala files
		".clj",        // Clojure files
		".hs",         // Haskell files
		".ml",         // OCaml files
		".fs",         // F# files
		".vb",         // VB.NET files
		".dart",       // Dart files
		".ts",         // TypeScript files
		".jsx",        // React JSX files
		".tsx",        // React TypeScript files
		".vue",        // Vue.js files
		".svelte",     // Svelte files
		".elm",        // Elm files
		".purs",       // PureScript files
		".rkt",        // Racket files
		".lisp",       // Lisp files
		".scm",        // Scheme files
		".r",          // R files
		".matlab",     // MATLAB files
		".octave",     // Octave files
		".jl",         // Julia files
		".pl",         // Perl files
		".pm",         // Perl module files
		".t",          // Perl test files
		".sh",         // Shell scripts
		".bash",       // Bash scripts
		".zsh",        // Zsh scripts
		".fish",       // Fish scripts
		".ps1",        // PowerShell scripts
		".psm1",       // PowerShell module files
		".psd1",       // PowerShell data files
		".bat",        // Batch files
		".cmd",        // Command files
		".vbs",        // VBScript files
		".wsf",        // Windows Script files
		".jse",        // JScript files
		".wsc",        // Windows Script Component files
		".sct",        // Windows Script Component files
		".wsh",        // Windows Script Host files
		".hta",        // HTML Application files
	}

	ext := strings.ToLower(filepath.Ext(filename))
	for _, relevantExt := range relevantExts {
		if ext == relevantExt {
			return true
		}
	}
	return false
}

// performSecurityAnalysis performs security-specific analysis
func (a *IOSAnalyzer) performSecurityAnalysis(extractDir string) ([]IOSVulnerability, error) {
	var vulnerabilities []IOSVulnerability

	// Check for common iOS security issues
	vulnerabilities = append(vulnerabilities, a.checkKeychainAccess(extractDir)...)
	vulnerabilities = append(vulnerabilities, a.checkURLSchemes(extractDir)...)
	vulnerabilities = append(vulnerabilities, a.checkFileProtection(extractDir)...)
	vulnerabilities = append(vulnerabilities, a.checkTransportSecurity(extractDir)...)
	vulnerabilities = append(vulnerabilities, a.checkJailbreakDetection(extractDir)...)

	return vulnerabilities, nil
}

// checkKeychainAccess checks for keychain access patterns
func (a *IOSAnalyzer) checkKeychainAccess(extractDir string) []IOSVulnerability {
	var vulnerabilities []IOSVulnerability

	// Look for keychain access patterns
	keychainPatterns := []string{
		`kSecAttrAccessibleWhenUnlocked`,
		`kSecAttrAccessibleAfterFirstUnlock`,
		`kSecAttrAccessibleAlways`,
		`SecItemAdd`,
		`SecItemUpdate`,
		`SecItemDelete`,
	}

	for _, pattern := range keychainPatterns {
		re := regexp.MustCompile(pattern)
		if matches := a.searchInFiles(extractDir, re); len(matches) > 0 {
			vulnerabilities = append(vulnerabilities, IOSVulnerability{
				Category:    "Keychain Access",
				Severity:    "Medium",
				Title:       "Keychain Access Detected",
				Description: "The app accesses the iOS keychain for storing sensitive data",
				Context:     strings.Join(matches, ", "),
			})
		}
	}

	return vulnerabilities
}

// checkURLSchemes checks for custom URL schemes
func (a *IOSAnalyzer) checkURLSchemes(extractDir string) []IOSVulnerability {
	var vulnerabilities []IOSVulnerability

	// Look for URL scheme patterns
	urlSchemePattern := regexp.MustCompile(`CFBundleURLSchemes.*?<string>([^<]+)</string>`)
	if matches := a.searchInFiles(extractDir, urlSchemePattern); len(matches) > 0 {
		vulnerabilities = append(vulnerabilities, IOSVulnerability{
			Category:    "URL Schemes",
			Severity:    "Low",
			Title:       "Custom URL Schemes Detected",
			Description: "The app defines custom URL schemes that could be exploited",
			Context:     strings.Join(matches, ", "),
		})
	}

	return vulnerabilities
}

// checkFileProtection checks for file protection settings
func (a *IOSAnalyzer) checkFileProtection(extractDir string) []IOSVulnerability {
	var vulnerabilities []IOSVulnerability

	// Look for file protection patterns
	protectionPatterns := []string{
		`NSFileProtectionComplete`,
		`NSFileProtectionCompleteUnlessOpen`,
		`NSFileProtectionCompleteUntilFirstUserAuthentication`,
		`NSFileProtectionNone`,
	}

	for _, pattern := range protectionPatterns {
		re := regexp.MustCompile(pattern)
		if matches := a.searchInFiles(extractDir, re); len(matches) > 0 {
			severity := "Low"
			if pattern == "NSFileProtectionNone" {
				severity = "High"
			}

			vulnerabilities = append(vulnerabilities, IOSVulnerability{
				Category:    "File Protection",
				Severity:    severity,
				Title:       "File Protection Settings Detected",
				Description: fmt.Sprintf("The app uses %s for file protection", pattern),
				Context:     strings.Join(matches, ", "),
			})
		}
	}

	return vulnerabilities
}

// checkTransportSecurity checks for transport security settings
func (a *IOSAnalyzer) checkTransportSecurity(extractDir string) []IOSVulnerability {
	var vulnerabilities []IOSVulnerability

	// Look for NSAppTransportSecurity settings
	atsPattern := regexp.MustCompile(`NSAppTransportSecurity`)
	if matches := a.searchInFiles(extractDir, atsPattern); len(matches) > 0 {
		vulnerabilities = append(vulnerabilities, IOSVulnerability{
			Category:    "Transport Security",
			Severity:    "Medium",
			Title:       "App Transport Security Configured",
			Description: "The app has custom ATS settings that may weaken security",
			Context:     strings.Join(matches, ", "),
		})
	}

	return vulnerabilities
}

// checkJailbreakDetection checks for jailbreak detection
func (a *IOSAnalyzer) checkJailbreakDetection(extractDir string) []IOSVulnerability {
	var vulnerabilities []IOSVulnerability

	// Look for jailbreak detection patterns
	jailbreakPatterns := []string{
		`/Applications/Cydia.app`,
		`/usr/sbin/sshd`,
		`/bin/bash`,
		`/etc/apt`,
		`cydia://`,
		`MobileSubstrate`,
	}

	for _, pattern := range jailbreakPatterns {
		re := regexp.MustCompile(regexp.QuoteMeta(pattern))
		if matches := a.searchInFiles(extractDir, re); len(matches) > 0 {
			vulnerabilities = append(vulnerabilities, IOSVulnerability{
				Category:    "Jailbreak Detection",
				Severity:    "Low",
				Title:       "Jailbreak Detection Detected",
				Description: "The app contains jailbreak detection mechanisms",
				Context:     strings.Join(matches, ", "),
			})
		}
	}

	return vulnerabilities
}

// searchInFiles searches for a pattern in all files
func (a *IOSAnalyzer) searchInFiles(extractDir string, pattern *regexp.Regexp) []string {
	var matches []string

	filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || a.isBinaryFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		if pattern.Match(content) {
			matches = append(matches, path)
		}

		return nil
	})

	return matches
}

// loadPatterns loads analysis patterns from the patterns file
func (a *IOSAnalyzer) loadPatterns() error {
	var content []byte
	var err error

	if a.config.PatternsPath != "" {
		content, err = os.ReadFile(a.config.PatternsPath)
		if err != nil {
			return err
		}
	} else {
		content, err = patternsFS.ReadFile("regexes.yaml")
		if err != nil {
			return err
		}
	}

	// Parse the existing patterns format
	var patternData struct {
		Patterns []struct {
			Name  string `yaml:"name"`
			Regex string `yaml:"regex"`
		} `yaml:"patterns"`
	}

	if err := yaml.Unmarshal(content, &patternData); err != nil {
		return err
	}

	// Convert to the expected format with better categorization
	a.patterns = make(map[string][]string)
	for _, pattern := range patternData.Patterns {
		// Better categorization for iOS apps
		category := "general"
		patternName := strings.ToLower(pattern.Name)

		if strings.Contains(patternName, "aws") || strings.Contains(patternName, "s3") {
			category = "aws"
		} else if strings.Contains(patternName, "api") || strings.Contains(patternName, "endpoint") {
			category = "api"
		} else if strings.Contains(patternName, "key") || strings.Contains(patternName, "secret") || strings.Contains(patternName, "token") {
			category = "keys"
		} else if strings.Contains(patternName, "url") || strings.Contains(patternName, "http") {
			category = "urls"
		} else if strings.Contains(patternName, "auth") || strings.Contains(patternName, "password") || strings.Contains(patternName, "credential") {
			category = "authentication"
		} else if strings.Contains(patternName, "database") || strings.Contains(patternName, "db") || strings.Contains(patternName, "sql") {
			category = "database"
		} else if strings.Contains(patternName, "email") || strings.Contains(patternName, "mail") {
			category = "email"
		} else if strings.Contains(patternName, "payment") || strings.Contains(patternName, "stripe") || strings.Contains(patternName, "paypal") {
			category = "payment"
		} else if strings.Contains(patternName, "social") || strings.Contains(patternName, "facebook") || strings.Contains(patternName, "twitter") || strings.Contains(patternName, "google") {
			category = "social"
		} else if strings.Contains(patternName, "analytics") || strings.Contains(patternName, "tracking") || strings.Contains(patternName, "crashlytics") {
			category = "analytics"
		} else if strings.Contains(patternName, "push") || strings.Contains(patternName, "notification") {
			category = "notifications"
		} else if strings.Contains(patternName, "config") || strings.Contains(patternName, "setting") {
			category = "configuration"
		}

		a.patterns[category] = append(a.patterns[category], pattern.Regex)
	}

	// Add iOS-specific patterns that work well with plist content
	iosPatterns := map[string][]string{
		"bundle_info": {
			"CFBundleIdentifier",
			"CFBundleName",
			"CFBundleVersion",
			"CFBundleShortVersionString",
			"com\\.[a-zA-Z0-9.-]+",
		},
		"url_schemes": {
			"CFBundleURLSchemes",
			"CFBundleURLName",
			"CFBundleURLTypes",
			"://[a-zA-Z0-9.-]+",
		},
		"permissions": {
			"NSCameraUsageDescription",
			"NSLocationUsageDescription",
			"NSMicrophoneUsageDescription",
			"NSPhotoLibraryUsageDescription",
			"NSContactsUsageDescription",
			"NSLocationWhenInUseUsageDescription",
			"NSLocationAlwaysUsageDescription",
		},
		"security": {
			"NSAppTransportSecurity",
			"NSAllowsArbitraryLoads",
			"NSExceptionDomains",
			"NSExceptionMinimumTLSVersion",
			"NSExceptionRequiresForwardSecrecy",
		},
		"capabilities": {
			"UIRequiredDeviceCapabilities",
			"UIBackgroundModes",
			"UIFileSharingEnabled",
			"UISupportsDocumentBrowser",
		},
		"app_info": {
			"LSRequiresIPhoneOS",
			"UIDeviceFamily",
			"UISupportedInterfaceOrientations",
			"UIMainStoryboardFile",
			"UILaunchStoryboardName",
		},
		"external_services": {
			"GoogleService-Info\\.plist",
			"Firebase",
			"Crashlytics",
			"Fabric",
			"Flurry",
			"Parse",
			"Realm",
			"Bolts",
		},
	}

	// Add iOS patterns to the main patterns
	for category, patterns := range iosPatterns {
		a.patterns[category] = append(a.patterns[category], patterns...)
	}

	fmt.Printf("Loaded %d patterns across %d categories\n", len(patternData.Patterns), len(a.patterns))
	return nil
}

// copyIOSFiles copies important iOS files to the report directory
func (a *IOSAnalyzer) copyIOSFiles(extractDir string) {
	// Find the .app bundle
	appBundlePath, err := a.findAppBundle(extractDir)
	if err != nil {
		fmt.Printf("Warning: Could not find app bundle for file copying: %v\n", err)
		return
	}

	// Files to copy from app bundle to report directory
	filesToCopy := []string{
		"Info.plist",
		"embedded.mobileprovision",
		"CodeResources",
	}

	for _, fileName := range filesToCopy {
		srcPath := filepath.Join(appBundlePath, fileName)
		dstPath := filepath.Join(a.config.OutputDir, fileName)

		// Check if source file exists
		if _, err := os.Stat(srcPath); err == nil {
			// Copy the file
			if err := a.copyFile(srcPath, dstPath); err != nil {
				fmt.Printf("Warning: Failed to copy %s: %v\n", fileName, err)
			} else {
				fmt.Printf("Copied %s to report directory\n", fileName)
			}
		}
	}

	// Also copy the main Info.plist to the root of the report directory for easy access
	mainInfoPlist := filepath.Join(appBundlePath, "Info.plist")
	if _, err := os.Stat(mainInfoPlist); err == nil {
		dstPath := filepath.Join(a.config.OutputDir, "Info.plist")
		if err := a.copyFile(mainInfoPlist, dstPath); err != nil {
			fmt.Printf("Warning: Failed to copy main Info.plist: %v\n", err)
		}
	}
}

// copyFile copies a file from src to dst
func (a *IOSAnalyzer) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// generateReports generates analysis reports
func (a *IOSAnalyzer) generateReports(ipaPath string, appInfo *IOSAppInfo, binaryInfo *IOSBinaryInfo, vulnerabilities []IOSVulnerability) error {
	// Generate JSON report
	if err := a.generateJSONReport(ipaPath, appInfo, binaryInfo, vulnerabilities); err != nil {
		return fmt.Errorf("failed to generate JSON report: %v", err)
	}

	// Generate HTML report if requested
	if a.config.HTMLOutput {
		if err := a.generateHTMLReport(ipaPath, appInfo, vulnerabilities); err != nil {
			return fmt.Errorf("failed to generate HTML report: %v", err)
		}
	}

	return nil
}

// generateJSONReport generates a JSON analysis report
func (a *IOSAnalyzer) generateJSONReport(ipaPath string, appInfo *IOSAppInfo, binaryInfo *IOSBinaryInfo, vulnerabilities []IOSVulnerability) error {
	report := map[string]interface{}{
		"app_info":        appInfo,
		"binary_info":     binaryInfo,
		"vulnerabilities": vulnerabilities,
		"patterns":        a.results,
		"analysis_time":   time.Now().Format(time.RFC3339),
		"ipa_file":        filepath.Base(ipaPath),
	}

	reportPath := filepath.Join(a.config.OutputDir, "results.json")
	file, err := os.Create(reportPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// generateHTMLReport generates an HTML analysis report
func (a *IOSAnalyzer) generateHTMLReport(ipaPath string, appInfo *IOSAppInfo, vulnerabilities []IOSVulnerability) error {
	// Count vulnerabilities by severity
	vulnStats := make(map[string]int)
	for _, vuln := range vulnerabilities {
		vulnStats[vuln.Severity]++
	}

	// Count pattern matches
	patternStats := make(map[string]int)
	for category, matches := range a.results {
		patternStats[category] = len(matches)
	}

	totalVulns := len(vulnerabilities)
	totalPatterns := 0
	for _, count := range patternStats {
		totalPatterns += count
	}

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iOS App Analysis Report - %s</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        :root {
            --bg-primary: #1a1a1a;
            --bg-secondary: #2d2d2d;
            --bg-tertiary: #3a3a3a;
            --text-primary: #ffffff;
            --text-secondary: #b0b0b0;
            --text-muted: #808080;
            --accent-primary: #00d4ff;
            --accent-secondary: #0099cc;
            --danger: #ff4757;
            --warning: #ffa502;
            --success: #2ed573;
            --border-color: #404040;
            --shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        }
        
        body {
            font-family: 'Inter', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-primary);
            min-height: 100vh;
            display: flex;
        }
        
        /* Sidebar */
        .sidebar {
            width: 320px;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            position: fixed;
            height: 100vh;
            overflow-y: auto;
            z-index: 1000;
            transition: transform 0.3s ease;
            box-shadow: var(--shadow);
        }
        
        .sidebar-header {
            padding: 2rem;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-tertiary);
        }
        
        .sidebar-header h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: var(--accent-primary);
        }
        
        .sidebar-header p {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .sidebar-nav {
            padding: 1rem 0;
        }
        
        .nav-section {
            margin-bottom: 2rem;
        }
        
        .nav-section h3 {
            padding: 0 2rem;
            margin-bottom: 1rem;
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .nav-item {
            display: block;
            padding: 0.75rem 2rem;
            color: var(--text-primary);
            text-decoration: none;
            transition: all 0.2s ease;
            border-left: 3px solid transparent;
        }
        
        .nav-item:hover {
            background: var(--bg-tertiary);
            border-left-color: var(--accent-primary);
        }
        
        .nav-item.active {
            background: var(--bg-tertiary);
            border-left-color: var(--accent-primary);
            color: var(--accent-primary);
        }
        
        .nav-badge {
            float: right;
            background: var(--accent-primary);
            color: var(--bg-primary);
            padding: 0.2rem 0.5rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: bold;
        }
        
        .nav-badge.danger { background: var(--danger); }
        .nav-badge.warning { background: var(--warning); }
        .nav-badge.success { background: var(--success); }
        
        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: 320px;
            padding: 2rem;
            max-width: calc(100vw - 320px);
        }
        
        .header {
            background: var(--bg-secondary);
            padding: 2rem;
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 1rem;
            color: var(--accent-primary);
        }
        
        .header-info {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }
        
        .info-item {
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--accent-primary);
        }
        
        .info-item h3 {
            color: var(--text-secondary);
            font-size: 0.8rem;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }
        
        .info-item p {
            color: var(--text-primary);
            font-size: 1.1rem;
            font-weight: 500;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: var(--bg-secondary);
            padding: 1.5rem;
            border-radius: 12px;
            text-align: center;
            box-shadow: var(--shadow);
            transition: transform 0.2s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
        }
        
        .stat-card.danger { border-left: 4px solid var(--danger); }
        .stat-card.warning { border-left: 4px solid var(--warning); }
        .stat-card.success { border-left: 4px solid var(--success); }
        .stat-card.info { border-left: 4px solid var(--accent-primary); }
        
        .stat-number {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        
        .stat-number.danger { color: var(--danger); }
        .stat-number.warning { color: var(--warning); }
        .stat-number.success { color: var(--success); }
        .stat-number.info { color: var(--accent-primary); }
        
        .stat-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .section {
            background: var(--bg-secondary);
            border-radius: 12px;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
            overflow: hidden;
        }
        
        .section-header {
            background: var(--bg-tertiary);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .section-header h2 {
            font-size: 1.5rem;
            color: var(--text-primary);
        }
        
        .section-content {
            padding: 2rem;
        }
        
        .vulnerability {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--warning);
            transition: all 0.2s ease;
        }
        
        .vulnerability:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        .vulnerability.high { border-left-color: var(--danger); }
        .vulnerability.medium { border-left-color: var(--warning); }
        .vulnerability.low { border-left-color: var(--success); }
        
        .vuln-header {
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .vuln-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .vuln-severity {
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .vuln-severity.high {
            background: var(--danger);
            color: white;
        }
        
        .vuln-severity.medium {
            background: var(--warning);
            color: var(--bg-primary);
        }
        
        .vuln-severity.low {
            background: var(--success);
            color: var(--bg-primary);
        }
        
        .vuln-description {
            color: var(--text-secondary);
            margin-bottom: 1rem;
            line-height: 1.6;
        }
        
        .vuln-context {
            background: var(--bg-primary);
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-muted);
            border: 1px solid var(--border-color);
        }
        
        .pattern-category {
            margin-bottom: 2rem;
        }
        
        .pattern-category h3 {
            color: var(--accent-primary);
            margin-bottom: 1rem;
            font-size: 1.2rem;
        }
        
        .pattern-item {
            background: var(--bg-tertiary);
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: 8px;
            border-left: 4px solid var(--accent-primary);
            transition: all 0.2s ease;
        }
        
        .pattern-item:hover {
            transform: translateX(4px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        }
        
        .pattern-header {
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }
        
        .pattern-header strong {
            color: var(--text-primary);
            font-size: 0.9rem;
        }
        
        .pattern-context {
            margin-top: 1rem;
        }
        
        .pattern-context pre {
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 1rem;
            margin: 0;
            overflow-x: auto;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 0.85rem;
            line-height: 1.4;
            color: var(--text-muted);
        }
        
        .pattern-context code {
            background: none;
            padding: 0;
            color: inherit;
            font-size: inherit;
        }
        
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
        }
        
        .empty-state h3 {
            margin-bottom: 1rem;
            color: var(--text-secondary);
        }
        
        /* Mobile Responsive */
        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%%);
            }
            
            .sidebar.open {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
                max-width: 100vw;
                padding: 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .stats-grid {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
        }
        
        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-primary);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--bg-tertiary);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--accent-primary);
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">
            <h1>📱 iOS Analysis</h1>
            <p>Security Report</p>
        </div>
        
        <nav class="sidebar-nav">
            <div class="nav-section">
                <h3>Overview</h3>
                <a href="#summary" class="nav-item active">
                    📊 Summary
                    <span class="nav-badge info">%d</span>
                </a>
                <a href="#vulnerabilities" class="nav-item">
                    🛡️ Vulnerabilities
                    <span class="nav-badge danger">%d</span>
                </a>
                <a href="#patterns" class="nav-item">
                    🔍 Pattern Matches
                    <span class="nav-badge info">%d</span>
                </a>
            </div>
            
            <div class="nav-section">
                <h3>App Details</h3>
                <a href="#app-info" class="nav-item">
                    ℹ️ App Information
                </a>
                <a href="#binary-info" class="nav-item">
                    🔧 Binary Analysis
                </a>
            </div>
        </nav>
    </div>
    
    <div class="main-content">
    <div class="header">
        <h1>iOS App Analysis Report</h1>
            <div class="header-info">
                <div class="info-item">
                    <h3>App Name</h3>
                    <p>%s</p>
                </div>
                <div class="info-item">
                    <h3>Bundle ID</h3>
                    <p>%s</p>
                </div>
                <div class="info-item">
                    <h3>Version</h3>
                    <p>%s</p>
                </div>
                <div class="info-item">
                    <h3>Analysis Time</h3>
                    <p>%s</p>
                </div>
            </div>
    </div>
    
        <div id="summary" class="stats-grid">
            <div class="stat-card danger">
                <div class="stat-number danger">%d</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-number warning">%d</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card success">
                <div class="stat-number success">%d</div>
                <div class="stat-label">Low Risk</div>
            </div>
            <div class="stat-card info">
                <div class="stat-number info">%d</div>
                <div class="stat-label">Total Patterns</div>
            </div>
        </div>
        
        <div id="vulnerabilities" class="section">
            <div class="section-header">
                <h2>🛡️ Security Vulnerabilities</h2>
            </div>
            <div class="section-content">
                %s
            </div>
    </div>
    
        <div id="patterns" class="section">
            <div class="section-header">
                <h2>🔍 Pattern Matches</h2>
            </div>
            <div class="section-content">
        %s
    </div>
        </div>
    </div>
    
    <script>
        // Simple navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Remove active class from all items
                document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                
                // Add active class to clicked item
                this.classList.add('active');
                
                // Scroll to section
                const targetId = this.getAttribute('href').substring(1);
                const targetElement = document.getElementById(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
        
        // Mobile menu toggle (if needed)
        function toggleSidebar() {
            document.querySelector('.sidebar').classList.toggle('open');
        }
    </script>
</body>
</html>`,
		filepath.Base(ipaPath),
		totalVulns,
		totalVulns,
		totalPatterns,
		filepath.Base(ipaPath),
		appInfo.BundleID,
		appInfo.Version,
		time.Now().Format("2006-01-02 15:04:05"),
		vulnStats["High"],
		vulnStats["Medium"],
		vulnStats["Low"],
		totalPatterns,
		a.formatVulnerabilitiesHTML(vulnerabilities),
		a.formatPatternsHTML(),
	)

	reportPath := filepath.Join(a.config.OutputDir, "security-report.html")
	return os.WriteFile(reportPath, []byte(htmlContent), 0644)
}

// formatVulnerabilitiesHTML formats vulnerabilities for HTML display
func (a *IOSAnalyzer) formatVulnerabilitiesHTML(vulnerabilities []IOSVulnerability) string {
	if len(vulnerabilities) == 0 {
		return `<div class="empty-state">
			<h3>🎉 No Security Vulnerabilities Found</h3>
			<p>This iOS app appears to be secure with no obvious security issues detected.</p>
		</div>`
	}

	html := ""
	for _, vuln := range vulnerabilities {
		severityClass := strings.ToLower(vuln.Severity)
		html += fmt.Sprintf(`
		<div class="vulnerability %s">
			<div class="vuln-header">
				<div class="vuln-title">%s</div>
				<div class="vuln-severity %s">%s</div>
			</div>
			<div class="vuln-description">%s</div>
			%s
		</div>`,
			severityClass,
			vuln.Title,
			severityClass,
			vuln.Severity,
			vuln.Description,
			a.formatVulnContext(vuln))
	}

	return html
}

// formatVulnContext formats vulnerability context for display
func (a *IOSAnalyzer) formatVulnContext(vuln IOSVulnerability) string {
	if vuln.Context == "" {
		return ""
	}

	context := vuln.Context
	if vuln.File != "" {
		context = fmt.Sprintf("File: %s\n%s", vuln.File, context)
	}
	if vuln.Line > 0 {
		context = fmt.Sprintf("Line: %d\n%s", vuln.Line, context)
	}

	return fmt.Sprintf(`<div class="vuln-context">%s</div>`, context)
}

// formatPatternsHTML formats pattern matches for HTML display
func (a *IOSAnalyzer) formatPatternsHTML() string {
	if len(a.results) == 0 {
		return `<div class="empty-state">
			<h3>🔍 No Pattern Matches Found</h3>
			<p>No sensitive information or patterns were detected in this iOS app.</p>
		</div>`
	}

	html := ""
	for category, matches := range a.results {
		if len(matches) == 0 {
			continue
		}

		html += fmt.Sprintf(`
		<div class="pattern-category">
			<h3>%s <span style="color: var(--text-muted); font-size: 0.9rem;">(%d matches)</span></h3>`,
			strings.Title(category), len(matches))

		for _, match := range matches {
			html += a.formatPatternMatch(match)
		}

		html += "</div>"
	}

	return html
}

// formatPatternMatch formats a single pattern match for HTML display
func (a *IOSAnalyzer) formatPatternMatch(match IOSPatternMatch) string {
	// HTML escape the content to prevent XSS
	file := htmlEscape(match.File)
	keyword := htmlEscape(match.Keyword)
	context := htmlEscape(match.Context)

	return fmt.Sprintf(`
	<div class="pattern-item">
		<div class="pattern-header">
			<strong>File:</strong> %s<br>
			<strong>Keyword:</strong> <span style="color: var(--accent-primary);">%s</span>
		</div>
		<div class="pattern-context">
			<pre><code>%s</code></pre>
		</div>
	</div>`, file, keyword, context)
}

// htmlEscape escapes HTML special characters
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
