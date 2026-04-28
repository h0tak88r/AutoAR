package scope

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/joeguo/tldextract"
	"github.com/sw33tLie/bbscope/pkg/platforms/bugcrowd"
	"github.com/sw33tLie/bbscope/pkg/platforms/hackerone"
	"github.com/sw33tLie/bbscope/pkg/platforms/immunefi"
	"github.com/sw33tLie/bbscope/pkg/platforms/intigriti"
	"github.com/sw33tLie/bbscope/pkg/platforms/yeswehack"
	"github.com/sw33tLie/bbscope/pkg/scope"
)

// Platform represents a bug bounty platform
type Platform string

const (
	PlatformHackerOne  Platform = "h1"
	PlatformBugcrowd   Platform = "bc"
	PlatformIntigriti  Platform = "it"
	PlatformYesWeHack  Platform = "ywh"
	PlatformImmunefi   Platform = "immunefi"
)

// Options contains options for fetching scope
type Options struct {
	Platform      Platform
	Username      string
	Token         string
	Email         string
	Password      string
	Categories    string
	BBPOnly       bool
	PvtOnly       bool
	IncludeOOS    bool
	Concurrency   int
	PublicOnly    bool // For HackerOne
	ActiveOnly    bool // For HackerOne
	ExtractRoots  bool // Extract root domains (default: true for backward compatibility)
}

// FetchScope fetches scope from the specified platform
func FetchScope(opts Options) ([]scope.ProgramData, error) {
	switch opts.Platform {
	case PlatformHackerOne:
		if opts.Username == "" || opts.Token == "" {
			return nil, fmt.Errorf("username and token are required for HackerOne")
		}
		auth := base64.StdEncoding.EncodeToString([]byte(opts.Username + ":" + opts.Token))
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		if opts.Concurrency == 0 {
			opts.Concurrency = 3
		}
		programs, err := hackerone.GetAllProgramsScope(auth, opts.BBPOnly, opts.PvtOnly, opts.PublicOnly, opts.Categories, opts.ActiveOnly, opts.Concurrency, false, "t", " ", opts.IncludeOOS)
		return programs, err

	case PlatformBugcrowd:
		if opts.Token == "" && (opts.Email == "" || opts.Password == "") {
			return nil, fmt.Errorf("token or email/password are required for Bugcrowd")
		}
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		if opts.Concurrency == 0 {
			opts.Concurrency = 3
		}
		token := opts.Token
		if token == "" {
			// Login with email/password
			var err error
			token, err = bugcrowd.Login(opts.Email, opts.Password, "", "")
			if err != nil {
				return nil, fmt.Errorf("failed to login to Bugcrowd: %w", err)
			}
		}
		programs, err := bugcrowd.GetAllProgramsScope(token, opts.BBPOnly, opts.PvtOnly, opts.Categories, "t", opts.Concurrency, " ", opts.IncludeOOS, false, nil)
		return programs, err

	case PlatformIntigriti:
		if opts.Token == "" {
			return nil, fmt.Errorf("token is required for Intigriti")
		}
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		programs := intigriti.GetAllProgramsScope(opts.Token, opts.BBPOnly, opts.PvtOnly, opts.Categories, "t", " ", opts.IncludeOOS, false)
		return programs, nil

	case PlatformYesWeHack:
		if opts.Token == "" && (opts.Email == "" || opts.Password == "") {
			return nil, fmt.Errorf("token or email/password are required for YesWeHack")
		}
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		token := opts.Token
		if token == "" {
			// Login with email/password
			var err error
			token, err = yeswehack.Login(opts.Email, opts.Password, "", "")
			if err != nil {
				return nil, fmt.Errorf("failed to login to YesWeHack: %w", err)
			}
		}
		programs := yeswehack.GetAllProgramsScope(token, opts.BBPOnly, opts.PvtOnly, opts.Categories, "t", " ", false)
		return programs, nil

	case PlatformImmunefi:
		if opts.Categories == "" {
			opts.Categories = "all"
		}
		if opts.Concurrency == 0 {
			opts.Concurrency = 5
		}
		programs := immunefi.GetAllProgramsScope(opts.Categories, opts.Concurrency)
		return programs, nil

	default:
		return nil, fmt.Errorf("unsupported platform: %s", opts.Platform)
	}
}

// isMobileOrAppTarget checks if a target is mobile/app/cloud-related and should be filtered out
func isMobileOrAppTarget(target, category string) bool {
	targetLower := strings.ToLower(target)
	categoryLower := strings.ToLower(category)
	
	// Filter by category first (more reliable)
	mobileCategories := []string{
		"mobile", "android", "apple", "ios", "executable", "code", "hardware",
		"google_play_app_id", "apple_store_app_id", "other_apk", "testflight",
		"downloadable_executables", "windows_app_store_app_id", "smart_contract",
		"source_code", "ai_model", "other", "hardware",
	}
	
	for _, cat := range mobileCategories {
		if strings.Contains(categoryLower, cat) {
			return true
		}
	}
	
	// Also check target string for keywords
	mobileKeywords := []string{
		"ios", "android", "apple", "google", "apk", "ipa", "exe", "dmg", "deb", "rpm",
		"aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda", "appstore", "playstore",
		"testflight", "f-droid", "apkmirror", "mobile", "app", "application",
		"package", "bundle", "executable", "installer", "binary", "smart_contract",
		"source_code", "hardware", "ai_model",
	}
	
	for _, keyword := range mobileKeywords {
		if strings.Contains(targetLower, keyword) {
			return true
		}
	}
	
	return false
}

// ExtractRootDomains extracts root domains from scope data
func ExtractRootDomains(programs []scope.ProgramData) ([]string, error) {
	// Create tldextract instance
	cacheDir := filepath.Join(os.TempDir(), "tld.cache")
	extract, err := tldextract.New(cacheDir, false)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tldextract: %w", err)
	}

	rootDomains := make(map[string]bool)

	// Process all programs
	for _, program := range programs {
		// Process in-scope targets
		for _, elem := range program.InScope {
			// Filter out mobile/app/cloud targets (check both target and category)
			if isMobileOrAppTarget(elem.Target, elem.Category) {
				continue
			}
			
			domains := extractRootFromTarget(elem.Target, extract)
			for _, domain := range domains {
				if domain != "" {
					rootDomains[domain] = true
				}
			}
		}

		// Process out-of-scope targets if needed
		for _, elem := range program.OutOfScope {
			// Filter out mobile/app/cloud targets (check both target and category)
			if isMobileOrAppTarget(elem.Target, elem.Category) {
				continue
			}
			
			domains := extractRootFromTarget(elem.Target, extract)
			for _, domain := range domains {
				if domain != "" {
					rootDomains[domain] = true
				}
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(rootDomains))
	for domain := range rootDomains {
		result = append(result, domain)
	}

	return result, nil
}

// extractRootFromTarget extracts root domains from a target string
func extractRootFromTarget(target string, extract *tldextract.TLDExtract) []string {
	domains := []string{}

	// Clean up the target
	target = strings.TrimSpace(target)
	if target == "" {
		return domains
	}

	// Handle wildcards - remove *. prefix
	if strings.HasPrefix(target, "*.") {
		target = target[2:]
	}

	// Handle URLs - extract domain part
	if strings.Contains(target, "://") {
		// Extract domain from URL
		parts := strings.Split(target, "://")
		if len(parts) > 1 {
			path := parts[1]
			// Remove path, query, fragment
			if idx := strings.Index(path, "/"); idx != -1 {
				path = path[:idx]
			}
			if idx := strings.Index(path, "?"); idx != -1 {
				path = path[:idx]
			}
			if idx := strings.Index(path, "#"); idx != -1 {
				path = path[:idx]
			}
			// Remove port
			if idx := strings.Index(path, ":"); idx != -1 {
				path = path[:idx]
			}
			target = path
		}
	}

	// Handle CIDR - skip IP ranges
	if strings.Contains(target, "/") {
		// This is likely a CIDR, skip it
		return domains
	}

	// Extract root domain
	result := extract.Extract(target)

	// Filter out IPs (Flag 2 = IPv4, Flag 3 = IPv6)
	if result.Flag == 2 || result.Flag == 3 {
		return domains
	}

	// Skip malformed domains
	if result.Flag == 0 {
		return domains
	}

	// Build root.tld format
	if result.Root != "" && result.Tld != "" {
		rootDomain := result.Root + "." + result.Tld
		domains = append(domains, rootDomain)
	} else if result.Root != "" {
		// Sometimes TLD might be empty, use Root only
		domains = append(domains, result.Root)
	}

	return domains
}

// ExtractRawTargets extracts raw targets from scope data (without root domain extraction)
func ExtractRawTargets(programs []scope.ProgramData) []string {
	targets := make(map[string]bool)

	// Process all programs
	for _, program := range programs {
		// Process in-scope targets
		for _, elem := range program.InScope {
			target := strings.TrimSpace(elem.Target)
			if target != "" {
				targets[target] = true
			}
		}

		// Process out-of-scope targets if needed
		for _, elem := range program.OutOfScope {
			target := strings.TrimSpace(elem.Target)
			if target != "" {
				targets[target] = true
			}
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(targets))
	for target := range targets {
		result = append(result, target)
	}

	return result
}

// WriteRootDomains writes root domains to file or stdout
func WriteRootDomains(domains []string, outputFile string) error {
	if outputFile == "" {
		// Write to stdout
		for _, domain := range domains {
			fmt.Println(domain)
		}
		return nil
	}

	// Write to file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	for _, domain := range domains {
		if _, err := fmt.Fprintln(file, domain); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}

