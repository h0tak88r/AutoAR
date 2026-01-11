package wpconfusion

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	reservedSlugs = []string{
		"about", "admin", "browse", "category", "developers", "developer",
		"featured", "filter", "new", "page", "plugins", "popular", "post",
		"search", "tag", "updated", "upload", "wp-admin", "jquery", "wordpress",
		"akismet-anti-spam", "site-kit-by-google", "yoast-seo", "woo",
		"wp-media-folder", "wp-file-download", "wp-table-manager",
	}

	trademarkedSlugs = []string{
		"adobe-", "adsense-", "advanced-custom-fields-", "adwords-", "akismet-",
		"all-in-one-wp-migration", "amazon-", "android-", "apple-", "applenews-",
		"aws-", "bbpress-", "bing-", "bootstrap-", "buddypress-", "contact-form-7-",
		"cpanel-", "disqus-", "divi-", "dropbox-", "easy-digital-downloads-",
		"elementor-", "envato-", "fbook", "facebook", "fb-", "fb-messenger",
		"fedex-", "feedburner", "ganalytics-", "gberg", "github-", "givewp-",
		"google-", "googlebot-", "googles-", "gravity-form-", "gravity-forms-",
		"gutenberg", "guten-", "hubspot-", "ig-", "insta-", "instagram",
		"internet-explorer-", "jetpack-", "macintosh-", "mailchimp-", "microsoft-",
		"ninja-forms-", "oculus", "onlyfans-", "only-fans-", "paddle-", "paypal-",
		"pinterest-", "stripe-", "tiktok-", "trustpilot", "twitter-", "tweet",
		"ups-", "usps-", "vvhatsapp", "vvcommerce", "vva-", "vvoo", "wa-",
		"wh4tsapps", "whatsapp", "whats-app", "watson", "windows-", "wocommerce",
		"woocom-", "woocommerce", "woocomerce", "woo-commerce", "woo-", "wo-",
		"wordpress", "wordpess", "wpress", "wp-", "wp-mail-smtp-", "yahoo-",
		"yoast", "youtube-",
	}

	premiumIndicators = []string{"pro", "premium", "business", "enterprise", "paid"}
)

// ScanOptions contains options for WordPress confusion scanning
type ScanOptions struct {
	URL      string
	List     string
	Output   string
	Theme    bool
	Plugins  bool
	Silent   bool
	Discord  bool
}

// ScanWPConfusion scans WordPress sites for plugin/theme confusion vulnerabilities
func ScanWPConfusion(opts ScanOptions) error {
	if opts.URL == "" && opts.List == "" {
		return fmt.Errorf("either URL or list file is required")
	}

	if !opts.Theme && !opts.Plugins {
		return fmt.Errorf("either theme or plugins scan is required")
	}

	if opts.Silent {
		os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		os.Stderr, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}

	fmt.Println(banner())

	var urls []string
	if opts.List != "" {
		file, err := os.Open(opts.List)
		if err != nil {
			return fmt.Errorf("error opening list file: %w", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
	} else {
		urls = []string{opts.URL}
	}

	allVulnerable := []string{}
	processedCount := 0
	vulnerableCount := 0

	fmt.Printf("[i] Processing %d targets\n\n", len(urls))

	for _, targetURL := range urls {
		vulnerable := []string{}
		fmt.Println("-------------------------\n")
		fmt.Printf("[i] Target: %s\n\n", targetURL)

		if opts.Theme {
			fmt.Println("[i] Searching theme\n")
			themeName := detectTheme(targetURL)
			if themeName != "" {
				fmt.Printf("[i] Found WP theme: %s\n\n", themeName)
				if isVulnerable := checkWordPressOrgTheme(themeName); isVulnerable {
					fmt.Println("\t[!] Vulnerable to WP Theme Confusion attack\n")
					fmt.Printf("\t[!] %s/wp-content/themes/%s\n", targetURL, themeName)
					fmt.Printf("\t[!] https://wordpress.org/themes/%s\n\n", themeName)
					vulnerable = append(vulnerable, fmt.Sprintf("%s/wp-content/themes/%s", targetURL, themeName))
				} else {
					fmt.Println("\t[i] Not vulnerable\n")
				}
			}
		}

		if opts.Plugins {
			fmt.Println("[i] Searching plugins\n")
			pluginList := detectPlugins(targetURL)

			for _, plugin := range pluginList {
				fmt.Printf("[i] Found WP plugin: %s\n", plugin)

				if !isAllowedSlug(plugin) {
					fmt.Println("\t[i] Not vulnerable - disallowed name\n")
					continue
				}

				// Check for premium indicators
				pluginLower := strings.ToLower(plugin)
				isPremium := false
				for _, ind := range premiumIndicators {
					if strings.Contains(pluginLower, "-"+ind+"-") ||
						strings.Contains(pluginLower, "-"+ind) ||
						strings.Contains(pluginLower, ind+"-") {
						isPremium = true
						break
					}
				}

				if isPremium {
					fmt.Printf("\t[i] Not vulnerable - premium plugin detected (%s)\n\n", plugin)
					continue
				}

				// Check against known paid plugins
				if isPaid := checkPaidPlugins(plugin); isPaid {
					fmt.Printf("\t[i] Not vulnerable - paid plugin (%s)\n\n", plugin)
					continue
				}

				if isVulnerable := checkWordPressOrgPlugin(plugin); isVulnerable {
					fmt.Println("\t[!] Vulnerable to WP Plugin Confusion attack\n")
					fmt.Printf("\t[!] %s/wp-content/plugins/%s\n", targetURL, plugin)
					fmt.Printf("\t[!] https://wordpress.org/plugins/%s\n\n", plugin)
					vulnerable = append(vulnerable, fmt.Sprintf("%s/wp-content/plugins/%s", targetURL, plugin))
				} else {
					fmt.Println("\t[i] Not vulnerable - already claimed\n")
				}
			}
		}

		allVulnerable = append(allVulnerable, vulnerable...)
		processedCount++

		if len(vulnerable) > 0 {
			vulnerableCount++
			fmt.Printf("[+] Found %d vulnerabilities for %s\n", len(vulnerable), targetURL)
		} else {
			fmt.Printf("[i] No vulnerabilities found for %s\n", targetURL)
		}
		fmt.Println()
	}

	// Handle output
	if opts.Output != "" {
		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(opts.Output), 0755); err != nil {
			log.Printf("[WARN] Failed to create directory for results %s: %v", opts.Output, err)
		}
		
		if len(allVulnerable) > 0 {
			// Save vulnerabilities to file
			if err := saveResults(opts.Output, allVulnerable); err != nil {
				return fmt.Errorf("error saving results: %w", err)
			}
			if opts.Discord {
				sendToDiscord(opts.Output, fmt.Sprintf("WordPress Plugin Confusion vulnerabilities across %d targets (%d total found)", processedCount, len(allVulnerable)))
			}
		} else {
			// Create empty file with summary when no vulnerabilities found
			logContent := fmt.Sprintf("WordPress Plugin Confusion Scan Results\n=====================================\nTargets: %d\nTimestamp: %s\nNo vulnerabilities found across all targets\n", processedCount, time.Now().Format(time.RFC3339))
			if err := os.WriteFile(opts.Output, []byte(logContent), 0644); err != nil {
				log.Printf("[WARN] Failed to write empty results to %s: %v", opts.Output, err)
			}
			if opts.Discord {
				sendToDiscord(opts.Output, fmt.Sprintf("WordPress Plugin Confusion scan log for %d targets (no vulnerabilities)", processedCount))
			}
		}
	}

	fmt.Printf("[i] Scan Summary:\n")
	fmt.Printf("[i] Targets processed: %d\n", processedCount)
	fmt.Printf("[i] Targets with vulnerabilities: %d\n", vulnerableCount)
	fmt.Printf("[i] Total vulnerabilities found: %d\n", len(allVulnerable))

	return nil
}

func banner() string {
	return "\n +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+\n" +
		" |W|o|r|d|P|r|e|s|s| |U|p|d|a|t|e| |C|o|n|f|u|s|i|o|n|\n" +
		" +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+\n"
}

func detectTheme(url string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(`wp-content/themes/([^/]+)/`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

func detectPlugins(url string) []string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	re := regexp.MustCompile(`wp-content/plugins/([^/]+)/`)
	matches := re.FindAllStringSubmatch(string(body), -1)

	pluginMap := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			pluginMap[match[1]] = true
		}
	}

	var plugins []string
	for p := range pluginMap {
		plugins = append(plugins, p)
	}

	return plugins
}

func isAllowedSlug(slug string) bool {
	slugLower := strings.ToLower(slug)
	for _, reserved := range reservedSlugs {
		if slugLower == reserved {
			return false
		}
	}
	for _, trademarked := range trademarkedSlugs {
		if strings.HasPrefix(slugLower, trademarked) {
			return false
		}
	}
	return true
}

func checkWordPressOrgTheme(theme string) bool {
	url := fmt.Sprintf("https://wordpress.org/themes/%s/", theme)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 404
}

func checkWordPressOrgPlugin(plugin string) bool {
	url := fmt.Sprintf("https://wordpress.org/plugins/%s/", plugin)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 404
}

func checkPaidPlugins(plugin string) bool {
	paidPlugins := []string{
		"woocommerce", "elementor", "divi", "wpml", "gravityforms",
		"advanced-custom-fields-pro", "wp-rocket", "ithemes-security",
	}
	pluginLower := strings.ToLower(plugin)
	for _, paid := range paidPlugins {
		if strings.Contains(pluginLower, paid) {
			return true
		}
	}
	return false
}

func saveResults(filename string, results []string) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, result := range results {
		fmt.Fprintf(f, "%s\n", result)
	}

	return nil
}

func sendToDiscord(file, message string) {
	// Discord integration would go here if needed
	// For now, just a placeholder
	fmt.Printf("[i] Discord notification: %s - %s\n", message, file)
}
