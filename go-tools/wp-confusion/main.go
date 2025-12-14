package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var url, list, output string
	var theme, plugins, silent, discord bool

	// Parse arguments
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "-u":
			if i+1 < len(os.Args) {
				url = os.Args[i+1]
				i++
			}
		case "-l":
			if i+1 < len(os.Args) {
				list = os.Args[i+1]
				i++
			}
		case "-o":
			if i+1 < len(os.Args) {
				output = os.Args[i+1]
				i++
			}
		case "-t", "--theme":
			theme = true
		case "-p", "--plugins":
			plugins = true
		case "-s", "--silent":
			silent = true
		case "--discord":
			discord = true
		}
	}

	if url == "" && list == "" {
		fmt.Fprintf(os.Stderr, "❌ Error: Either -u (URL) or -l (list) is required\n")
		os.Exit(1)
	}

	if !theme && !plugins {
		fmt.Fprintf(os.Stderr, "❌ Error: Either -t (theme) or -p (plugins) is required\n")
		os.Exit(1)
	}

	if silent {
		os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		os.Stderr, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}

	fmt.Println(banner())

	var urls []string
	if list != "" {
		file, err := os.Open(list)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error opening list file: %v\n", err)
			os.Exit(1)
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
		urls = []string{url}
	}

	allVulnerable := []string{}
	processedCount := 0
	vulnerableCount := 0

	fmt.Printf("[i] Processing %d targets\n\n", len(urls))

	for _, targetURL := range urls {
		vulnerable := []string{}
		fmt.Println("-------------------------\n")
		fmt.Printf("[i] Target: %s\n\n", targetURL)

		if theme {
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

		if plugins {
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
	if output != "" {
		if len(allVulnerable) > 0 {
			if err := saveResults(output, allVulnerable); err != nil {
				fmt.Fprintf(os.Stderr, "❌ Error saving results: %v\n", err)
			} else if discord {
				sendToDiscord(output, fmt.Sprintf("WordPress Plugin Confusion vulnerabilities across %d targets (%d total found)", processedCount, len(allVulnerable)))
			}
		} else if discord {
			logFile := strings.Replace(output, ".txt", ".log", 1)
			logContent := fmt.Sprintf("WordPress Plugin Confusion Scan Results\n=====================================\nTargets: %d\nTimestamp: %s\nNo vulnerabilities found across all targets\n", processedCount, time.Now().Format(time.RFC3339))
			if err := os.WriteFile(logFile, []byte(logContent), 0644); err == nil {
				sendToDiscord(logFile, fmt.Sprintf("WordPress Plugin Confusion scan log for %d targets (no vulnerabilities)", processedCount))
			}
		}
	}

	fmt.Printf("[i] Scan Summary:\n")
	fmt.Printf("[i] Targets processed: %d\n", processedCount)
	fmt.Printf("[i] Targets with vulnerabilities: %d\n", vulnerableCount)
	fmt.Printf("[i] Total vulnerabilities found: %d\n", len(allVulnerable))
}

func printUsage() {
	fmt.Println("Usage: wp-confusion -u <url> | -l <list> -t | -p [-o <output>] [--discord] [--silent]")
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

func checkWordPressOrgTheme(theme string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://wordpress.org/themes/%s", theme)
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 404
}

func checkWordPressOrgPlugin(plugin string) bool {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://plugins.svn.wordpress.org/%s/", plugin)
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 404
}

func checkPaidPlugins(plugin string) bool {
	// Try to load paid_plugins.json if it exists
	paidPluginsFile := "paid_plugins.json"
	if _, err := os.Stat(paidPluginsFile); os.IsNotExist(err) {
		return false
	}

	data, err := os.ReadFile(paidPluginsFile)
	if err != nil {
		return false
	}

	var paidPlugins map[string]bool
	if err := json.Unmarshal(data, &paidPlugins); err != nil {
		return false
	}

	return paidPlugins[plugin]
}

func isAllowedSlug(plugin string) bool {
	// Check allowed characters
	matched, _ := regexp.MatchString("^[a-z0-9-]*$", plugin)
	if !matched {
		return false
	}

	// Prevent short plugin names
	if len(plugin) < 5 {
		return false
	}

	// Check if reserved slug
	for _, reserved := range reservedSlugs {
		if plugin == reserved {
			return false
		}
	}

	// Check if trademarked slug
	for _, trademark := range trademarkedSlugs {
		if strings.HasSuffix(trademark, "-") {
			if strings.HasPrefix(plugin, trademark) {
				return false
			}
		} else {
			if strings.Contains(plugin, trademark) && !strings.HasSuffix(plugin, "for-"+trademark) {
				return false
			}
		}
	}

	return true
}

func saveResults(filename string, results []string) error {
	return os.WriteFile(filename, []byte(strings.Join(results, "\n")+"\n"), 0644)
}

func sendToDiscord(filePath, description string) {
	// Try to use shell discord_file function
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filePath))))
	discordScript := filepath.Join(projectRoot, "lib", "discord.sh")

	if _, err := os.Stat(discordScript); err == nil {
		// Use bash to source and call discord_file
		cmd := fmt.Sprintf(`bash -c 'source "%s" && discord_file "%s" "%s"'`, discordScript, filePath, description)
		if err := execCommand(cmd); err == nil {
			fmt.Printf("✅ Sent to Discord: %s\n", description)
			return
		}
	}

	// Fallback: try webhook
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		webhookURL = os.Getenv("DISCORD_WEBHOOK")
	}

	if webhookURL != "" {
		content, err := os.ReadFile(filePath)
		if err == nil && len(content) < 2000 {
			payload := map[string]string{
				"content": fmt.Sprintf("**%s**\n```\n%s\n```", description, string(content)),
			}
			jsonData, _ := json.Marshal(payload)
			if err := sendWebhook(webhookURL, jsonData); err == nil {
				fmt.Printf("✅ Sent to Discord via webhook: %s\n", description)
				return
			}
		}
	}

	fmt.Printf("⚠️ Discord integration failed\n")
}

func execCommand(cmd string) error {
	execCmd := exec.Command("bash", "-c", cmd)
	return execCmd.Run()
}

func sendWebhook(url string, data []byte) error {
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
