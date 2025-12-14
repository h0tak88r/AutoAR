package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	githubAPIBase = "https://api.github.com"
)

var ignoreFiles = []string{
	".gitignore",
	".eslintignore",
	".dockerignore",
	".npmignore",
	".prettierignore",
	".stylelintignore",
	".eslintrc",
	".eslintrc.js",
	".eslintrc.json",
	".prettierrc",
	".prettierrc.js",
	".prettierrc.json",
	".gitattributes",
	".editorconfig",
}

type repo struct {
	Name string `json:"name"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <organization>\n", os.Args[0])
		os.Exit(1)
	}

	org := os.Args[1]
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		fmt.Fprintf(os.Stderr, "❌ Error: GITHUB_TOKEN not found in environment\n")
		os.Exit(1)
	}

	fmt.Printf("🚀 Starting GitHub Target Based Wordlist generation for organization: %s\n", org)

	// Get repositories
	repos, err := getOrgRepos(org, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error fetching repositories: %v\n", err)
		os.Exit(1)
	}

	if len(repos) == 0 {
		fmt.Fprintf(os.Stderr, "❌ No repositories found\n")
		os.Exit(1)
	}

	// Limit to first 20 repositories
	if len(repos) > 20 {
		repos = repos[:20]
	}
	fmt.Printf("📊 Processing first %d repositories\n", len(repos))

	// Download ignore files and extract patterns
	allPatterns := make(map[string]bool)
	processedRepos := 0
	totalFiles := 0

	fmt.Printf("📥 Downloading ignore files from %d repositories\n", len(repos))

	for _, repoName := range repos {
		fmt.Printf("🔍 Processing repository: %s\n", repoName)
		repoPatterns := make(map[string]bool)

		for _, ignoreFile := range ignoreFiles {
			content, err := downloadIgnoreFile(org, repoName, ignoreFile, token)
			if err == nil && content != "" {
				patterns := extractPatterns(content)
				for p := range patterns {
					repoPatterns[p] = true
					allPatterns[p] = true
				}
				totalFiles++
				fmt.Printf("  ✅ Found %s\n", ignoreFile)
			}

			// Small delay to avoid rate limiting
			time.Sleep(50 * time.Millisecond)
		}

		processedRepos++
		if processedRepos%5 == 0 {
			fmt.Printf("📊 Processed %d/%d repositories, found %d ignore files\n", processedRepos, len(repos), totalFiles)
		}
	}

	fmt.Printf("✅ Downloaded %d ignore files from %d repositories\n", totalFiles, processedRepos)

	// Generate wordlist
	fmt.Println("🔧 Generating wordlist from patterns...")
	wordlist := generateWordlist(allPatterns)

	// Create output directory
	outputDir := filepath.Join("new-results", fmt.Sprintf("github-%s", org), "wordlists")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Save patterns
	patternsFile := filepath.Join(outputDir, "github-patterns.txt")
	if err := saveFile(patternsFile, allPatterns); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error saving patterns: %v\n", err)
		os.Exit(1)
	}

	// Save wordlist
	wordlistFile := filepath.Join(outputDir, "github-wordlist.txt")
	if err := saveFile(wordlistFile, wordlist); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error saving wordlist: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Generated wordlist with %d unique words\n", len(wordlist))
	fmt.Printf("📁 Patterns saved to: %s\n", patternsFile)
	fmt.Printf("📁 Wordlist saved to: %s\n", wordlistFile)
	fmt.Println("🎉 GitHub Target Based Wordlist generation completed!")
}

func getOrgRepos(org, token string) ([]string, error) {
	fmt.Printf("🔍 Fetching repositories for organization: %s\n", org)

	var repos []string
	page := 1
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		url := fmt.Sprintf("%s/orgs/%s/repos?per_page=100&page=%d&type=all", githubAPIBase, org, page)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		var data []repo
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, err
		}

		if len(data) == 0 {
			break
		}

		for _, repo := range data {
			repos = append(repos, repo.Name)
		}

		fmt.Printf("📦 Fetched %d repositories from page %d\n", len(data), page)
		page++

		// Rate limiting
		time.Sleep(500 * time.Millisecond)
	}

	fmt.Printf("✅ Found %d total repositories for %s\n", len(repos), org)
	return repos, nil
}

func downloadIgnoreFile(org, repo, ignoreFile, token string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/contents/%s", githubAPIBase, org, repo, ignoreFile)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("Accept", "application/vnd.github.v3.raw")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func extractPatterns(content string) map[string]bool {
	patterns := make(map[string]bool)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip negation patterns
		if strings.HasPrefix(line, "!") {
			continue
		}

		pattern := strings.TrimSpace(line)
		patterns[pattern] = true

		// Extract variations
		if strings.Contains(pattern, "/") {
			parts := strings.Split(pattern, "/")
			for _, part := range parts {
				if part != "" && !strings.HasPrefix(part, "*") {
					patterns[part] = true
				}
			}
		}

		// Extract file extensions
		if strings.Contains(pattern, ".") {
			parts := strings.Split(pattern, ".")
			if len(parts) > 0 {
				ext := parts[len(parts)-1]
				if ext != "" && !strings.HasPrefix(ext, "*") {
					patterns[ext] = true
				}
			}
		}

		// Extract base names from wildcards
		if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
			base := strings.ReplaceAll(pattern, "*", "")
			base = strings.ReplaceAll(base, "?", "")
			if base != "" {
				patterns[base] = true
			}
		}
	}

	return patterns
}

func generateWordlist(patterns map[string]bool) map[string]bool {
	wordlist := make(map[string]bool)

	for pattern := range patterns {
		wordlist[pattern] = true

		// Add variations
		if strings.Contains(pattern, "/") {
			parts := strings.Split(pattern, "/")
			for _, part := range parts {
				if part != "" && !strings.HasPrefix(part, "*") {
					wordlist[part] = true
				}
			}
		}

		// Add file extensions
		if strings.Contains(pattern, ".") {
			parts := strings.Split(pattern, ".")
			if len(parts) > 0 {
				ext := parts[len(parts)-1]
				if ext != "" && !strings.HasPrefix(ext, "*") {
					wordlist[ext] = true
				}
			}
		}

		// Add base names
		if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
			base := strings.ReplaceAll(pattern, "*", "")
			base = strings.ReplaceAll(base, "?", "")
			if base != "" {
				wordlist[base] = true
			}
		}
	}

	return wordlist
}

func saveFile(filename string, data map[string]bool) error {
	var sorted []string
	for k := range data {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, item := range sorted {
		fmt.Fprintf(f, "%s\n", item)
	}

	return nil
}
