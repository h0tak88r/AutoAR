package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// SecretPattern represents a regex pattern for secret detection
type SecretPattern struct {
	Name       string   `yaml:"name"`
	Regex      string   `yaml:"regex"`
	Regexes    []string `yaml:"regexes"`
	Confidence string   `yaml:"confidence"`
}

// PatternConfig represents the YAML structure of regex pattern files
type PatternConfig struct {
	Patterns []struct {
		Pattern SecretPattern `yaml:"pattern"`
	} `yaml:"patterns"`
}

// LoadSecretPatterns loads regex patterns from the regexes directory
func LoadSecretPatterns(regexesDir string) (map[string][]*regexp.Regexp, error) {
	patterns := make(map[string][]*regexp.Regexp)

	// Helper to load a file
	loadFile := func(filename string) error {
		file := filepath.Join(regexesDir, filename)
		data, err := os.ReadFile(file)
		if err != nil {
			// It's okay if file doesn't exist, just return nil
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		var config PatternConfig
		if err := yaml.Unmarshal(data, &config); err != nil {
			return fmt.Errorf("failed to unmarshal yaml in %s: %w", filename, err)
		}
		for _, p := range config.Patterns {
			pattern := p.Pattern
			var regexes []string
			if pattern.Regex != "" {
				regexes = []string{pattern.Regex}
			} else {
				regexes = pattern.Regexes
			}
			for _, regexStr := range regexes {
				if re, err := regexp.Compile(regexStr); err == nil {
					patterns[pattern.Name] = append(patterns[pattern.Name], re)
				}
			}
		}
		return nil
	}

	if err := loadFile("confident-regexes.yaml"); err != nil {
		return nil, fmt.Errorf("failed to load confident-regexes.yaml: %w", err)
	}
	if err := loadFile("risky-regexes.yaml"); err != nil {
		return nil, fmt.Errorf("failed to load risky-regexes.yaml: %w", err)
	}

	return patterns, nil
}

// ScanContentForSecrets scans text content for secrets using loaded patterns
func ScanContentForSecrets(content string, patterns map[string][]*regexp.Regexp) []string {
	var findings []string
	seen := make(map[string]bool)

	for patternName, regexes := range patterns {
		for _, re := range regexes {
			matches := re.FindAllString(content, -1)
			for _, match := range matches {
				// Truncate long matches
				if len(match) > 200 {
					match = match[:200] + "..."
				}
				key := fmt.Sprintf("%s:%s", patternName, match)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, fmt.Sprintf("[%s] %s", patternName, match))
				}
			}
		}
	}
	return findings
}
