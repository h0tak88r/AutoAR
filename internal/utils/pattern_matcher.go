package utils

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

// LoadPatternFile loads regex patterns from a single YAML file in regexesDir.
// Missing files are tolerated (empty map, no error); malformed YAML is not.
func LoadPatternFile(regexesDir, filename string) (map[string][]*regexp.Regexp, error) {
	patterns := make(map[string][]*regexp.Regexp)

	// Try common locations if directory not found
	if _, err := os.Stat(regexesDir); err != nil {
		rootDir := GetRootDir()
		regexesDir = filepath.Join(rootDir, "regexes")
	}

	file := filepath.Join(regexesDir, filename)
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return patterns, nil
		}
		return nil, err
	}
	var config PatternConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml in %s: %w", filename, err)
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
	return patterns, nil
}

// LoadSecretPatterns loads regex patterns from a directory (usually "regexes")
func LoadSecretPatterns(regexesDir string) (map[string][]*regexp.Regexp, error) {
	patterns := make(map[string][]*regexp.Regexp)

	// Try common locations if directory not found
	if _, err := os.Stat(regexesDir); err != nil {
		// Fallback to project root regexes
		rootDir := GetRootDir()
		regexesDir = filepath.Join(rootDir, "regexes")
	}

	for _, file := range []string{"confident-regexes.yaml", "risky-regexes.yaml"} {
		loaded, err := LoadPatternFile(regexesDir, file)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", file, err)
		}
		for name, res := range loaded {
			patterns[name] = append(patterns[name], res...)
		}
	}

	return patterns, nil
}

// ScanContentForSecrets scans text content for secrets using loaded patterns
func ScanContentForSecrets(content, source string, patterns map[string][]*regexp.Regexp) []string {
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
					if source != "" {
						findings = append(findings, fmt.Sprintf("[%s] %s -> %s", patternName, source, match))
					} else {
						findings = append(findings, fmt.Sprintf("[%s] %s", patternName, match))
					}
				}
			}
		}
	}
	return findings
}
