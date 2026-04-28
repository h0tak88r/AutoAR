package scanner

import (
	"regexp"

	"github.com/h0tak88r/AutoAR/internal/utils"
)

// SecretPattern is kept for backward compatibility but relocated to utils
type SecretPattern = utils.SecretPattern

// PatternConfig is kept for backward compatibility but relocated to utils
type PatternConfig = utils.PatternConfig

// LoadSecretPatterns is now a wrapper around utils.LoadSecretPatterns
func LoadSecretPatterns(regexesDir string) (map[string][]*regexp.Regexp, error) {
	return utils.LoadSecretPatterns(regexesDir)
}

// ScanContentForSecrets is now a wrapper around utils.ScanContentForSecrets
func ScanContentForSecrets(content string, patterns map[string][]*regexp.Regexp) []string {
	return utils.ScanContentForSecrets(content, "", patterns)
}
