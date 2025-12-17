package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	AutoARRoot     string
	AutoARResultsDir string
	AutoARConfigFile string
	AutoAREnv      string
)

func init() {
	AutoAREnv = DetectEnvironment()
	
	if AutoAREnv == "docker" {
		AutoARRoot = "/app"
		AutoARResultsDir = "/app/new-results"
		AutoARConfigFile = "/app/autoar.yaml"
	} else {
		AutoARRoot = GetRootDir()
		AutoARResultsDir = filepath.Join(AutoARRoot, "new-results")
		AutoARConfigFile = filepath.Join(AutoARRoot, "autoar.yaml")
	}
}

// DetectEnvironment detects if running in Docker or local
func DetectEnvironment() string {
	if _, err := os.Stat("/app/main.sh"); err == nil {
		return "docker"
	}
	return "local"
}

// GetRootDir returns the AutoAR root directory
func GetRootDir() string {
	if cwd, err := os.Getwd(); err == nil {
		if _, err := os.Stat(filepath.Join(cwd, "modules")); err == nil {
			return cwd
		}
	}
	
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if _, err := os.Stat(filepath.Join(exeDir, "modules")); err == nil {
			return exeDir
		}
	}
	
	return "."
}

// GetConfigValue gets a value from environment or YAML config
func GetConfigValue(key, defaultValue string) string {
	// First try environment variable
	if value := os.Getenv(key); value != "" {
		return value
	}
	
	// TODO: Add YAML parsing if needed
	// For now, just return default
	return defaultValue
}

// GetRoot returns the AutoAR root directory
func GetRoot() string {
	return AutoARRoot
}

// GetResultsDir returns the results directory
func GetResultsDir() string {
	return AutoARResultsDir
}

// GetConfigFile returns the config file path
func GetConfigFile() string {
	return AutoARConfigFile
}

// GetEnv returns the environment (docker/local)
func GetEnv() string {
	return AutoAREnv
}

// GenerateYAMLConfig generates YAML config from environment variables
func GenerateYAMLConfig(configFile string) error {
	dir := filepath.Dir(configFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}
	
	var builder strings.Builder
	builder.WriteString("# AutoAR Configuration\n")
	builder.WriteString("# Generated automatically from environment variables\n\n")
	builder.WriteString("# API Keys for various services\n")
	
	// List of API key environment variables
	apiKeys := []string{
		"GITHUB_TOKEN", "SECURITYTRAILS_API_KEY", "SHODAN_API_KEY",
		"VIRUSTOTAL_API_KEY", "WORDPRESS_API_KEY", "BEVIGIL_API_KEY",
		"BINARYEDGE_API_KEY", "URLSCAN_API_KEY", "CENSYS_API_ID",
		"CENSYS_API_SECRET", "CERTSPOTTER_API_KEY", "CHAOS_API_KEY",
		"FOFA_EMAIL", "FOFA_KEY", "FULLHUNT_API_KEY", "INTELX_API_KEY",
		"PASSIVETOTAL_USERNAME", "PASSIVETOTAL_API_KEY", "QUAKE_USERNAME",
		"QUAKE_PASSWORD", "THREATBOOK_API_KEY", "WHOISXMLAPI_API_KEY",
		"ZOOMEYE_USERNAME", "ZOOMEYE_PASSWORD", "ZOOMEYEAPI_API_KEY",
		"H1_API_KEY", "INTEGRITI_API_KEY", "OPENROUTER_API_KEY",
	}
	
	for _, key := range apiKeys {
		if value := os.Getenv(key); value != "" {
			yamlKey := strings.ToLower(key)
			yamlKey = strings.TrimSuffix(yamlKey, "_api_key")
			yamlKey = strings.TrimSuffix(yamlKey, "_username")
			yamlKey = strings.TrimSuffix(yamlKey, "_password")
			yamlKey = strings.TrimSuffix(yamlKey, "_email")
			yamlKey = strings.TrimSuffix(yamlKey, "_key")
			builder.WriteString(fmt.Sprintf("%s: [\"%s\"]\n", yamlKey, value))
		}
	}
	
	builder.WriteString("\n# Additional configuration\n")
	builder.WriteString(fmt.Sprintf("DISCORD_WEBHOOK: \"%s\"\n\n", os.Getenv("DISCORD_WEBHOOK")))
	builder.WriteString("# Database Configuration\n")
	builder.WriteString(fmt.Sprintf("SAVE_TO_DB: %s\n", getBoolEnv("SAVE_TO_DB", "true")))
	builder.WriteString(fmt.Sprintf("VERBOSE: %s\n", getBoolEnv("VERBOSE", "false")))
	builder.WriteString(fmt.Sprintf("DB_TYPE: \"%s\"\n", getEnv("DB_TYPE", "postgresql")))
	builder.WriteString(fmt.Sprintf("DB_HOST: \"%s\"\n", os.Getenv("DB_HOST")))
	builder.WriteString(fmt.Sprintf("DB_NAME: \"%s\"\n", getEnv("DB_NAME", "autoar")))
	
	return os.WriteFile(configFile, []byte(builder.String()), 0644)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return strings.ToLower(value)
}
