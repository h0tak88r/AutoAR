package config

import (
	"os"
	"testing"
)

func TestDetectEnvironment(t *testing.T) {
	env := DetectEnvironment()
	if env != "docker" && env != "local" {
		t.Errorf("DetectEnvironment() = %q, want \"docker\" or \"local\"", env)
	}
}

func TestGetConfigValueFromEnv(t *testing.T) {
	const key = "AUTOAR_TEST_CONFIG_KEY_98765"
	os.Setenv(key, "env-value")
	defer os.Unsetenv(key)

	got := GetConfigValue(key, "fallback")
	if got != "env-value" {
		t.Errorf("GetConfigValue() = %q, want %q", got, "env-value")
	}
}

func TestGetConfigValueFallback(t *testing.T) {
	const key = "AUTOAR_NONEXISTENT_KEY_98765"
	os.Unsetenv(key)

	got := GetConfigValue(key, "default-fallback")
	if got != "default-fallback" {
		t.Errorf("GetConfigValue() = %q, want %q", got, "default-fallback")
	}
}

func TestGetConfigValueEmptyEnvFallsBack(t *testing.T) {
	const key = "AUTOAR_EMPTY_KEY_98765"
	os.Setenv(key, "")
	defer os.Unsetenv(key)

	got := GetConfigValue(key, "fallback-val")
	if got != "fallback-val" {
		t.Errorf("GetConfigValue() = %q, want %q", got, "fallback-val")
	}
}

func TestGetRoot(t *testing.T) {
	got := GetRoot()
	if got == "" {
		t.Error("GetRoot() should not return empty string")
	}
}

func TestGetResultsDir(t *testing.T) {
	got := GetResultsDir()
	if got == "" {
		t.Error("GetResultsDir() should not return empty string")
	}
}

func TestGetConfigFile(t *testing.T) {
	got := GetConfigFile()
	if got == "" {
		t.Error("GetConfigFile() should not return empty string")
	}
}

func TestGetEnv(t *testing.T) {
	got := GetEnv()
	if got != "docker" && got != "local" {
		t.Errorf("GetEnv() = %q, want \"docker\" or \"local\"", got)
	}
}

func TestGenerateYAMLConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := tmpDir + "/autoar.yaml"

	os.Setenv("SHODAN_API_KEY", "test-shodan-key")
	os.Setenv("DB_HOST", "localhost")
	defer func() {
		os.Unsetenv("SHODAN_API_KEY")
		os.Unsetenv("DB_HOST")
	}()

	err := GenerateYAMLConfig(configFile)
	if err != nil {
		t.Fatalf("GenerateYAMLConfig() error = %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	content := string(data)
	if len(content) == 0 {
		t.Error("Generated config should not be empty")
	}
	if content[:1] != "#" || content[1:7] != " AutoA" {
		t.Error("Generated config should start with comment header")
	}
}
