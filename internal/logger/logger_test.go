package logger

import (
	"os"
	"testing"
)

func TestDefaultLogConfig(t *testing.T) {
	cfg := DefaultLogConfig()

	if cfg.Level != "info" {
		t.Errorf("Level = %q, want %q", cfg.Level, "info")
	}
	if cfg.FilePath != "autoar.log" {
		t.Errorf("FilePath = %q, want %q", cfg.FilePath, "autoar.log")
	}
	if cfg.MaxSize != 100 {
		t.Errorf("MaxSize = %d, want 100", cfg.MaxSize)
	}
	if cfg.MaxAge != 7 {
		t.Errorf("MaxAge = %d, want 7", cfg.MaxAge)
	}
	if cfg.MaxBackups != 3 {
		t.Errorf("MaxBackups = %d, want 3", cfg.MaxBackups)
	}
	if !cfg.Compress {
		t.Error("Compress should default to true")
	}
	if cfg.JSONFormat {
		t.Error("JSONFormat should default to false")
	}
}

func TestLogConfigFromEnv(t *testing.T) {
	cfg := LogConfigFromEnv("custom.log")

	if cfg.FilePath != "custom.log" {
		t.Errorf("FilePath = %q, want %q", cfg.FilePath, "custom.log")
	}

	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_MAX_SIZE", "50")
	os.Setenv("LOG_MAX_AGE", "14")
	os.Setenv("LOG_MAX_BACKUPS", "5")
	os.Setenv("LOG_COMPRESS", "false")
	os.Setenv("LOG_JSON", "true")
	defer func() {
		for _, k := range []string{"LOG_LEVEL", "LOG_MAX_SIZE", "LOG_MAX_AGE", "LOG_MAX_BACKUPS", "LOG_COMPRESS", "LOG_JSON"} {
			os.Unsetenv(k)
		}
	}()

	cfg = LogConfigFromEnv("")
	if cfg.Level != "debug" {
		t.Errorf("Level = %q, want %q", cfg.Level, "debug")
	}
	if cfg.MaxSize != 50 {
		t.Errorf("MaxSize = %d, want 50", cfg.MaxSize)
	}
	if cfg.MaxAge != 14 {
		t.Errorf("MaxAge = %d, want 14", cfg.MaxAge)
	}
	if cfg.MaxBackups != 5 {
		t.Errorf("MaxBackups = %d, want 5", cfg.MaxBackups)
	}
	if cfg.Compress {
		t.Error("Compress should be false from env")
	}
	if !cfg.JSONFormat {
		t.Error("JSONFormat should be true from env")
	}
}

func TestLogConfigFromEnvEmptyDefaults(t *testing.T) {
	cfg := LogConfigFromEnv("")
	if cfg.FilePath != "autoar.log" {
		t.Errorf("FilePath = %q, want %q", cfg.FilePath, "autoar.log")
	}
}
