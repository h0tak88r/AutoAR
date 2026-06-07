package envloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateEnvNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	origCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origCwd)

	err := UpdateEnv("TEST_KEY", "test_value")
	if err != nil {
		t.Fatalf("UpdateEnv() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	if !strings.Contains(string(data), `TEST_KEY="test_value"`) {
		t.Errorf(".env content = %q, want TEST_KEY=\"test_value\"", string(data))
	}

	if os.Getenv("TEST_KEY") != "test_value" {
		t.Errorf("os.Getenv(TEST_KEY) = %q, want %q", os.Getenv("TEST_KEY"), "test_value")
	}

	os.Unsetenv("TEST_KEY")
}

func TestUpdateEnvExistingKey(t *testing.T) {
	tmpDir := t.TempDir()
	origCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origCwd)

	os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("EXISTING_KEY=\"old_value\"\n"), 0644)

	err := UpdateEnv("EXISTING_KEY", "new_value")
	if err != nil {
		t.Fatalf("UpdateEnv() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	if !strings.Contains(string(data), `EXISTING_KEY="new_value"`) {
		t.Errorf(".env content = %q, want EXISTING_KEY=\"new_value\"", string(data))
	}

	os.Unsetenv("EXISTING_KEY")
}

func TestUpdateEnvAppendMissingKey(t *testing.T) {
	tmpDir := t.TempDir()
	origCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origCwd)

	os.WriteFile(filepath.Join(tmpDir, ".env"), []byte("EXISTING_KEY=\"val\"\n"), 0644)

	err := UpdateEnv("NEW_KEY", "new_val")
	if err != nil {
		t.Fatalf("UpdateEnv() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, `EXISTING_KEY="val"`) {
		t.Errorf("existing key should be preserved: %q", content)
	}
	if !strings.Contains(content, `NEW_KEY="new_val"`) {
		t.Errorf("new key should be appended: %q", content)
	}

	os.Unsetenv("NEW_KEY")
	os.Unsetenv("EXISTING_KEY")
}

func TestUpdateEnvQuotedValueHandling(t *testing.T) {
	tmpDir := t.TempDir()
	origCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origCwd)

	err := UpdateEnv("COMPLEX_KEY", "value with = signs")
	if err != nil {
		t.Fatalf("UpdateEnv() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, ".env"))
	if err != nil {
		t.Fatalf("failed to read .env: %v", err)
	}

	if !strings.Contains(string(data), `COMPLEX_KEY="value with = signs"`) {
		t.Errorf(".env content = %q, want COMPLEX_KEY=\"value with = signs\"", string(data))
	}

	os.Unsetenv("COMPLEX_KEY")
}

func TestLoadEnvNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origCwd)

	err := LoadEnv()
	if err != nil {
		t.Errorf("LoadEnv() with no .env file should not error: %v", err)
	}
}

func TestLoadEnvParsesFile(t *testing.T) {
	tmpDir := t.TempDir()
	origCwd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origCwd)

	content := "# Comment\nLOAD_TEST_KEY1=val1\nLOAD_TEST_KEY2=val2\n\nLOAD_TEST_KEY3=\"quoted val\"\n"
	os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(content), 0644)

	err := LoadEnv()
	if err != nil {
		t.Fatalf("LoadEnv() error = %v", err)
	}

	if got := os.Getenv("LOAD_TEST_KEY1"); got != "val1" {
		t.Errorf("LOAD_TEST_KEY1 = %q, want %q", got, "val1")
	}
	if got := os.Getenv("LOAD_TEST_KEY2"); got != "val2" {
		t.Errorf("LOAD_TEST_KEY2 = %q, want %q", got, "val2")
	}
	if got := os.Getenv("LOAD_TEST_KEY3"); got != "quoted val" {
		t.Errorf("LOAD_TEST_KEY3 = %q, want %q", got, "quoted val")
	}

	for _, k := range []string{"LOAD_TEST_KEY1", "LOAD_TEST_KEY2", "LOAD_TEST_KEY3"} {
		os.Unsetenv(k)
	}
}
