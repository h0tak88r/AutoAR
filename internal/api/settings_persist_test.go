package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// TestHydrateEnvFromDB verifies the redeploy-survival contract: a value written
// to the settings DB (as saveEnvSetting does) is copied back into the process
// env by HydrateEnvFromDB, while a key that was never persisted keeps whatever
// the container env provided.
func TestHydrateEnvFromDB(t *testing.T) {
	// Point the DB layer at a throwaway SQLite file for this test.
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "settings_test.db"))
	t.Setenv("AUTOAR_SILENT", "true")

	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	if err := db.EnsureSchema(); err != nil {
		t.Fatalf("db.EnsureSchema: %v", err)
	}

	// Simulate a UI save landing in the DB (the DB half of saveEnvSetting).
	if err := db.SetSetting("H1_TOKEN", "secret-token-123"); err != nil {
		t.Fatalf("SetSetting H1_TOKEN: %v", err)
	}
	if err := db.SetSetting("OPENCODE_MODEL", ""); err != nil { // explicitly-cleared override
		t.Fatalf("SetSetting OPENCODE_MODEL: %v", err)
	}

	// A persisted key never saved via the UI must keep the container-provided value.
	t.Setenv("CHAOS_API_KEY", "from-dokploy-env")
	// A stale value that the DB should overwrite on boot.
	t.Setenv("H1_TOKEN", "stale-env-value")

	HydrateEnvFromDB()

	if got := os.Getenv("H1_TOKEN"); got != "secret-token-123" {
		t.Errorf("H1_TOKEN = %q, want DB value %q", got, "secret-token-123")
	}
	if got := os.Getenv("OPENCODE_MODEL"); got != "" {
		t.Errorf("OPENCODE_MODEL = %q, want cleared empty", got)
	}
	if got := os.Getenv("CHAOS_API_KEY"); got != "from-dokploy-env" {
		t.Errorf("CHAOS_API_KEY = %q, want container env preserved %q", got, "from-dokploy-env")
	}
}
