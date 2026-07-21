package accounts

import (
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// TestMigrateEnvAccounts verifies the one-shot env→DB import: legacy env
// credentials become "default" DB accounts, For() then serves them from the DB
// without also injecting the env account (no duplicate), and re-running is a no-op.
func TestMigrateEnvAccounts(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "acct_test.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	if err := db.EnsureSchema(); err != nil {
		t.Fatalf("db.EnsureSchema: %v", err)
	}

	t.Setenv("H1_USERNAME", "0x88")
	t.Setenv("H1_TOKEN", "h1-secret")
	t.Setenv("BUGCROWD_TOKEN", "bc-secret")

	MigrateEnvAccounts()

	// h1 env creds imported as a "default" DB account.
	rows, err := db.ListBBPAccounts("h1")
	if err != nil {
		t.Fatalf("ListBBPAccounts(h1): %v", err)
	}
	if len(rows) != 1 || rows[0].Label != "default" || rows[0].Username != "0x88" || rows[0].Token != "h1-secret" {
		t.Fatalf("h1 not imported correctly: %+v", rows)
	}

	// After migration, For(h1) serves exactly the DB account — the env account is
	// no longer injected (would otherwise duplicate the same credential).
	acc := For("h1")
	if len(acc) != 1 || acc[0].Source != "db" || acc[0].Token != "h1-secret" {
		t.Fatalf("For(h1) after migration = %+v, want one db account", acc)
	}

	// Idempotent: a second run must not create duplicates.
	MigrateEnvAccounts()
	if rows2, _ := db.ListBBPAccounts("h1"); len(rows2) != 1 {
		t.Fatalf("migration not idempotent: %d h1 rows", len(rows2))
	}
}
