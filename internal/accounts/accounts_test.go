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

	// Use a distinct platform (Intigriti) + unique token so the assertions are
	// robust even though db.Init caches one global instance across tests.
	t.Setenv("INTIGRITI_TOKEN", "it-secret-xyz")

	MigrateEnvAccounts()

	// The env Intigriti token is imported as a "default" DB account.
	def := findAccount(t, "it", "default")
	if def.Token != "it-secret-xyz" {
		t.Fatalf("it/default not imported correctly: %+v", def)
	}

	// After migration, For(it) no longer injects an env-source account (DB is
	// authoritative) and does include the migrated credential.
	foundMigrated := false
	for _, a := range For("it") {
		if a.Source == "env" {
			t.Fatalf("env account still injected after migration: %+v", a)
		}
		if a.Token == "it-secret-xyz" {
			foundMigrated = true
		}
	}
	if !foundMigrated {
		t.Fatalf("migrated it account missing from For(it)")
	}

	// Idempotent: a second run must not create a duplicate "default".
	MigrateEnvAccounts()
	if n := countAccounts(t, "it", "default"); n != 1 {
		t.Fatalf("migration not idempotent: %d it/default accounts", n)
	}
}

func findAccount(t *testing.T, platform, label string) db.BBPAccount {
	t.Helper()
	rows, err := db.ListBBPAccounts(platform)
	if err != nil {
		t.Fatalf("ListBBPAccounts(%s): %v", platform, err)
	}
	for _, r := range rows {
		if r.Label == label {
			return r
		}
	}
	t.Fatalf("no %s/%s account found in %+v", platform, label, rows)
	return db.BBPAccount{}
}

func countAccounts(t *testing.T, platform, label string) int {
	t.Helper()
	rows, _ := db.ListBBPAccounts(platform)
	n := 0
	for _, r := range rows {
		if r.Label == label {
			n++
		}
	}
	return n
}
