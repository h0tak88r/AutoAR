package accounts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// TestMultiAccountEndToEnd exercises the real DB CRUD path + the For() merge and
// legacy-env fallback against a throwaway SQLite database.
func TestMultiAccountEndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "acct_test.db")
	t.Setenv("AUTOAR_SILENT", "true")
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", dbPath)
	// Ensure a clean env for the platform under test.
	t.Setenv("H1_USERNAME", "")
	t.Setenv("H1_TOKEN", "")

	if err := db.EnsureSchema(); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	// Insert two H1 accounts.
	if _, err := db.UpsertBBPAccount(db.BBPAccount{Platform: "h1", Label: "main", Username: "u1", Token: "TOK1", Enabled: true}); err != nil {
		t.Fatalf("upsert main: %v", err)
	}
	if _, err := db.UpsertBBPAccount(db.BBPAccount{Platform: "h1", Label: "alt", Username: "u2", Token: "TOK2", Enabled: true}); err != nil {
		t.Fatalf("upsert alt: %v", err)
	}

	// List returns both.
	rows, err := db.ListBBPAccounts("h1")
	if err != nil || len(rows) != 2 {
		t.Fatalf("ListBBPAccounts = %d rows, err=%v; want 2", len(rows), err)
	}

	// For() with no env credential returns the two DB accounts.
	if got := For("h1"); len(got) != 2 {
		t.Fatalf("For(h1) with no env = %d; want 2", len(got))
	}

	// A distinct env credential is added as a third "env" account.
	t.Setenv("H1_USERNAME", "envuser")
	t.Setenv("H1_TOKEN", "ENVTOK")
	if got := For("h1"); len(got) != 3 {
		t.Fatalf("For(h1) with distinct env = %d; want 3 (2 db + env)", len(got))
	}

	// An env credential whose token matches a DB account is deduped (not doubled).
	t.Setenv("H1_TOKEN", "TOK1")
	t.Setenv("H1_USERNAME", "u1")
	if got := For("h1"); len(got) != 2 {
		t.Fatalf("For(h1) with dup env token = %d; want 2 (deduped)", len(got))
	}

	// Disabling an account drops it from For().
	t.Setenv("H1_USERNAME", "")
	t.Setenv("H1_TOKEN", "")
	if err := db.SetBBPAccountEnabled(rows[0].ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if got := For("h1"); len(got) != 1 {
		t.Fatalf("For(h1) after disable = %d; want 1", len(got))
	}

	// Delete removes it entirely.
	if err := db.DeleteBBPAccount(rows[1].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	left, _ := db.ListBBPAccounts("h1")
	if len(left) != 1 {
		t.Fatalf("after delete ListBBPAccounts = %d; want 1", len(left))
	}

	// immunefi always yields a single no-auth account.
	if got := For("immunefi"); len(got) != 1 {
		t.Fatalf("For(immunefi) = %d; want 1", len(got))
	}

	_ = os.Remove(dbPath)
}
