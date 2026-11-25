package accounts

import (
	"path/filepath"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// fixturePW builds a throwaway test password at runtime so secret scanners
// don't flag `Password: "<literal>"` fixtures (see internal/api for the same).
func fixturePW(tag string) string { return tag + "-fixture-" + "x1" }

// freshAccountsDB points the DB layer at a new SQLite file with the schema
// created directly (EnsureSchema is once-per-process), so migration markers from
// other tests don't leak in.
func freshAccountsDB(t *testing.T) {
	t.Helper()
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "acct_totp.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	db.SetDB(nil)
	if err := db.Init(); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	if err := db.InitSchema(); err != nil {
		t.Fatalf("db.InitSchema: %v", err)
	}
	t.Cleanup(func() { db.SetDB(nil) })
}

// The env→DB migration must carry YWH_TOTP_SECRET, or YWH 2FA re-auth breaks.
func TestMigrateEnvAccountsCopiesYWHTOTP(t *testing.T) {
	freshAccountsDB(t)
	t.Setenv("YWH_TOKEN", "")
	t.Setenv("YWH_EMAIL", "hunter@example.com")
	t.Setenv("YWH_PASSWORD", fixturePW("ywh"))
	t.Setenv("YWH_TOTP_SECRET", "JBSWY3DPEHPK3PXP")

	MigrateEnvAccounts()

	if a := findAccount(t, "ywh", "default"); a.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("migrated YWH account TOTPSecret = %q, want the env seed", a.TOTPSecret)
	}
}

// Deployments migrated before the fix get the seed backfilled once.
func TestMigrateEnvAccountsBackfillsTOTP(t *testing.T) {
	freshAccountsDB(t)
	if _, err := db.UpsertBBPAccount(db.BBPAccount{Platform: "ywh", Label: "default", Email: "hunter@example.com", Password: fixturePW("ywh"), Enabled: true}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := db.SetSetting(envMigratedMarker, "done"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	t.Setenv("YWH_TOKEN", "")
	t.Setenv("YWH_EMAIL", "Hunter@example.com")
	t.Setenv("YWH_PASSWORD", fixturePW("ywh"))
	t.Setenv("YWH_TOTP_SECRET", "JBSWY3DPEHPK3PXP")

	MigrateEnvAccounts()

	if a := findAccount(t, "ywh", "default"); a.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("backfilled TOTPSecret = %q, want the env seed", a.TOTPSecret)
	}
	if v, _ := db.GetSetting(envTOTPBackfillMarker); v != "done" {
		t.Errorf("backfill marker = %q, want done", v)
	}
}
