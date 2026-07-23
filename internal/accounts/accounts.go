// Package accounts resolves the set of bug-bounty platform accounts to use for a
// fetch. It merges accounts stored in the DB with the legacy single-account env
// vars (H1_USERNAME/H1_TOKEN, BUGCROWD_TOKEN, ...) so existing single-account
// deployments keep working unchanged: the env credential shows up as an implicit
// "env" account alongside any accounts added through the UI.
package accounts

import (
	"os"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// Account is one resolved platform account ready to authenticate with.
type Account struct {
	ID         int64  `json:"id"`
	Platform   string `json:"platform"`
	Label      string `json:"label"`
	Username   string `json:"username"`
	Token      string `json:"token"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret"` // base32 2FA seed (YWH auto-reauth)
	Source     string `json:"source"`      // "db" or "env"
}

// Canonical maps platform aliases to the short codes used across AutoAR.
func Canonical(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "h1", "hackerone":
		return "h1"
	case "bc", "bugcrowd":
		return "bc"
	case "it", "intigriti":
		return "it"
	case "ywh", "yeswehack":
		return "ywh"
	case "immunefi":
		return "immunefi"
	default:
		return strings.ToLower(strings.TrimSpace(platform))
	}
}

// hasCreds reports whether an account carries usable credentials for its platform.
func hasCreds(a Account) bool {
	switch a.Platform {
	case "h1":
		return a.Username != "" && a.Token != ""
	case "immunefi":
		return true // no auth
	case "ywh":
		return a.Token != "" || (a.Email != "" && a.Password != "")
	default: // bc, it
		return a.Token != ""
	}
}

// envAccount builds the implicit legacy account from env vars, or a zero value
// (with empty creds) if none are configured for the platform.
func envAccount(platform string) Account {
	a := Account{Platform: platform, Label: "env", Source: "env"}
	switch platform {
	case "h1":
		a.Username = strings.TrimSpace(os.Getenv("H1_USERNAME"))
		a.Token = strings.TrimSpace(os.Getenv("H1_TOKEN"))
	case "bc":
		a.Token = strings.TrimSpace(os.Getenv("BUGCROWD_TOKEN"))
	case "it":
		a.Token = strings.TrimSpace(os.Getenv("INTIGRITI_TOKEN"))
		if a.Token == "" {
			a.Token = strings.TrimSpace(os.Getenv("INTIGRITI_API_KEY"))
		}
	case "ywh":
		a.Token = strings.TrimSpace(os.Getenv("YWH_TOKEN"))
		a.Email = strings.TrimSpace(os.Getenv("YWH_EMAIL"))
		a.Password = strings.TrimSpace(os.Getenv("YWH_PASSWORD"))
		a.TOTPSecret = strings.TrimSpace(os.Getenv("YWH_TOTP_SECRET"))
	}
	return a
}

// For returns every usable account for a platform: enabled DB accounts plus the
// legacy env account (deduped by token so the same credential isn't used twice).
// immunefi always returns a single no-auth account.
func For(platform string) []Account {
	p := Canonical(platform)
	if p == "immunefi" {
		return []Account{{Platform: p, Label: "public", Source: "env"}}
	}

	var out []Account
	seenTok := map[string]bool{}

	if rows, err := db.ListBBPAccounts(p); err == nil {
		for _, r := range rows {
			if !r.Enabled {
				continue
			}
			a := Account{
				ID: r.ID, Platform: p, Label: r.Label, Username: r.Username,
				Token: r.Token, Email: r.Email, Password: r.Password,
				TOTPSecret: r.TOTPSecret, Source: "db",
			}
			if !hasCreds(a) {
				continue
			}
			out = append(out, a)
			if a.Token != "" {
				seenTok[a.Token] = true
			}
		}
	}

	// Add the legacy env account unless its token is already represented — but only
	// until the env credentials have been migrated into the DB (see
	// MigrateEnvAccounts). After migration the DB is the single source of truth, so
	// the env vars are no longer injected as an implicit extra account.
	if !envMigrated() {
		if env := envAccount(p); hasCreds(env) && (env.Token == "" || !seenTok[env.Token]) {
			out = append(out, env)
		}
	}
	return out
}

const envMigratedMarker = "bbp_env_migrated"

// envMigrated reports whether the one-time env→DB account migration has run.
func envMigrated() bool {
	v, _ := db.GetSetting(envMigratedMarker)
	return v == "done"
}

// MigrateEnvAccounts imports the legacy single-account env credentials
// (H1_USERNAME/H1_TOKEN, BUGCROWD_TOKEN, INTIGRITI_TOKEN, YWH_*) into the
// bbp_accounts DB table as a "default" account per platform, so the DB becomes
// the single source of truth for the Settings accounts manager. It is idempotent
// and one-shot (guarded by a settings marker), so it is safe to call on every
// boot. An env credential already present as a DB account (same token) is skipped.
func MigrateEnvAccounts() {
	if envMigrated() {
		return
	}
	for _, p := range []string{"h1", "bc", "it", "ywh"} {
		env := envAccount(p)
		if !hasCreds(env) {
			continue
		}
		exists := false
		if rows, err := db.ListBBPAccounts(p); err == nil {
			for _, r := range rows {
				if r.Token != "" && r.Token == env.Token {
					exists = true
					break
				}
			}
		}
		if exists {
			continue
		}
		_, _ = db.UpsertBBPAccount(db.BBPAccount{
			Platform: p, Label: "default", Username: env.Username,
			Token: env.Token, Email: env.Email, Password: env.Password, Enabled: true,
		})
	}
	_ = db.SetSetting(envMigratedMarker, "done")
}

// Labels returns the account labels for a platform (for source tagging).
func Labels(platform string) []string {
	var ls []string
	for _, a := range For(platform) {
		ls = append(ls, a.Label)
	}
	return ls
}

// Count returns how many usable accounts a platform has.
func Count(platform string) int { return len(For(platform)) }
