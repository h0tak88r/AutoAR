// Package apikeys is the single, general-purpose accessor for provider API keys
// (Shodan, VirusTotal, Censys, GitHub, …). Any code — not just subfinder — reads
// keys through here so the resolution rule lives in one place:
//
//	database value (Settings) wins; the container environment is the fallback.
//
// Values are treated as lists: a provider may hold several keys entered over time
// (comma / newline / semicolon separated). Get returns the first; All returns all,
// deduplicated. Reading the DB live (not a boot-time env snapshot) means a key
// added in Settings is usable immediately, without waiting for a redeploy.
package apikeys

import (
	"os"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// All returns every key configured for name, DB-first with the env as fallback,
// split into a deduplicated list. Empty slice if none.
func All(name string) []string {
	if v, err := db.GetSetting(name); err == nil && strings.TrimSpace(v) != "" {
		return utils.ParseKeyList(v)
	}
	return utils.ParseKeyList(os.Getenv(name))
}

// Get returns the first configured key for name, or "".
func Get(name string) string {
	if all := All(name); len(all) > 0 {
		return all[0]
	}
	return ""
}

// Has reports whether at least one key is configured for name.
func Has(name string) bool { return len(All(name)) > 0 }

// Append merges newKeys into name's existing list (dedup, order preserved) and
// returns the combined list. It does not persist — the caller decides where to
// store the joined value (env + DB via the settings layer).
func Append(name string, newKeys []string) []string {
	combined := append(All(name), newKeys...)
	return utils.ParseKeyList(strings.Join(combined, ","))
}
