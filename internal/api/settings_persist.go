package api

import (
	"log"
	"os"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/envloader"
)

// persistedEnvKeys are the env-backed settings that must outlive a container
// restart. Dokploy (and Docker generally) recreates the container filesystem on
// every redeploy, so anything written only to .env / os.Setenv is lost. These
// keys are mirrored into the settings DB table on save and re-hydrated into the
// process env on boot (see HydrateEnvFromDB), which is why UI-entered API keys
// now survive redeployments the same way the scan-phase timeouts already do.
//
// Scan-phase timeouts are intentionally NOT here: they use "timeout_*" DB keys
// and are resolved directly from the DB via utils.GetTimeout.
var persistedEnvKeys = []string{
	"MONITOR_WEBHOOK_URL",
	"OPENROUTER_API_KEY", "OPENCODE_API_KEY", "GEMINI_API_KEY",
	"OPENROUTER_MODEL", "OPENCODE_MODEL",
	"H1_USERNAME", "H1_TOKEN",
	"BUGCROWD_TOKEN", "INTIGRITI_TOKEN", "YWH_TOKEN",
	"HACKADVISOR_TOKEN", "HACKADVISOR_INCLUDE_NATIVE",
	"CHAOS_API_KEY",
	"SHODAN_API_KEY", "SHODAN_API_KEYS",
}

// subfinderProviderKeys are the subfinder passive-source API keys manageable from
// Settings. They are appended to persistedEnvKeys so a UI-entered value is saved
// to the DB and re-hydrated into the process env on boot (DB wins over container
// env — see HydrateEnvFromDB). The subfinder config generator already reads these
// via os.Getenv, so "subfinder reads the DB value, falling back to the container
// env when absent" holds without touching the subfinder package. Names must match
// the providerMap in internal/scanner/subdomains (the subfinder env contract).
var subfinderProviderKeys = []string{
	"GITHUB_TOKEN",
	"SECURITYTRAILS_API_KEY",
	"VIRUSTOTAL_API_KEY",
	"BEVIGIL_API_KEY",
	"BINARYEDGE_API_KEY",
	"URLSCAN_API_KEY",
	"CENSYS_API_ID", "CENSYS_API_SECRET",
	"CERTSPOTTER_API_KEY",
	"FOFA_EMAIL", "FOFA_KEY",
	"FULLHUNT_API_KEY",
	"INTELX_API_KEY",
	"PASSIVETOTAL_USERNAME", "PASSIVETOTAL_API_KEY",
	"QUAKE_USERNAME", "QUAKE_PASSWORD",
	"THREATBOOK_API_KEY",
	"WHOISXMLAPI_API_KEY",
	"ZOOMEYE_USERNAME", "ZOOMEYE_PASSWORD",
	"ZOOMEYEAPI_API_KEY",
}

// subfinderProviderKeySet gates which keys the settings save endpoint accepts, so
// an arbitrary key from a request body can never be written to the env/DB.
var subfinderProviderKeySet = func() map[string]bool {
	m := make(map[string]bool, len(subfinderProviderKeys))
	for _, k := range subfinderProviderKeys {
		m[k] = true
	}
	return m
}()

func init() {
	// Fold the subfinder keys into the persisted allowlist so saveEnvSetting mirrors
	// them to the DB and HydrateEnvFromDB restores them after a redeploy.
	persistedEnvKeys = append(persistedEnvKeys, subfinderProviderKeys...)
	for _, k := range subfinderProviderKeys {
		persistedEnvSet[k] = true
	}
}

var persistedEnvSet = func() map[string]bool {
	m := make(map[string]bool, len(persistedEnvKeys))
	for _, k := range persistedEnvKeys {
		m[k] = true
	}
	return m
}()

// saveEnvSetting persists an env-backed setting to BOTH the live process
// (.env file + os.Setenv, via envloader) for immediate effect AND the settings
// DB table for durability across redeployments. Use this in place of a bare
// envloader.UpdateEnv for any value that must survive a container restart.
func saveEnvSetting(key, value string) {
	_ = envloader.UpdateEnv(key, value) // immediate: .env + os.Setenv
	if persistedEnvSet[key] {
		if err := db.SetSetting(key, value); err != nil {
			log.Printf("[settings] failed to persist %s to DB: %v", key, err)
		}
	}
}

// HydrateEnvFromDB copies persisted settings from the DB into the process env at
// boot so UI-saved API keys / webhooks survive a redeploy. A key present in the
// DB (even with an empty value, e.g. a cleared model override) wins over the
// container env; keys absent from the DB keep whatever the container env set.
func HydrateEnvFromDB() {
	all, err := db.GetAllSettings()
	if err != nil {
		log.Printf("[settings] hydrate from DB failed: %v", err)
		return
	}
	n := 0
	for _, k := range persistedEnvKeys {
		if v, ok := all[k]; ok {
			_ = os.Setenv(k, v)
			n++
		}
	}
	if n > 0 {
		log.Printf("[settings] hydrated %d persisted setting(s) from DB", n)
	}
}
