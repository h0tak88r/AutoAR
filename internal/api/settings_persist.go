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
