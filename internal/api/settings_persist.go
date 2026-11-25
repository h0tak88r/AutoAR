package api

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/envloader"
	"github.com/h0tak88r/AutoAR/internal/utils"
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
	// AI provider selection + the official DeepSeek default (Settings ▸ AI
	// Providers). ZHIPU_API_KEY powers the Z.ai option.
	"AI_PROVIDER", "DEEPSEEK_API_KEY", "DEEPSEEK_MODEL",
	"ZHIPU_API_KEY", "ZAI_MODEL", "GEMINI_MODEL",
	"H1_USERNAME", "H1_TOKEN",
	"BUGCROWD_TOKEN", "INTIGRITI_TOKEN", "YWH_TOKEN",
	"HACKADVISOR_TOKEN", "HACKADVISOR_INCLUDE_NATIVE",
	"CHAOS_API_KEY",
	"SHODAN_API_KEY", "SHODAN_API_KEYS",
	// ProjectDiscovery Cloud key — powers the nuclei template watch (falls back
	// to CHAOS_API_KEY when unset).
	"PDCP_API_KEY",
	// Nuclei template blocklist (comma-separated IDs) for templates with
	// known-broken matchers — see nucleiTemplateBlocked.
	"NUCLEI_TEMPLATE_IGNORE",
	// Cloudflare R2 storage — managed from Settings ▸ System ▸ Cloudflare R2.
	"USE_R2_STORAGE", "R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_KEY",
	"R2_BUCKET_NAME", "R2_PUBLIC_URL",
	// Global wall-clock scan ceilings (Go duration strings, e.g. "72h").
	// Managed from Settings ▸ Timeouts; 0 in the UI resets to the 24h default.
	"AUTOAR_SCAN_TIMEOUT", "AUTOAR_PIPELINE_TIMEOUT",
	// Purpose-routed Discord webhooks — Settings ▸ Notifications. Each falls
	// back to MONITOR_WEBHOOK_URL when unset.
	"WEBHOOK_SCANS", "WEBHOOK_NEW_SCOPES", "WEBHOOK_MONITORING", "WEBHOOK_FINDINGS",
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
	// Values are written to .env as KEY="value" lines; a CR/LF/NUL would let a
	// settings field smuggle extra lines (e.g. AUTOAR_API_AUTH_DISABLED=true)
	// into .env that take effect on the next restart. No setting is multi-line.
	if strings.ContainsAny(value, "\r\n\x00") {
		log.Printf("[settings] rejected %s: value contains a line break or NUL", key)
		return
	}
	_ = envloader.UpdateEnv(key, value) // immediate: .env + os.Setenv
	if persistedEnvSet[key] {
		if err := db.SetSetting(key, value); err != nil {
			log.Printf("[settings] failed to persist %s to DB: %v", key, err)
		}
	}
}

// SeedDBFromEnv makes the container env vars optional. For each persisted setting
// that is present in the container env but has NEVER been written to the DB, it
// copies the env value into the DB once. After this runs, the DB is the durable
// source of truth (HydrateEnvFromDB then loads it back), so the value can be
// removed from the deployment's env (e.g. Dokploy) without losing it on the next
// redeploy — the same "env is only a seed" model the accounts manager already
// uses. This is what lets MONITOR_WEBHOOK_URL and the provider keys move out of
// the required-env set.
//
// Idempotent and non-destructive: a key already in the DB — INCLUDING one
// deliberately cleared to empty in the UI — is never overwritten from the env, so
// re-seeding can't resurrect a value the user removed. Call it at boot BEFORE
// HydrateEnvFromDB.
func SeedDBFromEnv() {
	all, err := db.GetAllSettings()
	if err != nil {
		log.Printf("[settings] seed DB from env failed: %v", err)
		return
	}
	n := 0
	for _, k := range persistedEnvKeys {
		if _, ok := all[k]; ok {
			continue // DB is already authoritative for this key (empty counts)
		}
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			if err := db.SetSetting(k, v); err != nil {
				log.Printf("[settings] seed %s from env failed: %v", k, err)
				continue
			}
			n++
		}
	}
	if n > 0 {
		log.Printf("[settings] seeded %d setting(s) from env into DB — those env vars are now optional", n)
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
	var overridden []string
	for _, k := range persistedEnvKeys {
		if v, ok := all[k]; ok {
			// A different, non-empty container value is silently shadowed by
			// the DB — warn by KEY name only (never values).
			if ev := strings.TrimSpace(os.Getenv(k)); ev != "" && ev != strings.TrimSpace(v) {
				overridden = append(overridden, k)
			}
			_ = os.Setenv(k, v)
			n++
		}
	}
	if n > 0 {
		log.Printf("[settings] hydrated %d persisted setting(s) from DB", n)
	}
	if len(overridden) > 0 {
		sort.Strings(overridden)
		log.Printf("[settings] WARNING: container env differs from the value saved in Settings for %s — the saved (DB) value wins; "+
			"change it in Settings or remove the env var to silence this", strings.Join(overridden, ", "))
	}
}

// credentialTokenPrefixes are the distinctive leading markers of token formats
// the settings page accepts. One credential field must hold at most ONE token:
// the UI pre-fills the current value, so pasting a new token at the end of the
// field glues old+new into a single string that no separator can split — it
// then 401s forever while looking configured (seen live with GITHUB_TOKEN).
var credentialTokenPrefixes = []string{
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", // GitHub
	"sk-", // OpenAI-style / OpenRouter / DeepSeek
}

// countTokenPrefixes reports how many token-start markers appear in a value.
// >1 in one field is always a paste accident, never a valid credential.
func countTokenPrefixes(v string) int {
	n := 0
	for _, p := range credentialTokenPrefixes {
		n += strings.Count(v, p)
	}
	return n
}

// validateWebhookURL accepts only a public https URL for a notification
// webhook. The server POSTs to it, so an http:// or internal/loopback/metadata
// target would let a settings write probe the deployment's private network.
func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("webhook URL must use https")
	}
	if err := utils.ValidatePublicHTTPURL(raw); err != nil {
		return fmt.Errorf("webhook URL must point to a public host: %v", err)
	}
	return nil
}
