package api

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/apikeys"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// revealDenyKeys are persisted env keys that are NOT secrets (models, flags,
// identity handles, bucket coordinates) — never revealable via the API.
var revealDenyKeys = map[string]bool{
	"OPENROUTER_MODEL": true, "OPENCODE_MODEL": true,
	"HACKADVISOR_INCLUDE_NATIVE": true, "USE_R2_STORAGE": true,
	"R2_ACCOUNT_ID": true, "R2_BUCKET_NAME": true, "R2_PUBLIC_URL": true,
	"H1_USERNAME": true,
}

// revealableEnvKeySet is the allowlist the reveal endpoint serves: every
// persisted env key except the deny set. Anything outside it 404s, so the
// endpoint can never be used to probe arbitrary env vars.
var revealableEnvKeySet = func() map[string]bool {
	m := make(map[string]bool, len(persistedEnvKeys))
	for _, k := range persistedEnvKeys {
		if !revealDenyKeys[k] {
			m[k] = true
		}
	}
	return m
}()

// GET /api/config/reveal?key=NAME — returns the current value of one
// allowlisted secret so the Settings page can offer copy-to-clipboard.
// Authenticated like every other /api route (unlike public /api/config,
// which only exposes set/unset booleans).
func apiRevealEnvSecret(c *gin.Context) {
	key := strings.TrimSpace(c.Query("key"))
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing key"})
		return
	}
	if !revealableEnvKeySet[key] {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown or non-revealable key"})
		return
	}
	value := strings.TrimSpace(os.Getenv(key))
	if subfinderProviderKeySet[key] {
		// Provider keys are DB-first (apikeys) — env can lag a direct DB write.
		if list := apikeys.All(key); len(list) > 0 {
			value = strings.Join(list, ",")
		}
	} else if value == "" {
		// env may be empty when the value was written straight to the DB
		if v, err := db.GetSetting(key); err == nil {
			value = strings.TrimSpace(v)
		}
	}
	c.JSON(http.StatusOK, gin.H{"key": key, "value": value, "set": value != ""})
}

// GET /api/accounts/:id/reveal — full (unmasked) credentials for one stored
// platform account, backing the Settings copy button. Same authority as the
// account Test/Edit endpoints; the data only ever goes to the logged-in UI.
func apiRevealBBPAccount(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	rows, err := db.ListBBPAccounts("")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, a := range rows {
		if a.ID == id {
			c.JSON(http.StatusOK, gin.H{
				"id": a.ID, "platform": a.Platform, "label": a.Label,
				"username": a.Username, "email": a.Email, "token": a.Token,
				"password": a.Password, "totp_secret": a.TOTPSecret,
			})
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
}
