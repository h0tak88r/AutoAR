package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/accounts"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// maskSecret returns a safe preview of a secret — never the full value.
func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return "••••"
	}
	return "••••" + s[len(s)-4:]
}

// GET /api/accounts — list stored accounts (secrets masked). ?platform= filters.
func apiListBBPAccounts(c *gin.Context) {
	platform := accounts.Canonical(c.Query("platform"))
	rows, err := db.ListBBPAccounts(platform) // "" = all platforms
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	type acctOut struct {
		ID          int64  `json:"id"`
		Platform    string `json:"platform"`
		Label       string `json:"label"`
		Username    string `json:"username"`
		TokenMask   string `json:"token_mask"`
		TokenSet    bool   `json:"token_set"`
		Email       string `json:"email"`
		PasswordSet bool   `json:"password_set"`
		TOTPSet     bool   `json:"totp_set"`
		Enabled     bool   `json:"enabled"`
	}
	out := make([]acctOut, 0, len(rows))
	for _, r := range rows {
		out = append(out, acctOut{
			ID: r.ID, Platform: r.Platform, Label: r.Label, Username: r.Username,
			TokenMask: maskSecret(r.Token), TokenSet: r.Token != "",
			Email: r.Email, PasswordSet: r.Password != "", TOTPSet: r.TOTPSecret != "",
			Enabled: r.Enabled,
		})
	}
	c.JSON(http.StatusOK, gin.H{"accounts": out})
}

type bbpAccountBody struct {
	Platform   string `json:"platform"`
	Label      string `json:"label"`
	Username   string `json:"username"`
	Token      string `json:"token"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret"`
	Enabled    *bool  `json:"enabled"`
}

// POST /api/accounts — create or update an account (keyed by platform+label).
// An empty token/password in the body preserves the stored one (so editing a
// label/username after the UI masked the secret doesn't wipe it).
func apiUpsertBBPAccount(c *gin.Context) {
	var b bbpAccountBody
	if err := c.ShouldBindJSON(&b); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}
	p := accounts.Canonical(b.Platform)
	switch p {
	case "h1", "bc", "it", "ywh":
		// ok
	case "immunefi":
		c.JSON(http.StatusBadRequest, gin.H{"error": "immunefi needs no account"})
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported platform: " + b.Platform})
		return
	}

	label := strings.TrimSpace(b.Label)
	if label == "" {
		label = "main"
	}
	token := strings.TrimSpace(b.Token)
	password := b.Password
	totpSecret := strings.TrimSpace(b.TOTPSecret)
	// Preserve stored secrets when the body omits them (masked-edit case).
	if token == "" || password == "" || totpSecret == "" {
		if existing, err := db.ListBBPAccounts(p); err == nil {
			for _, e := range existing {
				if e.Label == label {
					if token == "" {
						token = e.Token
					}
					if password == "" {
						password = e.Password
					}
					if totpSecret == "" {
						totpSecret = e.TOTPSecret
					}
					break
				}
			}
		}
	}
	enabled := true
	if b.Enabled != nil {
		enabled = *b.Enabled
	}

	a := db.BBPAccount{
		Platform: p, Label: label, Username: strings.TrimSpace(b.Username),
		Token: token, Email: strings.TrimSpace(b.Email), Password: password,
		TOTPSecret: totpSecret, Enabled: enabled,
	}
	id, err := db.UpsertBBPAccount(a)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "platform": p, "label": label, "enabled": enabled})
}

// POST /api/accounts/:id/toggle — enable/disable an account.
func apiToggleBBPAccount(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var b struct {
		Enabled bool `json:"enabled"`
	}
	_ = c.ShouldBindJSON(&b)
	if err := db.SetBBPAccountEnabled(id, b.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "enabled": b.Enabled})
}

// DELETE /api/accounts/:id — remove an account.
func apiDeleteBBPAccount(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := db.DeleteBBPAccount(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": id})
}
