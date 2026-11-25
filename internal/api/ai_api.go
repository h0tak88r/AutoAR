package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/brain"
)

// aiProviderView is one row of the Settings ▸ AI Providers panel. Keys are never
// returned — only whether each is set.
type aiProviderView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	KeySet        bool   `json:"key_set"`
	Model         string `json:"model"`
	DefaultModel  string `json:"default_model"`
	KeyURL        string `json:"key_url"`
	KeyEnv        string `json:"key_env"`
	ListsModels   bool   `json:"lists_models"`
	Active        bool   `json:"active"`
	DefaultChoice bool   `json:"default_choice"`
}

// GET /api/ai/providers (admin) — the provider registry with live status.
func apiAIProviders(c *gin.Context) {
	active := brain.Active()
	list := brain.Providers()
	out := make([]aiProviderView, 0, len(list))
	for _, p := range list {
		out = append(out, aiProviderView{
			ID:            p.ID,
			Name:          p.Name,
			KeySet:        p.Configured(),
			Model:         p.Model(),
			DefaultModel:  p.DefaultModel,
			KeyURL:        p.KeyURL,
			KeyEnv:        p.KeyEnv,
			ListsModels:   p.SupportsModelList(),
			Active:        p.ID == active.ID,
			DefaultChoice: p.ID == brain.DefaultProviderID,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"active":    active.ID,
		"available": active.Configured(),
		"providers": out,
	})
}

// providerFromRequest resolves ?provider= / {"provider":...}, defaulting to the
// active provider. The bool is false (and a 400 written) for an unknown ID.
func providerFromRequest(c *gin.Context, id string) (brain.Provider, bool) {
	if strings.TrimSpace(id) == "" {
		return brain.Active(), true
	}
	p, ok := brain.ProviderByID(id)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown provider"})
	}
	return p, ok
}

// POST /api/ai/test (admin) — sends a one-word prompt to prove key + model work.
func apiAITest(c *gin.Context) {
	var body struct {
		Provider string `json:"provider"`
	}
	_ = c.ShouldBindJSON(&body) // empty body = test the active provider
	p, ok := providerFromRequest(c, body.Provider)
	if !ok {
		return
	}
	res, err := p.Test(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error(), "result": res})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "result": res})
}

// GET /api/ai/models?provider=ID (admin) — model IDs the provider offers.
func apiAIModels(c *gin.Context) {
	p, ok := providerFromRequest(c, c.Query("provider"))
	if !ok {
		return
	}
	models, err := p.ListModels(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"provider": p.ID, "models": models})
}
