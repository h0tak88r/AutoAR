package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// TestSettingsSaveAIProviderAndDeepSeekKey covers the Settings ▸ AI Providers
// contract: the DeepSeek key is persisted to the settings DB, the provider
// choice is validated before anything is saved, the provider listing reports
// set-state but never the key, and a line break can't be smuggled into .env.
func TestSettingsSaveAIProviderAndDeepSeekKey(t *testing.T) {
	setupUsersTestDB(t)  // no users → auth not enforced
	t.Chdir(t.TempDir()) // saveEnvSetting also writes ./.env
	for _, k := range []string{"AI_PROVIDER", "DEEPSEEK_API_KEY", "DEEPSEEK_MODEL", "OPENCODE_API_KEY"} {
		t.Setenv(k, "") // restore whatever the handler os.Setenv's
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/api/settings", apiUpdateSettingsHandler)
	r.GET("/api/ai/providers", apiAIProviders)
	post := func(body string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w.Code
	}

	// Unknown provider: rejected, and the key in the same request is NOT saved.
	if code := post(`{"ai_provider":"bogus","deepseek_key":"sk-should-not-save"}`); code != http.StatusBadRequest {
		t.Fatalf("bogus provider: status %d, want 400", code)
	}
	if v, _ := db.GetSetting("DEEPSEEK_API_KEY"); v != "" {
		t.Fatalf("key saved despite rejected request: %q", v)
	}

	if code := post(`{"ai_provider":"deepseek","deepseek_key":"sk-unit-test","deepseek_model":"deepseek-reasoner"}`); code != http.StatusOK {
		t.Fatalf("save: status %d", code)
	}
	for k, want := range map[string]string{"DEEPSEEK_API_KEY": "sk-unit-test", "DEEPSEEK_MODEL": "deepseek-reasoner", "AI_PROVIDER": "deepseek"} {
		if v, err := db.GetSetting(k); err != nil || v != want {
			t.Fatalf("DB %s = %q (%v), want %q", k, v, err, want)
		}
	}

	// .env line injection is refused; the stored key is unchanged.
	post(`{"deepseek_key":"sk-evil\nAUTOAR_API_AUTH_DISABLED=true"}`)
	if v, _ := db.GetSetting("DEEPSEEK_API_KEY"); v != "sk-unit-test" {
		t.Fatalf("multi-line value was persisted: %q", v)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/ai/providers", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("providers: status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "sk-unit-test") {
		t.Fatal("provider listing leaks the API key")
	}
	var got struct {
		Active    string           `json:"active"`
		Available bool             `json:"available"`
		Providers []aiProviderView `json:"providers"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Active != "deepseek" || !got.Available {
		t.Fatalf("active=%q available=%v, want deepseek/true", got.Active, got.Available)
	}
	if len(got.Providers) == 0 || got.Providers[0].ID != "deepseek" || !got.Providers[0].KeySet || got.Providers[0].Model != "deepseek-reasoner" {
		t.Fatalf("deepseek row = %+v", got.Providers[0])
	}

	// "default" clears a model override back to the provider default.
	post(`{"deepseek_model":"default"}`)
	if v, _ := db.GetSetting("DEEPSEEK_MODEL"); v != "" {
		t.Fatalf("model override not cleared: %q", v)
	}
}
