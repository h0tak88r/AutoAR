package brain

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// withProvider points one registry entry at a test server for the duration of t.
func withProvider(t *testing.T, id string, mutate func(*Provider)) {
	t.Helper()
	orig := append([]Provider(nil), providers...)
	t.Cleanup(func() { providers = orig })
	for i := range providers {
		if providers[i].ID == id {
			mutate(&providers[i])
			return
		}
	}
	t.Fatalf("no provider %q", id)
}

func TestActiveDefaultsToDeepSeek(t *testing.T) {
	t.Setenv(ProviderEnv, "")
	if got := Active().ID; got != "deepseek" {
		t.Fatalf("Active() = %q, want deepseek", got)
	}
	t.Setenv(ProviderEnv, "OpenRouter")
	if got := Active().ID; got != "openrouter" {
		t.Fatalf("Active() with AI_PROVIDER=OpenRouter = %q", got)
	}
	t.Setenv(ProviderEnv, "nope")
	if got := Active().ID; got != "deepseek" {
		t.Fatalf("unknown AI_PROVIDER should fall back to deepseek, got %q", got)
	}
}

func TestDeepSeekRequestShape(t *testing.T) {
	var gotAuth string
	var gotBody struct {
		Model     string    `json:"model"`
		Messages  []Message `json:"messages"`
		MaxTokens int       `json:"max_tokens"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"<think>hmm</think>\n  real answer "}}]}`)
	}))
	defer srv.Close()
	withProvider(t, "deepseek", func(p *Provider) { p.endpoint = srv.URL })
	t.Setenv(ProviderEnv, "")
	t.Setenv("DEEPSEEK_API_KEY", "sk-test")
	t.Setenv("DEEPSEEK_MODEL", "")

	out, err := Complete(context.Background(), "be terse", "hello", Options{MaxTokens: 50000})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out != "real answer" {
		t.Fatalf("reply = %q, want think-block stripped and trimmed", out)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotBody.Model != "deepseek-chat" {
		t.Fatalf("model = %q, want default deepseek-chat", gotBody.Model)
	}
	if len(gotBody.Messages) != 2 || gotBody.Messages[0].Role != "system" || gotBody.Messages[0].Content != "be terse" {
		t.Fatalf("system prompt must be a real system message, got %+v", gotBody.Messages)
	}
	if gotBody.MaxTokens != 8192 {
		t.Fatalf("max_tokens = %d, want clamp to 8192", gotBody.MaxTokens)
	}
}

func TestNotConfigured(t *testing.T) {
	t.Setenv(ProviderEnv, "deepseek")
	t.Setenv("DEEPSEEK_API_KEY", "")
	if Available() {
		t.Fatal("Available() should be false without a key")
	}
	_, err := Complete(context.Background(), "", "x", Options{})
	if !IsNotConfigured(err) {
		t.Fatalf("want not-configured error, got %v", err)
	}
}

func TestErrorIsReadableAndKeyFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		_, _ = io.WriteString(w, `{"error":{"message":"Insufficient Balance","type":"unknown_error"}}`)
	}))
	defer srv.Close()
	withProvider(t, "deepseek", func(p *Provider) { p.endpoint = srv.URL })
	t.Setenv(ProviderEnv, "deepseek")
	t.Setenv("DEEPSEEK_API_KEY", "sk-secret-value")

	_, err := Complete(context.Background(), "", "x", Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "402") || !strings.Contains(msg, "insufficient balance") || !strings.Contains(msg, "Insufficient Balance") {
		t.Fatalf("unhelpful error: %q", msg)
	}
	if strings.Contains(msg, "sk-secret-value") {
		t.Fatalf("error leaks the key: %q", msg)
	}
}

func TestRetriesOnceOnOverload(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}]}`)
	}))
	defer srv.Close()
	withProvider(t, "deepseek", func(p *Provider) { p.endpoint = srv.URL })
	t.Setenv(ProviderEnv, "deepseek")
	t.Setenv("DEEPSEEK_API_KEY", "k")

	out, err := Complete(context.Background(), "", "x", Options{})
	if err != nil || out != "ok" {
		t.Fatalf("got %q, %v", out, err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

func TestGeminiKeyInHeaderNotURL(t *testing.T) {
	var gotPath, gotQuery, gotKey string
	var gotBody map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotKey = r.URL.Path, r.URL.RawQuery, r.Header.Get("x-goog-api-key")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"candidates":[{"content":{"parts":[{"text":"hi "},{"text":"there"}]}}]}`)
	}))
	defer srv.Close()
	withProvider(t, "gemini", func(p *Provider) { p.endpoint = srv.URL + "/models/%s:generateContent" })
	t.Setenv(ProviderEnv, "gemini")
	t.Setenv("GEMINI_API_KEY", "AIza-test")
	t.Setenv("GEMINI_MODEL", "")

	out, err := Complete(context.Background(), "sys", "u", Options{})
	if err != nil || out != "hi there" {
		t.Fatalf("got %q, %v", out, err)
	}
	if gotKey != "AIza-test" || strings.Contains(gotQuery, "AIza") {
		t.Fatalf("key must travel in the header only (header=%q query=%q)", gotKey, gotQuery)
	}
	if gotPath != "/models/gemini-2.5-flash:generateContent" {
		t.Fatalf("path = %q", gotPath)
	}
	if _, ok := gotBody["systemInstruction"]; !ok {
		t.Fatal("system prompt should be sent as systemInstruction")
	}
}

func TestListModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"deepseek-reasoner"},{"id":"deepseek-chat"}]}`)
	}))
	defer srv.Close()
	withProvider(t, "deepseek", func(p *Provider) { p.modelsURL = srv.URL })
	t.Setenv("DEEPSEEK_API_KEY", "k")

	p, _ := ProviderByID("deepseek")
	got, err := p.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels: %v", err)
	}
	if strings.Join(got, ",") != "deepseek-chat,deepseek-reasoner" {
		t.Fatalf("models = %v", got)
	}
	z, _ := ProviderByID("zai")
	if _, err := z.ListModels(context.Background()); err == nil {
		t.Fatal("zai has no model listing; want an explanatory error")
	}
}

// Native function calling: declared tools go out as "tools" (no JSON mode,
// which conflicts) and the model's tool_calls come back structured.
func TestDeepSeekNativeToolCalls(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","content":"",
			"tool_calls":[{"id":"c1","type":"function","function":{"name":"bash","arguments":"{\"command\":\"git clone https://github.com/a/b\"}"}}]}}]}`)
	}))
	defer srv.Close()
	withProvider(t, "deepseek", func(p *Provider) { p.endpoint = srv.URL })
	t.Setenv(ProviderEnv, "")
	t.Setenv("DEEPSEEK_API_KEY", "sk-test")
	tools := []ToolDef{{Name: "bash", Description: "run a command", Parameters: map[string]any{
		"type": "object", "properties": map[string]any{"command": map[string]any{"type": "string"}}, "required": []string{"command"}}}}
	r, err := ChatReply(context.Background(), "sys", []Message{{Role: "user", Content: "clone it"}}, Options{JSON: true, Tools: tools})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Name != "bash" || !strings.Contains(r.ToolCalls[0].Arguments, "git clone") {
		t.Fatalf("tool calls: %+v", r)
	}
	if _, ok := gotBody["response_format"]; ok {
		t.Fatal("JSON mode must not be sent together with tools")
	}
	ts, _ := gotBody["tools"].([]any)
	if len(ts) != 1 || gotBody["tool_choice"] != "auto" {
		t.Fatalf("request tools: %v", gotBody)
	}
	fn := ts[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "bash" || ts[0].(map[string]any)["type"] != "function" {
		t.Fatalf("tool spec: %v", ts[0])
	}
	// Plain Chat never sends tools, keeps JSON mode, and a tool-only reply
	// is an empty text reply for it.
	gotBody = nil
	if _, err := Chat(context.Background(), "sys", []Message{{Role: "user", Content: "x"}}, Options{JSON: true, Tools: tools}); err == nil {
		t.Fatal("a tool-only reply has no text for Chat")
	}
	if _, ok := gotBody["tools"]; ok || gotBody["response_format"] == nil {
		t.Fatalf("Chat request: %v", gotBody)
	}
}

// A model that rejects "tools" (400) is retried once without them and
// remembered, so the agent keeps working on the text protocol.
func TestToolsRejectedFallsBackToText(t *testing.T) {
	noToolModels.Delete("deepseek|deepseek-chat")
	t.Cleanup(func() { noToolModels.Delete("deepseek|deepseek-chat") })
	var calls int32
	var lastHadTools bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, lastHadTools = body["tools"]
		if lastHadTools {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":{"message":"deepseek-chat does not support Function Calling"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"final\":\"ok\"}"}}]}`)
	}))
	defer srv.Close()
	withProvider(t, "deepseek", func(p *Provider) { p.endpoint = srv.URL })
	t.Setenv(ProviderEnv, "")
	t.Setenv("DEEPSEEK_API_KEY", "sk-test")
	t.Setenv("DEEPSEEK_MODEL", "")
	tools := []ToolDef{{Name: "bash"}}
	r, err := ChatReply(context.Background(), "sys", []Message{{Role: "user", Content: "x"}}, Options{JSON: true, Tools: tools})
	if err != nil || r.Text != `{"final":"ok"}` || atomic.LoadInt32(&calls) != 2 || lastHadTools {
		t.Fatalf("fallback: %+v err=%v calls=%d", r, err, calls)
	}
	// Remembered: the next call skips tools entirely.
	if _, err := ChatReply(context.Background(), "sys", []Message{{Role: "user", Content: "x"}}, Options{Tools: tools}); err != nil || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("second call: err=%v calls=%d", err, calls)
	}
}

// Z.ai answers an unpaid call with HTTP 429 code 1113. That is not rate
// limiting: say what it is, and don't retry it.
func TestBillingRefusalIsNotCalledRateLimiting(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"error":{"code":"1113","message":"Insufficient balance or no resource package. Please recharge."}}`)
	}))
	defer srv.Close()
	withProvider(t, "zai", func(p *Provider) { p.endpoint = srv.URL })
	t.Setenv(ProviderEnv, "zai")
	t.Setenv("ZHIPU_API_KEY", "k")
	_, err := Complete(context.Background(), "", "x", Options{})
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "rate limited") || !strings.Contains(msg, "insufficient balance —") || !strings.Contains(msg, "Coding Plan") {
		t.Fatalf("message: %s", msg)
	}
	if calls != 1 {
		t.Fatalf("a billing refusal must not be retried (calls=%d)", calls)
	}
	// A real rate limit keeps its wording.
	if e := statusError(http.StatusTooManyRequests, []byte(`{"error":{"message":"Rate limit reached for requests per minute"}}`)); !strings.Contains(e.Error(), "rate limited") {
		t.Fatalf("rate limit: %v", e)
	}
	if e := statusError(http.StatusTooManyRequests, []byte(`{"error":{"message":"Quota exceeded for metric: requests per minute"}}`)); !strings.Contains(e.Error(), "rate limited") {
		t.Fatalf("per-minute quota is a rate limit: %v", e)
	}
	if e := statusError(http.StatusPaymentRequired, []byte(`{}`)); !strings.Contains(e.Error(), "insufficient balance") || !errors.Is(e, errNotBilled) {
		t.Fatalf("402: %v", e)
	}
}
