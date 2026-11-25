// Package brain is AutoAR's single gateway to LLM providers.
//
// Exactly one provider is active at a time, picked by AI_PROVIDER (Settings ▸
// AI Providers). The official DeepSeek API is the default; OpenCode Zen,
// OpenRouter, Z.ai and Gemini are opt-in alternatives. There is deliberately
// no silent fallback chain: a request goes to the provider the operator chose,
// and a missing key or upstream error is reported as such instead of quietly
// landing on a different vendor.
//
// Keys and models live in the process env, which the API hydrates from the
// settings DB table at boot (see api.HydrateEnvFromDB), so a key saved from the
// dashboard is used immediately and survives redeploys.
package brain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Message is one chat turn. Role is "system", "user" or "assistant".
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Options tunes a single completion. The zero value is a sensible default.
type Options struct {
	// MaxTokens caps the reply length. 0 leaves the provider default; values
	// above the provider's own ceiling are clamped to it.
	MaxTokens int
	// Timeout bounds the whole call (retry included). 0 = DefaultTimeout.
	Timeout time.Duration
	// JSON asks for a single JSON object reply (DeepSeek/OpenAI-style
	// response_format, Gemini responseMimeType). The prompt must still describe
	// the object — and, for DeepSeek, mention "json".
	JSON bool
	// Feature labels the call in usage metering (triage, agent, report, …).
	Feature string
	// Tools declares functions the model may call natively (OpenAI-style
	// function calling). Providers that support it get them as "tools" (and
	// no JSON mode, which conflicts); the others ignore them and fall back to
	// the prompt's own text protocol. Read the calls with ChatReply.
	Tools []ToolDef
}

// ToolDef is one function the model may call.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

// ToolCall is one native function call the model made; Arguments is the
// JSON object text the model wrote.
type ToolCall struct {
	Name      string
	Arguments string
}

// Reply is a completion with any native tool calls. Text may be empty when
// the model only called tools.
type Reply struct {
	Text      string
	ToolCalls []ToolCall
}

const (
	// ProviderEnv selects the active provider (a Provider.ID).
	ProviderEnv = "AI_PROVIDER"
	// DefaultProviderID is used when AI_PROVIDER is unset or unknown.
	DefaultProviderID = "deepseek"
	// DefaultTimeout bounds one completion when Options.Timeout is 0.
	DefaultTimeout = 120 * time.Second

	maxResponseBytes = 8 << 20 // upstream bodies are capped before decoding
	maxErrorDetail   = 300     // chars of upstream error text kept in errors
)

// Provider describes one supported LLM backend.
type Provider struct {
	ID           string // stable identifier stored in AI_PROVIDER
	Name         string // display name
	KeyEnv       string // env/settings key holding the API key
	ModelEnv     string // env/settings key holding the model override
	DefaultModel string
	KeyURL       string // where the operator gets a key (UI hint)

	endpoint  string            // chat endpoint; for Gemini a format string taking the model
	modelsURL string            // OpenAI-style GET /models listing ("" = unsupported)
	headers   map[string]string // extra request headers
	maxOutput int               // ceiling for max_tokens (0 = never send max_tokens)
	jsonMode  bool              // accepts response_format {"type":"json_object"}
	tools     bool              // native function calling (OpenAI "tools")
	gemini    bool              // Gemini generateContent wire format instead of OpenAI chat
}

// providers is the registry, in the order the Settings page lists them.
var providers = []Provider{
	{
		ID:           "deepseek",
		Name:         "DeepSeek (official)",
		KeyEnv:       "DEEPSEEK_API_KEY",
		ModelEnv:     "DEEPSEEK_MODEL",
		DefaultModel: "deepseek-chat",
		KeyURL:       "https://platform.deepseek.com/api_keys",
		endpoint:     "https://api.deepseek.com/chat/completions",
		modelsURL:    "https://api.deepseek.com/models",
		maxOutput:    8192,
		jsonMode:     true,
		// DeepSeek emits its native tool-call markup (DSML) when a prompt
		// describes tools; without declared tools the API strips the call and
		// leaves fragments ("{}</｜｜DSML｜｜ invoke>") in the content.
		tools: true,
	},
	{
		ID:           "opencode",
		Name:         "OpenCode Zen",
		KeyEnv:       "OPENCODE_API_KEY",
		ModelEnv:     "OPENCODE_MODEL",
		DefaultModel: "deepseek-v4-flash-free",
		KeyURL:       "https://opencode.ai/zen",
		endpoint:     "https://opencode.ai/zen/v1/chat/completions",
		modelsURL:    "https://opencode.ai/zen/v1/models",
	},
	{
		ID:           "openrouter",
		Name:         "OpenRouter",
		KeyEnv:       "OPENROUTER_API_KEY",
		ModelEnv:     "OPENROUTER_MODEL",
		DefaultModel: "z-ai/glm-4.5-air:free",
		KeyURL:       "https://openrouter.ai/keys",
		endpoint:     "https://openrouter.ai/api/v1/chat/completions",
		modelsURL:    "https://openrouter.ai/api/v1/models",
		headers: map[string]string{
			"HTTP-Referer": "https://github.com/h0tak88r/AutoAR",
			"X-Title":      "AutoAR",
		},
	},
	{
		ID:           "zai",
		Name:         "Z.ai (GLM)",
		KeyEnv:       "ZHIPU_API_KEY",
		ModelEnv:     "ZAI_MODEL",
		DefaultModel: "glm-4.5-air",
		KeyURL:       "https://z.ai/manage-apikey/apikey-list",
		endpoint:     "https://api.z.ai/api/coding/paas/v4/chat/completions",
	},
	{
		ID:           "gemini",
		Name:         "Google Gemini",
		KeyEnv:       "GEMINI_API_KEY",
		ModelEnv:     "GEMINI_MODEL",
		DefaultModel: "gemini-2.5-flash",
		KeyURL:       "https://aistudio.google.com/apikey",
		endpoint:     "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent",
		gemini:       true,
	},
}

// Providers returns the registry (copy) in display order.
func Providers() []Provider {
	return append([]Provider(nil), providers...)
}

// ProviderByID looks a provider up by its ID (case-insensitive).
func ProviderByID(id string) (Provider, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

// Active returns the provider selected by AI_PROVIDER, or DeepSeek.
func Active() Provider {
	if p, ok := ProviderByID(os.Getenv(ProviderEnv)); ok {
		return p
	}
	p, _ := ProviderByID(DefaultProviderID)
	return p
}

// Key returns the provider's configured API key ("" when unset).
func (p Provider) Key() string { return strings.TrimSpace(os.Getenv(p.KeyEnv)) }

// Model returns the configured model override, or the provider default.
func (p Provider) Model() string {
	if m := strings.TrimSpace(os.Getenv(p.ModelEnv)); m != "" {
		return m
	}
	return p.DefaultModel
}

// Configured reports whether the provider has an API key.
func (p Provider) Configured() bool { return p.Key() != "" }

// SupportsModelList reports whether ListModels works for this provider.
func (p Provider) SupportsModelList() bool { return p.modelsURL != "" }

// Available reports whether the active provider is ready to take requests.
func Available() bool { return Active().Configured() }

// errNotConfigured is returned (wrapped) when the active provider has no key.
var errNotConfigured = errors.New("AI provider not configured")

// IsNotConfigured reports whether err means "no API key for the active provider".
func IsNotConfigured(err error) bool { return errors.Is(err, errNotConfigured) }

// Complete sends one system + user prompt to the active provider.
func Complete(ctx context.Context, system, user string, opt Options) (string, error) {
	return Chat(ctx, system, []Message{{Role: "user", Content: user}}, opt)
}

// Chat sends a conversation to the active provider and returns the reply text.
func Chat(ctx context.Context, system string, messages []Message, opt Options) (string, error) {
	return Active().Chat(ctx, system, messages, opt)
}

// ChatReply is Chat with native tool calls (see Options.Tools).
func ChatReply(ctx context.Context, system string, messages []Message, opt Options) (Reply, error) {
	return Active().ChatReply(ctx, system, messages, opt)
}

// SupportsTools reports whether the provider takes native function calls.
func (p Provider) SupportsTools() bool { return p.tools && !p.gemini }

// noToolModels remembers provider/model pairs that rejected "tools" (some
// reasoning models do), so later calls go straight to the text protocol.
var noToolModels sync.Map

func toolsRejected(p Provider, model string) bool {
	_, ok := noToolModels.Load(p.ID + "|" + model)
	return ok
}

// ChatWithAI is the legacy entry point (history, then the new user message,
// with a system prompt). Prefer Chat/Complete, which take a context.
func ChatWithAI(history []Message, userMessage string, systemPrompt string) (string, error) {
	msgs := append(append([]Message(nil), history...), Message{Role: "user", Content: userMessage})
	return Chat(context.Background(), systemPrompt, msgs, Options{})
}

// Chat sends a conversation to this specific provider.
func (p Provider) Chat(ctx context.Context, system string, messages []Message, opt Options) (string, error) {
	opt.Tools = nil // text callers never get tool calls
	r, err := p.ChatReply(ctx, system, messages, opt)
	if err != nil {
		return "", err
	}
	if r.Text == "" {
		return "", fmt.Errorf("%s (%s): provider returned an empty reply", p.Name, p.Model())
	}
	return r.Text, nil
}

// ChatReply sends a conversation and returns the text plus native tool calls.
func (p Provider) ChatReply(ctx context.Context, system string, messages []Message, opt Options) (Reply, error) {
	key := p.Key()
	if key == "" {
		return Reply{}, fmt.Errorf("%w: %s has no API key — add it in Settings ▸ AI Providers", errNotConfigured, p.Name)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	model := p.Model()
	if len(opt.Tools) > 0 && toolsRejected(p, model) {
		opt.Tools = nil
	}
	endpoint, body, err := p.buildRequest(model, system, messages, opt)
	if err != nil {
		return Reply{}, err
	}
	// Every call that reaches the network is metered, failures included; a
	// retried 429 is not billed, so only the final attempt is recorded.
	start := time.Now()
	meter := func(raw []byte, callErr error) {
		u := Usage{Time: start, Provider: p.ID, Model: model, Feature: opt.Feature,
			LatencyMS: time.Since(start).Milliseconds(), OK: callErr == nil}
		if callErr != nil {
			u.Error = truncate(callErr.Error(), 300)
		}
		if raw != nil {
			p.usageFields(raw, &u)
		}
		emitUsage(u)
	}

	// One retry on transient upstream trouble (rate limit / overloaded), which
	// DeepSeek in particular returns under load.
	var raw []byte
	for attempt := 0; ; attempt++ {
		var status int
		raw, status, err = p.post(ctx, endpoint, key, body)
		if err == nil {
			break
		}
		// A model that does not take native tools answers 400/422: remember it
		// and resend once with the prompt's text protocol instead.
		if (status == http.StatusBadRequest || status == http.StatusUnprocessableEntity) && len(opt.Tools) > 0 && p.SupportsTools() {
			noToolModels.Store(p.ID+"|"+model, true)
			opt.Tools = nil
			if endpoint, body, err = p.buildRequest(model, system, messages, opt); err != nil {
				return Reply{}, err
			}
			attempt--
			continue
		}
		if attempt > 0 || !retryable(status) || errors.Is(err, errNotBilled) {
			meter(nil, err)
			if errors.Is(err, errNotBilled) && p.ID == "zai" {
				err = fmt.Errorf("%w — a Z.ai Coding Plan key only covers Z.ai's supported coding tools; calls from AutoAR are billed to the pay-as-you-go balance", err)
			}
			return Reply{}, fmt.Errorf("%s (%s): %w", p.Name, model, err)
		}
		select {
		case <-ctx.Done():
			meter(nil, ctx.Err())
			return Reply{}, fmt.Errorf("%s (%s): %w", p.Name, model, ctx.Err())
		case <-time.After(2 * time.Second):
		}
	}

	reply, err := p.parseReply(raw)
	// Tokens are billed even when the reply is unusable (empty, blocked).
	meter(raw, err)
	if err != nil {
		return Reply{}, fmt.Errorf("%s (%s): %w", p.Name, model, err)
	}
	return reply, nil
}

func (p Provider) buildRequest(model, system string, messages []Message, opt Options) (string, []byte, error) {
	maxTokens := opt.MaxTokens
	if p.maxOutput > 0 && maxTokens > p.maxOutput {
		maxTokens = p.maxOutput
	}

	if p.gemini {
		type part struct {
			Text string `json:"text"`
		}
		type content struct {
			Role  string `json:"role,omitempty"`
			Parts []part `json:"parts"`
		}
		req := struct {
			SystemInstruction *content         `json:"systemInstruction,omitempty"`
			Contents          []content        `json:"contents"`
			GenerationConfig  *geminiGenConfig `json:"generationConfig,omitempty"`
		}{}
		if strings.TrimSpace(system) != "" {
			req.SystemInstruction = &content{Parts: []part{{Text: system}}}
		}
		for _, m := range messages {
			role := m.Role
			switch role {
			case "assistant":
				role = "model"
			case "system":
				role = "user" // Gemini only has user/model turns
			}
			req.Contents = append(req.Contents, content{Role: role, Parts: []part{{Text: m.Content}}})
		}
		if maxTokens > 0 || opt.JSON {
			req.GenerationConfig = &geminiGenConfig{MaxOutputTokens: maxTokens}
			if opt.JSON {
				req.GenerationConfig.ResponseMimeType = "application/json"
			}
		}
		b, err := json.Marshal(req)
		return fmt.Sprintf(p.endpoint, url.PathEscape(model)), b, err
	}

	msgs := make([]Message, 0, len(messages)+1)
	if strings.TrimSpace(system) != "" {
		msgs = append(msgs, Message{Role: "system", Content: system})
	}
	msgs = append(msgs, messages...)
	type responseFormat struct {
		Type string `json:"type"`
	}
	type toolSpec struct {
		Type     string  `json:"type"`
		Function ToolDef `json:"function"`
	}
	req := struct {
		Model          string          `json:"model"`
		Messages       []Message       `json:"messages"`
		MaxTokens      int             `json:"max_tokens,omitempty"`
		ResponseFormat *responseFormat `json:"response_format,omitempty"`
		Tools          []toolSpec      `json:"tools,omitempty"`
		ToolChoice     string          `json:"tool_choice,omitempty"`
		Stream         bool            `json:"stream"`
	}{Model: model, Messages: msgs, Stream: false}
	if p.maxOutput > 0 {
		req.MaxTokens = maxTokens
	}
	useTools := len(opt.Tools) > 0 && p.SupportsTools()
	if useTools {
		for _, t := range opt.Tools {
			if t.Parameters == nil {
				t.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			req.Tools = append(req.Tools, toolSpec{Type: "function", Function: t})
		}
		req.ToolChoice = "auto"
	}
	if opt.JSON && p.jsonMode && !useTools {
		req.ResponseFormat = &responseFormat{Type: "json_object"}
	}
	b, err := json.Marshal(req)
	return p.endpoint, b, err
}

// post sends the request and returns the (capped) body. On a non-2xx response
// it returns the status and a readable error that never echoes the API key.
func (p Provider) post(ctx context.Context, endpoint, key string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.gemini {
		// Header, not ?key= — a query-string key ends up in proxy logs and errors.
		req.Header.Set("x-goog-api-key", key)
	} else {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, scrubKey(err, key)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, resp.StatusCode, statusError(resp.StatusCode, raw)
	}
	return raw, resp.StatusCode, nil
}

func (p Provider) parseReply(raw []byte) (Reply, error) {
	var text string
	var calls []ToolCall
	if p.gemini {
		var r struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
				FinishReason string `json:"finishReason"`
			} `json:"candidates"`
			PromptFeedback struct {
				BlockReason string `json:"blockReason"`
			} `json:"promptFeedback"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return Reply{}, fmt.Errorf("unreadable response: %w", err)
		}
		if r.PromptFeedback.BlockReason != "" {
			return Reply{}, fmt.Errorf("prompt blocked by provider: %s", r.PromptFeedback.BlockReason)
		}
		if len(r.Candidates) == 0 {
			return Reply{}, errors.New("empty response (no candidates)")
		}
		var sb strings.Builder
		for _, pt := range r.Candidates[0].Content.Parts {
			sb.WriteString(pt.Text)
		}
		text = sb.String()
	} else {
		var r struct {
			Choices []struct {
				Message struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []struct {
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return Reply{}, fmt.Errorf("unreadable response: %w", err)
		}
		if r.Error != nil && r.Error.Message != "" {
			return Reply{}, errors.New(truncate(r.Error.Message, maxErrorDetail))
		}
		if len(r.Choices) == 0 {
			return Reply{}, errors.New("empty response (no choices)")
		}
		for _, tc := range r.Choices[0].Message.ToolCalls {
			if name := strings.TrimSpace(tc.Function.Name); name != "" {
				calls = append(calls, ToolCall{Name: name, Arguments: tc.Function.Arguments})
			}
		}
		text = r.Choices[0].Message.Content
		// Reasoning models (deepseek-reasoner and the deepseek-flash alias)
		// can exhaust the token budget on reasoning and return an empty
		// content with the whole answer in reasoning_content. Salvage it
		// rather than failing the call; the caller's parser is tolerant.
		if strings.TrimSpace(text) == "" && len(calls) == 0 {
			text = r.Choices[0].Message.ReasoningContent
		}
	}
	text = strings.TrimSpace(thinkRe.ReplaceAllString(text, ""))
	if text == "" && len(calls) == 0 {
		return Reply{}, errors.New("provider returned an empty reply")
	}
	return Reply{Text: text, ToolCalls: calls}, nil
}

// geminiGenConfig is Gemini's generationConfig block.
type geminiGenConfig struct {
	MaxOutputTokens  int    `json:"maxOutputTokens,omitempty"`
	ResponseMimeType string `json:"responseMimeType,omitempty"`
}

// TestResult is what Test reports back to the Settings page.
type TestResult struct {
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Model     string `json:"model"`
	LatencyMS int64  `json:"latency_ms"`
	Reply     string `json:"reply"`
}

// Test sends a tiny prompt to the provider to prove the key and model work.
func (p Provider) Test(ctx context.Context) (TestResult, error) {
	start := time.Now()
	reply, err := p.Chat(ctx, "You are a connectivity check. Answer with one word.",
		[]Message{{Role: "user", Content: "Reply with the single word: pong"}},
		Options{Timeout: 60 * time.Second, Feature: "test"})
	res := TestResult{Provider: p.ID, Name: p.Name, Model: p.Model(), LatencyMS: time.Since(start).Milliseconds()}
	if err != nil {
		return res, err
	}
	res.Reply = truncate(reply, 200)
	return res, nil
}

// ListModels returns the model IDs the provider offers (OpenAI-style /models).
func (p Provider) ListModels(ctx context.Context) ([]string, error) {
	if p.modelsURL == "" {
		return nil, fmt.Errorf("%s does not expose a model list — type the model name instead", p.Name)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.modelsURL, nil)
	if err != nil {
		return nil, err
	}
	key := p.Key()
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, scrubKey(err, key)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, statusError(resp.StatusCode, raw)
	}
	var r struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("unreadable model list: %w", err)
	}
	out := make([]string, 0, len(r.Data))
	for _, m := range r.Data {
		if id := strings.TrimSpace(m.ID); id != "" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if len(out) > 1000 {
		out = out[:1000]
	}
	return out, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// httpClient honours HTTPS_PROXY; per-call deadlines come from the context.
var httpClient = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}

// thinkRe strips <think>…</think> blocks some reasoning models put in content.
var thinkRe = regexp.MustCompile(`(?s)<think>.*?</think>`)

func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// statusError turns an upstream error response into a short, actionable error.
func statusError(status int, raw []byte) error {
	detail := ""
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && len(e.Error) > 0 {
		var obj struct {
			Message string `json:"message"`
		}
		var s string
		if json.Unmarshal(e.Error, &obj) == nil && obj.Message != "" {
			detail = obj.Message
		} else if json.Unmarshal(e.Error, &s) == nil {
			detail = s
		}
	}
	if detail == "" {
		detail = strings.TrimSpace(string(raw))
	}
	detail = truncate(detail, maxErrorDetail)

	hint := ""
	billing := status == http.StatusPaymentRequired || isBillingRefusal(detail)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		hint = "API key rejected — check it in Settings ▸ AI Providers"
	case billing:
		// Some providers (Z.ai: code 1113) answer an unpaid call with 429.
		hint = "insufficient balance — no credit on the account, or this key's plan doesn't cover the call"
	case status == http.StatusTooManyRequests:
		hint = "rate limited by the provider"
	case status == http.StatusNotFound:
		hint = "endpoint or model not found — check the model name"
	}
	msg := fmt.Sprintf("HTTP %d", status)
	if hint != "" {
		msg += " (" + hint + ")"
	}
	if detail != "" {
		msg += ": " + detail
	}
	if billing {
		return notBilledError{msg}
	}
	return errors.New(msg)
}

// errNotBilled marks a call the provider refused to charge (no credit, or a
// plan that doesn't cover it). Waiting doesn't help, so it is never retried.
var errNotBilled = errors.New("provider refused to bill the call")

// notBilledError reads like any status error but matches errNotBilled.
type notBilledError struct{ msg string }

func (e notBilledError) Error() string        { return e.msg }
func (e notBilledError) Is(target error) bool { return target == errNotBilled }

// billingRefusalRE recognises "no credit / not in your plan" replies, whatever
// status code carries them (Z.ai's 1113 comes as HTTP 429). Plain "quota" is
// left out on purpose: per-minute rate quotas use it too.
var billingRefusalRE = regexp.MustCompile(`(?i)insufficient[ _]?(balance|quota|credit|funds)|resource package|recharge|top[ -]?up|out of credits?|no credits?|billing|payment required`)

func isBillingRefusal(detail string) bool { return billingRefusalRE.MatchString(detail) }

// scrubKey removes the API key from a transport error string, defensively.
func scrubKey(err error, key string) error {
	if err == nil || key == "" || !strings.Contains(err.Error(), key) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), key, "[redacted]"))
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
