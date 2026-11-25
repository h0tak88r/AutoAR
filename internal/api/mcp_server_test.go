package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
)

func mcpTestSetup(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", filepath.Join(t.TempDir(), "mcp.db"))
	t.Setenv("AUTOAR_SILENT", "true")
	s := &db.SQLiteDB{}
	if err := s.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	r := gin.New()
	r.POST("/mcp", mcpHandle)
	tok := "mcp_test_token_123"
	if err := db.SetSetting("mcp_token", tok); err != nil {
		t.Fatalf("set token: %v", err)
	}
	return r, tok
}

func mcpCall(t *testing.T, r *gin.Engine, tok, method string, params map[string]any, id int) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestMCPProtocol(t *testing.T) {
	r, tok := mcpTestSetup(t)

	// No token → 401.
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no-token = %d, want 401", w.Code)
	}

	// initialize
	code, out := mcpCall(t, r, tok, "initialize", map[string]any{}, 1)
	if code != 200 || out["error"] != nil {
		t.Fatalf("initialize: %d %v", code, out)
	}
	res := out["result"].(map[string]any)
	if res["serverInfo"].(map[string]any)["name"] != "autoar" {
		t.Errorf("serverInfo wrong: %v", res["serverInfo"])
	}

	// tools/list — the submission-free guarantee is structural: no tool name
	// may contain submit.
	_, out = mcpCall(t, r, tok, "tools/list", map[string]any{}, 2)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) < 10 {
		t.Errorf("tools/list returned %d tools", len(tools))
	}
	for _, tl := range tools {
		name := tl.(map[string]any)["name"].(string)
		if containsSubmit(name) {
			t.Errorf("tool %q violates the no-submission rule", name)
		}
		// Strict clients (Claude Code) drop the whole list on one bad schema:
		// no JSON null anywhere, "required" (when present) is an array, and
		// "properties" is an object.
		schema := tl.(map[string]any)["inputSchema"].(map[string]any)
		if path := firstNullPath(schema, name+".inputSchema"); path != "" {
			t.Errorf("null in tool schema at %s", path)
		}
		if req, ok := schema["required"]; ok {
			if _, isArr := req.([]any); !isArr {
				t.Errorf("%s: required is %T, want an array", name, req)
			}
		}
		if _, ok := schema["properties"].(map[string]any); !ok {
			t.Errorf("%s: properties is not an object", name)
		}
	}

	// unknown method → -32601
	_, out = mcpCall(t, r, tok, "resources/list", map[string]any{}, 3)
	if out["error"] == nil {
		t.Errorf("unknown method must error, got %v", out)
	}
}

func containsSubmit(s string) bool {
	for _, part := range []string{"submit", "send_report", "publish"} {
		if len(s) >= len(part) && s == part || containsFold(s, part) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	ls, lsub := len(s), len(sub)
	if lsub == 0 || ls < lsub {
		return false
	}
	for i := 0; i+lsub <= ls; i++ {
		if equalFold(s[i:i+lsub], lsub, sub) {
			return true
		}
	}
	return false
}

func equalFold(a string, n int, b string) bool {
	for i := 0; i < n; i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 32
		}
		if y >= 'A' && y <= 'Z' {
			y += 32
		}
		if x != y {
			return false
		}
	}
	return true
}

func TestMCPFindingsTools(t *testing.T) {
	r, tok := mcpTestSetup(t)

	// create_finding
	_, out := mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "create_finding",
		"arguments": map[string]any{
			"title": "MCP test finding", "platform": "h1", "severity": "high", "host": "a.example.com",
		},
	}, 1)
	res := out["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] == true || text == "" {
		t.Fatalf("create_finding failed: %v", res)
	}

	// list_findings sees it
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "list_findings", "arguments": map[string]any{"status": "discovered"},
	}, 2)
	text = out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !containsFold(text, "MCP test finding") {
		t.Errorf("list_findings missing the created finding: %.200s", text)
	}

	// update to validated
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name":      "update_finding_status",
		"arguments": map[string]any{"id": float64(1), "status": "validated"},
	}, 3)
	if out["result"].(map[string]any)["isError"] == true {
		t.Errorf("update failed: %v", out["result"])
	}

	// run_scan rejects a bad type (whitelist)
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "run_scan", "arguments": map[string]any{"type": "rm -rf"},
	}, 4)
	if out["result"].(map[string]any)["isError"] != true {
		t.Errorf("run_scan accepted a non-whitelisted type: %v", out["result"])
	}
}

func TestMCPSettingsTools(t *testing.T) {
	r, tok := mcpTestSetup(t)

	// set + get a plain setting round-trips
	_, _ = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "set_setting", "arguments": map[string]any{"key": "mcp_test_flag", "value": "hello"},
	}, 1)
	_, out := mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "get_setting", "arguments": map[string]any{"key": "mcp_test_flag"},
	}, 2)
	text := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if text != "hello" {
		t.Errorf("plain setting roundtrip: %q", text)
	}

	// secret-shaped value is masked on read
	_, _ = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "set_setting", "arguments": map[string]any{"key": "FAKE_API_KEY", "value": "sk-supersecret-value"},
	}, 3)
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "get_setting", "arguments": map[string]any{"key": "FAKE_API_KEY"},
	}, 4)
	text = out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if containsFold(text, "supersecret") {
		t.Errorf("secret leaked unmasked: %q", text)
	}

	// denied keys are refused in both directions
	for _, args := range []map[string]any{
		{"key": "local_auth_jwt_secret", "value": "x"},
		{"key": "mcp_token", "value": "x"},
	} {
		_, out = mcpCall(t, r, tok, "tools/call", map[string]any{"name": "set_setting", "arguments": args}, 5)
		if out["result"].(map[string]any)["isError"] != true {
			t.Errorf("denied key writable: %v", args)
		}
	}
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "get_setting", "arguments": map[string]any{"key": "mcp_token"},
	}, 6)
	if out["result"].(map[string]any)["isError"] != true {
		t.Error("mcp_token readable over MCP")
	}
}

func TestMCCPocRunnerTools(t *testing.T) {
	r, tok := mcpTestSetup(t)

	// actionable_cves with an empty tracker returns the friendly empty message
	_, out := mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "actionable_cves", "arguments": map[string]any{},
	}, 1)
	text := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !containsFold(text, "no actionable CVEs") {
		t.Errorf("empty actionable list: %.100s", text)
	}

	// seed one actionable CVE (PoC confirmed, no template, network, unswept)
	if err := db.UpsertCVE(db.CVERecord{CVEID: "CVE-2026-TEST1", CVSSScore: 9.8,
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}); err != nil {
		t.Fatalf("seed cve: %v", err)
	}
	if err := db.MarkCVEPoC("CVE-2026-TEST1", 9.8, "github", "https://github.com/x/y", 1); err != nil {
		t.Fatalf("mark poc: %v", err)
	}
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "actionable_cves", "arguments": map[string]any{},
	}, 2)
	text = out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !containsFold(text, "CVE-2026-TEST1") {
		t.Errorf("actionable list missing seeded cve: %.150s", text)
	}

	// a local-vector CVE with a PoC must NOT be actionable
	if err := db.UpsertCVE(db.CVERecord{CVEID: "CVE-2026-TEST2", CVSSScore: 7.0,
		CVSSVector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}); err != nil {
		t.Fatalf("seed local cve: %v", err)
	}
	_ = db.MarkCVEPoC("CVE-2026-TEST2", 7.0, "github", "https://github.com/x/z", 1)
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "actionable_cves", "arguments": map[string]any{},
	}, 3)
	text = out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if containsFold(text, "CVE-2026-TEST2") {
		t.Errorf("local-vector CVE listed as actionable")
	}

	// corpus_filter requires a pattern
	_, out = mcpCall(t, r, tok, "tools/call", map[string]any{
		"name": "corpus_filter", "arguments": map[string]any{},
	}, 4)
	if out["result"].(map[string]any)["isError"] != true {
		t.Error("corpus_filter without pattern must error")
	}
}

// firstNullPath returns the path of the first JSON null under v ("" = none).
func firstNullPath(v any, path string) string {
	switch x := v.(type) {
	case nil:
		return path
	case map[string]any:
		for k, c := range x {
			if p := firstNullPath(c, path+"."+k); p != "" {
				return p
			}
		}
	case []any:
		for i, c := range x {
			if p := firstNullPath(c, fmt.Sprintf("%s[%d]", path, i)); p != "" {
				return p
			}
		}
	}
	return ""
}
