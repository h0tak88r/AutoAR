package brain

import (
	"strings"
	"testing"
)

func TestSmartTruncateShortString(t *testing.T) {
	s := "hello world"
	got := smartTruncate(s, 100)
	if got != s {
		t.Errorf("smartTruncate() = %q, want %q (unchanged)", got, s)
	}
}

func TestSmartTruncateEqualsMaxLen(t *testing.T) {
	s := strings.Repeat("a", 50)
	got := smartTruncate(s, 50)
	if got != s {
		t.Errorf("smartTruncate() = %q, want %q (unchanged)", got, s)
	}
}

func TestSmartTruncateLongString(t *testing.T) {
	s := strings.Repeat("x", 5000)
	got := smartTruncate(s, 3000)
	if !strings.Contains(got, "bytes omitted") {
		t.Error("smartTruncate() should contain omitted marker for long string")
	}
	if len(got) < 2500 || len(got) > 3100 {
		t.Errorf("smartTruncate() len = %d, want ~3000", len(got))
	}
}

func TestSmartTruncateVerySmallMaxLen(t *testing.T) {
	s := strings.Repeat("a", 200)
	got := smartTruncate(s, 10)
	if !strings.Contains(got, "truncated") {
		t.Error("smartTruncate() with small maxLen should show truncated suffix")
	}
	if !strings.HasPrefix(got, "aaaaaaaaaa") {
		t.Errorf("smartTruncate() = %q, want prefix of 10 'a's", got)
	}
}

func TestParseAgentActionValidJSON(t *testing.T) {
	reply := `{"action": "run_command", "command": "autoar subdomains get -d example.com", "reason": "Enumerate subdomains"}`
	action, err := parseAgentAction(reply)
	if err != nil {
		t.Fatalf("parseAgentAction() error = %v", err)
	}
	if action.Action != "run_command" {
		t.Errorf("action.Action = %q, want run_command", action.Action)
	}
	if action.Command != "autoar subdomains get -d example.com" {
		t.Errorf("action.Command = %q", action.Command)
	}
	if action.Reason != "Enumerate subdomains" {
		t.Errorf("action.Reason = %q", action.Reason)
	}
}

func TestParseAgentActionJSONInMarkdownFence(t *testing.T) {
	reply := "```json\n{\"action\": \"done\", \"summary\": \"Scan complete\"}\n```"
	action, err := parseAgentAction(reply)
	if err != nil {
		t.Fatalf("parseAgentAction() error = %v", err)
	}
	if action.Action != "done" {
		t.Errorf("action.Action = %q, want done", action.Action)
	}
	if action.Summary != "Scan complete" {
		t.Errorf("action.Summary = %q, want 'Scan complete'", action.Summary)
	}
}

func TestParseAgentActionJSONInPlainFence(t *testing.T) {
	reply := "```\n{\"action\": \"report\", \"content\": \"Found XSS\"}\n```"
	action, err := parseAgentAction(reply)
	if err != nil {
		t.Fatalf("parseAgentAction() error = %v", err)
	}
	if action.Action != "report" {
		t.Errorf("action.Action = %q, want report", action.Action)
	}
}

func TestParseAgentActionNoJSON(t *testing.T) {
	_, err := parseAgentAction("just some text with no json object")
	if err == nil {
		t.Error("parseAgentAction() should error on text without JSON")
	}
}

func TestParseAgentActionEmptyAction(t *testing.T) {
	_, err := parseAgentAction(`{"action": "", "command": "something"}`)
	if err == nil {
		t.Error("parseAgentAction() should error when action field is empty")
	}
}

func TestParseAgentActionInvalidJSON(t *testing.T) {
	_, err := parseAgentAction(`{"action": "run", "command": broken}`)
	if err == nil {
		t.Error("parseAgentAction() should error on invalid JSON")
	}
}

func TestParseAgentActionWithTextAroundJSON(t *testing.T) {
	reply := "Here's what I'll do: {\"action\": \"run_shell\", \"command\": \"ls\"} Hope that works."
	action, err := parseAgentAction(reply)
	if err != nil {
		t.Fatalf("parseAgentAction() error = %v", err)
	}
	if action.Action != "run_shell" {
		t.Errorf("action.Action = %q, want run_shell", action.Action)
	}
}

func TestIsJSSecretsContentValid(t *testing.T) {
	content := `[GitHub Token] https://example.com/app.js -> ghp_1234567890abcdef
[AWS Key] https://example.com/config.js -> AKIA1234567890ABCD
[API Key] https://api.example.com/main.js -> sk-abcdef1234567890`
	if !isJSSecretsContent(content) {
		t.Error("isJSSecretsContent() should return true for valid JS secrets content")
	}
}

func TestIsJSSecretsContentOnlyTwoLines(t *testing.T) {
	content := `[GitHub Token] https://example.com/app.js -> ghp_1234
[AWS Key] https://example.com/config.js -> AKIA1234`
	if isJSSecretsContent(content) {
		t.Error("isJSSecretsContent() should return false with only 2 matching lines")
	}
}

func TestIsJSSecretsContentNoPatternMatch(t *testing.T) {
	content := "This is just random text\nwith multiple lines\nbut no secret patterns"
	if isJSSecretsContent(content) {
		t.Error("isJSSecretsContent() should return false for non-matching content")
	}
}

func TestIsJSSecretsContentEmpty(t *testing.T) {
	if isJSSecretsContent("") {
		t.Error("isJSSecretsContent() should return false for empty string")
	}
}

func TestIsJSSecretsContentMixedLines(t *testing.T) {
	content := `[GitHub Token] https://example.com/a.js -> secret1
regular line here
[API Key] https://example.com/b.js -> secret2
another regular line
[AWS Key] https://example.com/c.js -> secret3
final regular line`
	if !isJSSecretsContent(content) {
		t.Error("isJSSecretsContent() should return true with 3+ matches among mixed lines")
	}
}
