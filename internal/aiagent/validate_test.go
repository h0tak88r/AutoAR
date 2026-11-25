package aiagent

import (
	"context"
	"strings"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/brain"
)

func TestParseValidation(t *testing.T) {
	v := ParseValidation("```json\n{\"verdict\":\"true_positive\",\"confidence\":140,\"severity\":\"high\",\"reportable\":true,\"summary\":\"s\",\"evidence\":\"curl -i … 200\"}\n```")
	if v.Verdict != "true_positive" || v.Confidence != 100 || !v.Reportable || v.Severity != "high" {
		t.Fatalf("parsed: %+v", v)
	}
	if v := ParseValidation(`{"verdict":"false_positive","confidence":80,"reportable":true}`); v.Reportable {
		t.Fatal("a false positive is never reportable")
	}
	if v := ParseValidation("I could not reach the host."); v.Verdict != "needs_manual_review" || !strings.Contains(v.Summary, "could not reach") {
		t.Fatalf("prose answer: %+v", v)
	}
	if v := ParseValidation(`{"verdict":"pwned"}`); v.Verdict != "needs_manual_review" {
		t.Fatalf("unknown verdict: %+v", v)
	}
}

// The validation persona runs the same tool loop with its own prompt and
// unwraps {"final": "<json string>"}.
func TestValidateRunsToolLoop(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", t.TempDir()+"/agent.db")
	t.Setenv("AUTOAR_SILENT", "true")
	orig := chatReply
	t.Cleanup(func() { chatReply = orig })
	Wire(func(name string, args map[string]any) string { return "IN SCOPE — h1 acme" })
	turn := 0
	chatReply = func(_ context.Context, system string, m []brain.Message, opt brain.Options) (brain.Reply, error) {
		turn++
		if !strings.Contains(system, "VALIDATION RULES") || opt.Feature != "agent-validate" || len(opt.Tools) == 0 {
			t.Fatalf("persona/feature/tools wrong: %q %d", opt.Feature, len(opt.Tools))
		}
		if turn == 1 {
			return brain.Reply{Text: `{"tool":"platform","args":{"tool":"scope_check","args":{"host":"app.acme.com"}}}`}, nil
		}
		if !strings.Contains(m[0].Content, "IN SCOPE") {
			t.Fatal("tool result not fed back")
		}
		return brain.Reply{Text: `{"final":"{\"verdict\":\"likely\",\"confidence\":70,\"summary\":\"marker reflected\"}"}`}, nil
	}
	v, log, err := Validate("validate-test-1", "Validate finding #1.")
	if err != nil || v.Verdict != "likely" || v.Confidence != 70 || len(log) != 1 || log[0].Tool != "platform" {
		t.Fatalf("v=%+v log=%+v err=%v", v, log, err)
	}
	Cleanup("validate-test-1")
}
