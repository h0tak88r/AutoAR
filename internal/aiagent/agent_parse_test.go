package aiagent

import (
	"context"
	"strings"
	"testing"

	"github.com/h0tak88r/AutoAR/internal/brain"
)

// Regression: deepseek-flash replies can carry a valid JSON action followed by
// the model's internal DSML drafting syntax — the whole-string Unmarshal used
// to fail and the raw markup leaked into the owner's chat.
func TestParseActionSurvivesDSML(t *testing.T) {
	cases := []string{
		`{"tool": "platform", "args": {"tool": "cve_lookup", "args": {"cve": "CVE-2026-104748"}}}<| DSML | calls >[{"function":"platform"}]<| end |>`,
		`<| DSML | calls >[{"function":"bash"}]<| end |>{"tool":"bash","args":{"command":"id"}}`,
		"Some prose first {\"final\": \"done — 3 hosts vulnerable\"} trailing junk",
		"{\"final\": \"clean reply\"}",
	}
	want := []struct{ tool, final string }{
		{"platform", ""},
		{"bash", ""},
		{"", "done — 3 hosts vulnerable"},
		{"", "clean reply"},
	}
	for i, in := range cases {
		var call agentCall
		if !parseAction(in, &call) {
			t.Fatalf("case %d: parse failed", i)
		}
		if call.Tool != want[i].tool || call.Final != want[i].final {
			t.Fatalf("case %d: got tool=%q final=%q, want %q/%q", i, call.Tool, call.Final, want[i].tool, want[i].final)
		}
	}
	cleaned := cleanLeakedSyntax("answer text <| DSML | calls >[x]<| end |> tail")
	if cleaned != "answer text  tail" && cleaned != "answer text tail" {
		t.Fatalf("cleanLeakedSyntax: %q", cleaned)
	}
}

// The reply that reached the owner on 2026-10-18 (session smvd62a0nvmut):
// DeepSeek wrote its native tool call as DSML with FULL-WIDTH doubled bars;
// the API kept the call and left "{}" plus closing tags in the content.
const prodGarbage = "{}</｜｜DSML｜｜ parameter>\n</｜｜DSML｜｜ invoke>\n</｜｜DSML｜｜ calls>"

func TestBrokenDSMLReplyIsNeverAnAnswer(t *testing.T) {
	if _, _, ok := actionFromReply(brain.Reply{Text: prodGarbage}); ok {
		t.Fatal("the garbage reply must not decode as an action")
	}
	if c := cleanLeakedSyntax(prodGarbage); looksLikeAnswer(c) {
		t.Fatalf("cleaned garbage %q must not be shown as an answer", c)
	}
	if c := cleanLeakedSyntax("Done.\n<｜｜DSML｜｜ calls>\n<｜｜DSML｜｜ invoke name=\"bash\">x</｜｜DSML｜｜ invoke>"); c != "Done." {
		t.Fatalf("trailing markup not stripped: %q", c)
	}
}

func TestDSMLToolCallInTextIsDecoded(t *testing.T) {
	text := "<｜｜DSML｜｜ calls>\n<｜｜DSML｜｜ invoke name=\"bash\">\n<｜｜DSML｜｜ parameter name=\"command\" string=\"true\">git clone https://github.com/a/poc</｜｜DSML｜｜ parameter>\n</｜｜DSML｜｜ invoke>\n</｜｜DSML｜｜ calls>"
	c, raw, ok := actionFromReply(brain.Reply{Text: text})
	if !ok || c.Tool != "bash" || c.Args["command"] != "git clone https://github.com/a/poc" || !strings.Contains(raw, `"tool":"bash"`) {
		t.Fatalf("decoded: %+v %s %v", c, raw, ok)
	}
	// A platform tool called by its own name; non-string parameter decoded.
	text = "<|DSML|invoke name=\"get_finding\"><|DSML|parameter name=\"id\" string=\"false\">12</|DSML|parameter></|DSML|invoke>"
	c, _, ok = actionFromReply(brain.Reply{Text: text})
	if !ok || c.Tool != "platform" || c.Args["tool"] != "get_finding" || c.Args["args"].(map[string]any)["id"] != float64(12) {
		t.Fatalf("platform call: %+v", c)
	}
}

func TestNativeToolCallIsDecoded(t *testing.T) {
	c, _, ok := actionFromReply(brain.Reply{ToolCalls: []brain.ToolCall{{Name: "read_skill", Arguments: `{"name":"hunt-ssrf"}`}}})
	if !ok || c.Tool != "read_skill" || c.Args["name"] != "hunt-ssrf" {
		t.Fatalf("native: %+v", c)
	}
	c, _, ok = actionFromReply(brain.Reply{ToolCalls: []brain.ToolCall{{Name: "final", Arguments: `{"text":"all good"}`}}})
	if !ok || c.Final != "all good" {
		t.Fatalf("native final: %+v", c)
	}
}

// The loop asks again on garbage (transiently — the nudge is not saved in
// the owner's history), runs the tool, and returns the real answer.
func TestRunRecoversFromGarbageReply(t *testing.T) {
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_HOST", t.TempDir()+"/agent.db")
	t.Setenv("AUTOAR_SILENT", "true")
	orig := chatReply
	t.Cleanup(func() { chatReply = orig })
	Wire(func(name string, args map[string]any) string { return "finding #12: passwordselfservice.mtn.co.za" })
	turn := 0
	chatReply = func(_ context.Context, _ string, m []brain.Message, opt brain.Options) (brain.Reply, error) {
		turn++
		switch turn {
		case 1:
			return brain.Reply{Text: prodGarbage}, nil
		case 2:
			if !strings.Contains(m[0].Content, "FORMAT ERROR") {
				t.Fatal("the retry must carry the format nudge")
			}
			return brain.Reply{ToolCalls: []brain.ToolCall{{Name: "platform", Arguments: `{"tool":"get_finding","args":{"id":12}}`}}}, nil
		default:
			if strings.Contains(m[0].Content, "FORMAT ERROR") {
				t.Fatal("the nudge must be dropped once the model recovered")
			}
			return brain.Reply{Text: "Finding #12 is on passwordselfservice.mtn.co.za; next I would clone the PoC."}, nil
		}
	}
	final, log, err := Chat("test-garbage", "check finding 12")
	if err != nil || !strings.Contains(final, "passwordselfservice") || len(log) != 1 || log[0].Tool != "platform" {
		t.Fatalf("final=%q log=%+v err=%v", final, log, err)
	}
	for _, msg := range Get("test-garbage").Messages {
		if strings.Contains(msg.Content, "FORMAT ERROR") || strings.Contains(msg.Content, "DSML") {
			t.Fatalf("history polluted: %q", msg.Content)
		}
	}
	Cleanup("test-garbage")
	// A model that never recovers gets an explicit message, not markup.
	chatReply = func(context.Context, string, []brain.Message, brain.Options) (brain.Reply, error) {
		return brain.Reply{Text: prodGarbage}, nil
	}
	final, _, _ = Chat("test-garbage-2", "hi")
	if strings.Contains(final, "DSML") || !strings.Contains(final, "malformed") {
		t.Fatalf("persistent garbage: %q", final)
	}
	Cleanup("test-garbage-2")
}
