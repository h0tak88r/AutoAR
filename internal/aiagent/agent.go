// Package aiagent is the in-product AI agent: a DeepSeek-driven chat agent
// with a cybersecurity harness — bash in a per-session workspace, the
// platform's own MCP tool surface, skill files, and Discord output.
//
// Protocol: JSON-mode ReAct. The system prompt offers tools; the model
// replies {"tool": "...", "args": {...}} or {"final": "text"}; the loop
// executes and appends results until a final answer or the iteration cap.
package aiagent

import (
	"context"
	"log"
	"regexp"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const (
	maxIterations = 12
	commandBudget = 40 // per session
	bashTimeout   = 180 * time.Second
	outputCap     = 16 << 10
	skillsDir     = "/app/skills"
)

// ToolFunc executes one platform (MCP) tool by name — wired by the api
// package to the MCP tool surface, so the agent gets every platform
// capability for free.
type ToolFunc func(name string, args map[string]any) string

// Session is one agent conversation with its scratch workspace.
type Session struct {
	ID        string
	Messages  []brain.Message
	Workspace string
	CmdCount  int
	UpdatedAt time.Time
}

// LogEntry is one step of the tool log shown in the UI.
type LogEntry struct {
	Step    int    `json:"step"`
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
	Output  string `json:"output,omitempty"`
}

var (
	sessions = map[string]*Session{}
	toolFn   ToolFunc
)

// Wire registers the platform tool executor (call once at boot).
func Wire(f ToolFunc) { toolFn = f }

// Get returns (creating if needed) a session. A session that exists in the
// persistent store but not in memory (e.g. after a restart) is rehydrated so
// the model keeps its context and the owner keeps his history.
func Get(id string) *Session {
	if s, ok := sessions[id]; ok {
		return s
	}
	s := &Session{ID: id, UpdatedAt: time.Now()}
	if msgs, err := db.ListAgentMessages(id); err == nil {
		for _, m := range msgs {
			s.Messages = append(s.Messages, brain.Message{Role: m.Role, Content: m.Content})
		}
	}
	sessions[id] = s
	return s
}

// push appends a message to the in-memory context and persists it. History
// must survive restarts; a failed persist is logged, never fatal to the turn.
func (s *Session) push(role, content string) {
	s.Messages = append(s.Messages, brain.Message{Role: role, Content: content})
	if err := db.SaveAgentMessage(s.ID, role, content); err != nil {
		log.Printf("[aiagent] persist %s turn failed: %v", s.ID, err)
	}
}

// Cleanup removes the session's workspace, memory history and durable rows.
func Cleanup(id string) {
	if s, ok := sessions[id]; ok {
		if s.Workspace != "" {
			os.RemoveAll(s.Workspace)
		}
		delete(sessions, id)
	}
	if err := db.DeleteAgentSession(id); err != nil {
		log.Printf("[aiagent] delete history for %s failed: %v", id, err)
	}
}

func (s *Session) workspace() string {
	if s.Workspace == "" {
		s.Workspace = filepath.Join(os.TempDir(), "agent-ws-"+s.ID)
		os.MkdirAll(s.Workspace, 0o755)
	}
	return s.Workspace
}

const systemPrompt = `You are the AutoAR security agent — a bug-bounty automation operator with REAL tool access, chatting with the platform owner.

` + toolMenu + `

OPERATING RULES:
- You hunt bugs on authorized targets (the owner's bug-bounty corpus). Stay within scope the platform reports (scope_check).
- Prefer the platform tools for platform state; use bash for analysis, PoC cloning (git clone into your workspace), scripting.
- Run public PoCs per the doctrine: run what the repo does against web-reachable targets, benign args (whoami/id/echo MARKER) where parameterized, sample before fleet.
- NEVER submit anything to a bug bounty platform — drafting findings is your ceiling.
- Be concise and technical. When you used tools, the final answer should summarize what you did and what you found.`

// toolMenu is the tool protocol + list shared by every agent persona.
const toolMenu = `You have these tools. Call ONE per turn — as a native function call, or as a SINGLE JSON object:
  {"tool": "<name>", "args": {...}}   to act
  {"final": "<markdown answer>"}      when done (answer the owner directly)

TOOLS:
- bash {"command": "..."} — run a shell command in your private workspace (python3, curl, nmap, sqlmap, jq, git, dig available). Long output is truncated. CWD is your workspace; files persist for the session and are wiped afterward.
- platform {"tool": "<mcp tool name>", "args": {...}} — call any AutoAR platform tool. The most useful: list_findings, create_finding, update_finding_status, list_scans, run_scan (type=discover|ports|nuclei, or type=clientside on a domain/host for JS secrets + DOM XSS/postMessage/open-redirect/prototype-pollution sink candidates, read back with clientside_results), scope_check, cve_lookup, port_lookup, corpus_filter (live hosts by tech/url substring), actionable_cves (PoC-confirmed worklist), set_cve_label, get_setting/set_setting (secrets masked; never submits anywhere), list_monitor_targets/add_monitor_target, write_finding_report.
- discord {"message": "..."} — send a message to the owner's Discord monitor channel (markdown supported). Use for results worth announcing; the owner also sees your chat here.
- list_skills {} — list the loaded cybersecurity skill guides.
- read_skill {"name": "..."} — read one skill's full guide.
- read_file {"path": "..."} / write_file {"path": "...", "content": "..."} — workspace files only.`

// Chat runs one user turn through the agent loop and returns the final
// answer plus the tool log.
func Chat(sessionID, userMsg string) (string, []LogEntry, error) {
	return run(sessionID, systemPrompt, userMsg, maxIterations, "agent")
}

// chatReply is the model call (a seam for tests).
var chatReply = brain.ChatReply

// agentCall is one decoded action: a tool with args, or the final answer.
type agentCall struct {
	Tool  string         `json:"tool"`
	Args  map[string]any `json:"args"`
	Final string         `json:"final"`
}

// agentTools declares the tool menu as native functions. DeepSeek drafts tool
// calls in its own markup (DSML); with no declared tools the API strips the
// call and leaves fragments in the text ("{}</｜｜DSML｜｜ invoke>"), which is
// exactly what reached the owner's chat on 2026-10-18.
var agentTools = []brain.ToolDef{
	{Name: "bash", Description: "Run a shell command in your private workspace (python3, curl, nmap, sqlmap, jq, git, dig).",
		Parameters: objSchema(map[string]any{"command": strSchema("the shell command")}, "command")},
	{Name: "platform", Description: "Call an AutoAR platform tool (list_findings, get_finding, scope_check, run_scan, corpus_filter, cve_lookup, …).",
		Parameters: objSchema(map[string]any{"tool": strSchema("platform tool name"),
			"args": map[string]any{"type": "object", "description": "the tool's arguments"}}, "tool")},
	{Name: "discord", Description: "Send a message to the owner's Discord monitor channel.",
		Parameters: objSchema(map[string]any{"message": strSchema("markdown message")}, "message")},
	{Name: "list_skills", Description: "List the loaded cybersecurity skill guides.", Parameters: objSchema(map[string]any{})},
	{Name: "read_skill", Description: "Read one skill guide.", Parameters: objSchema(map[string]any{"name": strSchema("skill name")}, "name")},
	{Name: "read_file", Description: "Read a file in your workspace.", Parameters: objSchema(map[string]any{"path": strSchema("path")}, "path")},
	{Name: "write_file", Description: "Write a file in your workspace.",
		Parameters: objSchema(map[string]any{"path": strSchema("path"), "content": strSchema("file content")}, "path", "content")},
}

var agentToolNames = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range agentTools {
		m[t.Name] = true
	}
	return m
}()

func objSchema(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

func strSchema(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

// callFromNamed maps a called function name onto the agent protocol: one of
// the agent's tools, a "final" answer, or any other name = a platform tool
// the model called directly.
func callFromNamed(name string, args map[string]any) agentCall {
	name = strings.TrimSpace(name)
	if args == nil {
		args = map[string]any{}
	}
	switch {
	case agentToolNames[name]:
		return agentCall{Tool: name, Args: args}
	case name == "final":
		for _, k := range []string{"final", "text", "answer", "message"} {
			if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
				return agentCall{Final: v}
			}
		}
		b, _ := json.Marshal(args)
		return agentCall{Final: string(b)}
	}
	return agentCall{Tool: "platform", Args: map[string]any{"tool": name, "args": args}}
}

// actionFromReply decodes the model's action: a native tool call first, then
// the JSON text protocol, then DSML markup that leaked into the text. raw is
// the canonical form stored in the conversation.
func actionFromReply(r brain.Reply) (agentCall, string, bool) {
	for _, tc := range r.ToolCalls {
		var args map[string]any
		if a := strings.TrimSpace(tc.Arguments); a != "" && json.Unmarshal([]byte(a), &args) != nil {
			continue
		}
		c := callFromNamed(tc.Name, args)
		return c, canonicalCall(c), true
	}
	var c agentCall
	if parseAction(r.Text, &c) {
		return c, canonicalCall(c), true
	}
	if name, args, ok := parseDSML(r.Text); ok {
		c := callFromNamed(name, args)
		return c, canonicalCall(c), true
	}
	return agentCall{}, "", false
}

func canonicalCall(c agentCall) string {
	var v any = map[string]any{"tool": c.Tool, "args": c.Args}
	if c.Tool == "" {
		v = map[string]any{"final": c.Final}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

const formatNudge = "FORMAT ERROR: your last reply was neither a tool call nor an answer. Call exactly one tool, or answer with {\"final\": \"...\"}."

// run is the agent loop with a persona prompt, an iteration cap and the
// usage-metering label.
func run(sessionID, system, userMsg string, maxIter int, feature string) (string, []LogEntry, error) {
	s := Get(sessionID)
	s.UpdatedAt = time.Now()
	s.push("user", userMsg)

	var log []LogEntry
	var nudges []brain.Message // transient: never persisted to the owner's history
	ctx := context.Background()
	for step := 1; step <= maxIter; step++ {
		transcript := msgs(append(append([]brain.Message(nil), s.Messages...), nudges...))
		reply, err := chatReply(ctx, system, []brain.Message{{Role: "user", Content: transcript}},
			brain.Options{JSON: true, MaxTokens: 8192, Timeout: 4 * time.Minute, Feature: feature, Tools: agentTools})
		if err != nil {
			return "", log, fmt.Errorf("model: %w", err)
		}
		call, raw, ok := actionFromReply(reply)
		if !ok {
			final := cleanLeakedSyntax(reply.Text)
			if looksLikeAnswer(final) {
				s.push("assistant", final)
				return final, log, nil
			}
			if len(nudges) < 2 {
				// Garbage (empty, "{}", markup fragments): ask again instead of
				// showing it to the owner.
				nudges = append(nudges, brain.Message{Role: "user", Content: formatNudge})
				continue
			}
			final = "The model kept returning malformed tool calls, so this turn has no answer. Send the message again or rephrase it."
			s.push("assistant", final)
			return final, log, nil
		}
		nudges = nil
		if call.Final != "" || call.Tool == "" {
			final := cleanLeakedSyntax(call.Final)
			if !looksLikeAnswer(final) {
				final = call.Final
			}
			s.push("assistant", final)
			return final, log, nil
		}
		out := execute(s, call.Tool, call.Args)
		log = append(log, LogEntry{Step: step, Tool: call.Tool,
			Summary: summarize(call.Tool, call.Args), Output: clip(out, 800)})
		s.push("assistant", raw)
		s.push("user", "TOOL RESULT:\n"+clip(out, outputCap))
	}
	final := "iteration cap reached — here is my state so far."
	s.push("assistant", final)
	return final, log, nil
}

func execute(s *Session, tool string, args map[string]any) string {
	str := func(k string) string { v, _ := args[k].(string); return v }
	switch tool {
	case "bash":
		if s.CmdCount >= commandBudget {
			return "error: command budget exhausted for this session"
		}
		s.CmdCount++
		return runBash(s.workspace(), str("command"))
	case "platform":
		if toolFn == nil {
			return "error: platform tools not wired"
		}
		name := str("tool")
		pargs, _ := args["args"].(map[string]any)
		return toolFn(name, pargs)
	case "discord":
		msg := str("message")
		if msg == "" {
			return "error: message required"
		}
		utils.SendMonitorWebhook("🤖 **AI agent** — " + msg)
		return "sent to discord"
	case "list_skills":
		return listSkills()
	case "read_skill":
		return readSkill(str("name"))
	case "read_file":
		p := safePath(s.workspace(), str("path"))
		b, err := os.ReadFile(p)
		if err != nil {
			return "error: " + err.Error()
		}
		return string(b)
	case "write_file":
		p := safePath(s.workspace(), str("path"))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return "error: " + err.Error()
		}
		if err := os.WriteFile(p, []byte(str("content")), 0o644); err != nil {
			return "error: " + err.Error()
		}
		return "wrote " + p
	}
	return "error: unknown tool " + tool
}

func runBash(dir, command string) string {
	if strings.TrimSpace(command) == "" {
		return "error: empty command"
	}
	ctx, cancel := context.WithTimeout(context.Background(), bashTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	res := string(out)
	if err != nil {
		res += "\n[exit: " + err.Error() + "]"
	}
	return clip(res, outputCap)
}

func safePath(ws, p string) string {
	p = strings.TrimSpace(p)
	if !filepath.IsAbs(p) {
		p = filepath.Join(ws, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Join(ws, "invalid")
	}
	return abs
}

func listSkills() string {
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		return "no skills directory"
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() {
			if desc := skillDesc(e.Name()); desc != "" {
				fmt.Fprintf(&b, "%s — %s\n", e.Name(), desc)
			} else {
				fmt.Fprintf(&b, "%s\n", e.Name())
			}
		}
	}
	if b.Len() == 0 {
		return "no skills loaded"
	}
	return b.String()
}

func skillDesc(name string) string {
	b, err := os.ReadFile(filepath.Join(skillsDir, name, "SKILL.md"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "description:") {
			return clip(strings.TrimSpace(strings.TrimPrefix(line, "description:")), 100)
		}
	}
	return ""
}

func readSkill(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), "/")
	if name == "" || strings.Contains(name, "..") || strings.Contains(name, "/") {
		return "error: plain skill name required"
	}
	b, err := os.ReadFile(filepath.Join(skillsDir, name, "SKILL.md"))
	if err != nil {
		b, err = os.ReadFile(filepath.Join(skillsDir, name+".md"))
		if err != nil {
			return "error: skill not found: " + name
		}
	}
	return clip(string(b), 24<<10)
}

func msgs(m []brain.Message) string {
	var b strings.Builder
	for _, msg := range m {
		who := "Owner"
		if msg.Role == "assistant" {
			who = "You"
		}
		fmt.Fprintf(&b, "%s: %s\n\n", who, msg.Content)
	}
	b.WriteString("Reply with ONE json object ({" + `"tool"...` + "} or " + `{"final"...}` + ").")
	return b.String()
}

func summarize(tool string, args map[string]any) string {
	switch tool {
	case "bash":
		c, _ := args["command"].(string)
		return clip(c, 120)
	case "platform":
		n, _ := args["tool"].(string)
		return n
	case "discord":
		return clip(strval(args["message"]), 80)
	default:
		b, _ := json.Marshal(args)
		return clip(string(b), 120)
	}
}

func strval(v any) string {
	s, _ := v.(string)
	return s
}

func trimCodeFence(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	return strings.TrimSpace(s)
}

// parseAction extracts the agent's action object from a reply. Reasoning
// models (deepseek-flash alias) often append their internal tool-drafting
// syntax (DSML markers, extra fenced blocks) AFTER a perfectly valid JSON
// action; a whole-string Unmarshal then fails and the call leaks into chat.
// Strategy: whole reply first, then the first balanced {...} object.
func parseAction(reply string, call *agentCall) bool {
	trimmed := trimCodeFence(reply)
	if json.Unmarshal([]byte(trimmed), call) == nil {
		return true
	}
	// First balanced top-level object anywhere in the reply.
	depth, start := 0, -1
	for i, r := range trimmed {
		switch r {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					if json.Unmarshal([]byte(trimmed[start:i+1]), call) == nil &&
						(call.Tool != "" || call.Final != "") {
						return true
					}
					start = -1
				}
			}
		}
	}
	return false
}

// dsmlRe matches the reasoning models' internal tool-drafting markers
// (<| DSML | calls >...<| end |>, <|tool_call|>, ...) that must never reach
// the owner's chat bubble.
var dsmlRe = regexp.MustCompile(`(?s)<\|[^|>]*\|[^>]*>(.*?)(<\|\s*end[^>]*>|$)`)

// DeepSeek's native tool-call markup uses FULL-WIDTH bars, single or doubled
// and with optional spaces: <｜｜DSML｜｜ invoke name="bash">. Both bar kinds
// are matched.
var (
	dsmlInvokeRE    = regexp.MustCompile(`<\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*invoke\s+name\s*=\s*"([^"]+)"[^>]*>`)
	dsmlInvokeEndRE = regexp.MustCompile(`<\s*/\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*invoke\s*>`)
	dsmlParamRE     = regexp.MustCompile(`(?s)<\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*parameter\s+name\s*=\s*"([^"]+)"([^>]*)>(.*?)<\s*/\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*parameter\s*>`)
	dsmlBlockRE     = regexp.MustCompile(`(?s)<\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*(?:function_|tool_)?calls\s*>.*?(?:<\s*/\s*[｜|]{1,2}\s*DSML\s*[｜|]{1,2}\s*(?:function_|tool_)?calls\s*>|<\s*[｜|]{1,2}\s*end[^>]*>|$)`)
	markupTagRE     = regexp.MustCompile(`<\s*/?\s*[｜|]{1,2}[^<>]{0,80}>`)
	asciiMarkerRE   = regexp.MustCompile(`<\|[^>]*\|>`)
)

// parseDSML decodes the first native tool call written as DSML markup.
func parseDSML(text string) (string, map[string]any, bool) {
	m := dsmlInvokeRE.FindStringSubmatchIndex(text)
	if m == nil {
		return "", nil, false
	}
	name := strings.TrimSpace(text[m[2]:m[3]])
	rest := text[m[1]:]
	if end := dsmlInvokeEndRE.FindStringIndex(rest); end != nil {
		rest = rest[:end[0]]
	}
	args := map[string]any{}
	for _, pm := range dsmlParamRE.FindAllStringSubmatch(rest, -1) {
		val := strings.TrimSpace(pm[3])
		if strings.Contains(strings.ReplaceAll(pm[2], " ", ""), `string="false"`) {
			var v any
			if json.Unmarshal([]byte(val), &v) == nil {
				args[pm[1]] = v
				continue
			}
		}
		args[pm[1]] = val
	}
	return name, args, name != ""
}

// cleanLeakedSyntax strips tool-drafting markup (ASCII or full-width bars)
// from text bound for the owner.
func cleanLeakedSyntax(s string) string {
	s = dsmlBlockRE.ReplaceAllString(s, "")
	s = dsmlRe.ReplaceAllString(s, "")
	s = markupTagRE.ReplaceAllString(s, "")
	s = asciiMarkerRE.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

// looksLikeAnswer rejects what is left of a broken reply: nothing, bare
// braces/brackets, or punctuation without a single word.
func looksLikeAnswer(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || t == "{}" || t == "[]" || t == "null" {
		return false
	}
	letters := 0
	for _, r := range t {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			letters++
		}
	}
	return letters >= 2
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…[truncated]"
}
