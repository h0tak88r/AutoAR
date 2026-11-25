package api

// edition.go — the seam between the public build and the private "edge" build.
//
// The competitive-edge features (full-corpus nuclei sweep, the CVE-PoC
// auto-run-on-all-DB pipeline, and monitor/scope auto-scan) live in files
// tagged `//go:build !public`. Those files register themselves here through
// init(): they set the hook variables and append to the registries below.
//
// In a PUBLIC build (`go build -tags public`, and in the public repo where the
// release script deletes the tagged files) none of those init()s run, so the
// hooks stay nil and the registries stay empty — the server compiles and runs
// with the edge capabilities simply absent. Public code therefore must reach
// the edge ONLY through these seams, never by direct symbol reference.

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/db"
)

// editionName is "private" when the edge files are compiled in (their init sets
// it), "public" otherwise. Surfaced at /api/config so the UI can hide edge-only
// controls.
var editionName = "public"

// Edition reports the build edition ("private" or "public").
func Edition() string { return editionName }

// ── Hooks: public callers invoke the edge only if the hook is wired ──────────

// pocdayEnqueueHook queues a CVE for the PoC-day pipeline (auto-run on corpus).
// Set by the edge build; nil in public (the CVE radar then only alerts).
var pocdayEnqueueHook func(cve, reason string, force bool) bool

// scopeAutopilotObserveHook lets the program watcher hand a program to the
// scope autopilot (auto-scan on new scope). Nil in public (watcher only
// records/alerts).
var scopeAutopilotObserveHook func(p ProgramSummary, newScope, seenBefore bool)

// raceAutoValidateFn hands a finished scan's race-pass hits to the AI agent for
// auto-validation (edge). A no-op in public. Assigned by the edge build and
// swapped by tests.
var raceAutoValidateFn = func(scanID string) int { return 0 }

// reportValidatedFindingFn posts a validated finding to the findings channel
// with its report attached (edge). Nil in public → the caller falls back to the
// short monitor line.
var reportValidatedFindingFn func(f *db.Finding, v *db.FindingValidation, host string) error

// ── Registries: populated by edge init() ─────────────────────────────────────

var (
	edgeDaemonHooks []func()                 // long-running edge daemons, started at boot
	edgeRouteHooks  []func(*gin.RouterGroup) // edge-only authenticated HTTP routes
	edgeMCPTools    []mcpTool                // edge-only MCP tool descriptors
	edgeMCPDispatch = map[string]func(args map[string]any) map[string]any{}
)

// StartEdgeDaemons starts every registered edge daemon (no-op in public).
func StartEdgeDaemons() {
	for _, start := range edgeDaemonHooks {
		start()
	}
}

// scopeAutopilotObserveSeam hands a program to the scope autopilot when the
// edge is compiled in; a no-op in public (the watcher just records/alerts).
func scopeAutopilotObserveSeam(p ProgramSummary, newScope, seenBefore bool) {
	if scopeAutopilotObserveHook != nil {
		scopeAutopilotObserveHook(p, newScope, seenBefore)
	}
}

// pocdayEnqueueSeam queues a CVE for the PoC-day pipeline when the edge is
// compiled in; returns false in public (nothing is auto-run on the corpus).
func pocdayEnqueueSeam(cve, reason string, force bool) bool {
	if pocdayEnqueueHook != nil {
		return pocdayEnqueueHook(cve, reason, force)
	}
	return false
}

// registerEdgeRoutes mounts edge-only routes on the authenticated group.
func registerEdgeRoutes(g *gin.RouterGroup) {
	for _, reg := range edgeRouteHooks {
		reg(g)
	}
}

// allMCPTools is the public tool set plus any edge tools (tools/list source).
func allMCPTools() []mcpTool {
	if len(edgeMCPTools) == 0 {
		return mcpTools
	}
	return append(append([]mcpTool{}, mcpTools...), edgeMCPTools...)
}

// mcpArgStr / mcpArgInt are the package-level arg readers edge MCP handlers use
// (mcpCallTool's own getStr/getInt are local closures).
func mcpArgStr(args map[string]any, k string) string {
	s, _ := args[k].(string)
	return strings.TrimSpace(s)
}

func mcpArgInt(args map[string]any, k string, def int) int {
	if f, ok := args[k].(float64); ok {
		return int(f)
	}
	return def
}
