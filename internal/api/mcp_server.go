package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/dorks"
	"github.com/h0tak88r/AutoAR/internal/seclab"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─────────────────────────────────────────────────────────────────────────────
// AutoAR as an MCP server (AI-Agent plan, Phase 4)
//
// Streamable-HTTP transport, stateless subset: every POST /mcp carries one
// JSON-RPC 2.0 message and gets one JSON response. Auth is a dedicated
// bearer token (settings: mcp_token) — rotated from the admin API; it grants
// read + whitelisted launch actions ONLY. By design there is no submission
// tool and no shell: the human-only-submission rule is enforced by the tool
// surface itself.
// ─────────────────────────────────────────────────────────────────────────────

const mcpTokenKey = "mcp_token"
const mcpLastUsedKey = "mcp_last_used"

var mcpLastUsedWritten atomic.Int64

// mcpTool describes one exposed tool in MCP's tools/list shape.
type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// obj builds a tool's input schema. "required" is left out when nothing is
// required: a JSON null there makes strict MCP clients (Claude Code) reject
// the whole tools/list, so none of the tools load.
func obj(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func intProp(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

var mcpTools = []mcpTool{
	{Name: "list_findings",
		Description: "List findings (the merged Findings tab: every scan hit from nuclei/zerodays/misconfig/takeover/secrets/... plus manual ones) with the AI review joined as `ai` (verdict, confidence, severity, reason, reportable, scope, human_verdict). Statuses: discovered/validated/drafted/approved/submitted/resolved/dup/rejected/wontfix.",
		InputSchema: obj(map[string]any{
			"status":   strProp("filter by status"),
			"ai":       strProp("AI label: reportable | true_positive | likely | needs_manual_review | false_positive | unreviewed | error"),
			"module":   strProp("source module: nuclei, zerodays, misconfig, dns-takeover, exposure, ..."),
			"scan_id":  strProp("only findings from this scan"),
			"q":        strProp("substring of title / host / template / CVE / URL"),
			"severity": strProp("critical | high | medium | low | info (the AI's severity when it has one)"),
			"platform": strProp("h1 | bc | ywh | bizone | other"),
			"program":  strProp("program handle (e.g. alibaba, or \"h1 alibaba\"), case-insensitive; __none__ = findings with no program. Each row's program / platform / program_match (in, out, paused, related, guess) says which program the host belongs to"),
			"report":   strProp("1 = only findings with a report link, 0 = only findings without one"),
			"hide_closed": map[string]any{"type": "boolean",
				"description": "leave out rejected / dup / wontfix findings (the dashboard's default view); ignored when status is set"},
			"limit":  intProp("max rows (default 50, max 500)"),
			"offset": intProp("skip this many rows (paging)"),
		})},
	{Name: "validate_findings",
		Description: "Queue findings for the AI agent's tool-backed validation (bash with curl/python3/nmap/sqlmap, every platform tool, skill guides; non-destructive rules). Each finding gets a verdict with evidence and reproduction steps on its `validation` field; true positives are announced on Discord.",
		InputSchema: obj(map[string]any{"ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "finding ids (max 25)"}}, "ids")},
	{Name: "get_finding",
		Description: "Load one finding by id, with its scanner evidence and the AI review (incl. the AI's draft report).",
		InputSchema: obj(map[string]any{"id": intProp("finding id")}, "id")},
	{Name: "import_scan_findings",
		Description: "Pull a finished scan's vulnerability hits into Findings now (queued). ai_review=true (default) also has the AI review medium+ hits; include_info also imports info-level nuclei detections.",
		InputSchema: obj(map[string]any{
			"scan_id":      strProp("scan id"),
			"ai_review":    map[string]any{"type": "boolean", "description": "run the AI review after import (default true)"},
			"include_info": map[string]any{"type": "boolean", "description": "also import info-level detections"},
		}, "scan_id")},
	{Name: "ai_review_finding",
		Description: "Run the AI review on one finding now (any severity; uses one unit of the daily AI budget). Returns the updated finding.",
		InputSchema: obj(map[string]any{"id": intProp("finding id")}, "id")},
	{Name: "set_finding_verdict",
		Description: "Record the operator verdict on a finding (overrides the AI label): true_positive | likely | needs_manual_review | false_positive, or empty to clear.",
		InputSchema: obj(map[string]any{"id": intProp("finding id"), "verdict": strProp("verdict or empty")}, "id", "verdict")},
	{Name: "create_finding",
		Description: "Add a finding to the pipeline. No submission — bookkeeping only.",
		InputSchema: obj(map[string]any{
			"title": strProp("short title"), "platform": strProp("h1/bc/ywh/bizone/other"),
			"severity": strProp("critical/high/medium/low/info"), "host": strProp("affected host"),
			"program": strProp("program handle"), "cve": strProp("CVE id if any"),
			"status": strProp("initial status (default discovered)"), "cvss": map[string]any{"type": "number", "description": "CVSS score 0-10"},
			"matched_at": strProp("exact URL/endpoint"), "notes": strProp("free notes"),
			"report_md": strProp("report draft (markdown)"), "report_ref": strProp("platform report id/URL"),
		}, "title")},
	{Name: "update_finding",
		Description: "Edit any field of a finding (only the fields you pass change; \"\" clears a text field): title, host, cve, program, platform, severity, cvss, status, notes, report_ref, matched_at, report_md.",
		InputSchema: obj(map[string]any{
			"id": intProp("finding id"), "title": strProp("title"), "host": strProp("host"), "cve": strProp("CVE id"),
			"program": strProp("program handle"), "platform": strProp("h1/bc/ywh/bizone/other"),
			"severity": strProp("critical/high/medium/low/info"), "cvss": map[string]any{"type": "number", "description": "0-10"},
			"status": strProp("discovered/validated/drafted/approved/submitted/resolved/dup/rejected/wontfix"),
			"notes":  strProp("notes"), "report_ref": strProp("platform report id/URL"), "matched_at": strProp("exact URL"),
			"report_md": strProp("full report markdown (replaces the stored report)"),
		}, "id")},
	{Name: "bulk_update_findings",
		Description: "Set the status of many findings at once.",
		InputSchema: obj(map[string]any{
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "finding ids (max 1000)"},
			"status": strProp("new status"),
		}, "ids", "status")},
	{Name: "delete_findings",
		Description: "Permanently delete findings (and their AI review). A later scan that sees the same hit recreates it; manual findings are gone for good.",
		InputSchema: obj(map[string]any{
			"ids": map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "finding ids (max 1000)"},
		}, "ids")},
	{Name: "send_finding_to_discord",
		Description: "Post a finding with its report (stored report, else the AI draft) to the Discord findings channel.",
		InputSchema: obj(map[string]any{"id": intProp("finding id")}, "id")},
	{Name: "update_finding_status",
		Description: "Move a finding through the pipeline (validated/drafted/submitted/resolved/dup/...). report_ref records the platform report id/URL.",
		InputSchema: obj(map[string]any{
			"id": intProp("finding id"), "status": strProp("new status"),
			"report_ref": strProp("platform report id/URL"), "notes": strProp("free note"),
		}, "id", "status")},
	{Name: "list_scans",
		Description: "Recent scans (id, type, target, status, name, description).",
		InputSchema: obj(map[string]any{"limit": intProp("max rows (default 20)")})},
	{Name: "scan_detail",
		Description: "One scan row by scan_id (status, command, timestamps).",
		InputSchema: obj(map[string]any{"scan_id": strProp("scan id")}, "scan_id")},
	{Name: "scan_results",
		Description: "Raw scan hits straight from the on-disk result JSONL (disk-truth: never the parsed API). Optional template substring filter; returns host, matched-at, template id/name, capped rows + total count.",
		InputSchema: obj(map[string]any{
			"scan_id":  strProp("scan id"),
			"template": strProp("optional substring filter on template id/name"),
			"limit":    intProp("max rows to return (default 20, max 100)"),
		}, "scan_id")},
	{Name: "scope_check",
		Description: "Is a host in scope, and for which program? (in/out/paused/unknown).",
		InputSchema: obj(map[string]any{"host": strProp("hostname or URL")}, "host")},
	{Name: "cve_lookup",
		Description: "Tracked CVE record: CVSS, attack vector, CWE, PoC links, template stage, sweep state.",
		InputSchema: obj(map[string]any{"cve": strProp("CVE id, e.g. CVE-2026-102489")}, "cve")},
	{Name: "port_lookup",
		Description: "Open ports known for a host (port-surface corpus).",
		InputSchema: obj(map[string]any{"host": strProp("hostname substring")}, "host")},
	{Name: "discovered_assets",
		Description: "Newest discovered assets (last N hours).",
		InputSchema: obj(map[string]any{"hours": intProp("lookback window (default 168)"), "limit": intProp("max rows (default 25)")})},
	{Name: "recon_dorks",
		Description: "Recon dork corpus — ready-to-run Google/GitHub/Shodan/FOFA/Censys/Wayback/crt.sh/urlscan/IntelX/... search queries for a target, each with a native query and a clickable URL. Pass `target` to substitute it into the {T} placeholder and get runnable URLs; omit it to get templates. Filter by category, platform, severity, or a text query `q`. Same corpus the Security Lab 'Recon Dorks' page uses.",
		InputSchema: obj(map[string]any{
			"target":   strProp("target domain/org to substitute into {T} (e.g. example.com); omit for raw templates"),
			"category": strProp("category id or title substring (e.g. secrets, cloud, panels, osint)"),
			"platform": strProp("only dorks for this platform: google, github, shodan, fofa, censys, wayback, crtsh, urlscan, intelx, gitlab, publicwww, ..."),
			"severity": strProp("critical | high | medium | low | info"),
			"q":        strProp("substring over title / query / description / tags"),
			"limit":    intProp("max dorks to return (default 100)"),
		})},
	{Name: "ssrf_payloads",
		Description: "SSRF bypass payloads (cloud-metadata, allow-list bypass, protocol smuggling, …) from the Security Lab. Each payload keeps the `<allowed>`/`<attacker>` placeholders — substitute your in-scope host and attacker host. Filter by text `q` or an exact `tag` (URL, HOST, CORS).",
		InputSchema: obj(map[string]any{
			"q":     strProp("substring over payload / description / group"),
			"tag":   strProp("exact tag filter: URL | HOST | CORS"),
			"limit": intProp("max payloads (default 100)"),
		})},
	{Name: "xss_payloads",
		Description: "XSS cheat-sheet payloads (PortSwigger-style) from the Security Lab: vectors with the HTML tag, event handler, and whether user interaction is required. Filter by text `q`, an exact HTML `tag` (svg, img, script, a, …), or an `event` substring (onload, onerror, onclick, …).",
		InputSchema: obj(map[string]any{
			"q":     strProp("substring over code / description"),
			"tag":   strProp("exact HTML tag: svg | img | script | a | iframe | ..."),
			"event": strProp("event-handler substring: onload | onerror | onclick | ..."),
			"limit": intProp("max payloads (default 100)"),
		})},
	{Name: "takeover_fingerprints",
		Description: "Subdomain and DNS/NS takeover fingerprints (can-i-take-over-xyz style): service/provider, vulnerable status, the response fingerprint to match, and claim instructions. Filter by `type` (subdomain | dns | all) and text `q` (service, status, fingerprint, instructions).",
		InputSchema: obj(map[string]any{
			"type":  strProp("subdomain | dns | all (default all)"),
			"q":     strProp("substring over service / status / fingerprint / instructions"),
			"limit": intProp("max rows (default 100)"),
		})},
	{Name: "write_finding_report",
		Description: "Generate (or return the stored) submission-report draft for a finding — uses the AI review's draft when there is one, else writes ONLY from platform evidence (gaps stay [NOT PROVIDED]). regenerate=true writes a fresh one. Editing/saving via the Findings page; the platform never submits.",
		InputSchema: obj(map[string]any{
			"id":         intProp("finding id"),
			"regenerate": map[string]any{"type": "boolean", "description": "ignore the stored report and AI draft"},
		}, "id")},
	{Name: "list_settings",
		Description: "All settings keys with masked values (secret-shaped values show ab…len).",
		InputSchema: obj(map[string]any{})},
	{Name: "get_setting",
		Description: "Read one setting. Secret-shaped values (tokens/keys/secrets) come back masked.",
		InputSchema: obj(map[string]any{"key": strProp("setting key, e.g. GITHUB_TOKEN, CVE_RADAR")}, "key")},
	{Name: "set_setting",
		Description: "Write one setting (webhooks, toggles like CVE_RADAR=off, provider keys, radar intervals…). The auth JWT secret and the MCP token itself can never be set here.",
		InputSchema: obj(map[string]any{"key": strProp("setting key"), "value": strProp("new value (empty clears)")}, "key", "value")},
	{Name: "list_monitor_targets",
		Description: "Subdomain monitor targets (the Monitor page).",
		InputSchema: obj(map[string]any{})},
	{Name: "add_monitor_target",
		Description: "Add a domain to the subdomain monitor.",
		InputSchema: obj(map[string]any{
			"domain": strProp("root domain to watch"), "interval_seconds": intProp("check interval (default 86400)"),
			"monitor_js": map[string]any{"type": "boolean", "description": "also watch JS files"},
		}, "domain")},
	{Name: "remove_monitor_target",
		Description: "Remove a subdomain monitor target by domain.",
		InputSchema: obj(map[string]any{"domain": strProp("the monitored domain")}, "domain")},
	{Name: "cancel_scan",
		Description: "Request cancellation of a running scan by scan_id.",
		InputSchema: obj(map[string]any{"scan_id": strProp("scan id")}, "scan_id")},
	{Name: "pause_scan",
		Description: "Pause a running scan by scan_id.",
		InputSchema: obj(map[string]any{"scan_id": strProp("scan id")}, "scan_id")},
	{Name: "resume_scan",
		Description: "Resume a paused scan by scan_id.",
		InputSchema: obj(map[string]any{"scan_id": strProp("scan id")}, "scan_id")},
	{Name: "edit_scan",
		Description: "Set a scan's dashboard title and/or description (omit a field to keep it; empty string clears it).",
		InputSchema: obj(map[string]any{
			"scan_id": strProp("scan id"), "name": strProp("new title"), "description": strProp("new description"),
		}, "scan_id")},
	{Name: "actionable_cves",
		Description: "PoC-confirmed, web-reachable CVEs with no nuclei template and no sweep yet — the PoC-runner worklist (run the public PoC repo against matching corpus hosts).",
		InputSchema: obj(map[string]any{"limit": intProp("max rows (default 20)")})},
	{Name: "corpus_filter",
		Description: "Live hosts matching a tech/URL substring — the PoC-runner target selector. Pattern examples: joomla, splunk, mobsf, /com_os_cck/, ahsay. Returns urls + tech fingerprints.",
		InputSchema: obj(map[string]any{
			"pattern": strProp("substring matched against techs and urls"),
			"limit":   intProp("max hosts (default 500)"),
		}, "pattern")},
	{Name: "clientside_results",
		Description: "What a client-side scan (run_scan type=clientside) found: JS files ranked as leads (a DOM XSS source and sink in the same file first, third-party hosts flagged), masked JS secrets, counts per pattern class (DOM XSS sources/sinks/flows, open-redirect sinks, postMessage listeners and '*' targets, prototype pollution, eval/new Function, credentials in storage), then the rows. Candidates only — trace each flow in the JS before calling it a bug.",
		InputSchema: obj(map[string]any{
			"scan_id":      strProp("client-side scan id (from run_scan)"),
			"kind":         map[string]any{"type": "string", "enum": []string{"all", "secrets", "sinks"}, "description": "all (default), secrets only, or client-side sinks only"},
			"min_severity": map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high"}, "description": "row floor (default info — sources alone are info)"},
			"pattern":      strProp("substring filter on class, file or match, e.g. postMessage, innerHTML, aws"),
			"leads":        intProp("JS files to rank (default 15, max 50)"),
			"limit":        intProp("rows to list (default 40, max 200)"),
			"js_urls":      map[string]any{"type": "boolean", "description": "also list the collected JS file URLs (up to 200)"},
		}, "scan_id")},
	{Name: "run_scan",
		Description: "Launch a whitelisted scan and get its scan id. Types — " + mcpScanTypeHelp() + ". Dashboard spellings (dns-takeover, js-endpoints) work too. Per-target types run the dashboard's own /scan handlers with the same target validation. Intrusive options (DoS tests, write tests, server file paths) are not exposed. No submissions, no shell.",
		InputSchema: obj(map[string]any{
			"type":        map[string]any{"type": "string", "enum": mcpScanTypeNames(), "description": "scan type"},
			"target":      strProp("domain, host, URL, bucket, owner/repo or org — whatever the type takes (blank ports = whole corpus)"),
			"root":        strProp("alias of target (older clients)"),
			"template":    strProp("nuclei template path/ID or raw YAML (type=nuclei)"),
			"hosts":       strProp("type=nuclei: comma-separated product words (e.g. 'gitlab' or 'zoneminder,zm') — runs only on live hosts whose tech/title/server fingerprint matches, in minutes, outside the full-sweep queue. Prefer this over a full sweep."),
			"max_hosts":   intProp("type=nuclei with hosts: cap on matched hosts (default 2000, max 5000)"),
			"targeted":    map[string]any{"type": "boolean", "description": "type=nuclei: auto-target by the template's own technology tags — run only on live hosts whose fingerprint matches (minutes, outside the full-sweep queue). Use when you don't want to name the product yourself."},
			"queue":       map[string]any{"type": "boolean", "description": "type=nuclei without hosts: wait behind a running full-corpus sweep instead of failing"},
			"mode":        strProp("nuclei_target: full | cves | panels | default-logins | vulnerabilities; asr: 1-5"),
			"skip_ffuf":   map[string]any{"type": "boolean", "description": "domain_run / subdomain_run: skip the FFuf phase"},
			"cves":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "zerodays: only these CVE checks"},
			"region":      strProp("s3 / s3_bucket: AWS region, e.g. us-east-1"),
			"name":        strProp("short human title shown on the dashboard, e.g. 'Smarty CVE-2026-82531 sweep' (always set one; nuclei defaults to the template's info.name)"),
			"description": strProp("optional notes: why this scan was launched, what to look for"),
		}, "type")},
	{Name: "list_cves",
		Description: "CVEs the radar tracks, newest first, with whether anything has run against them: run=never (no PoC-day run, never swept), active (queued/running), tried (picked up but nothing ran — no template, no matching hosts, gated), ran (a targeted pass or full sweep ran).",
		InputSchema: obj(map[string]any{
			"q":        strProp("substring of the CVE id or description"),
			"poc":      map[string]any{"type": "boolean", "description": "true = public PoC only, false = no PoC yet"},
			"run":      map[string]any{"type": "string", "enum": []string{"never", "active", "tried", "ran"}, "description": "run history filter"},
			"min_cvss": map[string]any{"type": "number", "description": "minimum CVSS score"},
			"limit":    intProp("max rows (default 25, max 200)"),
			"offset":   intProp("rows to skip"),
		})},
}

// mcpResult builds a tools/call result.
func mcpText(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func mcpJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}

// mcpCallTool executes one tool. Errors are tool RESULTS (isError), not
// transport errors — that's the MCP convention.
func mcpCallTool(name string, args map[string]any) map[string]any {
	getStr := func(k string) string { s, _ := args[k].(string); return strings.TrimSpace(s) }
	getInt := func(k string, def int) int {
		if f, ok := args[k].(float64); ok {
			return int(f)
		}
		return def
	}
	_ = db.Init()

	switch name {
	case "list_findings":
		limit := getInt("limit", 50)
		platform, program := getStr("platform"), getStr("program")
		// "h1 alibaba" is the label form the dashboard and triage show.
		if program != db.NoProgram && strings.Contains(program, " ") {
			if pl, pr := db.ProgramOf(program); pl != "other" {
				program = pr
				if platform == "" {
					platform = pl
				}
			}
		}
		report := getStr("report")
		if report != "" && report != "1" && report != "0" {
			return mcpErr(fmt.Errorf("report must be 1 or 0"))
		}
		hideClosed, _ := args["hide_closed"].(bool)
		rows, total, err := db.ListFindings(db.FindingFilter{Status: getStr("status"), AI: getStr("ai"), Module: getStr("module"),
			ScanID: getStr("scan_id"), Q: getStr("q"), Severity: getStr("severity"), Platform: platform,
			Program: program, Report: report, HideClosed: hideClosed,
			Limit: limit, Offset: getInt("offset", 0)})
		if err != nil {
			return mcpErr(err)
		}
		attachValidations(rows...)
		attachProgramURLs(rows...)
		return mcpText(fmt.Sprintf("%d finding(s) (total %d):\n%s", len(rows), total, mcpJSON(rows)))

	case "get_finding":
		f, err := db.GetFinding(int64(getInt("id", 0)))
		if err != nil {
			return mcpErr(err)
		}
		attachValidations(f)
		attachProgramURLs(f)
		return mcpText(mcpJSON(f))
	case "validate_findings":
		var ids []int64
		if raw, ok := args["ids"].([]any); ok {
			for _, x := range raw {
				if n, ok := x.(float64); ok && n > 0 {
					ids = append(ids, int64(n))
				}
			}
		}
		if len(ids) == 0 || len(ids) > findingValidateMaxBatch {
			return mcpErr(fmt.Errorf("ids: 1-%d finding ids", findingValidateMaxBatch))
		}
		if !brain.Available() {
			return mcpErr(fmt.Errorf("no AI provider key configured"))
		}
		queued := 0
		for _, id := range ids {
			if f, err := db.GetFinding(id); err == nil && f != nil && enqueueFindingValidation(id) {
				queued++
			}
		}
		return mcpText(fmt.Sprintf("%d finding(s) queued for agent validation — results land on each finding (get_finding → validation)", queued))

	case "create_finding":
		f := &db.Finding{Title: getStr("title"), Platform: getStr("platform"), Severity: strings.ToLower(getStr("severity")),
			Host: getStr("host"), Program: getStr("program"), CVE: strings.ToUpper(getStr("cve")), Status: getStr("status"),
			MatchedAt: getStr("matched_at"), Notes: getStr("notes"), ReportRef: getStr("report_ref"), Source: "mcp"}
		if f.Title == "" {
			return mcpErr(fmt.Errorf("title is required"))
		}
		if v, ok := args["cvss"].(float64); ok && v >= 0 && v <= 10 {
			f.CVSS = v
		}
		if f.Platform == "" {
			f.Platform = "other"
		}
		if err := db.CreateFinding(f); err != nil {
			return mcpErr(err)
		}
		if md, _ := args["report_md"].(string); strings.TrimSpace(md) != "" {
			_ = db.UpdateFindingReport(f.ID, md)
		}
		return mcpText("created finding #" + fmt.Sprint(f.ID))

	case "update_finding":
		id := int64(getInt("id", 0))
		var e db.FindingEdit
		strField := func(k string) *string {
			if v, ok := args[k].(string); ok {
				return &v
			}
			return nil
		}
		e.Title, e.Host, e.CVE, e.Program, e.Platform = strField("title"), strField("host"), strField("cve"), strField("program"), strField("platform")
		e.Severity, e.Status, e.Notes, e.ReportRef = strField("severity"), strField("status"), strField("notes"), strField("report_ref")
		e.MatchedAt, e.ReportMD = strField("matched_at"), strField("report_md")
		if v, ok := args["cvss"].(float64); ok {
			e.CVSS = &v
		}
		if err := db.UpdateFindingFields(id, e); err != nil {
			return mcpErr(err)
		}
		f, _ := db.GetFinding(id)
		return mcpText(mcpJSON(f))

	case "bulk_update_findings":
		ids := mcpIDs(args["ids"])
		st := getStr("status")
		if len(ids) == 0 || len(ids) > 1000 {
			return mcpErr(fmt.Errorf("ids: 1-1000 finding ids"))
		}
		n := 0
		for _, id := range ids {
			if err := db.UpdateFindingFields(id, db.FindingEdit{Status: &st}); err != nil {
				if errors.Is(err, db.ErrFindingNotFound) {
					continue
				}
				return mcpErr(fmt.Errorf("after %d updated: %w", n, err))
			}
			n++
		}
		return mcpText(fmt.Sprintf("%d finding(s) set to %s", n, st))

	case "delete_findings":
		ids := mcpIDs(args["ids"])
		if len(ids) == 0 || len(ids) > 1000 {
			return mcpErr(fmt.Errorf("ids: 1-1000 finding ids"))
		}
		n, err := db.DeleteFindings(ids)
		if err != nil {
			return mcpErr(err)
		}
		auditActor("mcp", "findings.delete", "", fmt.Sprintf("%d deleted", n))
		return mcpText(fmt.Sprintf("%d finding(s) deleted", n))

	case "send_finding_to_discord":
		f, err := db.GetFinding(int64(getInt("id", 0)))
		if err != nil {
			return mcpErr(err)
		}
		at, err := notifyFindingDiscord(context.Background(), f, "mcp")
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(fmt.Sprintf("sent finding #%d to Discord at %d", f.ID, at))

	case "update_finding_status":
		if err := db.UpdateFindingStatus(int64(getInt("id", 0)), getStr("status"), getStr("report_ref"), getStr("notes")); err != nil {
			return mcpErr(err)
		}
		return mcpText("updated")

	case "list_scans":
		rows, err := db.ListRecentScans(getInt("limit", 20))
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(mcpJSON(rows))

	case "scan_detail":
		rec, err := db.GetScan(getStr("scan_id"))
		if err != nil || rec == nil {
			return mcpErr(fmt.Errorf("scan not found"))
		}
		return mcpText(mcpJSON(rec))

	case "scan_results":
		return mcpScanResults(args)

	case "clientside_results":
		return mcpClientSideResults(args)

	case "scope_check":
		sc := triageScopeFor(getStr("host"))
		return mcpText(mcpJSON(sc))

	case "cve_lookup":
		rec, err := db.GetCVE(strings.ToUpper(getStr("cve")))
		if err != nil {
			return mcpErr(fmt.Errorf("CVE not tracked"))
		}
		return mcpText(mcpJSON(rec))

	case "port_lookup":
		rows, total, err := db.ListHostPorts(getStr("host"), 0, 100)
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(fmt.Sprintf("%d open port(s) (total %d):\n%s", len(rows), total, mcpJSON(rows)))

	case "discovered_assets":
		hours := getInt("hours", 168)
		limit := getInt("limit", 25)
		rows, err := db.ListRecentlyDiscoveredSubdomains(limit, hours)
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(fmt.Sprintf("%d asset(s):\n%s", len(rows), mcpJSON(rows)))

	case "recon_dorks":
		dd, err := dorks.Load()
		if err != nil {
			return mcpErr(err)
		}
		opts := dorks.FilterOpts{
			Category: getStr("category"), Platform: getStr("platform"),
			Severity: getStr("severity"), Query: getStr("q"),
		}
		res := dd.Resolve(opts, getStr("target"))
		if limit := getInt("limit", 100); limit > 0 && len(res) > limit {
			res = res[:limit]
		}
		return mcpText(mcpJSON(map[string]any{"count": len(res), "version": dd.Version, "dorks": res}))

	case "ssrf_payloads":
		res, err := seclab.FilterSSRF(getStr("q"), getStr("tag"), getInt("limit", 100))
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(mcpJSON(map[string]any{"count": len(res), "payloads": res}))

	case "xss_payloads":
		res, err := seclab.FilterXSS(getStr("q"), getStr("tag"), getStr("event"), getInt("limit", 100))
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(mcpJSON(map[string]any{"count": len(res), "payloads": res}))

	case "takeover_fingerprints":
		res, err := seclab.FilterTakeover(getStr("type"), getStr("q"), getInt("limit", 100))
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(mcpJSON(map[string]any{"count": len(res), "fingerprints": res}))

	case "write_finding_report":
		id := int64(getInt("id", 0))
		f, err := db.GetFinding(id)
		if err != nil {
			return mcpErr(err)
		}
		regenerate, _ := args["regenerate"].(bool)
		if !regenerate && strings.TrimSpace(f.ReportMD) != "" {
			return mcpText(f.ReportMD)
		}
		if !regenerate && f.AI != nil && strings.TrimSpace(f.AI.ReportMD) != "" {
			_ = db.UpdateFindingReport(id, f.AI.ReportMD)
			return mcpText(f.AI.ReportMD)
		}
		evidence := buildEvidencePack(f)
		reply, cerr := brainComplete(reportSpecSystem, evidence)
		if cerr == nil && strings.TrimSpace(reply) != "" {
			_ = db.UpdateFindingReport(id, reply)
			return mcpText(reply)
		}
		sc := reportScaffold(f, evidence)
		_ = db.UpdateFindingReport(id, sc)
		return mcpText(sc)
	case "list_settings", "get_setting", "set_setting":
		return mcpSettingTool(name, getStr("key"), getStr("value"))

	case "list_monitor_targets":
		targets, err := db.ListSubdomainMonitorTargets()
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(mcpJSON(targets))

	case "add_monitor_target":
		domain := getStr("domain")
		if domain == "" {
			return mcpErr(fmt.Errorf("domain is required"))
		}
		interval := getInt("interval_seconds", 86400)
		if interval < 300 {
			interval = 300
		}
		if err := db.AddSubdomainMonitorTarget(domain, interval, 100, true, getStr("monitor_js") == "true"); err != nil {
			return mcpErr(err)
		}
		return mcpText("monitor target added: " + domain)

	case "remove_monitor_target":
		if getStr("domain") == "" {
			return mcpErr(fmt.Errorf("domain is required"))
		}
		if err := db.RemoveSubdomainMonitorTarget(getStr("domain")); err != nil {
			return mcpErr(err)
		}
		return mcpText("monitor target removed")

	case "cancel_scan":
		if err := CancelScanByID(getStr("scan_id")); err != nil {
			return mcpErr(err)
		}
		return mcpText("cancel requested")
	case "pause_scan":
		if err := PauseScanByID(getStr("scan_id")); err != nil {
			return mcpErr(err)
		}
		return mcpText("paused")
	case "resume_scan":
		if err := ResumeScanByID(getStr("scan_id")); err != nil {
			return mcpErr(err)
		}
		return mcpText("resumed")
	case "edit_scan":
		id := getStr("scan_id")
		if id == "" || strings.ContainsAny(id, " /\\") {
			return mcpErr(fmt.Errorf("scan_id required"))
		}
		var name, desc *string
		if v, ok := args["name"].(string); ok {
			v = cleanScanText(v, scanNameMax, false)
			name = &v
		}
		if v, ok := args["description"].(string); ok {
			v = cleanScanText(v, scanDescMax, true)
			desc = &v
		}
		if name == nil && desc == nil {
			return mcpErr(fmt.Errorf("give name and/or description"))
		}
		if _, err := applyScanMeta(id, name, desc); err != nil {
			return mcpErr(err)
		}
		return mcpText("scan updated")
	case "import_scan_findings":
		id := getStr("scan_id")
		if rec, err := db.GetScan(id); err != nil || rec == nil {
			return mcpErr(fmt.Errorf("scan not found"))
		}
		withAI := true
		if v, ok := args["ai_review"].(bool); ok {
			withAI = v
		}
		info, _ := args["include_info"].(bool)
		withAI = withAI && brain.Available()
		enqueueTriage(triageJob{ScanID: id, Reason: "mcp import", AI: withAI, IncludeInfo: info}, true)
		return mcpText(fmt.Sprintf("queued import of %s (ai_review=%v include_info=%v)", id, withAI, info))
	case "ai_review_finding":
		f, err := db.GetFinding(int64(getInt("id", 0)))
		if err != nil {
			return mcpErr(err)
		}
		if !brain.Available() {
			return mcpErr(fmt.Errorf("no AI provider key configured"))
		}
		tf, err := findingForReview(f)
		if err != nil {
			return mcpErr(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
		defer cancel()
		if _, err := triageEngine.ReviewOne(ctx, loadTriageConfig(), tf, true); err != nil {
			return mcpErr(err)
		}
		out, _ := db.GetFinding(f.ID)
		return mcpText(mcpJSON(out))
	case "set_finding_verdict":
		f, err := db.GetFinding(int64(getInt("id", 0)))
		if err != nil {
			return mcpErr(err)
		}
		v := getStr("verdict")
		if !findingVerdicts[v] {
			return mcpErr(fmt.Errorf("verdict must be true_positive, likely, needs_manual_review, false_positive or empty"))
		}
		if f.FKey == "" {
			if _, err := findingForReview(f); err != nil {
				return mcpErr(err)
			}
		}
		if err := db.SetFindingVerdict(f, v); err != nil {
			return mcpErr(err)
		}
		return mcpText("verdict recorded")

	case "actionable_cves":
		recs, err := db.ActionableCVEs(getInt("limit", 20))
		if err != nil {
			return mcpErr(err)
		}
		if len(recs) == 0 {
			return mcpText("no actionable CVEs right now — everything PoC-confirmed is either templated, swept, or not web-reachable")
		}
		return mcpText(mcpJSON(recs))

	case "corpus_filter":
		hosts, total, err := db.FilterLiveHosts(getStr("pattern"), getInt("limit", 500))
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(fmt.Sprintf("%d host(s) (total %d):\n%s", len(hosts), total, mcpJSON(hosts)))

	case "list_cves":
		f := db.CVEFilter{Q: getStr("q"), RunState: strings.ToLower(getStr("run")), Limit: getInt("limit", 25), Offset: getInt("offset", 0)}
		if v, ok := args["poc"].(bool); ok {
			f.PoCOnly, f.NoPoCOnly = v, !v
		}
		if v, ok := args["min_cvss"].(float64); ok {
			f.MinScore = v
		}
		if f.Limit > 200 {
			f.Limit = 200
		}
		rows, total, err := db.ListCVEs(f)
		if err != nil {
			return mcpErr(err)
		}
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			ids = append(ids, r.CVEID)
		}
		runs, _ := db.PocdayRunsFor(ids)
		var b strings.Builder
		fmt.Fprintf(&b, "%d CVE(s) (total %d)\n", len(rows), total)
		for _, r := range rows {
			run := runs[r.CVEID]
			line := fmt.Sprintf("%s | CVSS %.1f | %s | poc=%t | run=%s", r.CVEID, r.CVSSScore, firstNonEmptyStr(r.AttackVector, "vector ?"),
				r.PoCPublished, db.CVERunState(r, run))
			if run != nil {
				line += fmt.Sprintf(" (pocday %s, %d hits)", run.Status, run.Hits)
			}
			if r.Label != "" {
				line += " | label " + r.Label
			}
			fmt.Fprintf(&b, "%s | %s\n", line, clipText(r.Description, 140))
		}
		return mcpText(b.String())
	case "run_scan":
		name := cleanScanText(getStr("name"), scanNameMax, false)
		scanID, msg, err := mcpLaunchScan(getStr("type"), firstNonEmptyStr(getStr("target"), getStr("root")), getStr("template"), name, args)
		if err != nil {
			return mcpErr(err)
		}
		var namePtr, descPtr *string
		if name != "" {
			namePtr = &name
		}
		if d := cleanScanText(getStr("description"), scanDescMax, true); d != "" {
			descPtr = &d
		}
		if namePtr != nil || descPtr != nil {
			_, _ = applyScanMeta(scanID, namePtr, descPtr)
		}
		return mcpText(msg + " (scan_id: " + scanID + ")")
	}
	if h, ok := edgeMCPDispatch[name]; ok {
		return h(args)
	}
	return mcpErr(fmt.Errorf("unknown tool %q", name))
}

// mcpIDs reads a JSON array of ids.
func mcpIDs(v any) []int64 {
	var out []int64
	raw, _ := v.([]any)
	for _, x := range raw {
		if n, ok := x.(float64); ok && n > 0 {
			out = append(out, int64(n))
		}
	}
	return out
}

func mcpErr(err error) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": "error: " + err.Error()}}, "isError": true}
}

// ─────────────────────────────────────────────────────────────────────────────
// Transport
// ─────────────────────────────────────────────────────────────────────────────

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  map[string]any  `json:"params"`
}

// mcpHandle is the /mcp endpoint: bearer mcp_token, one JSON-RPC per POST.
func mcpHandle(c *gin.Context) {
	tok := strings.TrimSpace(strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer "))
	want, _ := db.GetSetting(mcpTokenKey)
	if tok == "" || want == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(want)) != 1 {
		c.JSON(http.StatusUnauthorized, gin.H{"jsonrpc": "2.0", "error": gin.H{"code": -32001, "message": "invalid or missing MCP token"}, "id": nil})
		return
	}
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad body"})
		return
	}
	var req jsonRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		c.JSON(http.StatusOK, gin.H{"jsonrpc": "2.0", "error": gin.H{"code": -32700, "message": "parse error"}, "id": nil})
		return
	}
	// last-used is informational: one DB write per minute, not per request.
	if now := time.Now().UTC().Unix(); now-mcpLastUsedWritten.Load() >= 60 {
		mcpLastUsedWritten.Store(now)
		_ = db.SetSetting(mcpLastUsedKey, fmt.Sprintf("%d", now))
	}

	// Notifications (no id) get a bare 202.
	if len(req.ID) == 0 {
		c.Status(http.StatusAccepted)
		return
	}
	resp := gin.H{"jsonrpc": "2.0", "id": req.ID}
	switch req.Method {
	case "initialize":
		resp["result"] = gin.H{
			"protocolVersion": "2025-03-26",
			"capabilities":    gin.H{"tools": gin.H{}},
			"serverInfo":      gin.H{"name": "autoar", "version": "1.0"},
		}
	case "ping":
		resp["result"] = gin.H{}
	case "tools/list":
		resp["result"] = gin.H{"tools": allMCPTools()}
	case "tools/call":
		name, _ := req.Params["name"].(string)
		args, _ := req.Params["arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		resp["result"] = mcpCallTool(name, args)
	default:
		resp["error"] = gin.H{"code": -32601, "message": "method not found: " + req.Method}
	}
	c.JSON(http.StatusOK, resp)
}

// apiMCPRotateToken issues a fresh MCP token (admin only; shown once).
func apiMCPRotateToken(c *gin.Context) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	tok := "mcp_" + hex.EncodeToString(raw)
	if err := db.SetSetting(mcpTokenKey, tok); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok, "note": "store it now — retrievable only by rotating again. Use as 'Authorization: Bearer <token>' on POST /mcp"})
}

// apiMCPStatus reports whether a token exists and when it was last used.
func apiMCPStatus(c *gin.Context) {
	tok, _ := db.GetSetting(mcpTokenKey)
	last := db.GetSettingInt(mcpLastUsedKey, 0)
	c.JSON(http.StatusOK, gin.H{
		"enabled":   tok != "",
		"last_used": time.Unix(int64(last), 0).UTC().Format(time.RFC3339),
		"endpoint":  "/mcp",
		"tools":     len(allMCPTools()),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings tools — broad control with two hard denials and secret masking.
// ─────────────────────────────────────────────────────────────────────────────

// mcpDeniedSettings can never be read (unmasked) or written over MCP: the
// local JWT signing secret and the MCP token itself.
var mcpDeniedSettings = map[string]bool{
	"local_auth_jwt_secret": true,
	mcpTokenKey:             true,
}

// mcpSecretKeyShape reports whether a value looks like a credential (masked
// in listings/reads so secrets never flow through an AI context window).
func mcpSecretKeyShape(key string) bool {
	k := strings.ToUpper(key)
	for _, p := range []string{"TOKEN", "SECRET", "PASSWORD", "API_KEY"} {
		if strings.Contains(k, p) {
			return true
		}
	}
	return strings.HasSuffix(k, "_KEY")
}

func mcpMask(key, v string) string {
	if !mcpSecretKeyShape(key) {
		return v
	}
	if len(v) <= 4 {
		return "••••"
	}
	return v[:4] + "…(" + fmt.Sprint(len(v)) + " chars)"
}

func mcpSettingTool(name, key, value string) map[string]any {
	key = strings.ToUpper(strings.TrimSpace(key))
	switch name {
	case "list_settings":
		all, err := db.GetAllSettings()
		if err != nil {
			return mcpErr(err)
		}
		keys := make([]string, 0, len(all))
		for k := range all {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s = %s\n", k, mcpMask(k, all[k]))
		}
		return mcpText(b.String())
	case "get_setting":
		if key == "" {
			return mcpErr(fmt.Errorf("key is required"))
		}
		if mcpDeniedSettings[strings.ToLower(key)] {
			return mcpErr(fmt.Errorf("%s is not readable over MCP", key))
		}
		v, err := db.GetSetting(key)
		if err != nil {
			return mcpErr(err)
		}
		return mcpText(mcpMask(key, v))
	case "set_setting":
		if key == "" {
			return mcpErr(fmt.Errorf("key is required"))
		}
		if mcpDeniedSettings[strings.ToLower(key)] {
			return mcpErr(fmt.Errorf("%s can never be written over MCP", key))
		}
		if err := db.SetSetting(key, value); err != nil {
			return mcpErr(err)
		}
		// env-backed settings need the live env update too (same contract as
		// the settings page): webhook URLs, provider keys, toggles.
		saveEnvSetting(key, value)
		return mcpText("set " + key)
	}
	return mcpErr(fmt.Errorf("unknown settings tool"))
}

// mcpScanResults reads a scan's hits straight from the raw result JSONL on
// disk (the disk-truth rule: conclusions come from the container files, not
// the parsed-results API). Watch scans keep one JSONL under
// global-subdomains/vulnerabilities/; per-scan dirs hold *.jsonl.
func mcpScanResults(args map[string]any) map[string]any {
	getStr := func(k string) string { v, _ := args[k].(string); return strings.TrimSpace(v) }
	scanID := getStr("scan_id")
	if scanID == "" || strings.ContainsAny(scanID, " /\\") {
		return mcpErr(fmt.Errorf("scan_id required"))
	}
	tpl := strings.ToLower(getStr("template"))
	limit := 20
	if v, ok := args["limit"].(float64); ok && int(v) > 0 {
		limit = int(v)
	}
	if limit > 100 {
		limit = 100
	}
	root := utils.GetResultsDir()
	candidates := []string{
		filepath.Join(root, scanID),
		filepath.Join(root, "global-subdomains", "vulnerabilities", "nuclei-"+scanID+".json"),
	}
	var files []string
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			files = append(files, c)
			break
		}
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			entries, _ := os.ReadDir(c)
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
					files = append(files, filepath.Join(c, e.Name()))
				}
			}
			if len(files) > 0 {
				break
			}
		}
	}
	if len(files) == 0 {
		return mcpErr(fmt.Errorf("no result files on disk for %s (scan may have no results dir)", scanID))
	}
	type hit struct {
		Host      string `json:"host"`
		MatchedAt string `json:"matched_at"`
		Template  string `json:"template"`
		Name      string `json:"name,omitempty"`
	}
	var hits []hit
	total := 0
	scanned := 0
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			scanned++
			var r struct {
				Host      string `json:"host"`
				MatchedAt string `json:"matched-at"`
				Template  string `json:"template-id"`
				Info      struct {
					Name string `json:"name"`
				} `json:"info"`
			}
			if json.Unmarshal([]byte(line), &r) != nil {
				continue
			}
			if r.Host == "" && r.MatchedAt == "" {
				continue
			}
			if tpl != "" && !strings.Contains(strings.ToLower(r.Template+" "+r.Info.Name), tpl) {
				continue
			}
			total++
			if len(hits) < limit {
				hits = append(hits, hit{Host: r.Host, MatchedAt: r.MatchedAt, Template: r.Template, Name: r.Info.Name})
			}
		}
		fh.Close() // per file: a deferred close held every file open until return
	}
	return mcpText(mcpJSON(map[string]any{
		"scan_id":    scanID,
		"files":      files,
		"lines_read": scanned,
		"total_hits": total,
		"returned":   hits,
	}))
}
