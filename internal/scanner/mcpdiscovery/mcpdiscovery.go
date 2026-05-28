// Package mcpdiscovery probes target hosts for exposed MCP (Model Context Protocol)
// servers, enumerates their tools/resources/prompts, and flags security issues.
package mcpdiscovery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const moduleName = "mcp-discovery"

// MCP endpoint paths to probe.
var probePaths = []string{
	"/sse",
	"/mcp",
	"/message",
	"/mcp/message",
	"/mcp/sse",
	"/.well-known/mcp",
}

// JSON-RPC initialize request sent to verify MCP servers.
var initRequest = map[string]interface{}{
	"jsonrpc": "2.0",
	"id":      1,
	"method":  "initialize",
	"params": map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"clientInfo": map[string]string{
			"name":    "autoar-mcp-check",
			"version": "1.0.0",
		},
		"capabilities": map[string]interface{}{},
	},
}

// Options configures the MCP discovery scan.
type Options struct {
	Target       string
	LiveHostsFile string
	Threads      int
	Timeout      time.Duration
}

// Finding represents a single MCP-related discovery.
type Finding struct {
	Host     string `json:"host"`
	Endpoint string `json:"endpoint"`
	URL      string `json:"url"`
	Protocol string `json:"protocol"` // sse or streamable-http

	// Server info
	ServerName    string `json:"server_name,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`

	// Enumeration results
	Tools        []string `json:"tools,omitempty"`
	Resources    []string `json:"resources,omitempty"`
	Prompts      []string `json:"prompts,omitempty"`

	// Security flags
	NoAuth       bool `json:"no_auth"`
	HasDangerous bool `json:"has_dangerous"` // tool names suggesting exec/shell/file access
	StatusCode   int  `json:"status_code"`
	ResponseSize int  `json:"response_size"`
}

// Result holds aggregated scan results.
type Result struct {
	Findings []Finding
}

// aggregated JSON output shape for the scan-output file.
type jsonFinding struct {
	Target        string   `json:"target"`
	Host          string   `json:"host"`
	Endpoint      string   `json:"endpoint"`
	URL           string   `json:"url"`
	Protocol      string   `json:"protocol"`
	ServerName    string   `json:"server_name,omitempty"`
	ServerVersion string   `json:"server_version,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	Resources     []string `json:"resources,omitempty"`
	Prompts       []string `json:"prompts,omitempty"`
	NoAuth        bool     `json:"no_auth"`
	HasDangerous  bool     `json:"has_dangerous"`
	Severity      string   `json:"severity"`
	Type          string   `json:"type"`
	Module        string   `json:"module"`
	Description   string   `json:"description"`
}

// Run is the main entry point for the MCP discovery scanner.
func Run(opts Options) (*Result, error) {
	if opts.Threads <= 0 {
		opts.Threads = 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 8 * time.Second
	}

	hosts, err := loadHosts(opts.Target, opts.LiveHostsFile)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		if scanID := utils.GetCurrentScanID(); scanID != "" {
			utils.WriteNoFindingsJSON(scanID, opts.Target, moduleName, "mcp-server-findings.json")
		}
		return &Result{}, nil
	}

	logger.GetLogger().Infof("[MCP-Discovery] Probing %d host(s) for MCP servers", len(hosts))

	findings := probeConcurrently(hosts, opts.Threads, opts.Timeout)

	// Write findings to scan dir
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		if len(findings) == 0 {
			utils.WriteNoFindingsJSON(scanID, opts.Target, moduleName, "mcp-server-findings.json")
		} else {
			out := make([]jsonFinding, 0, len(findings))
			for _, f := range findings {
				sev := severity(f)
				out = append(out, jsonFinding{
					Target:        opts.Target,
					Host:          f.Host,
					Endpoint:      f.Endpoint,
					URL:           f.URL,
					Protocol:      f.Protocol,
					ServerName:    f.ServerName,
					ServerVersion: f.ServerVersion,
					Tools:         f.Tools,
					Resources:     f.Resources,
					Prompts:       f.Prompts,
					NoAuth:        f.NoAuth,
					HasDangerous:  f.HasDangerous,
					Severity:      sev,
					Type:          "mcp-server-exposed",
					Module:        moduleName,
					Description:   describeFinding(f),
				})
			}
			if err := utils.WriteJSONToScanDir(scanID, "mcp-server-findings.json", out); err != nil {
				logger.GetLogger().Errorf("[MCP-Discovery] Failed to write findings: %v", err)
			}
		}
	}

	// Update files_uploaded count using cumulative findings count
	if scanID := utils.GetCurrentScanID(); scanID != "" {
		rec, _ := db.GetScan(scanID)
		if rec != nil {
			_ = db.UpdateScanStats(scanID, rec.FilesUploaded+len(findings), rec.ErrorCount)
		}
	}

	return &Result{Findings: findings}, nil
}

func loadHosts(target string, liveHostsFile string) ([]string, error) {
	// Prefer live hosts file if it exists
	if liveHostsFile != "" {
		data, err := os.ReadFile(liveHostsFile)
		if err == nil && len(data) > 0 {
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			var hosts []string
			for _, l := range lines {
				l = strings.TrimSpace(l)
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				hosts = append(hosts, normalizeHost(l))
			}
			if len(hosts) > 0 {
				return hosts, nil
			}
		}
	}

	// Fallback to target directly
	if target == "" {
		return nil, fmt.Errorf("no target or live hosts file")
	}
	return []string{normalizeHost(target)}, nil
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimSuffix(host, "/")
	// Strip port for deduplication, but we'll probe both http and https
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

func probeConcurrently(hosts []string, threads int, timeout time.Duration) []Finding {
	// Deduplicate hosts
	seen := make(map[string]bool)
	var unique []string
	for _, h := range hosts {
		h = normalizeHost(h)
		if !seen[h] {
			seen[h] = true
			unique = append(unique, h)
		}
	}

	jobs := make(chan string, len(unique))
	results := make(chan Finding, len(unique)*len(probePaths)*2)

	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				for _, path := range probePaths {
					for _, scheme := range []string{"https", "http"} {
						f, ok := probeEndpoint(scheme, host, path, timeout)
						if ok {
							results <- f
						}
					}
				}
			}
		}()
	}

	for _, h := range unique {
		jobs <- h
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var findings []Finding
	for f := range results {
		findings = append(findings, f)
	}
	return findings
}

func probeEndpoint(scheme, host, path string, timeout time.Duration) (Finding, bool) {
	url := fmt.Sprintf("%s://%s%s", scheme, host, path)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// First, try a GET to check for SSE
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept", "text/event-stream, application/json")
	req.Header.Set("User-Agent", "AutoAR-MCP-Discovery/1.0")

	resp, err := client.Do(req)
	if err != nil {
		// Try POST (some MCP endpoints only accept POST)
		initBody, _ := json.Marshal(initRequest)
		req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(initBody))
		req2.Header.Set("Content-Type", "application/json")
		req2.Header.Set("Accept", "application/json, text/event-stream")
		req2.Header.Set("User-Agent", "AutoAR-MCP-Discovery/1.0")

		resp2, err2 := client.Do(req2)
		if err2 != nil {
			return Finding{}, false
		}
		defer resp2.Body.Close()
		return processResponse(scheme, host, url, path, resp2, client, timeout)
	}
	defer resp.Body.Close()

	return processResponse(scheme, host, url, path, resp, client, timeout)
}

func processResponse(scheme, host, url, path string, resp *http.Response, client *http.Client, timeout time.Duration) (Finding, bool) {
	// Check for MCP indicators
	isMCP := false
	protocol := "unknown"

	// Check headers
	for key, vals := range resp.Header {
		kl := strings.ToLower(key)
		for _, v := range vals {
			vl := strings.ToLower(v)
			if kl == "mcp-protocol-version" || kl == "mcp-protocol" {
				isMCP = true
			}
			if strings.Contains(vl, "text/event-stream") || kl == "mcp-session-id" {
				isMCP = true
				protocol = "sse"
			}
		}
	}

	// Read body for JSON-RPC indicators
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	bodyStr := string(body)

	if strings.Contains(bodyStr, `"jsonrpc"`) &&
		(strings.Contains(bodyStr, "serverInfo") || strings.Contains(bodyStr, "Mcp-Server")) {
		isMCP = true
	}

	// Also check for SSE stream data
	if strings.HasPrefix(strings.TrimSpace(bodyStr), "event:") ||
		strings.HasPrefix(strings.TrimSpace(bodyStr), "data:") {
		// Could be SSE - try POSTing an initialize
		isMCP = true
		protocol = "sse"
	}

	// If not MCP indicators from GET, try POST with initialize
	if !isMCP && resp.StatusCode >= 200 && resp.StatusCode < 500 {
		// Try POST with JSON-RPC initialize
		initBody, _ := json.Marshal(initRequest)
		postURL := url
		// If GET found something but not MCP, try POST to same endpoint
		req, _ := http.NewRequest(http.MethodPost, postURL, bytes.NewReader(initBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		req = req.WithContext(ctx)

		postResp, err := client.Do(req)
		if err != nil {
			// Not MCP
			return Finding{}, false
		}
		defer postResp.Body.Close()

		postBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 8192))
		postBodyStr := string(postBody)

		if strings.Contains(postBodyStr, `"serverInfo"`) && strings.Contains(postBodyStr, `"jsonrpc"`) {
			isMCP = true
			protocol = "streamable-http"
			body = postBody
			bodyStr = postBodyStr
		} else {
			return Finding{}, false
		}
	}

	if !isMCP {
		return Finding{}, false
	}

	if protocol == "unknown" {
		protocol = "streamable-http"
	}

	f := Finding{
		Host:     host,
		Endpoint: path,
		URL:      url,
		Protocol: protocol,
	}

	// Parse server info from initialize response
	if strings.Contains(bodyStr, `"serverInfo"`) {
		var initResp struct {
			Result struct {
				ServerInfo struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"serverInfo"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &initResp) == nil {
			f.ServerName = initResp.Result.ServerInfo.Name
			f.ServerVersion = initResp.Result.ServerInfo.Version
		}
	}

	f.StatusCode = resp.StatusCode
	f.ResponseSize = len(body)

	// Enumerate tools, resources, prompts
	toolsReq := map[string]interface{}{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
	toolsBody, _ := json.Marshal(toolsReq)
	f.Tools = callMCPMethod(client, url, timeout, toolsBody)

	resourcesReq := map[string]interface{}{"jsonrpc": "2.0", "id": 3, "method": "resources/list"}
	resourcesBody, _ := json.Marshal(resourcesReq)
	f.Resources = callMCPMethod(client, url, timeout, resourcesBody)

	promptsReq := map[string]interface{}{"jsonrpc": "2.0", "id": 4, "method": "prompts/list"}
	promptsBody, _ := json.Marshal(promptsReq)
	f.Prompts = callMCPMethod(client, url, timeout, promptsBody)

	// Check auth
	f.NoAuth = checkNoAuth(f.Tools, resp.StatusCode)

	// Check for dangerous tools
	f.HasDangerous = checkDangerous(f.Tools)

	logger.GetLogger().Infof("[MCP-Discovery] Found MCP server at %s (%s, %s v%s)",
		url, protocol, f.ServerName, f.ServerVersion)

	return f, true
}

// callMCPMethod sends a JSON-RPC request and extracts tool/resource/prompt names from the response.
func callMCPMethod(client *http.Client, url string, timeout time.Duration, body []byte) []string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	var rpcResp struct {
		Result interface{} `json:"result"`
	}
	if err := json.Unmarshal(raw, &rpcResp); err != nil || rpcResp.Result == nil {
		return nil
	}

	// Extract names from the result
	resultMap, ok := rpcResp.Result.(map[string]interface{})
	if !ok {
		return nil
	}

	var items []interface{}
	// Try both "tools" key and array directly
	if arr, ok := resultMap["tools"].([]interface{}); ok {
		items = arr
	} else if arr, ok := resultMap["resources"].([]interface{}); ok {
		items = arr
	} else if arr, ok := resultMap["prompts"].([]interface{}); ok {
		items = arr
	}

	var names []string
	for _, item := range items {
		if m, ok := item.(map[string]interface{}); ok {
			if name, ok := m["name"].(string); ok && name != "" {
				// Append description if available
				desc := ""
				if d, ok := m["description"].(string); ok && d != "" {
					desc = " - " + d
					if len(desc) > 80 {
						desc = desc[:80] + "..."
					}
				}
				names = append(names, name+desc)
			}
		}
	}
	return names
}

// checkNoAuth returns true if the MCP server appears to be unauthenticated.
func checkNoAuth(tools []string, statusCode int) bool {
	// If we got a successful tools list, the server is accessible without auth
	return len(tools) > 0 || statusCode == 200
}

// checkDangerous checks tool names for potentially dangerous operations.
func checkDangerous(tools []string) bool {
	dangerousKeywords := []string{
		"exec", "shell", "bash", "cmd", "run", "spawn",
		"read", "write", "delete", "upload", "download", "file",
		"sql", "query", "raw", "eval", "script", "system",
		"sudo", "root", "admin",
	}

	// Also check descriptions (after " - " separator)
	for _, tool := range tools {
		lower := strings.ToLower(tool)
		for _, kw := range dangerousKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return false
}

func severity(f Finding) string {
	if f.HasDangerous && f.NoAuth {
		return "critical"
	}
	if f.HasDangerous {
		return "high"
	}
	if f.NoAuth && len(f.Tools) > 0 {
		return "medium"
	}
	return "info"
}

func describeFinding(f Finding) string {
	parts := []string{fmt.Sprintf("MCP server exposed at %s", f.URL)}

	if f.ServerName != "" {
		parts = append(parts, fmt.Sprintf("Server: %s", f.ServerName))
		if f.ServerVersion != "" {
			parts[len(parts)-1] += " v" + f.ServerVersion
		}
	}
	parts = append(parts, fmt.Sprintf("Protocol: %s", f.Protocol))
	parts = append(parts, fmt.Sprintf("%d tools, %d resources, %d prompts found",
		len(f.Tools), len(f.Resources), len(f.Prompts)))

	if f.NoAuth {
		parts = append(parts, "NO AUTHENTICATION REQUIRED")
	}
	if f.HasDangerous {
		parts = append(parts, "DANGEROUS TOOLS EXPOSED (exec/shell/file access)")
	}

	return strings.Join(parts, " | ")
}
