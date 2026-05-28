package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

const protocolVersion = "2024-11-05"
const serverName = "autoar-mcp"
const serverVersion = "0.1.0"

// JSON-RPC 2.0 types
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func newJSONRPCError(id interface{}, code int, msg string) jsonRPCResponse {
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	}
}

// MCP Tool definition
type Tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]property `json:"properties"`
	Required   []string            `json:"required,omitempty"`
}

type property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// Server is the MCP server.
type Server struct {
	tools   map[string]*registeredTool
	mu      sync.RWMutex
	initialized bool
}

type registeredTool struct {
	definition Tool
	handler    func(args map[string]interface{}) (string, error)
}

// NewServer creates a new MCP server with all scan exploration tools registered.
func NewServer() *Server {
	s := &Server{
		tools: make(map[string]*registeredTool),
	}
	s.registerTools()
	return s
}

func (s *Server) registerTool(t Tool, handler func(args map[string]interface{}) (string, error)) {
	s.tools[t.Name] = &registeredTool{definition: t, handler: handler}
}

// Run starts the MCP server, reading JSON-RPC from stdin and writing to stdout.
// Logs go to stderr to avoid corrupting the MCP transport.
func (s *Server) Run() error {
	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	for {
		req, err := readRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			fmt.Fprintf(os.Stderr, "[autoar-mcp] read error: %v\n", err)
			return err
		}

		resp := s.handleRequest(req)
		if resp != nil {
			if err := writeResponse(writer, *resp); err != nil {
				fmt.Fprintf(os.Stderr, "[autoar-mcp] write error: %v\n", err)
				return err
			}
		}
	}
}

func (s *Server) handleRequest(req jsonRPCRequest) *jsonRPCResponse {
	// Notifications have no ID — no response.
	if req.ID == nil {
		s.handleNotification(req)
		return nil
	}

	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "ping":
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{},
		}
	default:
		errResp := newJSONRPCError(req.ID, -32601, fmt.Sprintf("unknown method: %s", req.Method))
		return &errResp
	}
}

func (s *Server) handleNotification(req jsonRPCRequest) {
	switch req.Method {
	case "notifications/initialized":
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
	default:
		fmt.Fprintf(os.Stderr, "[autoar-mcp] unhandled notification: %s\n", req.Method)
	}
}

func (s *Server) handleInitialize(req jsonRPCRequest) *jsonRPCResponse {
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": protocolVersion,
			"serverInfo": map[string]string{
				"name":    serverName,
				"version": serverVersion,
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{},
			},
		},
	}
}

func (s *Server) handleToolsList(req jsonRPCRequest) *jsonRPCResponse {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tools := make([]Tool, 0, len(s.tools))
	for _, t := range s.tools {
		tools = append(tools, t.definition)
	}

	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

func (s *Server) handleToolsCall(req jsonRPCRequest) *jsonRPCResponse {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		errResp := newJSONRPCError(req.ID, -32602, "invalid params: "+err.Error())
		return &errResp
	}

	s.mu.RLock()
	tool, ok := s.tools[params.Name]
	s.mu.RUnlock()

	if !ok {
		errResp := newJSONRPCError(req.ID, -32602, fmt.Sprintf("unknown tool: %s", params.Name))
		return &errResp
	}

	resultText, err := tool.handler(params.Arguments)
	if err != nil {
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{"type": "text", "text": fmt.Sprintf("Error: %s", err.Error())},
				},
				"isError": true,
			},
		}
	}

	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": resultText},
			},
		},
	}
}

// --- Transport framing ---

func readRequest(r *bufio.Reader) (jsonRPCRequest, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return jsonRPCRequest{}, err
		}
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimSuffix(line, "\n")

		if line == "" {
			// empty line — skip header separators
			continue
		}

		if strings.HasPrefix(line, "Content-Length:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:"))
			cl, err := strconv.Atoi(v)
			if err != nil {
				return jsonRPCRequest{}, fmt.Errorf("bad Content-Length: %s", v)
			}
			// Read the trailing \r\n after the header
			r.ReadString('\n')

			body := make([]byte, cl)
			_, err = io.ReadFull(r, body)
			if err != nil {
				return jsonRPCRequest{}, fmt.Errorf("reading body: %w", err)
			}

			var req jsonRPCRequest
			if err := json.Unmarshal(body, &req); err != nil {
				return jsonRPCRequest{}, fmt.Errorf("bad JSON: %w", err)
			}
			return req, nil
		}

		// Try parsing the line as JSON directly (some clients send raw JSON lines)
		var req jsonRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err == nil {
			return req, nil
		}
	}
}

func writeResponse(w io.Writer, resp jsonRPCResponse) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "Content-Length: %d\r\n\r\n%s", len(data), data)
	return err
}
