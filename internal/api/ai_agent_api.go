package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/h0tak88r/AutoAR/internal/aiagent"
	"github.com/h0tak88r/AutoAR/internal/db"
)

// AI agent endpoints: the chat harness over the platform + container shell.

func init() {
	// The agent's platform tool = the MCP tool surface, in-process.
	aiagent.Wire(func(name string, args map[string]any) string {
		res := mcpCallTool(name, args)
		return res["content"].([]map[string]any)[0]["text"].(string)
	})
}

type agentChatReq struct {
	SessionID string `json:"session_id"`
	Message   string `json:"message"`
}

// apiAgentChat (POST /api/ai/agent/chat) runs one turn (bounded tool loop).
func apiAgentChat(c *gin.Context) {
	var req agentChatReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Message) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message required"})
		return
	}
	if req.SessionID == "" {
		req.SessionID = "default"
	}
	if len(req.SessionID) > 64 || strings.ContainsAny(req.SessionID, " /\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session id"})
		return
	}
	reply, log, err := aiagent.Chat(req.SessionID, req.Message)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"reply": reply, "tool_log": log, "session_id": req.SessionID})
}

// apiAgentReset (DELETE /api/ai/agent/session/:id) wipes history + workspace.
func apiAgentReset(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" || strings.ContainsAny(id, " /\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session id"})
		return
	}
	aiagent.Cleanup(id)
	c.JSON(http.StatusOK, gin.H{"status": "cleared"})
}

// apiAgentSessions (GET /api/ai/agent/sessions) lists past conversations.
func apiAgentSessions(c *gin.Context) {
	list, err := db.ListAgentSessions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sessions": list})
}

// apiAgentSessionHistory (GET /api/ai/agent/session/:id) returns one
// conversation's stored turns so a refresh restores the chat.
func apiAgentSessionHistory(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" || strings.ContainsAny(id, " /\\") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session id"})
		return
	}
	msgs, err := db.ListAgentMessages(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"session_id": id, "messages": msgs})
}

// apiAgentSkills (GET /api/ai/agent/skills) lists the loaded skill guides.
func apiAgentSkills(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"skills": aiagentListSkills()})
}

func aiagentListSkills() []string {
	entries, err := os.ReadDir("/app/skills")
	if err != nil {
		return []string{}
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out
}
