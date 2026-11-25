package db

// AI-agent chat history. Sessions used to live only in process memory, so
// every deploy wiped them; these rows make a session survive restarts and
// reappear on refresh. The workspace itself stays ephemeral by design (wiped
// on reset) — only the conversation is durable.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var agentSchema = []string{
	`CREATE TABLE IF NOT EXISTS ai_agent_messages (
		id BIGSERIAL PRIMARY KEY,
		session_id TEXT NOT NULL,
		role TEXT NOT NULL,
		content TEXT NOT NULL DEFAULT '',
		created_at BIGINT NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS idx_agent_msgs_session ON ai_agent_messages(session_id)`,
}

type AgentMessage struct {
	Role      string `json:"role"`
	Content   string `json:"content"`
	CreatedAt int64  `json:"created_at"`
}

type AgentSessionInfo struct {
	SessionID string `json:"session_id"`
	Messages  int    `json:"messages"`
	UpdatedAt int64  `json:"updated_at"`
	Preview   string `json:"preview"`
}

var (
	agentReadyOn   DB
	agentReadyOnce bool
)

func agentDB() (triageConn, error) {
	if err := Init(); err != nil {
		return nil, err
	}
	if !agentReadyOnce || agentReadyOn != dbInstance {
		var c triageConn
		switch d := dbInstance.(type) {
		case *PostgresDB:
			c = pgTriage{p: d}
		case *SQLiteDB:
			c = sqliteTriage{s: d}
		default:
			return nil, errors.New("agent msgs: unsupported backend")
		}
		for _, q := range agentSchema {
			if err := c.exec(q); err != nil {
				// SQLite says "already exists", PG says "duplicate table" —
				// both wordings mean the object is there (cves lesson).
				low := strings.ToLower(err.Error())
				if !strings.Contains(low, "already exists") && !strings.Contains(low, "duplicate table") {
					return nil, fmt.Errorf("agent msgs schema: %w", err)
				}
			}
		}
		agentReadyOn, agentReadyOnce = dbInstance, true
	}
	switch d := dbInstance.(type) {
	case *PostgresDB:
		return pgTriage{p: d}, nil
	case *SQLiteDB:
		return sqliteTriage{s: d}, nil
	}
	return nil, errors.New("agent msgs: unsupported backend")
}

// SaveAgentMessage appends one turn of a conversation.
func SaveAgentMessage(sessionID, role, content string) error {
	c, err := agentDB()
	if err != nil {
		return err
	}
	if len(content) > 60000 {
		content = content[:60000]
	}
	return c.exec(`INSERT INTO ai_agent_messages (session_id, role, content, created_at) VALUES (?, ?, ?, ?)`,
		sessionID, role, content, time.Now().UTC().Unix())
}

// ListAgentMessages returns a session's conversation in order.
func ListAgentMessages(sessionID string) ([]AgentMessage, error) {
	c, err := agentDB()
	if err != nil {
		return nil, err
	}
	var out []AgentMessage
	err = c.query(`SELECT role, content, created_at FROM ai_agent_messages WHERE session_id = ? ORDER BY id ASC`,
		func(r rowScanner) error {
			var m AgentMessage
			if err := r.Scan(&m.Role, &m.Content, &m.CreatedAt); err != nil {
				return err
			}
			out = append(out, m)
			return nil
		}, sessionID)
	return out, err
}

// ListAgentSessions summarizes every conversation, newest first, with the
// first user message as a preview.
func ListAgentSessions() ([]AgentSessionInfo, error) {
	c, err := agentDB()
	if err != nil {
		return nil, err
	}
	var out []AgentSessionInfo
	err = c.query(`SELECT session_id,
			COUNT(*) AS n,
			MAX(created_at) AS last_at,
			COALESCE((SELECT content FROM ai_agent_messages m2
				WHERE m2.session_id = m.session_id AND m2.role = 'user'
				ORDER BY m2.id ASC LIMIT 1), '') AS preview
		FROM ai_agent_messages m
		GROUP BY session_id
		ORDER BY last_at DESC
		LIMIT 100`,
		func(r rowScanner) error {
			var s AgentSessionInfo
			if err := r.Scan(&s.SessionID, &s.Messages, &s.UpdatedAt, &s.Preview); err != nil {
				return err
			}
			if len(s.Preview) > 90 {
				s.Preview = s.Preview[:90]
			}
			out = append(out, s)
			return nil
		})
	return out, err
}

// DeleteAgentSession wipes a conversation's rows (called on session reset).
func DeleteAgentSession(sessionID string) error {
	c, err := agentDB()
	if err != nil {
		return err
	}
	return c.exec(`DELETE FROM ai_agent_messages WHERE session_id = ?`, sessionID)
}
