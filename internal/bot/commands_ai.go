package bot

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"strconv"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/brain"
	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// ─────────────────────────────────────────────
// Conversation memory (per Discord channel)
// ─────────────────────────────────────────────

const maxHistoryTurns = 10 // keep last N user+assistant message pairs

var (
	aiConversations   = make(map[string][]brain.Message) // channelID → history
	aiConversationsMu sync.Mutex
)

func getAIHistory(channelID string) []brain.Message {
	aiConversationsMu.Lock()
	defer aiConversationsMu.Unlock()
	return append([]brain.Message{}, aiConversations[channelID]...)
}

func appendAIHistory(channelID string, userMsg, assistantMsg string) {
	aiConversationsMu.Lock()
	defer aiConversationsMu.Unlock()

	history := aiConversations[channelID]
	history = append(history, brain.Message{Role: "user", Content: userMsg})
	history = append(history, brain.Message{Role: "assistant", Content: assistantMsg})

	// Trim to last maxHistoryTurns pairs (each pair = 2 messages)
	if len(history) > maxHistoryTurns*2 {
		history = history[len(history)-maxHistoryTurns*2:]
	}
	aiConversations[channelID] = history
}

// ─────────────────────────────────────────────
// AI system prompt – describes all AutoAR skills
// ─────────────────────────────────────────────

const aiSystemPrompt = `You are AutoAR-AI, a conversational assistant built into the AutoAR bug-bounty automation framework.
You help security researchers by understanding their natural-language requests and mapping them to AutoAR scan capabilities.

## Available AutoAR capabilities (skills):

| Skill (type)  | What it does |
|---------------|-------------|
| domain_run    | Full domain workflow: subdomain enum → live hosts → URLs/JS → reflection → ports → nuclei → tech → DNS → backup → misconfig |
| subdomain_run | Full single-subdomain workflow: live check → all scans |
| lite_scan     | Lighter full scan: livehosts → reflection → JS → CNAME → backup → DNS → misconfig |
| fast_look     | Quick recon: subdomain enum → live hosts → URL/JS collection |
| subdomains    | Enumerate subdomains for a domain |
| livehosts     | Filter which subdomains/IPs are currently live (HTTP-probe) |
| urls          | Collect URLs and JS file URLs for a domain |
| js_scan       | Scan JavaScript files for secrets / endpoints |
| tech          | Detect technologies used on live hosts |
| ports         | Port scan live hosts for a domain (naabu) |
| nuclei        | Run nuclei vulnerability templates |

## How to respond:

Always reply with a **single JSON object** — no Markdown fences, no extra text outside the object:

{
  "reply": "<friendly message explaining what you are doing or answering their question>",
  "autoar_commands": [
    {"type": "<skill_type>", "domain": "<domain>"},
    ...
  ]
}

Rules:
- "reply" is REQUIRED.
- "autoar_commands" is OPTIONAL — omit when the user is just asking questions.
- Each command must have "type" and at least "domain" (or "subdomain" for subdomain_run).
- For subdomain_run use the "subdomain" key; for all others use "domain".
- "threads" is optional; only include if the user explicitly requested a custom count.
- Only include commands explicitly requested or strongly implied.
- If the domain is unclear, ask the user in "reply" and set autoar_commands to [].
- Never invent domain names.
- If the user says "dry run" or "only explain", set autoar_commands to [].

Example:
User: "do a domain scan and port scan on example.com"
Response:
{"reply":"Sure! Starting a full domain scan and port scan on example.com.","autoar_commands":[{"type":"domain_run","domain":"example.com"},{"type":"ports","domain":"example.com"}]}
`

// ─────────────────────────────────────────────
// Parsed AI response structures
// ─────────────────────────────────────────────

type aiResponse struct {
	Reply          string      `json:"reply"`
	AutoARCommands []aiCmdSpec `json:"autoar_commands"`
}

type aiCmdSpec struct {
	Type      string `json:"type"`
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain"`
	Mode      string `json:"mode"`    // optional, for nuclei
	Threads   int    `json:"threads"` // optional
}

// ─────────────────────────────────────────────
// Main /ai command handler
// ─────────────────────────────────────────────

func handleAIChat(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options

	var userMessage string
	dryRun := false
	agentMode := false

	for _, opt := range options {
		switch opt.Name {
		case "message":
			userMessage = opt.StringValue()
		case "dry_run":
			dryRun = opt.BoolValue()
		case "agent_mode":
			agentMode = opt.BoolValue()
		}
	}

	if strings.TrimSpace(userMessage) == "" {
		respond(s, i, "❌ Please provide a message.", true)
		return
	}

	// Acknowledge immediately to avoid Discord 3-second timeout
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	}); err != nil {
		log.Printf("[AI] Failed to ack interaction: %v", err)
		return
	}

	// ── Agent Mode: full autonomous loop ──────────────────────────────────────
	if agentMode && !dryRun {
		log.Printf("[AI] Agent mode activated for: %s", userMessage)

		// Send an initial message we can edit with progress
		initMsg, _ := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("🤖 **AutoAR AI Agent** — *%s*\n\n⏳ Starting autonomous agent loop…", userMessage),
		})

		var progressLines []string
		progressFn := func(msg string) {
			log.Printf("[AI/AGENT] %s", msg)
			progressLines = append(progressLines, msg)
			if initMsg != nil {
				body := fmt.Sprintf("🤖 **AutoAR AI Agent** — *%s*\n\n%s", userMessage, strings.Join(progressLines, "\n"))
				if len(body) > 2000 {
					body = body[:1990] + "\n…"
				}
				s.FollowupMessageEdit(i.Interaction, initMsg.ID, &discordgo.WebhookEdit{Content: &body})
			}
		}

		result, err := brain.RunAgentLoop(userMessage, progressFn)
		if err != nil {
			s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
				Content: fmt.Sprintf("❌ Agent error: %v", err),
			})
			return
		}

		// Post validated reports the AI flagged as worthy of sending
		for idx, report := range result.Reports {
			title := fmt.Sprintf("🧠 AI Finding #%d", idx+1)
			if len(result.Reports) == 1 {
				title = "🧠 AI Finding"
			}
			if len(report) > 4096 {
				s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
					Content: fmt.Sprintf("**%s** (too large — attached as file)", title),
					Files: []*discordgo.File{
						{Name: fmt.Sprintf("ai-finding-%d.md", idx+1), ContentType: "text/markdown", Reader: strings.NewReader(report)},
					},
				})
			} else {
				embed := &discordgo.MessageEmbed{
					Title:       title,
					Description: report,
					Color:       0xFF6600,
					Footer:      &discordgo.MessageEmbedFooter{Text: "AutoAR AI Agent · Step-3.5 Flash"},
				}
				s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
					Embeds: []*discordgo.MessageEmbed{embed},
				})
			}
		}

		summary := result.Summary
		if summary == "" {
			if len(result.Reports) == 0 {
				summary = "No notable findings."
			} else {
				summary = fmt.Sprintf("%d report(s) generated.", len(result.Reports))
			}
		}
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("✅ **Agent done** — %s", summary),
		})
		return
	}

	// ── Conversational Mode: ChatWithAI + direct module dispatch ──────────────
	channelID := i.ChannelID

	// Get conversation history for this channel
	history := getAIHistory(channelID)

	// If dry_run, append instruction to the message
	effectiveMessage := userMessage
	if dryRun {
		effectiveMessage = userMessage + "\n\n[DRY RUN: only explain what you would do, set autoar_commands to []]"
	}

	// Call AI
	log.Printf("[AI] Sending message to AI for channel %s: %s", channelID, userMessage)
	rawResponse, err := brain.ChatWithAI(history, effectiveMessage, aiSystemPrompt)
	if err != nil {
		sendAIFollowupError(s, i, fmt.Sprintf("AI service error: %v", err))
		return
	}

	// Parse structured AI response; fall back to raw text if JSON is malformed
	parsed, parseErr := parseAIResponse(rawResponse)
	if parseErr != nil {
		log.Printf("[AI] Could not parse AI JSON (%v), surfacing raw text", parseErr)
		parsed = &aiResponse{Reply: rawResponse}
	}

	// Persist conversation turn
	assistantContent := parsed.Reply
	if len(parsed.AutoARCommands) > 0 {
		assistantContent += fmt.Sprintf(" (triggering %d scan(s))", len(parsed.AutoARCommands))
	}
	appendAIHistory(channelID, userMessage, assistantContent)

	// ── Build reply embed ──────────────────────────────────────────────
	replyText := parsed.Reply
	if replyText == "" {
		replyText = "🤖 Got it!"
	}

	// Append queued scan summary to the reply
	if len(parsed.AutoARCommands) > 0 && !dryRun {
		var sb strings.Builder
		sb.WriteString("\n\n**Queued scans:**")
		for _, cmd := range parsed.AutoARCommands {
			target := cmd.Domain
			if cmd.Subdomain != "" {
				target = cmd.Subdomain
			}
			sb.WriteString(fmt.Sprintf("\n• `%s` → `%s`", cmd.Type, target))
		}
		replyText += sb.String()
	}

	embed := &discordgo.MessageEmbed{
		Title:       "🤖 AutoAR AI",
		Description: replyText,
		Color:       0x7289DA,
		Footer:      &discordgo.MessageEmbedFooter{Text: "Powered by Step-3.5 Flash · AutoAR AI Mode"},
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	if _, err := s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
	}); err != nil {
		log.Printf("[AI] Failed to send reply embed: %v", err)
	}

	// ── Dispatch commands ──────────────────────────────────────────────
	if dryRun || len(parsed.AutoARCommands) == 0 {
		return
	}

	for _, cmd := range parsed.AutoARCommands {
		cmd := cmd // capture loop variable
		go func() {
			if err := runAICommand(s, i, cmd); err != nil {
				log.Printf("[AI] Command %s failed: %v", cmd.Type, err)
				s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
					Content: fmt.Sprintf("⚠️ **%s** encountered an error: %v", cmd.Type, err),
				})
			}
		}()
	}
}

// ─────────────────────────────────────────────
// Parse the AI's JSON response
// ─────────────────────────────────────────────

func parseAIResponse(raw string) (*aiResponse, error) {
	// Strip Markdown fences
	clean := strings.TrimSpace(raw)
	for _, fence := range []string{"```json", "```"} {
		if strings.HasPrefix(clean, fence) {
			clean = strings.TrimPrefix(clean, fence)
			clean = strings.TrimSuffix(strings.TrimSpace(clean), "```")
			clean = strings.TrimSpace(clean)
			break
		}
	}

	// Extract outermost JSON object
	start := strings.Index(clean, "{")
	end := strings.LastIndex(clean, "}")
	if start != -1 && end != -1 && end > start {
		clean = clean[start : end+1]
	}

	var resp aiResponse
	if err := json.Unmarshal([]byte(clean), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ─────────────────────────────────────────────
// Execute a single AI-requested scan command
// ─────────────────────────────────────────────

func runAICommand(s *discordgo.Session, i *discordgo.InteractionCreate, cmd aiCmdSpec) error {
	threads := cmd.Threads
	if threads <= 0 {
		threads = 100
	}

	domain := strings.TrimSpace(cmd.Domain)
	subdomain := strings.TrimSpace(cmd.Subdomain)

	// Resolve primary target for display
	target := domain
	if subdomain != "" {
		target = subdomain
	}
	if target == "" {
		return fmt.Errorf("no domain specified for %s", cmd.Type)
	}

	// Notify start
	s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Content: fmt.Sprintf("🚀 Starting **%s** on `%s`…", cmd.Type, target),
	})

	// Create a unique scan ID
	scanID := fmt.Sprintf("%s_%d", cmd.Type, time.Now().Unix())
	var command []string

	// ── Build CLI arguments based on the AI's requested command type ──
	switch cmd.Type {
	case "domain_run":
		if domain == "" {
			return fmt.Errorf("domain_run requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "domain", "run", "-d", domain}

	case "subdomain_run":
		t := domain
		if subdomain != "" {
			t = subdomain
		}
		if t == "" {
			return fmt.Errorf("subdomain_run requires a subdomain or domain field")
		}
		target = t
		command = []string{utils.GetAutoarScriptPath(), "subdomain", "run", "-s", target}

	case "lite_scan", "lite":
		if domain == "" {
			return fmt.Errorf("lite_scan requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "lite", "scan", "-d", domain}

	case "fast_look", "fastlook":
		if domain == "" {
			return fmt.Errorf("fast_look requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "fastlook", "-d", domain}

	case "subdomains":
		if domain == "" {
			return fmt.Errorf("subdomains requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "subdomains", "get", "-d", domain, "-c", strconv.Itoa(threads)}

	case "livehosts":
		if domain == "" {
			return fmt.Errorf("livehosts requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "livehosts", "get", "-d", domain, "-c", strconv.Itoa(threads)}

	case "urls":
		if domain == "" {
			return fmt.Errorf("urls requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "urls", "get", "-d", domain, "-c", strconv.Itoa(threads)}

	case "js_scan", "js":
		if domain == "" {
			return fmt.Errorf("js_scan requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "js", "scan", "-d", domain, "-c", strconv.Itoa(threads)}

	case "tech":
		if domain == "" {
			return fmt.Errorf("tech requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "tech", "detect", "-d", domain, "-c", strconv.Itoa(threads)}

	case "ports":
		if domain == "" {
			return fmt.Errorf("ports requires a domain")
		}
		command = []string{utils.GetAutoarScriptPath(), "ports", "scan", "-d", domain, "-c", strconv.Itoa(threads)}

	case "nuclei":
		if domain == "" {
			return fmt.Errorf("nuclei requires a domain")
		}
		mode := cmd.Mode
		if mode == "" {
			mode = "full"
		}
		command = []string{utils.GetAutoarScriptPath(), "nuclei", "scan", "-d", domain, "-m", mode, "-c", strconv.Itoa(threads)}

	default:
		return fmt.Errorf("unknown scan type: %s", cmd.Type)
	}

	// Handle standard command thread creation and execution
	embed := createScanEmbed(cmd.Type, target, "running in background")
	s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
	})

	threadID := createScanThread(s, i, scanID, cmd.Type, target)
	if threadID != "" {
		log.Printf("[INFO] Created thread %s for AI-triggered scan %s", threadID, scanID)
	}

	// Create database scan record for tracking
	now := time.Now()
	scanRecord := &db.ScanRecord{
		ScanID:      scanID,
		ScanType:    cmd.Type,
		Target:      target,
		Status:      "running",
		ChannelID:   i.ChannelID,
		ThreadID:    threadID,
		TotalPhases: 1, // Basic count, adjust if needed
		StartedAt:   now,
		LastUpdate:  now,
		Command:     strings.Join(command, " "),
	}
	if err := db.CreateScan(scanRecord); err != nil {
		log.Printf("[ERROR] Failed to create scan record in database: %v", err)
	}

	// Execute it in the background just like standard commands do
	go runScanBackground(scanID, cmd.Type, target, command, s, i)

	return nil
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func sendAIFollowupError(s *discordgo.Session, i *discordgo.InteractionCreate, msg string) {
	s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Content: fmt.Sprintf("❌ **AI Error:** %s", msg),
	})
}
