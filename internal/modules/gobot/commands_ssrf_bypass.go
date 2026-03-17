package gobot

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/bwmarrin/discordgo"
)

// handleSSRFBypass handles the /ssrf_bypass Discord command.
// It reads the bundled URL-validation-bypass.txt wordlist, replaces placeholder
// domains with the user-supplied attacker and victim domains, and returns the
// result as a .txt file attachment ready for Burp Suite Intruder.
func handleSSRFBypass(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options

	var attacker, victim, scheme string
	scheme = "https" // default

	for _, opt := range options {
		switch opt.Name {
		case "attacker":
			attacker = strings.TrimSpace(opt.StringValue())
		case "victim":
			victim = strings.TrimSpace(opt.StringValue())
		case "scheme":
			scheme = opt.StringValue()
		}
	}

	// Strip any trailing slashes/spaces from domains
	attacker = strings.TrimRight(attacker, "/")
	victim = strings.TrimRight(victim, "/")

	if attacker == "" || victim == "" {
		respond(s, i, "❌ Both `attacker` and `victim` domain are required.", true)
		return
	}

	// Acknowledge immediately (Discord 3-second timeout)
	if err := s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseDeferredChannelMessageWithSource,
	}); err != nil {
		log.Printf("[ERROR] ssrf_bypass: failed to acknowledge interaction: %v", err)
		return
	}

	// Locate the wordlist
	wordlistPath := filepath.Join(getRootDir(), "Wordlists", "vulns", "URL-validation-bypass.txt")
	rawBytes, err := os.ReadFile(wordlistPath)
	if err != nil {
		s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
			Content: fmt.Sprintf("❌ Could not read wordlist: `%v`\nExpected path: `%s`", err, wordlistPath),
		})
		return
	}

	content := string(rawBytes)

	// ------------------------------------------------------------------
	// Replace both sets of placeholder domains used in the wordlist:
	//   Section 1 (URL-encoded payloads):  web-attacker.com / example.com
	//   Section 2 (plain payloads):        me.com / target.com
	// ------------------------------------------------------------------
	replacements := []struct{ old, new string }{
		{"web-attacker.com", attacker},
		{"example.com", victim},
		{"me.com", attacker},
		{"target.com", victim},
		// Also replace occurrences that appear in full URLs with http/https
	}
	for _, r := range replacements {
		content = strings.ReplaceAll(content, r.old, r.new)
	}

	// Optionally prepend scheme to lines that don't already have one
	var lines []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if scheme != "none" {
			// Only prepend if the line doesn't already start with a scheme
			lower := strings.ToLower(trimmed)
			hasScheme := strings.HasPrefix(lower, "http://") ||
				strings.HasPrefix(lower, "https://") ||
				strings.HasPrefix(lower, "//") ||
				strings.HasPrefix(lower, "0://") ||
				strings.HasPrefix(lower, "%")
			if !hasScheme {
				trimmed = scheme + "://" + trimmed
			}
		}
		lines = append(lines, trimmed)
	}

	output := strings.Join(lines, "\n")
	totalPayloads := len(lines)

	// Build summary embed
	embed := &discordgo.MessageEmbed{
		Title: "🔀 SSRF / Open Redirect Bypass Wordlist",
		Description: fmt.Sprintf(
			"Generated **%d payloads** ready for Burp Suite Intruder.\n\n"+
				"**Attacker domain:** `%s`\n"+
				"**Victim domain:** `%s`\n"+
				"**Scheme:** `%s`\n\n"+
				"💡 Load the attached file into Intruder → Payloads → Payload Options",
			totalPayloads, attacker, victim, scheme,
		),
		Color: 0x7b2d8b, // Purple – fitting for URL tricks
		Footer: &discordgo.MessageEmbedFooter{
			Text: "Source: PortSwigger URL Validation Bypass Cheat Sheet",
		},
	}

	fileName := fmt.Sprintf("ssrf-bypass-%s.txt", victim)

	_, err = s.FollowupMessageCreate(i.Interaction, false, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{embed},
		Files: []*discordgo.File{
			{
				Name:        fileName,
				ContentType: "text/plain",
				Reader:      strings.NewReader(output),
			},
		},
	})
	if err != nil {
		log.Printf("[ERROR] ssrf_bypass: failed to send followup: %v", err)
	}

	log.Printf("[ + ] ssrf_bypass: generated %d payloads for attacker=%s victim=%s scheme=%s",
		totalPayloads, attacker, victim, scheme)
}
