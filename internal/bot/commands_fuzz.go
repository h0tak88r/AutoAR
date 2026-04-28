package bot

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

// handleFuzz handles the /fuzz Discord slash command.
// Accepts either a single host string or a file attachment with multiple hosts (one per line).
// Runs ffuf against the provided host(s) using the autoar script.
func handleFuzz(s *discordgo.Session, i *discordgo.InteractionCreate) {
	data := i.ApplicationCommandData()

	host := ""
	wordlist := ""
	extensions := ""
	threads := 50
	rateLimit := 0
	matchCodes := "200,204,301,302,307,401,403,405,500"
	filterSize := ""
	recursive := false
	var filePath string

	// Check for file attachment first
	if data.Resolved != nil && data.Resolved.Attachments != nil {
		for _, opt := range data.Options {
			if opt.Type == discordgo.ApplicationCommandOptionAttachment {
				if attID, ok := opt.Value.(string); ok {
					if att, ok := data.Resolved.Attachments[attID]; ok && att != nil {
						tmpFile, err := os.CreateTemp("", "fuzz-hosts-*.txt")
						if err != nil {
							respond(s, i, fmt.Sprintf("❌ Failed to create temp file: %v", err), true)
							return
						}
						defer tmpFile.Close()

						resp, err := http.Get(att.URL)
						if err != nil {
							respond(s, i, fmt.Sprintf("❌ Failed to download attachment: %v", err), true)
							return
						}
						defer resp.Body.Close()

						if _, err := io.Copy(tmpFile, resp.Body); err != nil {
							respond(s, i, fmt.Sprintf("❌ Failed to save attachment: %v", err), true)
							return
						}
						tmpFile.Close()
						filePath = tmpFile.Name()
					}
				}
			}
		}
	}

	// Parse other options
	for _, opt := range data.Options {
		switch opt.Name {
		case "host":
			host = strings.TrimSpace(opt.StringValue())
		case "wordlist":
			wordlist = opt.StringValue()
		case "extensions":
			extensions = opt.StringValue()
		case "threads":
			threads = int(opt.IntValue())
		case "rate_limit":
			rateLimit = int(opt.IntValue())
		case "match_codes":
			matchCodes = opt.StringValue()
		case "filter_size":
			filterSize = opt.StringValue()
		case "recursive":
			recursive = opt.BoolValue()
		}
	}

	if host == "" && filePath == "" {
		respond(s, i, "❌ Either a `host` or a file attachment with hosts is required.", false)
		return
	}
	if host != "" && filePath != "" {
		respond(s, i, "❌ Cannot use both `host` and file attachment at the same time. Please choose one.", false)
		return
	}

	// Resolve wordlist path
	root := getRootDir()
	wordlistPath := filepath.Join(root, "Wordlists", "quick_fuzz.txt") // default
	switch wordlist {
	case "large":
		wordlistPath = filepath.Join(root, "Wordlists", "directory-list-2.3-big.txt")
	case "medium":
		wordlistPath = filepath.Join(root, "Wordlists", "directory-list-2.3-medium.txt")
	case "small":
		wordlistPath = filepath.Join(root, "Wordlists", "directory-list-2.3-small.txt")
	case "api":
		wordlistPath = filepath.Join(root, "Wordlists", "api_wordlist.txt")
	case "":
		// keep default quick_fuzz.txt
	default:
		wordlistPath = wordlist // allow custom path
	}

	// Build command
	var command []string
	scanTarget := host

	if filePath != "" {
		// Multi-host mode: run ffuf for all hosts in the file
		command = []string{utils.GetAutoarScriptPath(), "fuzz", "file", "-f", filePath, "-w", wordlistPath}
		scanTarget = filePath
	} else {
		// Single host mode
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "https://" + host
		}
		command = []string{utils.GetAutoarScriptPath(), "fuzz", "host", "-u", host + "/FUZZ", "-w", wordlistPath}
		scanTarget = host
	}

	// Common ffuf flags
	command = append(command, "-t", fmt.Sprintf("%d", threads))
	command = append(command, "-mc", matchCodes)

	if extensions != "" {
		command = append(command, "-e", extensions)
	}
	if rateLimit > 0 {
		command = append(command, "-rate", fmt.Sprintf("%d", rateLimit))
	}
	if filterSize != "" {
		command = append(command, "-fs", filterSize)
	}
	if recursive {
		command = append(command, "-recursion")
	}

	// Build description for the embed
	targetDisplay := scanTarget
	mode := "Single Host"
	if filePath != "" {
		mode = "Multi-Host File"
		targetDisplay = "Uploaded hosts file"
	}

	embed := &discordgo.MessageEmbed{
		Title: "🔍 Directory Fuzzing",
		Description: fmt.Sprintf(
			"**Mode:** %s\n**Target:** `%s`\n**Wordlist:** `%s`\n**Threads:** %d\n**Match Codes:** %s",
			mode, targetDisplay, filepath.Base(wordlistPath), threads, matchCodes,
		),
		Color: 0xe67e22,
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Status", Value: "🟡 Running ffuf...", Inline: false},
		},
	}

	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Embeds: []*discordgo.MessageEmbed{embed},
		},
	})

	scanID := fmt.Sprintf("fuzz_%d", time.Now().Unix())
	go runScanBackground(scanID, "fuzz", scanTarget, command, s, i)
}
