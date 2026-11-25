package utils

import "strings"

// discordEscaper backslash-escapes Discord markdown so untrusted text (feed
// titles, repo descriptions, program names, scope strings, template names)
// renders literally: no masked links like [nvd.nist.gov](https://evil), no
// fake code blocks or headings.
var discordEscaper = strings.NewReplacer(
	`\`, `\\`,
	"`", "\\`",
	"*", `\*`,
	"_", `\_`,
	"~", `\~`,
	"|", `\|`,
	">", `\>`,
	"#", `\#`,
	"[", `\[`,
	"]", `\]`,
	"(", `\(`,
	")", `\)`,
	"<", `\<`,
)

// DiscordEscape makes untrusted text safe to embed in a Discord message: it
// escapes markdown and defuses @mentions (@everyone, @here, <@id>) by putting a
// zero-width space after every '@'. Payloads should ALSO set
// allowed_mentions {"parse": []} — this is the belt to that braces.
func DiscordEscape(s string) string {
	s = discordEscaper.Replace(s)
	return strings.ReplaceAll(s, "@", "@​")
}

// DiscordEscapeTrunc escapes s and caps the raw input at n runes first, so one
// hostile field can't push a message past Discord's 2000-char limit.
func DiscordEscapeTrunc(s string, n int) string {
	if r := []rune(s); n > 0 && len(r) > n {
		s = string(r[:n]) + "…"
	}
	return DiscordEscape(s)
}
