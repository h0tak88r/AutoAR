package gflib

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// simplePatterns defines lightweight regexes inspired by common gf patterns.
// These are not 1:1 replacements for the original gf JSON patterns but
// provide similar filtering capability without requiring the gf binary.
var simplePatterns = map[string][]*regexp.Regexp{
	"debug_logic": mustCompileMany(
		`(?i)debug=1`,
		`(?i)env=dev`,
		`(?i)stage=testing`,
	),
	"idor": mustCompileMany(
		`(?i)(user|account|profile)_?id=\d+`,
		`(?i)(uid|id)=\d+`,
	),
	"iext": mustCompileMany(
		`(?i)\.(bak|old|backup|cfg|conf)(?:$|[&#?])`,
	),
	"img-traversal": mustCompileMany(
		`(?i)\.(png|jpg|jpeg|gif|svg)(?:\?.*)?`,
		`(?i)\.\./`,
	),
	"iparams": mustCompileMany(
		`(?i)(ip|host|hostname|server)=`,
	),
	"isubs": mustCompileMany(
		`(?i)(subdomain|tenant|org|workspace)=`,
	),
	"jsvar": mustCompileMany(
		`(?i)var\s+[a-zA-Z0-9_]+\s*=`,
		`(?i)const\s+[a-zA-Z0-9_]+\s*=`,
	),
	"lfi": mustCompileMany(
		`(?i)(file|path|page)=\.\./`,
		`(?i)(file|path|page)=/etc/passwd`,
	),
	"rce": mustCompileMany(
		`(?i)(cmd|exec|execute|command)=`,
		`(?i)(system|passthru|shell_exec)`,
	),
	"redirect": mustCompileMany(
		`(?i)(redirect|url|next|return|r)=https?://`,
		`(?i)(redirect|url|next|return|r)=//`,
	),
	"sqli": mustCompileMany(
		`(?i)(union[+\s]+select)`,
		`(?i)or[+\s]+1=1`,
		`(?i)sleep\s*\(\s*\d+\s*\)`,
	),
	"ssrf": mustCompileMany(
		`(?i)(url|target|dest|redirect)=https?://`,
		`(?i)metadata.google.internal`,
	),
	"ssti": mustCompileMany(
		`\{\{.*\}\}`,
		`\$\{.*\}`,
	),
	"xss": mustCompileMany(
		`(?i)<script[^>]*>`,
		`(?i)onerror=`,
		`(?i)onload=`,
		`(?i)javascript:`,
	),
}

// ScanFile applies the named pattern to all lines in the given file and
// returns the subset of lines that match.
func ScanFile(path string, patternName string) ([]string, error) {
	regexes, ok := simplePatterns[patternName]
	if !ok {
		return nil, fmt.Errorf("unknown gf pattern: %s", patternName)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var matches []string
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if lineMatches(trimmed, regexes) {
			matches = append(matches, trimmed)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

func lineMatches(line string, regexes []*regexp.Regexp) bool {
	for _, re := range regexes {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

func mustCompileMany(exprs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(exprs))
	for _, e := range exprs {
		out = append(out, regexp.MustCompile(e))
	}
	return out
}
