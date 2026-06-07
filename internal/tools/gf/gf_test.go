package gflib

import (
	"regexp"
	"testing"
)

func TestLineMatchesEmptyRegexes(t *testing.T) {
	if lineMatches("anything", nil) {
		t.Error("lineMatches() should be false with nil regexes")
	}
	if lineMatches("anything", []*regexp.Regexp{}) {
		t.Error("lineMatches() should be false with empty regexes")
	}
}

func TestLineMatchesNoMatch(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`ERROR`), regexp.MustCompile(`FATAL`)}
	if lineMatches("this is a warning log", regexes) {
		t.Error("lineMatches() should be false when no regex matches")
	}
}

func TestLineMatchesSingleMatch(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`ERROR`)}
	if !lineMatches("this is an ERROR message", regexes) {
		t.Error("lineMatches() should be true when regex matches")
	}
}

func TestLineMatchesFirstRegexMatches(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`ERROR`), regexp.MustCompile(`DEBUG`)}
	if !lineMatches("ERROR: something went wrong", regexes) {
		t.Error("lineMatches() should be true when first regex matches")
	}
}

func TestLineMatchesSecondRegexMatches(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`ERROR`), regexp.MustCompile(`WARNING`)}
	if !lineMatches("WARNING: deprecated usage", regexes) {
		t.Error("lineMatches() should be true when second regex matches")
	}
}

func TestLineMatchesEmptyLine(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`.+`)}
	if !lineMatches("not empty", regexes) {
		t.Error("lineMatches() should be true for non-empty line with .+")
	}
	if lineMatches("", []*regexp.Regexp{regexp.MustCompile(`.+`)}) {
		t.Error("lineMatches() should be false for empty line with .+")
	}
}
