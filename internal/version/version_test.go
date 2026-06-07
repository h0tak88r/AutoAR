package version

import (
	"regexp"
	"testing"
)

// semverRe matches a plain semantic version (no leading "v"), optionally with a
// pre-release/build suffix. Asserting the shape — not a hardcoded value — means
// version bumps don't break CI.
var semverRe = regexp.MustCompile(`^\d+\.\d+\.\d+([-+].+)?$`)

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Fatal("Version should not be empty")
	}
	if !semverRe.MatchString(Version) {
		t.Errorf("Version = %q, want semantic version like 1.2.3", Version)
	}
}
