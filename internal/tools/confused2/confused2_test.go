package confused2

import (
	"testing"
)

func TestFilterVulnerableEmpty(t *testing.T) {
	got := filterVulnerable(nil)
	if got != nil {
		t.Errorf("filterVulnerable(nil) = %v, want nil", got)
	}
}

func TestFilterVulnerableAllFalsePositives(t *testing.T) {
	in := []string{"main", "test", "."}
	got := filterVulnerable(in)
	if len(got) != 0 {
		t.Errorf("filterVulnerable() = %v, want empty (all false positives)", got)
	}
}

func TestFilterVulnerableValidOnly(t *testing.T) {
	in := []string{"github.com/pkg/errors", "golang.org/x/net", "example.com/lib"}
	got := filterVulnerable(in)
	if len(got) != 3 {
		t.Errorf("filterVulnerable() len = %d, want 3: %v", len(got), got)
	}
}

func TestFilterVulnerableMixed(t *testing.T) {
	in := []string{"main", "github.com/pkg/errors", "test", "golang.org/x/net", "."}
	got := filterVulnerable(in)
	if len(got) != 2 {
		t.Errorf("filterVulnerable() len = %d, want 2: %v", len(got), got)
	}
	want := []string{"github.com/pkg/errors", "golang.org/x/net"}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("filterVulnerable()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestFilterVulnerableCaseInsensitive(t *testing.T) {
	in := []string{"MAIN", "Test", "Github.Com/Pkg/Errors"}
	got := filterVulnerable(in)
	// MAIN and Test are false positives (case-insensitive), but Github.Com/Pkg/Errors is not
	if len(got) != 1 || got[0] != "Github.Com/Pkg/Errors" {
		t.Errorf("filterVulnerable() = %v, want [Github.Com/Pkg/Errors]", got)
	}
}

func TestFilterVulnerableTrimsWhitespace(t *testing.T) {
	in := []string{" main ", "github.com/pkg/errors"}
	got := filterVulnerable(in)
	if len(got) != 1 {
		t.Errorf("filterVulnerable() len = %d, want 1: %v", len(got), got)
	}
	if got[0] != "github.com/pkg/errors" {
		t.Errorf("filterVulnerable()[0] = %q, want %q", got[0], "github.com/pkg/errors")
	}
}
