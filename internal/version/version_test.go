package version

import "testing"

func TestVersion(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if Version != "4.2.0" {
		t.Errorf("Version = %q, want %q", Version, "4.2.0")
	}
}
