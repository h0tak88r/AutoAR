package asr

import (
	"testing"
)

func TestDeduplicateEmpty(t *testing.T) {
	got := deduplicate(nil)
	if len(got) != 0 {
		t.Errorf("deduplicate(nil) len = %d, want 0", len(got))
	}
	got = deduplicate([]string{})
	if len(got) != 0 {
		t.Errorf("deduplicate([]) len = %d, want 0", len(got))
	}
}

func TestDeduplicateNoDupes(t *testing.T) {
	in := []string{"a", "b", "c"}
	got := deduplicate(in)
	if len(got) != 3 {
		t.Fatalf("deduplicate() len = %d, want 3", len(got))
	}
	for i, v := range []string{"a", "b", "c"} {
		if got[i] != v {
			t.Errorf("deduplicate()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestDeduplicateWithDupes(t *testing.T) {
	in := []string{"x", "y", "x", "z", "y"}
	got := deduplicate(in)
	want := []string{"x", "y", "z"}
	if len(got) != len(want) {
		t.Fatalf("deduplicate() len = %d, want %d: %v", len(got), len(want), got)
	}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("deduplicate()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestDeduplicateAllSame(t *testing.T) {
	in := []string{"a", "a", "a", "a"}
	got := deduplicate(in)
	if len(got) != 1 || got[0] != "a" {
		t.Errorf("deduplicate() = %v, want [a]", got)
	}
}

func TestDeduplicatePreservesOrder(t *testing.T) {
	in := []string{"z", "a", "m", "a", "z", "b"}
	got := deduplicate(in)
	want := []string{"z", "a", "m", "b"}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("deduplicate()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

func TestDeduplicateSingleElement(t *testing.T) {
	in := []string{"only"}
	got := deduplicate(in)
	if len(got) != 1 || got[0] != "only" {
		t.Errorf("deduplicate() = %v, want [only]", got)
	}
}
