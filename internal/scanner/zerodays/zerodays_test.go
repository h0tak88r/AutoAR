package zerodays

import (
	"testing"
)

func TestContainsEmpty(t *testing.T) {
	if contains(nil, "x") {
		t.Error("contains(nil) should be false")
	}
	if contains([]string{}, "x") {
		t.Error("contains(empty) should be false")
	}
}

func TestContainsFound(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if !contains(slice, "b") {
		t.Error("contains(a,b,c, b) should be true")
	}
}

func TestContainsFirst(t *testing.T) {
	slice := []string{"x", "y", "z"}
	if !contains(slice, "x") {
		t.Error("contains(x,y,z, x) should be true for first element")
	}
}

func TestContainsLast(t *testing.T) {
	slice := []string{"x", "y", "z"}
	if !contains(slice, "z") {
		t.Error("contains(x,y,z, z) should be true for last element")
	}
}

func TestContainsNotFound(t *testing.T) {
	slice := []string{"a", "b", "c"}
	if contains(slice, "d") {
		t.Error("contains(a,b,c, d) should be false")
	}
}

func TestContainsExact(t *testing.T) {
	slice := []string{"abc", "def"}
	if contains(slice, "ab") {
		t.Error("contains(abc,def, ab) should be false (exact match only)")
	}
	if !contains(slice, "abc") {
		t.Error("contains(abc,def, abc) should be true")
	}
}
