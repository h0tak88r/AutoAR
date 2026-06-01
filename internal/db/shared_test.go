package db

import (
	"testing"
)

func TestMarshalPhaseJSON(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect string
	}{
		{name: "nil slice", input: nil, expect: "[]"},
		{name: "empty slice", input: []string{}, expect: "[]"},
		{name: "single element", input: []string{"subfinder"}, expect: `["subfinder"]`},
		{name: "multiple elements", input: []string{"subfinder", "dnsx", "httpx"}, expect: `["subfinder","dnsx","httpx"]`},
		{name: "element with special chars", input: []string{`a"b`}, expect: `["a\"b"]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := marshalPhaseJSON(tt.input)
			if got != tt.expect {
				t.Errorf("marshalPhaseJSON(%v) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestUnmarshalPhaseJSON(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected []string
	}{
		{name: "empty string", raw: "", expected: nil},
		{name: "empty array", raw: "[]", expected: nil},
		{name: "single element", raw: `["subfinder"]`, expected: []string{"subfinder"}},
		{name: "multiple elements", raw: `["subfinder","dnsx","httpx"]`, expected: []string{"subfinder", "dnsx", "httpx"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			unmarshalPhaseJSON(tt.raw, &got)

			if tt.expected == nil {
				if len(got) != 0 {
					t.Errorf("unmarshalPhaseJSON(%q) = %v, want nil/empty", tt.raw, got)
				}
				return
			}

			if len(got) != len(tt.expected) {
				t.Errorf("unmarshalPhaseJSON(%q) len = %d, want %d", tt.raw, len(got), len(tt.expected))
				return
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("unmarshalPhaseJSON(%q)[%d] = %q, want %q", tt.raw, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestUnmarshalPhaseJSONInvalidJSON(t *testing.T) {
	var target []string
	// Should not panic on invalid JSON; just leaves target unchanged
	unmarshalPhaseJSON(`{bad`, &target)
	if len(target) != 0 {
		t.Errorf("expected empty target after invalid JSON, got %v", target)
	}
}
