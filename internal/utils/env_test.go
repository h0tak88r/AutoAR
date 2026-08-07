package utils

import (
	"os"
	"testing"
)

func TestGetEnv(t *testing.T) {
	const testKey = "AUTOAR_TEST_ENV_VAR_12345"
	const fallback = "fallback_value"

	// Ensure the key is not set before testing
	os.Unsetenv(testKey)

	if got := GetEnv(testKey, fallback); got != fallback {
		t.Errorf("GetEnv(unset, %q) = %q, want %q", fallback, got, fallback)
	}

	os.Setenv(testKey, "custom_value")
	defer os.Unsetenv(testKey)

	if got := GetEnv(testKey, fallback); got != "custom_value" {
		t.Errorf("GetEnv(set, %q) = %q, want %q", fallback, got, "custom_value")
	}

	// Empty string in env should fall back
	os.Setenv(testKey, "")
	if got := GetEnv(testKey, fallback); got != fallback {
		t.Errorf("GetEnv(empty, %q) = %q, want %q", fallback, got, fallback)
	}
}

func TestParseKeyList(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", "", nil},
		{"single", "key1", []string{"key1"}},
		{"comma separated", "key1,key2,key3", []string{"key1", "key2", "key3"}},
		{"newline separated", "key1\nkey2\nkey3", []string{"key1", "key2", "key3"}},
		{"mixed separators", "key1, key2\nkey3;key4 key5", []string{"key1", "key2", "key3", "key4", "key5"}},
		{"dedupes", "key1,key1,key2", []string{"key1", "key2"}},
		{"strips quotes", `"key1", 'key2'`, []string{"key1", "key2"}},
		{"ignores empties", "key1,, ,key2", []string{"key1", "key2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseKeyList(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseKeyList(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ParseKeyList(%q) = %v, want %v", tc.raw, got, tc.want)
				}
			}
		})
	}
}
