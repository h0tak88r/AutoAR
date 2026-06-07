package utils

import (
	"os"
	"strconv"
	"testing"
)

func TestUpperKey(t *testing.T) {
	tests := []struct{ input, want string }{
		{"nuclei", "NUCLEI"},
		{"backup", "BACKUP"},
		{"zerodays", "ZERODAYS"},
		{"alreadyUPPER", "ALREADYUPPER"},
		{"mixedCase", "MIXEDCASE"},
		{"", ""},
	}
	for _, tt := range tests {
		got := upperKey(tt.input)
		if got != tt.want {
			t.Errorf("upperKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestLowerKey(t *testing.T) {
	tests := []struct{ input, want string }{
		{"NUCLEI", "nuclei"},
		{"BACKUP", "backup"},
		{"ZERODAYS", "zerodays"},
		{"alreadylower", "alreadylower"},
		{"MixedCase", "mixedcase"},
		{"", ""},
	}
	for _, tt := range tests {
		got := lowerKey(tt.input)
		if got != tt.want {
			t.Errorf("lowerKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGetTimeoutDefaultFallback(t *testing.T) {
	// Reset DB hook
	oldDB := dbGetSetting
	dbGetSetting = nil
	defer func() { dbGetSetting = oldDB }()

	// Ensure env is unset
	os.Unsetenv("AUTOAR_TIMEOUT_UNIQUEKEYTEST")
	defer os.Unsetenv("AUTOAR_TIMEOUT_UNIQUEKEYTEST")

	got := GetTimeout("uniquekeytest", 300)
	if got != 300 {
		t.Errorf("GetTimeout() = %d, want 300 (default)", got)
	}
}

func TestGetTimeoutFromEnvVar(t *testing.T) {
	oldDB := dbGetSetting
	dbGetSetting = nil
	defer func() { dbGetSetting = oldDB }()

	os.Setenv("AUTOAR_TIMEOUT_NUCLEI", "180")
	defer os.Unsetenv("AUTOAR_TIMEOUT_NUCLEI")

	got := GetTimeout("nuclei", 300)
	if got != 180 {
		t.Errorf("GetTimeout() = %d, want 180 (from env)", got)
	}
}

func TestGetTimeoutFromDBHook(t *testing.T) {
	dbGetSetting = func(key string) (string, error) {
		return strconv.Itoa(120), nil
	}
	defer func() { dbGetSetting = nil }()

	os.Unsetenv("AUTOAR_TIMEOUT_DBTEST")
	defer os.Unsetenv("AUTOAR_TIMEOUT_DBTEST")

	got := GetTimeout("dbtest", 300)
	if got != 120 {
		t.Errorf("GetTimeout() = %d, want 120 (from DB)", got)
	}
}

func TestGetTimeoutDBPriorityOverEnv(t *testing.T) {
	dbGetSetting = func(key string) (string, error) {
		return "90", nil
	}
	defer func() { dbGetSetting = nil }()

	os.Setenv("AUTOAR_TIMEOUT_PRIORITY", "60")
	defer os.Unsetenv("AUTOAR_TIMEOUT_PRIORITY")

	// DB takes priority over env
	got := GetTimeout("priority", 300)
	if got != 90 {
		t.Errorf("GetTimeout() = %d, want 90 (DB overrides env)", got)
	}
}

func TestGetTimeoutNegativeIgnored(t *testing.T) {
	dbGetSetting = func(key string) (string, error) {
		return "-1", nil
	}
	defer func() { dbGetSetting = nil }()

	os.Unsetenv("AUTOAR_TIMEOUT_NEGATIVE")
	defer os.Unsetenv("AUTOAR_TIMEOUT_NEGATIVE")

	// Negative DB value falls through to default
	got := GetTimeout("negative", 300)
	if got != 300 {
		t.Errorf("GetTimeout() = %d, want 300 (negative ignored)", got)
	}
}

func TestInitTimeoutDB(t *testing.T) {
	called := false
	fn := func(key string) (string, error) {
		called = true
		return "test", nil
	}
	InitTimeoutDB(fn)
	if dbGetSetting == nil {
		t.Fatal("InitTimeoutDB should wire dbGetSetting")
	}
	_, _ = dbGetSetting("any")
	if !called {
		t.Error("InitTimeoutDB should wire the provided function")
	}
	dbGetSetting = nil
}

func TestGetTimeoutZeroAllowed(t *testing.T) {
	dbGetSetting = func(key string) (string, error) {
		return "0", nil
	}
	defer func() { dbGetSetting = nil }()

	os.Unsetenv("AUTOAR_TIMEOUT_ZERO")
	defer os.Unsetenv("AUTOAR_TIMEOUT_ZERO")

	// Zero is a valid timeout (means unlimited)
	got := GetTimeout("zero", 300)
	if got != 0 {
		t.Errorf("GetTimeout() = %d, want 0 (zero allowed)", got)
	}
}
