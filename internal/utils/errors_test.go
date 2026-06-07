package utils

import (
	"errors"
	"strings"
	"testing"
)

func TestNewScanError(t *testing.T) {
	underlying := errors.New("connection refused")
	se := NewScanError("subdomain-enum", "example.com", "subfinder", underlying, true, ErrCodeNetwork)

	if se.Phase != "subdomain-enum" {
		t.Errorf("Phase = %q, want %q", se.Phase, "subdomain-enum")
	}
	if se.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", se.Domain, "example.com")
	}
	if se.Tool != "subfinder" {
		t.Errorf("Tool = %q, want %q", se.Tool, "subfinder")
	}
	if se.Err != underlying {
		t.Errorf("Err = %v, want %v", se.Err, underlying)
	}
	if !se.Retryable {
		t.Error("Retryable should be true")
	}
	if se.Code != ErrCodeNetwork {
		t.Errorf("Code = %q, want %q", se.Code, ErrCodeNetwork)
	}
}

func TestScanErrorError(t *testing.T) {
	underlying := errors.New("timeout after 30s")
	se := NewScanError("port-scan", "target.io", "naabu", underlying, true, ErrCodeTimeout)

	msg := se.Error()
	if !strings.Contains(msg, ErrCodeTimeout) {
		t.Errorf("Error() = %q, want it to contain %q", msg, ErrCodeTimeout)
	}
	if !strings.Contains(msg, "port-scan") {
		t.Errorf("Error() = %q, want it to contain %q", msg, "port-scan")
	}
	if !strings.Contains(msg, "target.io") {
		t.Errorf("Error() = %q, want it to contain %q", msg, "target.io")
	}
}

func TestScanErrorUnwrap(t *testing.T) {
	underlying := errors.New("inner error")
	se := NewScanError("phase", "domain", "tool", underlying, false, ErrCodeInternal)

	if !errors.Is(se, underlying) {
		t.Error("errors.Is(se, underlying) should be true")
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"retryable ScanError", NewScanError("p", "d", "t", errors.New("e"), true, ErrCodeNetwork), true},
		{"non-retryable ScanError", NewScanError("p", "d", "t", errors.New("e"), false, ErrCodeInternal), false},
		{"non-ScanError", errors.New("plain error"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRetryable(tt.err); got != tt.want {
				t.Errorf("IsRetryable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserFriendlyError(t *testing.T) {
	underlying := errors.New("underlying")

	tests := []struct {
		name     string
		err      error
		contains string
	}{
		{"timeout", NewScanError("phase", "domain", "tool", underlying, true, ErrCodeTimeout), "timed out"},
		{"network", NewScanError("phase", "domain", "tool", underlying, true, ErrCodeNetwork), "Network error"},
		{"permission", NewScanError("phase", "domain", "tool", underlying, true, ErrCodePermission), "Permission denied"},
		{"not_found", NewScanError("phase", "domain", "tool", underlying, true, ErrCodeNotFound), "not found"},
		{"invalid_input", NewScanError("phase", "domain", "tool", underlying, true, ErrCodeInvalidInput), "Invalid input"},
		{"rate_limit", NewScanError("phase", "domain", "tool", underlying, true, ErrCodeRateLimit), "Rate limit"},
		{"unknown_code", NewScanError("phase", "domain", "tool", underlying, false, "CUSTOM"), "Error during"},
		{"non_scan_error", errors.New("bare error"), "An error occurred"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := GetUserFriendlyError(tt.err)
			if !strings.Contains(msg, tt.contains) {
				t.Errorf("GetUserFriendlyError() = %q, want to contain %q", msg, tt.contains)
			}
		})
	}
}

func TestErrorCodeConstants(t *testing.T) {
	codes := []string{ErrCodeTimeout, ErrCodeNetwork, ErrCodePermission, ErrCodeNotFound, ErrCodeInvalidInput, ErrCodeInternal, ErrCodeRateLimit}
	seen := make(map[string]bool)
	for _, c := range codes {
		if c == "" {
			t.Error("error code should not be empty")
		}
		if seen[c] {
			t.Errorf("duplicate error code: %q", c)
		}
		seen[c] = true
	}
}
