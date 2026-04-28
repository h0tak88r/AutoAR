package utils

import "fmt"

// ScanError represents a scan-related error with context
type ScanError struct {
	Phase     string
	Domain    string
	Tool      string
	Err       error
	Retryable bool
	Code      string
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("[%s] %s failed for %s: %v", e.Code, e.Phase, e.Domain, e.Err)
}

func (e *ScanError) Unwrap() error {
	return e.Err
}

// Common error codes
const (
	ErrCodeTimeout      = "TIMEOUT"
	ErrCodeNetwork      = "NETWORK"
	ErrCodePermission   = "PERMISSION"
	ErrCodeNotFound     = "NOT_FOUND"
	ErrCodeInvalidInput = "INVALID_INPUT"
	ErrCodeInternal     = "INTERNAL"
	ErrCodeRateLimit    = "RATE_LIMIT"
)

// NewScanError creates a new scan error
func NewScanError(phase, domain, tool string, err error, retryable bool, code string) *ScanError {
	return &ScanError{
		Phase:     phase,
		Domain:    domain,
		Tool:      tool,
		Err:       err,
		Retryable: retryable,
		Code:      code,
	}
}

// IsRetryable checks if error is retryable
func IsRetryable(err error) bool {
	if scanErr, ok := err.(*ScanError); ok {
		return scanErr.Retryable
	}
	return false
}

// GetUserFriendlyError converts technical error to user-friendly message
func GetUserFriendlyError(err error) string {
	if scanErr, ok := err.(*ScanError); ok {
		switch scanErr.Code {
		case ErrCodeTimeout:
			return fmt.Sprintf("⏱️ **%s** timed out. The target may be slow or unreachable.", scanErr.Phase)
		case ErrCodeNetwork:
			return fmt.Sprintf("🌐 Network error during **%s**. Please check your connection.", scanErr.Phase)
		case ErrCodePermission:
			return fmt.Sprintf("🔒 Permission denied during **%s**. Check API keys or credentials.", scanErr.Phase)
		case ErrCodeNotFound:
			return fmt.Sprintf("❓ **%s** not found. The target may not exist.", scanErr.Domain)
		case ErrCodeInvalidInput:
			return fmt.Sprintf("⚠️ Invalid input for **%s**. Please check your parameters.", scanErr.Phase)
		case ErrCodeRateLimit:
			return fmt.Sprintf("🚦 Rate limit hit during **%s**. Slowing down...", scanErr.Phase)
		default:
			return fmt.Sprintf("❌ Error during **%s**: %v", scanErr.Phase, scanErr.Err)
		}
	}
	
	return fmt.Sprintf("❌ An error occurred: %v", err)
}
