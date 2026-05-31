package utils

import "fmt"

// ScanError is the standard error type for AutoAR scan phases.
// It captures which phase and tool produced the error, whether it can be
// retried, and a short machine-readable code for structured handling.
type ScanError struct {
	Phase     string // e.g. "subdomain-enum"
	Domain    string // target domain
	Tool      string // tool that failed
	Err       error  // underlying error
	Retryable bool   // true if the caller may retry
	Code      string // one of the ErrCode* constants
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("[%s] %s failed for %s: %v", e.Code, e.Phase, e.Domain, e.Err)
}

func (e *ScanError) Unwrap() error {
	return e.Err
}

// Common error codes used in [ScanError.Code].
const (
	ErrCodeTimeout      = "TIMEOUT"       // operation exceeded its time limit
	ErrCodeNetwork      = "NETWORK"       // network connectivity problem
	ErrCodePermission   = "PERMISSION"    // API key or filesystem permission denied
	ErrCodeNotFound     = "NOT_FOUND"     // target or resource does not exist
	ErrCodeInvalidInput = "INVALID_INPUT" // caller supplied bad parameters
	ErrCodeInternal     = "INTERNAL"      // unexpected internal error
	ErrCodeRateLimit    = "RATE_LIMIT"    // external rate limit hit
)

// NewScanError constructs a [ScanError] with all context fields populated.
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

// IsRetryable reports whether err is a [ScanError] with Retryable set.
func IsRetryable(err error) bool {
	if scanErr, ok := err.(*ScanError); ok {
		return scanErr.Retryable
	}
	return false
}

// GetUserFriendlyError converts a [ScanError] into a markdown-formatted,
// human-readable message suitable for Discord or dashboard display.
// Non-ScanError values fall back to a generic message.
func GetUserFriendlyError(err error) string {
	if scanErr, ok := err.(*ScanError); ok {
		switch scanErr.Code {
		case ErrCodeTimeout:
			return fmt.Sprintf("**%s** timed out. The target may be slow or unreachable.", scanErr.Phase)
		case ErrCodeNetwork:
			return fmt.Sprintf("Network error during **%s**. Please check your connection.", scanErr.Phase)
		case ErrCodePermission:
			return fmt.Sprintf("Permission denied during **%s**. Check API keys or credentials.", scanErr.Phase)
		case ErrCodeNotFound:
			return fmt.Sprintf("**%s** not found. The target may not exist.", scanErr.Domain)
		case ErrCodeInvalidInput:
			return fmt.Sprintf("Invalid input for **%s**. Please check your parameters.", scanErr.Phase)
		case ErrCodeRateLimit:
			return fmt.Sprintf("Rate limit hit during **%s**. Slowing down...", scanErr.Phase)
		default:
			return fmt.Sprintf("Error during **%s**: %v", scanErr.Phase, scanErr.Err)
		}
	}

	return fmt.Sprintf("An error occurred: %v", err)
}
