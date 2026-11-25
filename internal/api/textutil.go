package api

// clipText truncates s to at most n bytes, appending a truncation marker.
// Shared text helper used across the API (kept build-tag-free).
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n…[truncated]"
}
