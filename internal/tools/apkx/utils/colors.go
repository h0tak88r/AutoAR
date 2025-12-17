package utils

const (
	ColorEnd     = "\033[0m"
	ColorBlue    = "\033[34m"
	ColorGreen   = "\033[32m"
	ColorRed     = "\033[31m"
	ColorYellow  = "\033[33m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorHeader  = "\033[1;30m"
	ColorWarning = "\033[1;33m"
	ColorBold    = "\033[1m"
	
	// Bright variants
	ColorBrightBlue   = "\033[94m"
	ColorBrightGreen  = "\033[92m"
	ColorBrightYellow = "\033[93m"
)

func Colorize(text string, color string) string {
	return color + text + ColorEnd
}
