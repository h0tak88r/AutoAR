package ffuf

import (
	"io"
	"log"
	"github.com/h0tak88r/AutoAR/internal/logger"
	"strings"
	"sync"
)
// LogFilter suppresses noisy log output
type LogFilter struct {
	w io.Writer
}

func (f *LogFilter) Write(p []byte) (n int, err error) {
	s := string(p)
	// Filter out specific noisy errors
	if strings.Contains(s, "read tcp") && strings.Contains(s, "connection reset by peer") {
		return len(p), nil
	}
	if strings.Contains(s, "context canceled") {
		return len(p), nil
	}
	if strings.Contains(s, "remote error: tls: unrecognized name") {
		return len(p), nil
	}
	if strings.Contains(s, "Client.Timeout exceeded") {
		return len(p), nil
	}
	return f.w.Write(p)
}

var logFilterOnce sync.Once

// setupLogFilter configures the global logger to filter noisy messages
func setupLogFilter() {
	logFilterOnce.Do(func() {
		// Wrap existing writer (stderr by default)
		currentWriter := log.Writer()
		log.SetOutput(&LogFilter{w: currentWriter})
		logger.GetLogger().Infof("[DEBUG] Global log filter installed to silence FFuf noise")
	})
}
