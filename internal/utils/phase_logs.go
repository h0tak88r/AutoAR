package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// phaseLogEntry is a single captured log line.
type phaseLogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// phaseLogBuffer holds entries for one (scanID + phaseKey) combination.
type phaseLogBuffer struct {
	mu      sync.RWMutex
	entries []phaseLogEntry
}

// phaseLogHook is a global logrus hook that routes entries to the right
// per-phase buffer based on the current goroutine's scanID + phaseKey.
type phaseLogHook struct {
	mu      sync.RWMutex
	buffers map[string]*phaseLogBuffer // key = "scanID:phaseKey"
	hookRef logrus.Hook
}

var (
	globalPhaseLogHook = &phaseLogHook{
		buffers: make(map[string]*phaseLogBuffer),
	}
	phaseLogHookOnce sync.Once
)

// Levels returns all log levels.
func (h *phaseLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// Fire captures the log entry if the current goroutine is running inside
// a tracked phase.
func (h *phaseLogHook) Fire(entry *logrus.Entry) error {
	scanID := GetCurrentScanID()
	phaseKey := GetCurrentPhaseKey()
	if scanID == "" || phaseKey == "" {
		return nil
	}

	key := scanID + ":" + phaseKey

	h.mu.RLock()
	buf, ok := h.buffers[key]
	h.mu.RUnlock()
	if !ok {
		h.mu.Lock()
		buf, ok = h.buffers[key]
		if !ok {
			buf = &phaseLogBuffer{entries: make([]phaseLogEntry, 0, 128)}
			h.buffers[key] = buf
		}
		h.mu.Unlock()
	}

	fields := make(map[string]interface{}, len(entry.Data))
	for k, v := range entry.Data {
		fields[k] = v
	}

	buf.mu.Lock()
	buf.entries = append(buf.entries, phaseLogEntry{
		Timestamp: entry.Time,
		Level:     entry.Level.String(),
		Message:   entry.Message,
		Fields:    fields,
	})
	buf.mu.Unlock()
	return nil
}

// RegisterPhaseLogHook installs the global phase log hook on logrus.
func RegisterPhaseLogHook() {
	phaseLogHookOnce.Do(func() {
		logger := GetLogger()
		if logger != nil {
			logger.AddHook(globalPhaseLogHook)
		}
	})
}

// StartPhaseLogCapture ensures the hook is registered and returns a flush func.
func StartPhaseLogCapture(scanID, phaseKey string) func() {
	RegisterPhaseLogHook()
	return func() {
		_ = FlushPhaseLogBuffer(scanID, phaseKey)
	}
}

// FlushPhaseLogBuffer writes captured logs for a scanID+phaseKey to disk
// and clears the in-memory buffer.
func FlushPhaseLogBuffer(scanID, phaseKey string) error {
	key := scanID + ":" + phaseKey

	globalPhaseLogHook.mu.Lock()
	buf, ok := globalPhaseLogHook.buffers[key]
	if ok {
		delete(globalPhaseLogHook.buffers, key)
	}
	globalPhaseLogHook.mu.Unlock()

	if !ok || buf == nil {
		return nil
	}

	buf.mu.RLock()
	entries := make([]phaseLogEntry, len(buf.entries))
	copy(entries, buf.entries)
	buf.mu.RUnlock()

	if len(entries) == 0 {
		return nil
	}

	logDir := filepath.Join(GetScanResultsDir(scanID), "phase-logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return err
	}

	filename := sanitizePhaseKey(phaseKey) + ".jsonl"
	path := filepath.Join(logDir, filename)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// ReadPhaseLogBuffer returns the current in-memory entries for a phase
// without flushing or deleting the buffer.
func ReadPhaseLogBuffer(scanID, phaseKey string) []phaseLogEntry {
	key := scanID + ":" + phaseKey
	globalPhaseLogHook.mu.RLock()
	buf, ok := globalPhaseLogHook.buffers[key]
	globalPhaseLogHook.mu.RUnlock()
	if !ok || buf == nil {
		return nil
	}
	buf.mu.RLock()
	defer buf.mu.RUnlock()
	out := make([]phaseLogEntry, len(buf.entries))
	copy(out, buf.entries)
	return out
}

// ReadPhaseLogFile reads the persisted JSONL log file for a scan+phase.
func ReadPhaseLogFile(scanID, phaseKey string) ([]phaseLogEntry, error) {
	logDir := filepath.Join(GetScanResultsDir(scanID), "phase-logs")
	filename := sanitizePhaseKey(phaseKey) + ".jsonl"
	path := filepath.Join(logDir, filename)

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []phaseLogEntry
	dec := json.NewDecoder(f)
	for {
		var e phaseLogEntry
		if err := dec.Decode(&e); err != nil {
			if err.Error() == "EOF" {
				break
			}
			// Continue reading remaining lines even if one is malformed.
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

var sanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizePhaseKey(key string) string {
	s := strings.ToLower(strings.TrimSpace(key))
	s = sanitizeRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return "unknown"
	}
	return s
}
