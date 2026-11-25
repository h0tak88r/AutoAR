package bbcatalog

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// childEnv marks a disposable child so it can never spawn another one.
const childEnv = "AUTOAR_DISPOSABLE_CHILD"

// childTailBytes bounds how much child output the parent keeps: the reason a
// bbscope child died (log.Fatal) is its LAST line, and a 45-minute sync must
// not buffer its whole log in the API process.
const childTailBytes = 4096

// RunChild runs `<this binary> args... --out <tmpfile>` as a DISPOSABLE CHILD
// PROCESS and returns what the child wrote to --out plus the tail of its
// combined stdout/stderr.
//
// Anything that loads bbscope must go through here: bbscope calls log.Fatal
// (os.Exit) on HTTP errors, stale-token 401s and rate limits, and indexes
// upstream strings unchecked — in the API process that kills every running
// scan with it. In a child it costs one failed fetch. stdin (e.g. JSON
// options carrying credentials) is piped, never put on the command line where
// other local users could read it from /proc.
func RunChild(ctx context.Context, args []string, stdin []byte) (result []byte, tail string, err error) {
	if os.Getenv(childEnv) == "1" {
		return nil, "", errors.New("refusing to spawn a nested disposable child")
	}
	self, _ := os.Executable()
	if strings.HasSuffix(self, ".test") {
		return nil, "", errors.New("disposable child processes are disabled under go test")
	}
	exe := "/proc/self/exe" // survives the binary being replaced on disk
	if _, statErr := os.Stat(exe); statErr != nil {
		if self == "" {
			return nil, "", errors.New("cannot resolve own executable")
		}
		exe = self
	}

	f, err := os.CreateTemp("", "autoar-child-*.json")
	if err != nil {
		return nil, "", err
	}
	outPath := f.Name()
	f.Close()
	defer os.Remove(outPath)

	cmd := exec.CommandContext(ctx, exe, append(append([]string{}, args...), "--out", outPath)...)
	cmd.Env = append(os.Environ(), childEnv+"=1")
	setChildAttrs(cmd)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	tb := NewTailBuffer(childTailBytes)
	cmd.Stdout, cmd.Stderr = tb, tb
	// A grandchild holding the output pipe must not hang Wait after a kill.
	cmd.WaitDelay = 10 * time.Second
	runErr := cmd.Run()
	result, _ = os.ReadFile(outPath)
	return result, tb.String(), runErr
}

// LastLine returns the last non-empty line of s, capped at max bytes (the
// usual carrier of a log.Fatal reason).
func LastLine(s string, max int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if max > 0 && len(l) > max {
		l = l[len(l)-max:]
	}
	return l
}

// TailBuffer is an io.Writer that keeps only the last max bytes written.
type TailBuffer struct {
	mu      sync.Mutex
	max     int
	buf     []byte
	dropped bool
}

// NewTailBuffer returns a TailBuffer bounded to max bytes.
func NewTailBuffer(max int) *TailBuffer {
	return &TailBuffer{max: max, buf: make([]byte, 0, max)}
}

func (t *TailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(p)
	if len(p) >= t.max {
		p = p[len(p)-t.max:]
		t.buf = t.buf[:0]
		t.dropped = true
	} else if over := len(t.buf) + len(p) - t.max; over > 0 {
		t.buf = t.buf[:copy(t.buf, t.buf[over:])]
		t.dropped = true
	}
	t.buf = append(t.buf, p...)
	return n, nil
}

// String returns the retained tail ("…" prefixed when output was dropped).
func (t *TailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dropped {
		return "…" + string(t.buf)
	}
	return string(t.buf)
}
