package ffuf

import (
	"bytes"
	"testing"
)

func TestLogFilterWritePassthrough(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "Starting scan on example.com\n"
	n, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("wrote %d bytes, want %d", n, len(input))
	}
	if buf.String() != input {
		t.Errorf("got %q, want %q", buf.String(), input)
	}
}

func TestLogFilterWriteSuppressesConnectionReset(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "ERRO read tcp 192.168.1.1:8080->10.0.0.1:443: connection reset by peer\n"
	n, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("wrote %d bytes, want %d", n, len(input))
	}
	if buf.Len() != 0 {
		t.Errorf("expected suppressed output, got %q", buf.String())
	}
}

func TestLogFilterWriteSuppressesContextCanceled(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "context canceled\n"
	n, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("wrote %d bytes, want %d", n, len(input))
	}
	if buf.Len() != 0 {
		t.Errorf("expected suppressed output, got %q", buf.String())
	}
}

func TestLogFilterWriteSuppressesTLSError(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "ERRO remote error: tls: unrecognized name\n"
	n, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("wrote %d bytes, want %d", n, len(input))
	}
	if buf.Len() != 0 {
		t.Errorf("expected suppressed output, got %q", buf.String())
	}
}

func TestLogFilterWriteSuppressesTimeout(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "ERRO Client.Timeout exceeded while awaiting headers\n"
	n, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(input) {
		t.Errorf("wrote %d bytes, want %d", n, len(input))
	}
	if buf.Len() != 0 {
		t.Errorf("expected suppressed output, got %q", buf.String())
	}
}

func TestLogFilterWriteMixedMessages(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}

	// Suppressed
	f.Write([]byte("ERRO read tcp 1.2.3.4:8080->5.6.7.8:443: connection reset by peer\n"))
	f.Write([]byte("context canceled\n"))
	f.Write([]byte("ERRO remote error: tls: unrecognized name\n"))
	f.Write([]byte("ERRO Client.Timeout exceeded\n"))

	// Not suppressed
	f.Write([]byte("ERRO unexpected EOF\n"))
	f.Write([]byte("INFO connected to example.com\n"))

	output := buf.String()
	if output != "ERRO unexpected EOF\nINFO connected to example.com\n" {
		t.Errorf("got %q", output)
	}
}

func TestLogFilterWriteEmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	n, err := f.Write([]byte{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("wrote %d bytes, want 0", n)
	}
}

func TestLogFilterWritePartialMatch(t *testing.T) {
	// "read tcp" without "connection reset by peer" should pass through
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "ERRO read tcp connection established\n"
	_, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != input {
		t.Errorf("got %q, want %q (should pass through)", buf.String(), input)
	}
}

func TestLogFilterWriteNearMiss(t *testing.T) {
	// Verify "timeout" alone doesn't trigger, only "Client.Timeout exceeded"
	var buf bytes.Buffer
	f := LogFilter{w: &buf}
	input := "ERRO connection timeout\n"
	_, err := f.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.String() != input {
		t.Errorf("got %q, want %q (should pass through)", buf.String(), input)
	}
}
