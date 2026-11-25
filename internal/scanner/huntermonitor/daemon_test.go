package huntermonitor

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEffectiveIntervalFloor(t *testing.T) {
	if got := effectiveInterval(1); got != minCheckInterval {
		t.Fatalf("effectiveInterval(1) = %v, want %v", got, minCheckInterval)
	}
	if got := effectiveInterval(3600); got != time.Hour {
		t.Fatalf("effectiveInterval(3600) = %v", got)
	}
}

func TestFailureBackoff(t *testing.T) {
	interval := 12 * time.Hour
	for n, want := range map[int]time.Duration{1: 5 * time.Minute, 2: 10 * time.Minute, 3: 20 * time.Minute, 20: interval} {
		if got := failureBackoff(n, interval); got != want {
			t.Errorf("failureBackoff(%d) = %v, want %v", n, got, want)
		}
	}
	if got := failureBackoff(5, 15*time.Minute); got != 15*time.Minute {
		t.Errorf("backoff must cap at the interval, got %v", got)
	}
}

// TestRetryBackoffOnFailure: a failing target is not retried on the next tick,
// and success clears the backoff.
func TestRetryBackoffOnFailure(t *testing.T) {
	const id = int64(424242)
	now := time.Now()
	if !retryDue(id, now) {
		t.Fatal("unknown target should be due")
	}
	recordAttempt(id, false, time.Hour, now)
	if retryDue(id, now.Add(time.Minute)) {
		t.Fatal("failed target retried after 1 minute")
	}
	if !retryDue(id, now.Add(5*time.Minute)) {
		t.Fatal("failed target not retried after the first backoff step")
	}
	recordAttempt(id, false, time.Hour, now)
	if retryDue(id, now.Add(6*time.Minute)) {
		t.Fatal("second failure should double the backoff")
	}
	recordAttempt(id, true, time.Hour, now)
	if !retryDue(id, now) {
		t.Fatal("success should clear the backoff")
	}
}

// TestLoopSurvivesPanickingTickAndClearsFlag: a panic in one tick must not kill
// the loop, and when the loop ends daemonRunning is reset so StartDaemon works.
func TestLoopSurvivesPanickingTickAndClearsFlag(t *testing.T) {
	oldInterval, oldFn := tickInterval, tickFn
	defer func() { tickInterval, tickFn = oldInterval, oldFn }()

	var ticks int32
	tickInterval = 5 * time.Millisecond
	tickFn = func() {
		atomic.AddInt32(&ticks, 1)
		panic("boom")
	}

	daemonMutex.Lock()
	daemonRunning = true
	daemonMutex.Unlock()
	stop := make(chan struct{})
	daemonWg.Add(1)
	go superviseLoop(stop)

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&ticks) < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := atomic.LoadInt32(&ticks); n < 3 {
		t.Fatalf("loop died after a panicking tick (ticks=%d)", n)
	}
	if !IsDaemonRunning() {
		t.Fatal("daemon reported stopped while the loop is alive")
	}
	close(stop)
	daemonWg.Wait()
	if IsDaemonRunning() {
		t.Fatal("daemonRunning not cleared after the loop exited")
	}
}
