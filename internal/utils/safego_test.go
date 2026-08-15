package utils

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestRecoverPanicContainsPanic is the deterministic guarantee: a panic inside a
// function guarded by `defer RecoverPanic(...)` must not propagate. If it did, the
// "boom" panic would unwind past the IIFE and crash the test binary (an
// unrecovered panic is fatal), so simply reaching the line after the IIFE proves
// the panic was contained.
func TestRecoverPanicContainsPanic(t *testing.T) {
	func() {
		defer RecoverPanic("test-recover")
		panic("boom")
	}()
	// Reached only if the panic above was recovered.
	t.Log("panic contained")
}

// TestSafeGoRunsAndContainsPanic checks the goroutine wrapper: the fn runs, and a
// panic inside it does not take down the process. SafeGo is `go func(){ defer
// RecoverPanic(label); fn() }()`, so its recovery is the same primitive proven
// deterministically above; here we confirm the wrapper actually invokes fn and
// survives a panic.
func TestSafeGoRunsAndContainsPanic(t *testing.T) {
	var ran int32
	SafeGo("test-safego", func() {
		atomic.StoreInt32(&ran, 1)
		panic("boom")
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&ran) == 1 {
			// Give the deferred RecoverPanic a moment to run. If it failed to
			// recover, the panic would crash the binary here rather than let the
			// test finish.
			time.Sleep(50 * time.Millisecond)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("SafeGo did not run fn within timeout")
}
