package utils

import "runtime/debug"

// SafeGo runs fn in a new goroutine behind a panic barrier. AutoAR is a single
// process: a panic in a bare `go func` — a monitor daemon, a scan phase, an async
// task — would otherwise crash the whole server (the API and every monitor with
// it). SafeGo contains the panic, logs it with a stack trace under label, and
// lets the rest of the process keep running. Use it for any goroutine whose panic
// should not be fatal, which is nearly all of them.
func SafeGo(label string, fn func()) {
	go func() {
		defer RecoverPanic(label)
		fn()
	}()
}

// RecoverPanic is the deferred recover body, for goroutines that manage their own
// `go` and defers (e.g. one that must also call wg.Done()). Add it as the FIRST
// deferred call: `defer utils.RecoverPanic("subdomain-monitor:check")`.
func RecoverPanic(label string) {
	if r := recover(); r != nil {
		GetLogger().Errorf("[panic] %s: %v\n%s", label, r, debug.Stack())
	}
}

// GuardedRun runs fn with a per-call panic recovery and returns whether it
// completed without panic. Unlike a deferred RecoverPanic at the top of a
// goroutine (which saves the process but lets the goroutine — and its ticker
// loop — die), GuardedRun is for the BODY of a loop tick: the enclosing
// goroutine keeps ticking after a panic, so one bad cycle can't silently kill
// a background daemon until the next restart.
func GuardedRun(label string, fn func()) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			GetLogger().Errorf("[panic] %s: %v\n%s", label, r, debug.Stack())
		}
	}()
	fn()
	return true
}
