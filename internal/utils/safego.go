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
