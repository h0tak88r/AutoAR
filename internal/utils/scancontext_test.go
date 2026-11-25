package utils

import (
	"context"
	"testing"
)

// TestGoroutineScanContextOverride: a phase child goroutine that registers its
// (cancellable) context must see it from CurrentScanContext, and the override
// must not leak to other goroutines.
func TestGoroutineScanContextOverride(t *testing.T) {
	if CurrentScanContext().Done() != nil {
		t.Fatal("no scan registered: want context.Background()")
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan context.Context, 1)
	other := make(chan context.Context, 1)
	go func() {
		SetGoroutineScanContext(ctx)
		defer ClearGoroutineScanContext()
		go func() { other <- CurrentScanContext() }()
		got <- CurrentScanContext()
	}()
	if c := <-got; c != ctx {
		t.Fatal("CurrentScanContext ignored the goroutine's registered context")
	}
	if c := <-other; c == ctx {
		t.Fatal("context override leaked to another goroutine")
	}
	cancel()
	if ctx.Err() == nil {
		t.Fatal("cancel did not propagate")
	}
	if CurrentScanContext() == ctx {
		t.Fatal("override leaked to the test goroutine")
	}
}
