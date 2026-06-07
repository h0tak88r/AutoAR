package observability

import (
	"context"
	"testing"
)

func TestIsTracingEnabledDefaultFalse(t *testing.T) {
	oldTP := TracerProvider
	TracerProvider = nil
	defer func() { TracerProvider = oldTP }()

	if IsTracingEnabled() {
		t.Error("IsTracingEnabled() should be false when TracerProvider is nil")
	}
}

func TestIsTracingEnabledTrue(t *testing.T) {
	oldTP := TracerProvider
	TracerProvider = nil
	defer func() { TracerProvider = oldTP }()

	_ = InitializeTracing("stdout")
	if !IsTracingEnabled() {
		t.Error("IsTracingEnabled() should be true after InitializeTracing")
	}
	TracerProvider = nil
}

func TestInitCreatesLogger(t *testing.T) {
	oldLogger := Logger
	Logger = nil
	defer func() { Logger = oldLogger }()

	Init()
	if Logger == nil {
		t.Fatal("Init() should set Logger")
	}
}

func TestInitializeCallsInit(t *testing.T) {
	oldLogger := Logger
	Logger = nil
	defer func() { Logger = oldLogger }()

	Initialize()
	if Logger == nil {
		t.Fatal("Initialize() should set Logger via Init()")
	}
}

func TestInitializeTracing(t *testing.T) {
	oldTP := TracerProvider
	TracerProvider = nil
	defer func() { TracerProvider = oldTP }()

	err := InitializeTracing("stdout")
	if err != nil {
		t.Errorf("InitializeTracing() error = %v", err)
	}
	if TracerProvider == nil {
		t.Error("InitializeTracing() should set TracerProvider")
	}
	TracerProvider = nil
}

func TestSpanFromContext(t *testing.T) {
	ctx := context.Background()
	span := SpanFromContext(ctx)
	if span == nil {
		t.Error("SpanFromContext() should return a non-nil span")
	}
}

func TestEndSpanNoopWithoutTracing(t *testing.T) {
	oldTP := TracerProvider
	TracerProvider = nil
	defer func() { TracerProvider = oldTP }()

	// Should not panic when no span is in context and no TracerProvider
	ctx := context.Background()
	EndSpan(ctx)
}

func TestLogTraceInfoNoopWithoutLogger(t *testing.T) {
	oldLogger := Logger
	Logger = nil
	defer func() { Logger = oldLogger }()

	Init()
	ctx := context.Background()
	LogTraceInfo(ctx, "test message")
}
