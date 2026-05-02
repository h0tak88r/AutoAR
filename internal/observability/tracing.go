package observability

import "context"

// LogTraceInfo logs trace-related information when the observability logger is initialized.
func LogTraceInfo(ctx context.Context, msg string) {
	LogWithTrace(ctx).Info().Msg(msg)
}

// EndSpan safely ends the current span from context.
func EndSpan(ctx context.Context) {
	SpanFromContext(ctx).End()
}

// IsTracingEnabled returns true when tracing has been configured.
func IsTracingEnabled() bool {
	return TracerProvider != nil
}
