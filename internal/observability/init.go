package observability

import (
	"context"
	"os"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

var Logger *zerolog.Logger
var TracerProvider *sdktrace.TracerProvider

// Init prepares lightweight observability helpers. Tracing is disabled unless
// AUTOAR_TRACING_ENABLED=true so normal logs stay readable in local runs.
func Init() {
	if Logger == nil {
		logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout}).
			With().
			Timestamp().
			Str("service", "autoar").
			Logger()
		Logger = &logger
	}

	if os.Getenv("AUTOAR_TRACING_ENABLED") == "true" {
		if err := InitializeTracing("stdout"); err != nil {
			Logger.Error().Err(err).Msg("Failed to initialize tracing")
		}
	}
}

// Initialize is kept for older startup paths.
func Initialize() {
	Init()
}

// InitializeTracing sets up OpenTelemetry tracing. The exporterType argument is
// accepted for forward compatibility with external exporters.
func InitializeTracing(exporterType string) error {
	TracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String("autoar"),
			semconv.ServiceVersionKey.String("dev"),
		)),
	)

	otel.SetTracerProvider(TracerProvider)
	return nil
}

// StartSpan starts a new trace span and returns context with a cleanup function.
func StartSpan(ctx context.Context, name string) (context.Context, func()) {
	tracer := otel.Tracer("autoar")
	ctx, span := tracer.Start(ctx, name)
	return ctx, span.End
}

// LogWithTrace adds trace/span information to zerolog logger for correlation.
func LogWithTrace(ctx context.Context) *zerolog.Logger {
	Init()
	spanCtx := trace.SpanContextFromContext(ctx)
	if !spanCtx.IsValid() {
		return Logger
	}
	logger := Logger.With().
		Str("trace_id", spanCtx.TraceID().String()).
		Str("span_id", spanCtx.SpanID().String()).
		Logger()
	return &logger
}

// LogErrorWithCtx logs an error with context information for trace correlation.
func LogErrorWithCtx(ctx context.Context, err error, msg string) {
	LogWithTrace(ctx).Err(err).Msg(msg)
}

// SpanFromContext extracts the span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
