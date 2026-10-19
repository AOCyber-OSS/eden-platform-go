# platform/observability

Canonical observability surface for the Eden portfolio. Beta.

## What this package owns

- `Setup(Config)` — boot helper that wires errortrack (Sentry), slog default
  handler, and the multi-handler that tees logs to BOTH Sentry and stdout.
- `*Metrics` — Prometheus registry + RPS / latency / active-connection
  collectors. Re-exposed as `MetricsHandler()` for `/metrics` HTTP routes.
- `*AuthMetrics` — Auth-specific Prometheus counters (logins / signups /
  token refresh).
- `NewObservabilityInterceptor(*Metrics)` — ConnectRPC unary interceptor that
  records counts, duration, and a structured `rpc` log line per call.
- `WithTraceContext` / `TraceContextFromContext` — inject trace_id and span_id
  from any upstream propagator (OpenTelemetry, custom). The interceptor reads
  them and includes them in the per-request log line.

## Relationship to errortrack

`platform/errortrack` is the Sentry transport (DSN, PII scrubber, slog handler,
HTTP middleware). `Setup` wires errortrack into the canonical slog default so
consumers don't have to compose handlers themselves. Use errortrack directly
only when you need its HTTP middleware or `CaptureException` / `Recover`.

## Quickstart

```go
import (
    "log"
    "os"

    "go.aocyber.ai/eden-platform-go/platform/observability"
)

func main() {
    shutdown, err := observability.Setup(observability.Config{
        ServiceName: "biz-api",
        Environment: os.Getenv("EDEN_ENV"),
        Release:     os.Getenv("GIT_SHA"),
        SentryDSN:   os.Getenv("SENTRY_DSN"),
        LogLevel:    os.Getenv("LOG_LEVEL"),
        LogFormat:   os.Getenv("LOG_FORMAT"),
    })
    if err != nil {
        log.Fatalf("observability: %v", err)
    }
    defer shutdown()

    metrics := observability.NewMetrics()
    auth := observability.NewAuthMetrics(metrics.Registry)
    _ = auth

    interceptor := observability.NewObservabilityInterceptor(metrics)
    // ... pass interceptor to connect handlers
}
```

## Adding product-specific metrics

```go
metrics := observability.NewMetrics()

myCounter := prometheus.NewCounter(prometheus.CounterOpts{
    Name: "biz_orders_total",
    Help: "Total orders created.",
})
metrics.Registry.MustRegister(myCounter)
```

`metrics.MetricsHandler()` then exposes the merged registry — yours plus the
platform's HTTP / auth metrics.

## Trace-context propagation

The interceptor is OTel-SDK-agnostic. Any upstream middleware that calls
`observability.WithTraceContext(ctx, observability.TraceContext{TraceID, SpanID})`
results in `trace_id` and `span_id` attributes on the per-RPC log line.
Downstream services that want full OTel propagation should wrap the interceptor
with their preferred propagator (e.g. `otelconnect`).

## Stability

This package is **beta**. All listed exports are stable. New helpers are added
non-breakingly.
