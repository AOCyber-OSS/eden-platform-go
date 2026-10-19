# platform/ratelimit

Multi-tier, fleet-aware rate limiter for the Eden portfolio. Beta.

## Donor

`aosentry/internal/llm/provider_limiter.go` — adaptive token bucket with optional
Redis-backed fixed-window counter. Production-tested by AOSentry's LLM provider
rate-limit subsystem (handles bursts, adapts to upstream `X-RateLimit-*` headers,
honors `Retry-After`).

## Two-layer design

- **In-process token bucket** — smooths bursts, holds adaptive state. Hot path
  stays local so requests don't pay a Redis round trip.
- **Optional Redis fixed-window counter** — `INCR` + `EXPIRE NX` per minute,
  enforces fleet-wide caps. Best-effort: if Redis is down we fall through to the
  local bucket only.

When `RedisClient` is nil, behaviour is identical to the in-process-only
implementation.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/ratelimit"

// Single-instance / dev / tests
limiter := ratelimit.NewMemory()

// Fleet-aware (production)
limiter := ratelimit.NewRedis(myRedisAdapter, "myapp:rate:")

// Hot path
tier := ratelimit.Tier{Name: "free", RequestsPerMinute: 60}
key := ratelimit.BucketKey("tenant", tenantID, "endpoint", req.URL.Path)

dec, err := limiter.Check(ctx, key, tier)
if errors.Is(err, ratelimit.ErrFleetLimit) || !dec.Allow {
    w.Header().Set("Retry-After", strconv.Itoa(int(dec.RetryAfter.Seconds())))
    http.Error(w, "rate limited", http.StatusTooManyRequests)
    return
}

// Adapt from upstream response headers (LLM provider, etc.)
limiter.Update(key, ratelimit.Observation{
    LimitRequests:     parseInt(resp.Header.Get("X-RateLimit-Limit")),
    RemainingRequests: parseInt(resp.Header.Get("X-RateLimit-Remaining")),
    RetryAfter:        ratelimit.MustParseRetryAfter(resp.Header.Get("Retry-After")),
})
```

## Redis adapter pattern

The package does NOT import `go-redis` at its boundary. Adapt your Redis
client to the `RedisClient` interface (4 methods). Example for `go-redis/v9`:

```go
import "github.com/redis/go-redis/v9"

type goRedisAdapter struct{ c *redis.Client }

func (a goRedisAdapter) Incr(ctx context.Context, k string) (int64, error) {
    return a.c.Incr(ctx, k).Result()
}
func (a goRedisAdapter) ExpireNX(ctx context.Context, k string, ttl time.Duration) error {
    return a.c.ExpireNX(ctx, k, ttl).Err()
}
func (a goRedisAdapter) Get(ctx context.Context, k string) (int64, error) {
    return a.c.Get(ctx, k).Int64()
}
func (a goRedisAdapter) TTL(ctx context.Context, k string) (time.Duration, error) {
    return a.c.TTL(ctx, k).Result()
}
```

## Topology requirements

- **Single Redis instance / Sentinel HA**: works as-is.
- **Redis Cluster**: keys are independent per `BucketKey()`; no multi-key transactions.
  Counters hash across slots fine, but don't expect atomicity across keys.
- **Eviction**: counter keys auto-expire 60s after first INCR. No explicit cleanup needed.
- **Sharding**: prefix and key composition is the caller's responsibility (`BucketKey()` helper).
- **Mixed fleet (some Redis-equipped, some not)**: SILENTLY allows overshoot on
  Redis-less instances. In production, set Redis on EVERY instance or none.

## Tier policies (per-endpoint)

The `Tier` struct is the per-key policy. Compose per-endpoint policies in your
HTTP middleware:

```go
tiers := map[string]ratelimit.Tier{
    "/v1/chat/completions": {Name: "chat", RequestsPerMinute: 100},
    "/v1/embeddings":       {Name: "embed", RequestsPerMinute: 1000},
}
tier := tiers[r.URL.Path]
```

## What this package replaces

- `aosentry/internal/llm/provider_limiter` (this package's donor) — migration in obj 24/25.
- `eden-biz/middleware` ratelimit (per-IP simple counter) — migration in obj 21.
- `aohealth-go` in-memory ratelimit — migration in respective consumer PR.

The replacement happens consumer-side; this objective only promotes the platform package.
