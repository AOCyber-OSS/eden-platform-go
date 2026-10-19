# platform/realtime

Portable WebSocket fan-out hub abstraction. Beta.

## Donor

`aodex-go/internal/ws` (Hub + Connection + redis_fanout). The platform package
promotes the **API surface** here; AODex's actual donation (deleting its in-tree
copy and importing `platform/realtime`) is tracked in `ws-aodex-realtime-donor`
(Obj 11).

## Concepts

- **Channel**: a logical fan-out target. Subscribers receive every Publish on the channel.
- **Subscriber**: wraps a transport (WebSocket, SSE) and consumes Messages.
- **Hub**: routes Publish to local Subscribers, optionally fans out via Redis pub/sub.

The transport itself (e.g. `gorilla/websocket`) is consumer-owned. This package
provides the channel/subscriber/publisher contract that's portable across products.

## Quickstart

```go
import "go.aocyber.ai/eden-platform-go/platform/realtime"

// Single-instance
hub := realtime.NewHub()

// Fleet-wide via Redis pub/sub
hub := realtime.NewRedisFanout(realtime.NewHub(), myRedisAdapter, "myapp:rt:")

// Wrap an incoming WebSocket as a Subscriber
sub := realtime.NewBufferedSubscriber(connID, "room:123", 256)
hub.Subscribe(ctx, "room:123", sub)
defer hub.Unsubscribe("room:123", sub)

// Pump received messages out to the WebSocket
go func() {
    for {
        msg, ok := sub.Recv(ctx)
        if !ok { return }
        ws.WriteJSON(msg)
    }
}()

// Anywhere — broadcast
hub.Publish(ctx, realtime.Message{
    Channel: "room:123",
    Type:    "chat.message",
    Data:    json.RawMessage(`{"text": "hi"}`),
})
```

## Backpressure

`BufferedSubscriber` drops the OLDEST message when its buffer is full (so
slow subscribers see the most recent state, not an ancient backlog). The drop
is reported via `Hub.Stats().Dropped`.

Hub never blocks publishers on slow subscribers — bad subscribers' slots cap
at buffer size; everyone else proceeds at full speed.

Sizing recommendation: buffer ≥ 4× expected publish rate over your transport's
typical write latency. For chat rooms with ~10 msg/sec and ~100ms write latency,
buffer 32-64 is a sane starting point.

## Reconnection

The hub does NOT track reconnections. Consumers (the transport wrapper) re-Subscribe
the same Channel after a reconnect; Subscribe is idempotent on the same `(channel, id)`
pair within the local hub.

For multi-instance reconnection persistence (e.g. presence that survives a page
refresh hitting a different instance), the consumer needs to record presence
externally — out of scope for the platform package.

## Redis adapter pattern

Same approach as `platform/ratelimit` — adapt your Redis pub/sub client to the
2-method `RedisClient` interface. Example for `go-redis/v9`:

```go
type goRedisAdapter struct{ c *redis.Client }

func (a goRedisAdapter) Publish(ctx context.Context, channel string, payload []byte) error {
    return a.c.Publish(ctx, channel, payload).Err()
}
func (a goRedisAdapter) Subscribe(ctx context.Context, channel string) (<-chan []byte, func(), error) {
    sub := a.c.Subscribe(ctx, channel)
    out := make(chan []byte, 64)
    cancel := func() { _ = sub.Close() }
    go func() {
        defer close(out)
        for msg := range sub.Channel() {
            select {
            case out <- []byte(msg.Payload):
            case <-ctx.Done():
                return
            }
        }
    }()
    return out, cancel, nil
}
```

## Migration paths

- AODex retires `internal/ws/hub.go` and routes through `platform/realtime`
  (tracked in `ws-aodex-realtime-donor`, Obj 11).
- aohealth-go, recycling-oracle, eden-circle migrate next (their PRs).

## What this package is not

- **Not a transport.** Wrap your WebSocket / SSE library as a `Subscriber`.
- **Not auth.** Channel ACLs are the consumer's responsibility (filter at Subscribe time).
- **Not message persistence.** Hub fans out live; no replay.
