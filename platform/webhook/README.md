# platform/webhook

Outbound webhook delivery: registration, HMAC-signed POST, exponential-backoff retry, dead-letter on exhaustion, auto-pause after consecutive failures, cron-callable retry queue.

This is the canonical implementation for the Eden portfolio. Consumers retiring forks (`aosentry/internal/webhook`, `eden-biz/internal/webhooks`): see [Migration](#migration-retiring-forks) below.

## Quick start

```go
store := pgstore.NewWebhookStore(pool)
svc := webhook.NewService(store)
defer svc.Shutdown(context.Background())

// Register a subscription. Pass empty secret to auto-generate one.
wh, err := svc.Register(ctx, companyID, "https://example.com/hook", "", []string{"key.created", "spend.*"})

// Fire an event.
err = svc.Trigger(ctx, companyID, webhook.EventKeyCreated, `{"key_id":"abc"}`)
```

## HMAC signature scheme

### Headers sent on every POST

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Eden-Signature` | `t=<unix-seconds>,v1=<hex-hmac-sha256>` |
| `X-Eden-Event` | The event type (e.g. `key.created`) |
| `X-Eden-Delivery` | UUID of this delivery attempt |

### Algorithm

1. Take the unix timestamp (seconds) at send time. Call this `t`.
2. Concatenate `t + "." + payload` (exact request body, byte-for-byte).
3. `signature = hex(HMAC-SHA256(secret, t + "." + payload))`.
4. Send `X-Eden-Signature: t=<t>,v1=<signature>`.

The secret is per-subscription and stored at registration time.

### Verification (receiver responsibilities)

1. Parse the `t=` and `v1=` parts of the header. Reject on missing or malformed.
2. Reject if `|now - t| > 300` seconds (5-minute replay window). Tighten or loosen per your threat model.
3. Recompute `expected = hex(HMAC-SHA256(secret, t + "." + body))` using the **raw** request body (do not re-marshal).
4. Compare with constant-time compare (`hmac.Equal` in Go, manual byte XOR in Dart). Reject on mismatch.

### Why timestamp-bound?

The timestamp is part of the signed payload, so an attacker who replays an old request cannot reuse the signature outside the 5-minute window. Without timestamp binding, any captured signed body could be replayed forever.

## Verifier examples

### Go

The package exports `VerifySignature` for the HMAC check. Wrap it with the timestamp window check yourself (recommended):

```go
import (
    "net/http"
    "strconv"
    "strings"
    "time"

    "go.aocyber.ai/eden-platform-go/platform/webhook"
)

func receiveWebhook(w http.ResponseWriter, r *http.Request, secret string) {
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "bad body", http.StatusBadRequest)
        return
    }

    sig := r.Header.Get("X-Eden-Signature")
    if !acceptableSignature(sig, secret, body) {
        http.Error(w, "bad signature", http.StatusUnauthorized)
        return
    }

    // ... handle event ...
    w.WriteHeader(http.StatusOK)
}

func acceptableSignature(header, secret string, body []byte) bool {
    parts := strings.Split(header, ",")
    var ts string
    for _, p := range parts {
        if strings.HasPrefix(p, "t=") {
            ts = strings.TrimPrefix(p, "t=")
        }
    }
    sec, err := strconv.ParseInt(ts, 10, 64)
    if err != nil {
        return false
    }
    delta := time.Since(time.Unix(sec, 0))
    if delta < 0 {
        delta = -delta
    }
    if delta > 5*time.Minute {
        return false
    }
    return webhook.VerifySignature(secret, header, string(body))
}
```

### Dart

```dart
import 'dart:convert';
import 'package:crypto/crypto.dart';

bool verifyEdenSignature({
  required String header,        // X-Eden-Signature value
  required String secret,
  required List<int> bodyBytes,
}) {
  final parts = header.split(',');
  String? ts;
  String? sig;
  for (final p in parts) {
    if (p.startsWith('t=')) ts = p.substring(2);
    if (p.startsWith('v1=')) sig = p.substring(3);
  }
  if (ts == null || sig == null) return false;

  // Replay window: 5 minutes.
  final tsInt = int.tryParse(ts);
  if (tsInt == null) return false;
  final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
  if ((now - tsInt).abs() > 300) return false;

  final hmacSha256 = Hmac(sha256, utf8.encode(secret));
  final body = utf8.decode(bodyBytes);
  final expected = hmacSha256.convert(utf8.encode('$ts.$body')).toString();

  // Constant-time compare.
  if (sig.length != expected.length) return false;
  var diff = 0;
  for (var i = 0; i < sig.length; i++) {
    diff |= sig.codeUnitAt(i) ^ expected.codeUnitAt(i);
  }
  return diff == 0;
}
```

## Retry policy

- **Max attempts** per delivery: configurable via `webhook.WithMaxRetries(n)` (default 5).
- **Backoff schedule**: 2^attempt minutes (2, 4, 8, 16, 32...). After `maxRetries` attempts the row is marked `exhausted`.
- **Status flow**: `pending` -> `success` | `failed` (NextRetryAt set) | `exhausted` (no further retries).
- **Auto-pause**: after `webhook.WithMaxConsecutiveFailures(n)` consecutive non-success deliveries (default 10), the webhook flips to `Active=false`. Restart from your admin surface; new triggers will skip the inactive subscription until then.

### Cron retry hook

`Service.RetryFailedDeliveries(ctx)` re-enqueues `failed` deliveries whose webhook is still active. Call this from a cron job at whatever cadence you prefer (every minute is reasonable).

```go
// e.g. River job, k8s CronJob, etc.
n, err := svc.RetryFailedDeliveries(ctx)
if err != nil {
    slog.Error("retry failed deliveries", "error", err)
}
slog.Info("retried", "count", n)
```

`Service.ExecuteDelivery(ctx, deliveryID)` runs a single delivery synchronously when a caller wants to drive delivery itself. Most callers should prefer `Trigger`.

## Configurable options

| Option | Default | Notes |
|---|---|---|
| `WithMaxRetries(n)` | 5 | Per-delivery cap. |
| `WithMaxConsecutiveFailures(n)` | 10 | Auto-pause threshold. |
| `WithHTTPTimeout(d)` | 10s | `http.Client.Timeout`. |
| `WithDeliveryTimeout(d)` | 30s | Per-delivery `context.WithTimeout`. |
| `WithHTTPClient(c)` | new client | Replace for custom transport / telemetry. |

## Standard event vocabulary

Defined in `events.go`. Consumers MAY use their own event types; these are the platform-published ones so subscribers can wildcard across products.

```text
key.created           user.created          budget.exceeded     guardrail.blocked
key.deleted           user.deleted          spend.alert         model.error
key.blocked           team.created                              health.down
                                                                health.up
                                                                anomaly.detected
```

## Migration: retiring forks

| Fork | Replace with |
|---|---|
| `aosentry/internal/webhook` (DeliveryService + Dispatcher) | `webhook.Service.Trigger(ctx, companyID, eventType, payload)`. The event constants in `events.go` are a 1:1 promotion of AOSentry's catalogue. |
| `eden-biz/internal/webhooks` (Service + WebhookDispatcher) | `webhook.Service` directly. `RetryFailedDeliveries` and `ExecuteDelivery` are 1:1 ports — see `retry.go`. |

### Header rename note

AOSentry's existing fork emits `X-Webhook-Signature: sha256=<hex>` (no timestamp, no version prefix). `platform/webhook` emits `X-Eden-Signature: t=<unix>,v1=<hex>`. The two are not interchangeable. AOSentry consumers verifying old signatures must either dual-emit during cutover or invalidate existing subscriptions and re-register against the new scheme.

Eden-biz's existing fork already emits `X-Eden-Signature` but without the `t=...,v1=...` prefix structure. Consumers verifying eden-biz signatures must update their verifier to parse the new format.
