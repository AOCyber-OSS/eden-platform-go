# platform/billing-rail

Adapter contract for "payment received → notify Eden-Biz." Beta. Interface only — concrete adapters land in later objectives.

## Why this exists

Per decisions D1 and D2 in `PORTFOLIO_STANDARDIZATION_PLAN.md`:

- **D1**: Eden-Biz is the single financial system of record.
- **D2**: Stripe (and Apple IAP, Google Play, ACH) are payment processors only — they do not own the ledger.

`platform/billing-rail` is the seam between those two facts. Every rail (Stripe, Apple, Google, ACH, future) implements the `Rail` interface. Eden-Biz implements the `EdenBizSink` interface. The `Dispatcher` wires webhooks from a rail into the sink. The rest of the portfolio never speaks to a rail directly.

## Boundaries — three packages, three jobs

| Question | Package |
|---|---|
| Is this code path turned on? | `platform/feature-flags` |
| Did this caller pay for tier X? | `platform/entitlements` |
| Did the rail process the payment? | `platform/billing-rail` (this) |

A typical product gate composes all three:

```go
if !flags.IsEnabled(ctx, "household_billing", featureflags.Eval{TenantID: t}) {
    return ErrFeatureDisabled
}
if !ent.HasEntitlement(ctx, customer, "household_billing") {
    return ErrUpgradeRequired
}
// proceed — billing-rail charges the customer when an upgrade is purchased
```

## What this package ships

- `Rail` interface — every adapter implements it
- `EdenBizSink` interface — every consumer (i.e. Eden-Biz) implements it
- `Dispatcher` — glues a Rail's webhook intake to a Sink
- `MockRail` / `MockSink` — programmable mocks for tests
- Canonical types (`Money`, `Customer`, `ChargeRequest/Result`, `RefundRequest/Result`, `SubscriptionRequest/Result`, `WebhookEvent`)
- Canonical event taxonomy (`EventChargeSucceeded`, `EventSubCreated`, etc.)

## What this package does NOT ship

- Stripe adapter (lives in `platform/billing-rail/stripe`, future objective)
- Apple IAP adapter (future objective)
- Google Play adapter (future objective)
- ACH adapter (deferred — not needed for Eden Family launch)
- Eden-Biz `EdenBizSink` implementation (lives in eden-biz-dev)

## Quickstart — adapter author

```go
type StripeAdapter struct { /* ... */ }

func (a *StripeAdapter) Name() string { return "stripe" }

func (a *StripeAdapter) Charge(ctx context.Context, req billingrail.ChargeRequest) (billingrail.ChargeResult, error) {
    // 1. Translate req → Stripe params (idempotency key, customer, amount).
    // 2. Call Stripe.
    // 3. Map Stripe response → billingrail.ChargeResult.
    // 4. Return; do NOT call the sink — the consumer drives the call.
}

func (a *StripeAdapter) ParseWebhook(ctx context.Context, headers map[string]string, body []byte) (billingrail.WebhookEvent, error) {
    if !verifyStripeSignature(headers, body, a.signingSecret) {
        return billingrail.WebhookEvent{}, billingrail.ErrInvalidSignature
    }
    // ... parse body → billingrail.WebhookEvent
}
```

## Quickstart — consumer (Eden-Biz)

```go
import billingrail "go.aocyber.ai/eden-platform-go/platform/billing-rail"

type EdenBizSink struct { db *sql.DB }

func (s *EdenBizSink) RecordCharge(ctx context.Context, c billingrail.Customer, amt billingrail.Money, r billingrail.ChargeResult) error {
    // upsert into eden-biz charges table; idempotent on r.RailChargeID
}

// HTTP webhook endpoint
d := billingrail.NewDispatcher(stripeAdapter, edenBizSink)
http.HandleFunc("/webhooks/stripe", func(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)
    headers := flattenHeaders(r.Header)
    if err := d.Handle(r.Context(), headers, body); err != nil {
        switch {
        case errors.Is(err, billingrail.ErrInvalidSignature):
            http.Error(w, "bad signature", http.StatusBadRequest)
        case errors.Is(err, billingrail.ErrUnsupportedEvent):
            w.WriteHeader(http.StatusNoContent) // tell rail not to retry
        default:
            http.Error(w, "sink failed", http.StatusInternalServerError) // rail will retry
        }
        return
    }
    w.WriteHeader(http.StatusOK)
})
```

## Event taxonomy

| Constant | Sink method called by Dispatcher |
|---|---|
| `EventChargeSucceeded` | `RecordCharge` (status=succeeded) |
| `EventChargeFailed` | `RecordCharge` (status=failed) |
| `EventChargeRefunded` | `RecordRefund` |
| `EventSubCreated` | `RecordSubscriptionEvent` |
| `EventSubUpdated` | `RecordSubscriptionEvent` |
| `EventSubCanceled` | `RecordSubscriptionEvent` |
| `EventSubRenewed` | `RecordSubscriptionEvent` |
| `EventSubTrialEnded` | `RecordSubscriptionEvent` |

Adapters MAP rail-native event names (Stripe's `payment_intent.succeeded`, Apple's `DID_RENEW`, etc.) to these constants. Unknown events surface as `ErrUnsupportedEvent` from `Dispatcher.Handle`.

## Idempotency contract

- **Charge / Refund / Subscription writes**: the consumer mints `IdempotencyKey` and the rail enforces dedup. Adapters MUST pass the key through unchanged.
- **Webhook processing**: rails redeliver. The sink MUST dedupe on `WebhookEvent.RailEventID`. The dispatcher does NOT retry; sink errors return up so the HTTP layer can return 5xx and let the rail retry.

## Signature verification

Always done in `ParseWebhook` by the adapter. `Dispatcher.Handle` returns `ErrInvalidSignature` for bad signatures and DOES NOT call the sink. Convert to HTTP 400 (do not retry).

## Money handling

`Money` carries amounts in **minor units** (cents, pence, etc.). Adapters convert to and from rail-native representations. Currency uses ISO-4217 alpha-3 codes (lowercase preferred to match Stripe).

## Testing

`MockRail` and `MockSink` are part of the public API:

```go
rail := &billingrail.MockRail{
    ParseWebhookResp: billingrail.WebhookEvent{
        Type:     billingrail.EventChargeSucceeded,
        Customer: billingrail.Customer{ID: "cust_1"},
        Amount:   billingrail.Money{AmountMinor: 1500, Currency: "usd"},
        ChargeID: "ch_test_1",
    },
}
sink := &billingrail.MockSink{}
d := billingrail.NewDispatcher(rail, sink)

if err := d.Handle(ctx, headers, body); err != nil {
    t.Fatal(err)
}
if len(sink.ChargeCalls) != 1 {
    t.Errorf("expected 1 charge")
}
```

## Stability

Beta. The interface is stable; method additions to `Rail` or `EdenBizSink` are intentionally avoided to keep adapters portable. `EventType` and status constants are append-only.

## Migration notes

Per-product Stripe code (in eden-biz, justinforme, AOFamily, etc.) will migrate to consuming this package once the Stripe adapter ships. Until then, those callsites stay where they are.
