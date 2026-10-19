# platform/feature-flags

Runtime feature gating for the Eden portfolio. Beta.

## Purpose

`platform/feature-flags` answers "is feature X turned on for this caller right
now?" It is **distinct** from billing entitlements:

| Question | Use |
|---|---|
| "Is this code path turned on?" | `platform/feature-flags` |
| "Did this caller pay for tier X?" | `platform/entitlements` (Eden-Biz) |
| "Did the rail process the payment?" | `platform/billing-rail` |

The three compose. A feature is shown to a user only when the flag is on AND
the entitlement is satisfied:

```go
if !flags.IsEnabled(ctx, "household_billing", featureflags.Eval{TenantID: t}) {
    return ErrFeatureDisabled
}
if !ent.HasEntitlement(ctx, customer, "household_billing") {
    return ErrUpgradeRequired
}
// proceed
```

## Quickstart

```go
import featureflags "go.aocyber.ai/eden-platform-go/platform/feature-flags"

src := featureflags.NewMemorySourceWithFlags(
    featureflags.Flag{Key: "new_dashboard", Enabled: true},
    featureflags.Flag{
        Key:     "billing_v2",
        Enabled: true,
        Rollout: &featureflags.Rollout{Percentage: 25, Salt: "billing_v2"},
    },
)
client := featureflags.New(src)

if client.IsEnabled(ctx, "new_dashboard", featureflags.Eval{TenantID: tenantID}) {
    // ...
}

// Variant flags
name, value, ok := client.Variant(ctx, "checkout_layout", featureflags.Eval{
    SubjectID: userID,
    TenantID:  tenantID,
})
```

## Targeting axes

`Eval` carries the per-call evaluation context:

| Axis | Use |
|---|---|
| `SubjectID` | User / actor id |
| `HouseholdID` | Household scope (Eden Family) |
| `TenantID` | Tenant / company id |
| `Environment` | "dev" / "staging" / "prod" |

All axes are optional; an empty `Eval` matches only environment-agnostic flags.

## Resolution order

For a given `Flag` and `Eval`:

1. **Master switch** — if `Flag.Enabled == false`, the result is OFF.
2. **Best-matching override** — overrides match by axis equality (empty axes
   wildcard). When multiple overrides match, the one pinning more specific
   axes wins (subject > household > tenant > environment). Ties go to the
   earlier-declared override.
3. **Rollout** — if `Flag.Rollout` is set, a deterministic
   `(SubjectID, Salt)` hash decides the bucket. Same subject + salt → same
   bucket forever.
4. **Default** — boolean flags fall through to `Enabled`. Variant flags fall
   through to `Default` if non-empty, otherwise OFF.

## Flag shapes

### Boolean

```go
featureflags.Flag{
    Key:     "household_billing",
    Enabled: true,
    Overrides: []featureflags.Override{
        {Environment: "dev", Value: true},
        {TenantID: "evilco", Value: false},
    },
}
```

### Variant

```go
featureflags.Flag{
    Key:     "checkout_layout",
    Enabled: true,
    Variants: map[string]any{
        "classic":  CheckoutClassic,
        "express":  CheckoutExpress,
        "two_step": CheckoutTwoStep,
    },
    Default: "classic",
    Overrides: []featureflags.Override{
        {TenantID: "early-access-co", Value: "express"},
    },
}
```

`IsEnabled` on a variant flag returns true when the resolved variant equals
`Default`. Use `Variant` for direct variant inspection.

## Sources

The `Source` interface decouples evaluation from storage:

| Implementation | Use |
|---|---|
| `MemorySource` | Tests; small static configs at boot. Threadsafe. |
| `EnvSource` | Boolean flags via `FEATURE_FLAGS_<KEY>` env vars. |
| Custom (e.g. Eden-Biz API, Unleash, ConfigCat) | Wrap a remote service; cache aggressively. |

`Source.Lookup` should be cheap. The Client treats it as the read-mostly hot
path and does not internally cache results — wrap your remote source with a
cache layer if you need one.

### EnvSource example

```bash
FEATURE_FLAGS_HOUSEHOLD_BILLING=true
FEATURE_FLAGS_NEW_DASHBOARD=false
```

### Custom source

```go
type EdenBizSource struct{ client *edenbiz.Client }

func (s *EdenBizSource) Lookup(ctx context.Context, key string) (featureflags.Flag, bool, error) {
    // RPC + cache + decode → featureflags.Flag
}
```

When `Lookup` returns an error, the Client defaults to OFF and forwards the
error to the optional `ErrorLogger`:

```go
client := featureflags.New(src).WithErrorLogger(func(key string, err error) {
    log.Warn("feature flag lookup failed", "key", key, "err", err)
})
```

## Boundary vs `platform/entitlements`

`platform/entitlements` answers tier-aware billing questions backed by
Eden-Biz's bootstrap cache. It already exposes a `FeatureFlagClient` that
returns tier-derived feature flags shipped from Eden-Biz.

This package is for **runtime toggles** — the kind that get flipped during a
deploy or experiment, not the kind that change when a customer upgrades. Use
the appropriate one:

- Operator toggle, gradual rollout, kill switch → `platform/feature-flags`
- Tier upgrade, paid feature, plan-driven gating → `platform/entitlements`

You will frequently use both in one decision. That's fine.

## Stability

Beta. Public API is stable; additions are non-breaking. The `Source`
interface is the integration contract — implementing it lets a flag store
plug in without touching the Client.
