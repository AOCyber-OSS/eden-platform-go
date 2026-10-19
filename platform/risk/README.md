# `platform/risk` — Rule-Based Risk Evaluator

[`risk`](.) is the AUTH-07 risk-evaluation primitive for the Eden platform.
It scores every authentication attempt on a [0, 100] scale by running a
configurable, ordered list of pluggable `Signal` implementations and summing
their weights. The score plus a verbose `Triggered` trace is surfaced to the
caller so the audit pipeline can capture *why* a score was produced — not
just the number.

The package is **interpretable by design**: signals are rule-based, not
ML-driven. FedRAMP auditors strongly prefer explainable risk decisions; ML
ensembles can be added later as additional `Signal` implementations without
changing the orchestrator or the audit contract.

**Donor:** none — fresh primitive for AOID Obj 9, designed to be reusable by
any future Eden service that authenticates users.

---

## SLO

| Metric                | Target          | Measured (M4 Max, 8 baseline signals, fake lookups) |
| --------------------- | --------------- | --------------------------------------------------- |
| `Evaluator.Eval` p99  | **< 10 ms**     | ~60 ns/op (165000x headroom)                        |
| Single Signal latency | sub-millisecond | < 1 µs for in-process signals                       |

The SLO assumes a **warm** GeoIP DB — the underlying `*maxminddb.Reader` is
memory-mapped, so cold-start lookups can spike on the first miss. Operators
SHOULD warm the cache at boot by running a synthetic lookup against a known
IP.

Hot-path I/O is restricted to:

1. `HistoricalLookups` queries — implemented by the caller (typically AOID
   over Postgres). Caller is responsible for pooling, prepared statements,
   and result caching.
2. `GeoIPLookup.Lookup` — in-process mmap read, no network.

Signals MUST NOT perform external network calls.

---

## Default v1 Signal Set

| Signal                    | Weight | Triggers when …                                                                  | Depends on            | Tunable via                                                |
| ------------------------- | -----: | -------------------------------------------------------------------------------- | --------------------- | ---------------------------------------------------------- |
| `geo_velocity_anomaly`    |     25 | distance/Δt between last login geo and current geo ≥ 900 km/h                    | GeoIP, Historical     | `WithVelocityThreshold`, `WithSignalWeight`                |
| `new_geo_country`         |     15 | current country never appeared in `RecentAttempts(window)`                       | GeoIP, Historical     | `WithHistoryWindow`, `WithSignalWeight`                    |
| `new_device_fingerprint`  |     10 | sha256(UA + Accept-Language) not in `KnownDeviceFingerprints(window)`            | Historical            | `WithHistoryWindow`, `WithSignalWeight`                    |
| `ua_mismatch_from_baseline` |    5 | UA family token differs from every recent attempt's UA family                    | Historical            | `WithHistoryWindow`, `WithSignalWeight`                    |
| `failed_attempt_recency`  |     15 | ≥ N failures in window M (default 3-in-15 min)                                   | Historical            | `WithFailureThreshold`, `WithSignalWeight`                 |
| `tor_anonymizer_ip`       |     30 | source IP is on the operator's anonymizer / Tor exit-node list                   | Historical            | `WithSignalWeight`                                         |
| `impossible_travel`       |     40 | velocity ≥ 900 km/h (specialization of `geo_velocity_anomaly` at the same bar)   | GeoIP, Historical     | `WithVelocityThreshold`, `WithSignalWeight`                |
| `mfa_bypass_attempted`    |     50 | `PolicyContext["mfa_required"]==true` AND `mfa_factors_presented`==0             | PolicyContext         | `WithSignalWeight`                                         |

`geo_velocity_anomaly` and `impossible_travel` will both fire at high
velocities — that's intentional. The combined `25 + 40 = 65` score escalates
beyond what either signal would produce alone, and the per-signal trace lets
auditors see both reasons in the `RiskAttestation` record.

A signal MUST treat **missing input data as "no trigger"**. There are no
false positives from null IPs, empty User-Agents, empty histories, or nil
PolicyContext maps.

---

## Wiring Example

```go
package main

import (
    "context"
    "log/slog"
    "net/http"
    "time"

    "go.aocyber.ai/eden-platform-go/platform/risk"
    "github.com/google/uuid"
)

func newRiskEvaluator(historicalLookups risk.HistoricalLookups, dbPath string) *risk.Evaluator {
    // GeoIP — degrades gracefully if dbPath is missing.
    geo := risk.NewMaxMindGeoIP(dbPath)
    if !geo.Healthy() {
        slog.Warn("risk: GeoIP DB not available; geo signals will no-op")
    }

    // Compose the per-tenant signal set. Operators can vary this list per
    // tenant by reading their policy and constructing a separate Evaluator.
    signals := []risk.Signal{
        risk.NewMFABypassAttemptedSignal(),
        risk.NewImpossibleTravelSignal(),
        risk.NewTorAnonymizerIPSignal(),
        risk.NewGeoVelocityAnomalySignal(),
        risk.NewFailedAttemptRecencySignal(),
        risk.NewNewGeoCountrySignal(),
        risk.NewNewDeviceFingerprintSignal(),
        risk.NewUAMismatchFromBaselineSignal(),
    }
    return risk.NewEvaluator(signals)
}

func evaluateLogin(ctx context.Context, eval *risk.Evaluator, hist risk.HistoricalLookups,
    geo risk.GeoIPLookup, r *http.Request, tenantID, accountID uuid.UUID,
    mfaRequired bool, factorsPresented int,
) risk.Result {
    req := risk.Request{
        TenantID:       tenantID,
        AccountID:      accountID,
        SourceIP:       r.RemoteAddr,
        UserAgent:      r.Header.Get("User-Agent"),
        AcceptLanguage: r.Header.Get("Accept-Language"),
        AttemptedAt:    time.Now(),
        PolicyContext: map[string]any{
            "mfa_required":          mfaRequired,
            "mfa_factors_presented": factorsPresented,
        },
        HistoricalLookups: hist,
        GeoIP:             geo,
    }
    return eval.Eval(ctx, req)
}
```

### Per-tenant tuning

```go
strictSignals := []risk.Signal{
    risk.NewGeoVelocityAnomalySignal(
        risk.WithVelocityThreshold(500), // tighter than the 900 default
        risk.WithSignalWeight(30),       // bump weight
    ),
    risk.NewFailedAttemptRecencySignal(
        risk.WithFailureThreshold(2, 5*time.Minute),
    ),
    // ... omit signals not relevant to this tenant
}
strictEval := risk.NewEvaluator(strictSignals, risk.WithClip(100))
```

---

## Integration Contract

Callers provide two interfaces:

### `HistoricalLookups`

```go
type HistoricalLookups interface {
    RecentAttempts(ctx context.Context, accountID uuid.UUID, window time.Duration) ([]Attempt, error)
    KnownDeviceFingerprints(ctx context.Context, accountID uuid.UUID, window time.Duration) ([]string, error)
    LastLoginGeo(ctx context.Context, accountID uuid.UUID) (*GeoLocation, error)
    IsAnonymizerIP(ctx context.Context, ip net.IP) (bool, error)
}
```

AOID's TRD 09-05 implements this against:

- `aoid.auth_attempts` for `RecentAttempts` and `LastLoginGeo` (the
  most-recent successful row's `source_country`, `source_city`, `lat`,
  `lng`, `attempted_at`).
- `aoid.account_known_devices` for `KnownDeviceFingerprints`.
- An operator-supplied anonymizer IP list (refreshed weekly via cron) for
  `IsAnonymizerIP`.

All methods MUST be safe for concurrent use and cheap on the hot path
(milliseconds, not seconds — see SLO above).

### `GeoIPLookup`

```go
type GeoIPLookup interface {
    Lookup(ip net.IP) (*GeoLocation, error)
    RefreshedAt() time.Time
    Healthy() bool
}
```

Two implementations ship in this package:

- `*MaxMindGeoIP` — wraps a memory-mapped GeoLite2-City.mmdb or GeoIP2-City
  via `github.com/oschwald/maxminddb-golang/v2`. Safe for concurrent
  `Lookup` calls; close via `Close()`.
- `*NoOpGeoIP` — sentinel returned by `NewMaxMindGeoIP` when the DB file is
  missing or corrupt. Every `Lookup` returns `(nil, nil)`. `Healthy()` is
  false.

`NewMaxMindGeoIP` **never returns nil** — geo-dependent signals will simply
no-op if the DB is unavailable. This matters in air-gapped IL5 deployments
where operators can't pull a MaxMind DB at deploy time.

---

## Failure Modes

| Condition                                       | Behavior                                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------------------ |
| `HistoricalLookups` is `nil`                    | Every historical signal no-ops (returns triggered=false).                            |
| `HistoricalLookups.X` returns an error          | Caller logs; signal treats it as no-data and no-ops.                                 |
| `GeoIPLookup` is `nil`                          | Every geo signal no-ops.                                                             |
| MaxMind DB file is missing                      | `NewMaxMindGeoIP` returns `*NoOpGeoIP`; `slog.Warn` emitted. `Healthy()`=false.      |
| MaxMind DB file is corrupt                      | Same as missing: `NoOpGeoIP` fallback.                                               |
| `SourceIP` empty or unparseable                 | IP-dependent signals no-op.                                                          |
| `UserAgent` empty                               | UA-dependent signals no-op.                                                          |
| `AccountID` is `uuid.Nil`                       | Historical signals no-op (no account → no history).                                  |
| `PolicyContext` is `nil`                        | Policy-dependent signals (`mfa_bypass_attempted`) no-op.                             |

The package **never panics** for any input. A `Request{}` zero-value yields
a clean `Result{Score: 0, Triggered: []}`.

---

## Operating the MaxMind DB

The DB file is **operator-supplied** — the package ships no GeoIP data.

- **GeoLite2-City** (free tier from MaxMind) requires registration,
  attribution, and EULA-bound use. Update weekly via the MaxMind
  `geoipupdate` tool or a customer-managed mirror.
- **GeoIP2-City** (commercial) has stricter terms; consult MaxMind for
  redistribution rules inside AOID's deployment.
- **Air-gapped IL5**: customers procure their own MaxMind license and
  bind-mount the DB into the AOID container at a known path. AOID's deploy
  manifest exposes `AOID_RISK_GEOIP_PATH` (TRD 09-05) for the bind-mount.

Atomic DB replacement is the operator's responsibility: drop the new file
at the same path while AOID is running, then restart the AOID process to
pick it up. Live reload via inotify is **out of scope** for v1.

---

## Future Extensions

The `Signal` interface is intentionally minimal (`Name() + Evaluate()`) so
future work can plug in:

- **ML / ensemble models**: implement `Signal` that wraps an in-process
  inference call. Score and weight remain interpretable to auditors via
  the `Details` map.
- **Remote behavior-analytics services**: implement `Signal` that calls a
  separate behavior service via Connect. Beware the SLO — these signals
  MUST budget their RPC tightly (<10 ms total Eval budget).
- **Per-tenant Bayesian priors**: implement an Option that adjusts weights
  per tenant based on observed false-positive rates. Out of scope for v1
  but the API is forward-compatible.

Adding a new signal does not break callers. Adding new methods to the
`Signal` interface DOES — keep the interface stable.

---

## See also

- AOID TRD 09-05 (`aoid-risk-service`) — consumer of this package.
- AOID TRD 09-04 (`aoid-schema-audit-recovery-recert`) — defines the
  `auth_attempts` and `account_known_devices` schemas that `HistoricalLookups`
  queries.
- `platform/audit` — the Logger that emits the `RiskAttestation` payload
  alongside the `RiskScore` integer.
