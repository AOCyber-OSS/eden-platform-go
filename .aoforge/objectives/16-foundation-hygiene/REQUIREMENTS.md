# Objective 16 — Platform Foundation Hygiene Consolidation

**Maps to roadmap requirement:** R26
**Source:** `PORTFOLIO_STANDARDIZATION_PLAN.md` §4 Phase 1A items #1–4
**Milestone:** M1 (Tier-A consolidation done)
**Workstream:** ws-platform-foundation (Wave 1, gates the largest downstream fan-out)

## Scope

Consolidate four foundational Tier-A duplications into single sources of truth in `eden-platform-go/platform/`:
1. `audit`
2. `observability`
3. `encryption`
4. `config`

This objective is **platform-side only** — it promotes platform packages and documents canonical APIs so downstream workstreams (eden-biz, aosentry, aodex, aofamily) can migrate consumers in their own PRs.

## Out-of-scope here
- Migrating consumer code (eden-biz/audit, aosentry/audit, aodex consumers) — those happen in their own workstreams once these packages stabilize.
- `platform/session`, `platform/apikey`, `platform/rbac`, `platform/webhook` (covered by other objectives).

## Detailed Requirements

### R26.1: Audit Pipeline Unification (TRD-01)
- Extend `platform/audit` so it can absorb the patterns we know exist in `aosentry/audit` and `eden-biz/audit`:
  - First-class `Action` constants (most-used domains)
  - HTTP-aware request metadata helper (extract IP / user-agent into Event)
  - Structured `Details` JSON shape with `before/after` semantics for change events
  - Synchronous fallback (`LogSync`) when consumers cannot tolerate dropped events
- Document audit event schema in `platform/audit/README.md`
- Public-API test coverage for every export
- No consumer migration here.

### R26.2: Observability Consolidation (TRD-02)
- Promote and consolidate the slog + sentry helpers:
  - Re-export `errortrack` helpers under canonical paths so consumers have one entrypoint
  - Provide a `MustInit(cfg)` boot helper and `SetupSlog(cfg)` that wires the Sentry-aware multi-handler
  - Add OpenTelemetry trace-context propagation hooks on the existing interceptor (logs include trace_id / span_id when available; no-op when not)
- Document the canonical observability surface in `platform/observability/README.md`
- Public-API test coverage of every export

### R26.3: Encryption Reconciliation (TRD-03)
- `platform/encryption` is already production-grade — reconcile feature parity vs. aosentry/pkg/crypto and eden-biz/internal/crypto patterns we know about:
  - `EncryptString` / `DecryptString` convenience helpers
  - Key parsing from base64/hex/file (matches Eden-Biz `KeyFromEnv`)
  - Versioned ciphertext envelope (`v1:` prefix) so future key rotations are non-breaking
  - HMAC blind-index helpers for case-insensitive lookups (`BlindIndexLower`)
- Document migration guide in `platform/encryption/README.md` (including key derivation compatibility for at-rest data)
- Public-API test coverage

### R26.4: Config Promotion (TRD-04)
- Promote `platform/config` from alpha → beta:
  - Generic typed env-var loaders (`GetInt`, `GetBool`, `GetDuration`, `MustGet`, `Required`)
  - Multi-environment override: `LoadFor(env)` helper; document `.env.{environment}` precedence convention
  - First-class secret loading via `_FILE` (already present) plus support for `_BASE64` decoded secrets
  - `Validate()` function on `PlatformConfig` so consumers fail fast with a clear list of missing required values
- Document standard env-var loading conventions in `platform/config/README.md`
- Public-API test coverage

## Test Coverage Gate (per `PORTFOLIO_STANDARDIZATION_PLAN.md` §10)
- Every package in this objective has unit tests covering all public APIs.
- Integration test stays out of scope here (no consumer in this repo wires audit→metric→trace end-to-end). It is added as part of Objective 17 / 18 when downstream consumers integrate.

## Migration Discipline
- Backward-compatible changes only. No existing public symbol changes shape; new symbols are additive.
- Each TRD = single atomic commit on `ws-platform-foundation` branch.

## Exit Criteria
- All four packages have ≥1 README.md documenting their canonical surface.
- All four packages have unit-test coverage of every public API symbol.
- `go test ./...`, `go vet ./...`, `go build ./...` all pass for `eden-platform-go`.
- PR opened against `main` and merged.
