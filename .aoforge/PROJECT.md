---
org: AO-Cyber-Systems
github_repo: AO-Cyber-Systems/eden-platform-go
---

# Project

## What this is

`eden-platform-go` is the Go backend platform that every Eden-family product
consumes for shared infrastructure: auth, RBAC, audit, webhooks, household /
parent-of-record modeling, consent ledger, feature flags, billing rail,
storage, attachments, jobs, rate limiting, real-time, scheduler, web-fetch,
AI gateway, and the platform `connectapi` handler surface.

It also owns:

- The **protobuf contracts** in `proto/platform/v1` — the single source of
  truth for backend ↔ frontend communication.
- The generated **Go** clients/handlers under `gen/go` (generated; never
  hand-edited).
- The **AO ID standalone OIDC service** (`cmd/aoid` + `internal/aoid`) — a
  second binary in this repo that will graduate to its own deployment once
  Obj 30/31 fully harden the issuer + federation surface.
- The **PostgreSQL migrations** under `migrations/platform/` and sqlc query
  sources under `queries/platform/`.

## Position in the workspace

This repository is **one of several siblings** under
`/Users/justin/dev/eden-libs/`. The parent workspace owns the portfolio-wide
strategy:

- **`eden-libs/PORTFOLIO_STANDARDIZATION_PLAN.md`** — the locked decisions
  (D1–D13), six-workstream layout, and milestone-level (M1–M9) sequencing.
  M9 was reached 2026-05-11.
- **`eden-libs/CAPABILITIES.md`** — the canonical scoping reference for new
  products. Section 6 documents `eden-platform-go` in detail.
- **`eden-libs/.planning/`** — the canonical portfolio DevFlow state.
  `ROADMAP.md` there lists Objectives 1–33 spanning all sibling repos.

`eden-platform-go/.planning/` (this directory) is therefore a **child**
DevFlow context. Use it for repo-local quick tasks and per-objective TRDs
that ship as eden-platform-go code; consult the parent for cross-repo
ordering and portfolio milestones.

## Current focus

- **Post-M9 maintenance** — production hardening of the standardized
  platform: integration-bug fixes (issue #20 households-name collision,
  PR #21 streaming-interceptor security gap), CI infrastructure repair
  (PR #22 driver scheme + aoid-smoke staleness + sqlc pinning).
- **AO ID continued buildout** — incremental work tracked via commit
  prefixes (`aoid-09-*`, `aoid-11-*`, `10-0*`, `13-0*` for KMS) ahead of
  the next portfolio-level objective stand-up. The canonical AO ID plan
  lives in `eden-libs/.planning/objectives/29-aoid-service-scaffold/`,
  `30-aoid-oidc-issuer-aodex-pilot/`, and
  `31-aoid-federation-decommission/`.

## Requirements

### Validated (shipped, tests green, in use by ≥1 consumer)

| Surface | Reference | Consumers |
|---|---|---|
| `platform/{audit,observability,encryption,config}` | Obj 16 (M1) | eden-biz, AOSentry, AODex |
| `platform/{rbac,webhook}` | Obj 17 | platform-internal + eden-biz |
| `platform/{jobs,ratelimit,realtime,email,storage,attachments,statemachine,scheduler,webfetch}` | Obj 18–20 (M2) | Tier-B promotions |
| `platform/auth` (full absorption inc. SAML SP+IdP, sessions, apikey) | Obj 22 (M4), Obj 23 | AODex (post-migration), eden-biz |
| `platform/household` + `platform/consent` | Obj 24, 25 | AOFamily-AI, Eden Family (launching) |
| `platform/{feature-flags,billing-rail}` | Obj 27 | Eden Family billing |
| `platform/livekit` | Obj 28 | AOFamily realtime |
| `platform/aigateway` | Obj 26 | eden-circle, eden-biz/docprocessing, aohealth-go, justinforme, smartWellness, aofamily-{ai,browser} |
| `cmd/aoid` (OIDC discovery + JWKS, issuer active per Obj 30 Phase A) | Obj 29 + 30A | AODex (pilot client) |
| Eden Family platform integration (cross-package end-to-end) | Obj 33 (M9) | AOFamily (Eden Family launch) |

### Active

- AO ID issuer hardening, KMS signer integration, audit-pipeline OTLP sink,
  policy-cache infrastructure, federation surface. Tracked via commit
  prefixes; objective stand-up TBD.

### Out of scope for this repo

- Frontend shell (`eden-platform-flutter`) and UI widgets (`eden-ui-flutter`).
- Generated Dart bindings (`eden-platform-api-dart`).
- Consumer migrations (eden-biz, AODex, AOSentry, AOFamily) — those live in
  their own repos.

## Key decisions

These are the portfolio decisions that constrain this repo. Full rationale
in `eden-libs/PORTFOLIO_STANDARDIZATION_PLAN.md` §2.

- **D2** AO ID is a standalone OIDC service — built in Go, lives in this
  repo as `cmd/aoid` until it graduates to its own deployment.
- **D9** Auth seed = absorb AODex's `internal/auth` wholesale into
  `platform/auth` (done — Obj 22).
- **D10** Eden-Biz infrastructure packages migrate INTO `eden-platform-go`;
  Eden-Biz becomes a pure consumer (done — Obj 21 closed M3).
- **D11** `pkg/` is the portfolio-wide staging convention
  (`internal/` → `pkg/` → eden-libs).
- **Backend/frontend contracts** live in `proto/platform/v1`; generated
  artifacts refresh via `just generate` in the eden-libs root.

## Constraints

- **Go 1.26.x** (see `go.mod`); CI pins matching version in
  `.github/workflows/ci.yml`.
- **Connect-Go** for RPC (not grpc-go). Server-streaming RPCs MUST go
  through the streaming-aware interceptor chain in `platform/server`
  (PR #21 fix).
- **sqlc v1.30.0** for query generation; CI pins this in
  `sqlc verify`. Bumping requires regenerating and committing the new
  version-comment headers.
- **golang-migrate with pgx/v5 driver only** — `DATABASE_URL` must use the
  `pgx5://` scheme. See `platform/pgstore/migrate.go` for the imported
  driver registration.
- **Platform tables are un-prefixed by convention**, with one documented
  exception: `platform_households` / `platform_household_members` /
  `platform_parent_of_record` (see issue #20 + `platform/household/README.md`
  for rationale).
- **`just test`, `just lint`, `just check`** must pass before any PR merge.
  Run from eden-libs root (parent justfile) or per-repo as appropriate.

## Operational notes

- Local Postgres: `pgx5://justin@localhost/<db>?sslmode=disable` works on the
  dev machine; CI uses `pgx5://test:test@localhost:5432/eden_platform_test`.
- Two binaries: `cmd/eden-platform-dev` (workspace dev server),
  `cmd/aoid` (AO ID OIDC service). Both go-build outputs are gitignored.
- PIV/CAC test fixtures live under `platform/mtls/piv/testdata/` and have
  their own regen recipe (see that README).

## See also

- `eden-libs/.planning/STATE.md` — portfolio-wide current position
- `eden-libs/.planning/ROADMAP.md` — Objectives 1–33
- `eden-libs/PORTFOLIO_STANDARDIZATION_PLAN.md` — decision log + workstreams
- `eden-libs/CAPABILITIES.md` §6 — eden-platform-go capability reference
