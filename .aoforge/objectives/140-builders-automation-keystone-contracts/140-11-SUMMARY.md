---
objective: 140-builders-automation-keystone-contracts
trd: "11"
subsystem: platform/experience
tags: [transport-agnostic-binding, repository-abstraction, aocore-rest, connect, org-scope, company-scope, tdd, cassette]
requires: [140-04, 140-09]
provides:
  - experience.Repository (backend-neutral Get/List/Create/Update/Delete abstraction)
  - experience.RepositoryFor (transport x scope selector)
  - Connect/COMPANY stub repo + aocore-REST/ORG cassette-replayed stub repo
  - experience.ErrTransportNotSupported (forward-compat typed error)
  - fixtures/cassettes/aocore_org.json (committed org-scoped aocore cassette)
affects: [140-12-binding-freeze-gate]
tech-stack:
  added: []
  patterns: [one-interface-two-transports, httptest-cassette-replay, repo-chokepoint-scope-enforcement, no-existence-oracle]
key-files:
  created:
    - platform/experience/repository.go
    - platform/experience/repository_connect_stub.go
    - platform/experience/repository_aocore_rest_stub.go
    - platform/experience/repository_test.go
    - platform/experience/fixtures/cassettes/aocore_org.json
  modified: []
decisions:
  - "RESERVED TransportKind in the test-list maps to the proto's UNSPECIFIED (proto FROZEN, no RESERVED enumerant); UNSPECIFIED is the not-yet-bindable forward-compat case rejected via ErrTransportNotSupported."
  - "aocore-REST stub makes REAL loopback HTTP requests to an in-process httptest server replaying a committed cassette — the REST transport is genuinely exercised while staying fully offline (no live aocore call)."
  - "Scope enforced at a shared repo chokepoint (authorizeScope re-projects from the ONE AoidIdentity) BEFORE any HTTP/data access; forged/cross-org contexts never reach the cassette server."
metrics:
  duration: ~18m
  completed: 2026-06-29
---

# Objective 140 TRD 11: Transport-Agnostic Binding Proof (stub aocore-REST Repository) Summary

ONE `Repository` abstraction (Get/List/Create/Update/Delete over a backend-neutral `Entity`, honoring pagination + a `ScopedContext`) now backs BOTH a CONNECT/COMPANY stub (eden-biz-shaped, in-memory fixtures) AND a REST_OPENAPI/ORG stub (aocore-shaped, org-scoped, cassette-replayed over loopback httptest). `RepositoryFor(binding, identity)` selects the impl by `TransportKind x ScopeAuthority`; the SAME surface code (`exerciseSurface`) drives either repo with ZERO transport branching — that sameness is the agnosticism proof and the precondition for freezing must-have #3 (140-12).

## What was built

- **`Repository` interface** (`repository.go`) — backend-neutral `Get/List/Create/Update/Delete(ctx, ScopedContext, ...)` plus `Transport()/Authority()` diagnostics. Neutral `Entity{ID, ScopeID, Fields}`, `PageRequest{Cursor, Limit}`, `Page{Items, NextCursor}`.
- **`RepositoryFor` selector** — keys on `(transport_kind x scope_authority)`: CONNECT×COMPANY → biz stub, REST_OPENAPI×ORG → aocore stub, anything else (incl. UNSPECIFIED) → `(nil, ErrTransportNotSupported)`.
- **Connect/COMPANY stub** (`repository_connect_stub.go`) — biz-shaped in-memory fixtures, company-scoped, chokepoint-authorized.
- **aocore-REST/ORG stub** (`repository_aocore_rest_stub.go`) — org-scoped, edge-signed shape (org id carried in the `/v1/orgs/{org}/tenants` path, NEVER the body). Spins up an httptest server replaying the committed cassette and makes real loopback HTTP requests. Org scope enforced BEFORE the HTTP call.
- **`fixtures/cassettes/aocore_org.json`** — hand-built recorded GET/LIST/CREATE/UPDATE/DELETE org-scoped exchanges (org-fixture-0001).
- **`authorizeScope` shared chokepoint** — re-projects the inbound `ScopedContext` from the ONE `AoidIdentity`; any mismatch (wrong company, wrong org, forged, missing) collapses to a single `ErrScopeDenied` with no existence oracle.

## Agnosticism proof — CONFIRMED across BOTH transports

`TestSurface_IdenticalCode_BothTransports` runs the exact same `exerciseSurface` closure against the Connect/COMPANY repo and the aocore-REST/ORG repo — read (Get), paginated list (List), and write (Create) — with no per-transport branch. The surface is unaware which concrete impl it holds. PASS for both. The binding is proven transport- AND auth-shape-agnostic → freezable.

## Wrong-tenant / cross-org non-leak — CONFIRMED

- `TestConnectCompany_CrossCompany_Denied_NoOracle`: a forged COMPANY context naming `fixtures.WrongTenantID` is denied at the repo chokepoint; `Get(existing)` and `Get(missing)` return the IDENTICAL `ErrScopeDenied` text (no oracle).
- `TestRestOrg_CrossOrg_Denied_NoOracle`: a forged ORG context naming `fixtures.WrongOrgID` is denied BEFORE any cassette request; existing vs missing ids return identical denial. No cross-org data served.

## No-live-call — CONFIRMED

`TestRestOrg_NoLiveCall` asserts the aocore repo's `BaseURL()` is loopback (httptest). The cassette server returns 501 for any unrecorded request, so a drifting caller cannot fall through to a real aocore host.

## Deviations from Plan

**1. [Rule 3 - Blocking] RESERVED TransportKind not in frozen proto.** The TRD test-list named `TransportKind=RESERVED` for the forward-compat "no impl bound" case, but the FROZEN proto has only `UNSPECIFIED/CONNECT/REST_OPENAPI` (no `RESERVED` enumerant). Mapped the forward-compat case to `UNSPECIFIED` — already the not-yet-bindable sentinel per `BindingIsBindable` (140-04) — and asserted a typed `ErrTransportNotSupported`. No proto change. Test renamed `TestRepositoryFor_UnspecifiedTransport_TypedNotSupported`.

No other deviations. No locked decisions re-opened. No proto regen.

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1 (RED) | `go test -count=1 ./platform/experience/...` | non-zero (build failed: Repository/RepositoryFor/Entity undefined) | PASS (failed for the right reason) |
| 2 (GREEN) | `go test -count=1 ./platform/experience/...` | 0 | PASS |
| 2 (GREEN) | `go vet ./platform/experience/...` | 0 | PASS |

## Validation Gate Results

| Gate | Command | Exit Code | Status |
|---|---|---|---|
| lint (scoped) | `go vet ./platform/experience/...` | 0 | PASS |
| test (scoped) | `go test -count=1 ./platform/experience/...` | 0 | PASS |
| build (CI-scope) | `go build ./...` | 0 | PASS |
| vet (CI-scope) | `go vet ./...` | 0 | PASS |

## TDD Evidence

| Phase | Command | Exit Code | Expected |
|---|---|---|---|
| RED | `go test -count=1 ./platform/experience/...` | non-zero (undefined symbols) | FAIL (correct) |
| GREEN | `go test -count=1 ./platform/experience/...` | 0 | PASS (correct) |
| REFACTOR | n/a — minimal impl already clean (dead `mux` removed before commit) | — | — |

## Post-TRD Verification

- Auto-fix cycles used: 0 (compiled + green on first GREEN run after impl)
- Must-haves verified: 3/3 (one abstraction backs both stubs; same surface binds to either; aocore stub org-scoped + cassette-replayed no-live-call)
- Gate failures: None
- Commits: `33e821d` test: RED, `24be680` feat: GREEN
- Branch: `df/140-11-aocore-rest-repo` (off `feat/experience-v1-contracts` tip `ff46343`) — FF-merge back

## Self-Check: PASSED

All 5 created files present; both commit hashes (`33e821d`, `24be680`) found in history.
