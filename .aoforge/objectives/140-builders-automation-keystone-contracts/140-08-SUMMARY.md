---
objective: 140-builders-automation-keystone-contracts
trd: "08"
subsystem: experience
tags: [resolution-filter, content-hash, locked-surface, entitlements-single-source, tenancy, tdd]
requires: ["140-04", "140-06"]
provides:
  - "experience.Resolve(ctx, spec, tuple, cfg) -> resolvedSpec  (server-side FILTER)"
  - "experience.ContentHash(resolvedSpec, tuple)  (tuple-in-preimage cache key)"
  - "experience.ErrResolutionDenied  (single non-leaking tenancy sentinel)"
  - "experience.ResolverConfig{Version, ResolvedAt}"
  - "fixtures.ResolutionTuple + NewTuple/WithResolutionTuple/WithGrantedEntitlements/WrongTenantTuple"
affects:
  - "140-09 M0 validator (composes the same scope-chokepoint / non-leak posture)"
tech-stack:
  added: []
  patterns:
    - "single tenancy chokepoint -> single ErrResolutionDenied sentinel (no existence oracle)"
    - "content-hash preimage = length-framed (deterministic-proto spec bytes ++ canonical tuple bytes)"
    - "entitlement grant = already-evaluated SET (tuple.Granted), rules never ship to device"
key-files:
  created:
    - eden-platform-go/platform/experience/resolve.go
    - eden-platform-go/platform/experience/content_hash.go
    - eden-platform-go/platform/experience/resolve_test.go
  modified:
    - eden-platform-go/platform/experience/fixtures/spec_factory.go
decisions:
  - "Resolution tuple is a Go-only value (NOT a proto field): the resolved spec ships only the RESULT; the tuple lives server-side in the hash preimage + resolver call"
  - "Grant decision is the entitlements service's already-evaluated SET (tuple.Granted), modeled as map[string]struct{} -- resolver never reads verticalpreset.FeatureGates"
  - "ResolvedAt is injected via ResolverConfig (pure function, deterministic, no wall-clock read)"
  - "content_hash is a fixed point: ContentHash zeroes the spec's content_hash before hashing so stamping it back does not change the recomputed value"
metrics:
  duration: "~22m"
  completed: "2026-06-29"
  tasks: "2/2"
  commits: 2
---

# Objective 140 TRD 08: Server-Side Resolution Filter + Content-Hash Preimage + LockedSurface Summary

Server-authoritative `Resolve(spec, tuple)` filter in `platform/experience/`: granted surfaces pass, ungranted referenced surfaces become `LockedSurface{id, upsell_reason}` (so devices render "locked" without ever holding entitlement RULES), a `ResolutionContext{tenant, org, resolved_at, resolver_version}` is stamped, and `content_hash` is computed with the FULL resolution tuple `{role, entitlements, form_factor, tenant, org}` in the preimage — the irreversible cache-key shape, test-locked before any device caches a spec. Proto was NOT touched (frozen at 28f8649); all resolution proto types (`ExperienceSpec.{resolution_context,locked_surfaces}`, `ResolutionContext`, `LockedSurface`) already existed.

## What was built

- **`resolve.go`** — `Resolve(ctx, spec, tuple, ResolverConfig) -> (*ExperienceSpec, error)`:
  - **Tenancy chokepoint (one place):** if `tuple.{TenantID,OrgID}` diverge from `spec.{TenantId,OrgId}` → `ErrResolutionDenied`, a SINGLE non-leaking sentinel identical for wrong-tenant and nonexistent-tenant (no existence oracle). Mirrors `binding.ResolveScope`'s `ErrScopeDenied` and navgraph's `CoherenceSurfaceNotEntitled`.
  - **Filter:** referenced surfaces ∈ `tuple.Granted` pass through; the rest are dropped from `referenced_surface_ids` AND emitted as `LockedSurface` with a non-empty `upsell_reason` (never a silent drop).
  - **No phantom:** a surface granted but NOT referenced by the spec never appears — the server cannot mint an unrequested surface.
  - **Single-source entitlements:** grant = `tuple.Granted` (the entitlements service's already-evaluated result). Never reads `verticalpreset.FeatureGates`.
- **`content_hash.go`** — `ContentHash(resolvedSpec, tuple)`: reuses the biz `website/build_artifact.go` `SHA256Hex` precedent (canonical bytes → SHA-256 → 64-char hex). Preimage = length-framed( `proto.Marshal(Deterministic:true)` of the resolved spec with `content_hash` zeroed ) ++ length-framed( canonical tuple encoding: role|entitlements|form_factor|tenant|org + sorted granted set ). Length-framing makes the spec/tuple boundary collision-free.
- **`fixtures/spec_factory.go`** (extended) — `ResolutionTuple` value + `NewTuple` / `WithResolutionTuple` / `WithGrantedEntitlements` / `WrongTenantTuple` (the tuple analogue of `WrongTenant`).

## Hash-preimage confirmation

**The content-hash preimage includes the FULL resolution tuple `{role, entitlements, form_factor, tenant, org}`** (plus the sorted granted set). `TestContentHash_EveryTupleAxisChangesHash` holds the resolved spec fixed and varies exactly one tuple axis at a time, asserting each of the 5 axes moves the hash — and `TestContentHash_DeterministicForIdenticalInputs` asserts identical inputs reproduce an identical hash. Irreversibility is proven: two users with different role/entitlements get different hashes; identical inputs get the same deterministic hash.

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1: Extend factory + RED tests | `go test ./platform/experience/...` (expect build-fail: undefined Resolve/ContentHash/ResolverConfig/ErrResolutionDenied) | 1 | PASS (RED correct) |
| 2: GREEN filter + hash + LockedSurface | `go vet ./platform/experience/... && go test -count=1 ./platform/experience/...` | 0 | PASS |

## TDD Evidence

| Phase | Command | Exit Code | Expected |
|---|---|---|---|
| RED | `go test -count=1 ./platform/experience/...` | 1 (build failed: 4 symbols undefined) | FAIL (correct) |
| GREEN | `go test -count=1 ./platform/experience/...` | 0 | PASS (correct) |
| RACE | `go test -race -count=1 ./platform/experience/...` | 0 | PASS |

## Validation Gate Results

| Gate | Command | Exit Code | Status |
|---|---|---|---|
| lint | `go vet ./platform/experience/...` | 0 | PASS |
| test | `go test -count=1 ./platform/experience/...` | 0 | PASS |
| race | `go test -race -count=1 ./platform/experience/...` | 0 | PASS |

12 new resolution/content-hash tests added, all passing; full experience package = 68 tests green.

## Test list -> coverage

- Filter: granted pass, ungranted → `LockedSurface{id, non-empty reason}` — `TestResolve_FiltersUngrantedIntoLockedSurfaces`
- `ResolutionContext` stamp (tenant/org/resolved_at/resolver_version) — `TestResolve_StampsResolutionContext`
- No phantom surface — `TestResolve_GrantedButNotInSpec_NoPhantomSurface`
- Deterministic hash for identical inputs — `TestContentHash_DeterministicForIdenticalInputs`
- Every tuple axis in preimage — `TestContentHash_EveryTupleAxisChangesHash`
- Entitlement rules NOT serialized into output — `TestResolve_EntitlementRulesNotSerializedIntoOutput`
- Wrong-tenant: no cross-tenant grant + denial — `TestResolve_WrongTenant_NoCrossTenantGrant`
- Wrong-tenant == nonexistent (no existence oracle) — `TestResolve_WrongTenant_NoExistenceOracle`
- Cross-org non-leaking denial — `TestResolve_CrossOrg_NonLeakingDenial`

## Post-TRD Verification

- Auto-fix cycles used: 1 (scope-aligned the 3 happy-path test specs with their tuples once after first GREEN run; not a behavior change)
- Must-haves verified: 3/3 (server-side filter+LockedSurface; tuple-in-preimage; entitlement single-source)
- Gate failures: None

## Deviations from Plan

None functionally — TRD executed as written. One implementation note (within scope, no permission needed):

- **[Rule 3 - Blocking] Resolver input is the entitlements-service RESULT, not the HTTP client.** The TRD's Task-2 sketch passed an `entitlementsClient`. The existing `platform/entitlements` package is a live HTTP client (`Bootstrap`/`CheckEntitlement`), which would make the resolver impure and HTTP-bound and contradict the must-have ("entitlement RULES never ship / single source = the service's *answer*"). I modeled the grant as the already-evaluated SET on the `ResolutionTuple` (`tuple.Granted`), matching the established `navgraph.ValidateNavGraph(entitled map[string]struct{})` precedent in the same package. The single-source contract is honored (grant = the service's decision, never `verticalpreset.FeatureGates`); wiring the real HTTP `EntitlementClient` to populate `tuple.Granted` at the call site is a thin downstream adapter, not contract logic.

## Branch / commits (for FF-merge)

- **Branch:** `worktree-agent-a11eae9b312e889e5` (in worktree `/Users/markemerson/Source/eden-platform-go/.claude/worktrees/agent-a11eae9b312e889e5`), based on `feat/experience-v1-contracts` HEAD `28f8649` — FF-mergeable back into `feat/experience-v1-contracts`.
- `8c0fbe1` — `test(140-08): RED ...`
- `e750260` — `feat(140-08): GREEN ...`

## Self-Check: PASSED

- FOUND: `platform/experience/resolve.go`
- FOUND: `platform/experience/content_hash.go`
- FOUND: `platform/experience/resolve_test.go`
- FOUND: `platform/experience/fixtures/spec_factory.go` (extended)
- FOUND commit: `8c0fbe1`
- FOUND commit: `e750260`
