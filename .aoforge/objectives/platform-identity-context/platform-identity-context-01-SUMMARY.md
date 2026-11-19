---
objective: platform-identity-context
trd: 01
subsystem: auth
tags: [jwt, identity, claims, wire-contract, versioning, go]

# Dependency graph
requires: []
provides:
  - "platform/identity.Claims — the frozen identity-context claim set (tnt/ent/aal/ctx_ver/tok_ref + registered claims)"
  - "platform/identity.JWTType — the identity-context+jwt token type constant"
  - "platform/identity.Version — the schema version this package emits (1)"
  - "platform/identity.VersionSet / NewVersionSet / DefaultVersionSet / Accepts / Versions — the configurable accepted-version set"
  - "platform/identity.Claims.Validate — the single home for semantic claim rules"
  - "platform/identity.TokRef — truncated SHA-256 correlation handle"
  - "Four exported sentinel errors a verifier can collapse into one rejection"
  - "AAL1/AAL2/AAL3 assurance-level constants"
affects: [identity-minter, identity-key-sources, identity-verifier, identity-roundtrip-tests]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Tag-level wire assertions: marshal, decode into map[string]any, assert on JSON keys"
    - "Accepted-version set as injected configuration with a fail-closed zero value"
    - "Semantic validation lives in exactly one place; sentinel errors let callers collapse it"

key-files:
  created:
    - platform/identity/claims.go
    - platform/identity/claims_test.go
  modified: []

key-decisions:
  - "VersionSet is map[int]struct{} so its zero value accepts nothing — an unconfigured verifier fails closed rather than admitting every version."
  - "DefaultVersionSet() allocates a fresh set per call, so a caller widening its copy cannot reach another caller's."
  - "Validate takes the accepted set as a parameter and therefore deliberately does NOT satisfy jwt.ClaimsValidator — per-consumer configuration must not become package state."
  - "ErrUnsupportedVersion wraps a message naming both the version received and the versions configured, because undiagnosable version drift is the failure this package exists to prevent."
  - "TokRef(\"\") returns \"\" rather than the SHA-256 of the empty string, which would stamp one identical constant onto every context lacking an upstream credential."
  - "Entitlements carries no omitempty, so `ent` is always on the wire — 'no entitlements' stays distinguishable from 'issuer does not speak the claim'."
  - "AAL1/AAL2/AAL3 are defined here rather than in the minter, so TRD 02 does not redeclare contract surface."

patterns-established:
  - "Wire-format tests assert on JSON keys, never on a struct round trip — a round trip passes unchanged through a full tag rename."
  - "Exported sentinel errors + errors.Is at the call site, so a boundary can collapse every reason into one opaque rejection without losing internal detail."

requirements-completed: [IC-01]

# Verification evidence
verification:
  gates_defined: 3
  gates_passed: 3
  auto_fix_cycles: 0
  tdd_evidence: true
  test_pairing: true

# Metrics
duration: ~20min
completed: 2026-08-19
---

# Objective platform-identity-context TRD 01: The Claim Contract Summary

**The frozen identity-context claim set, its token type, and a configurable accepted-version set that turns silent cross-service version drift into a deployment-time decision — pinned by tag-level wire assertions rather than a struct round trip.**

## What Was Built

New package `platform/identity` (2 files, 665 lines):

**`claims.go` (238 lines)**

| Symbol | Purpose |
|---|---|
| `Claims` | The frozen claim set: `jwt.RegisteredClaims` + `tnt` / `ent` / `aal` / `ctx_ver` / `tok_ref` |
| `JWTType` | `"identity-context+jwt"` — the `typ` header value |
| `Version` | `1` — the schema version this package emits |
| `AAL1` / `AAL2` / `AAL3` | Assurance levels reported in `aal` |
| `VersionSet` | `map[int]struct{}`; zero value accepts nothing |
| `NewVersionSet(...int)` | Build an arbitrary accepted set |
| `DefaultVersionSet()` | Exactly `{1}`; a fresh set per call |
| `VersionSet.Accepts(int)` | Membership |
| `VersionSet.Versions()` | Members ascending, for diagnostics |
| `Claims.Validate(VersionSet)` | The semantic rules a JWT parser does not apply |
| `TokRef(string)` | First 8 bytes of SHA-256, hex, 16 lowercase chars |
| `ErrUnsupportedVersion`, `ErrMissingSubject`, `ErrMissingTenant`, `ErrMissingAssurance` | Sentinels for `errors.Is` |

A compile-time assertion (`var _ jwt.Claims = (*Claims)(nil)`) pins that `Claims` drops straight into `jwt.NewWithClaims` / `jwt.ParseWithClaims`, which TRDs 02 and 04 depend on.

**`claims_test.go` (427 lines)** — 20 test functions, 18 subtests.

## TDD Evidence

Two commits, strictly ordered. The RED commit contains **only** `claims_test.go`; the package could not build at that revision.

| Phase | Commit | Command | Exit | Expected |
|---|---|---|---|---|
| RED | `8682b90` | `go test ./platform/identity/ -race -count=1 -v` | 1 | FAIL — `undefined: Claims`, `undefined: JWTType`, `undefined: Version`, `undefined: AAL1`, `[build failed]` (correct) |
| GREEN | `1c79f9e` | `go test ./platform/identity/ -race -count=1 -v` | 0 | PASS — 38 PASS, 0 SKIP, 0 FAIL (correct) |

REFACTOR: not needed — implementation landed clean, `gofmt -l` empty, `go vet` clean.

### Mutation check on the load-bearing assertion

The whole TRD turns on one claim: that the marshal test catches a tag rename a struct round trip would sail through. That was verified rather than assumed — `json:"tnt"` was temporarily changed to `json:"tenant"` and the suite was re-run:

```
--- FAIL: TestClaimsMarshalsToExactlyTheFrozenWireKeys (0.00s)
    claims_test.go:100: wire key "tnt" is missing; consumers decode this key by name and would read the claim as unset
    claims_test.go:106: unexpected wire key "tenant"; adding a key is a schema change and needs a version bump, not a struct field
```

The tag was restored (`mv claims.go.bak claims.go`), the sed backup removed, and all gates re-run green on the restored file. The mutation never entered a commit.

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1: Write failing wire + validation tests | `go test ./platform/identity/ -race -count=1 -v` | 1 (build failed — RED) | PASS |
| 2: Implement the contract | `go test ./platform/identity/ -race -count=1 -v` | 0 (38 PASS / 0 SKIP) | PASS |

## Validation Gate Results

| Gate | Command | Exit Code | Status |
|---|---|---|---|
| test | `go test ./platform/identity/ -race -count=1 -v` | 0 | PASS — 38 PASS, 0 SKIP |
| vet | `go vet ./platform/identity/` | 0 | PASS — no output |
| deps | `git diff --exit-code go.mod go.sum` | 0 | PASS — unchanged |
| format | `gofmt -l platform/identity/` | 0 | PASS — no output |

## Must-Haves Verified

| Must-have | Pinned by |
|---|---|
| Marshals to exactly `tnt`, `ent`, `aal`, `ctx_ver`, `tok_ref` + `iss`/`sub`/`iat`/`exp`/`jti` | `TestClaimsMarshalsToExactlyTheFrozenWireKeys` (presence, no extras, exact count) |
| `JWTType == "identity-context+jwt"` byte-for-byte | `TestFrozenTokenType` |
| `Version == 1` | `TestFrozenEmittedVersion` |
| `DefaultVersionSet()` accepts exactly `{1}` | `TestDefaultVersionSetAcceptsOnlyTheEmittedVersion` |
| `{1,2}` accepts both, rejects 3 | `TestVersionSetMembership` |
| Validate rejects bad version / empty sub / empty tnt / empty aal | `TestClaimsValidate` (table, `errors.Is` per row) |
| Validate accepts a fully populated in-set context | `TestClaimsValidate/fully_populated_context_is_accepted` |
| Empty `ent` is valid | `TestClaimsValidate/{nil,empty}_entitlements_are_accepted` |
| `TokRef` = first 8 bytes of SHA-256, 16 lowercase hex | `TestTokRefIsSixteenLowercaseHexCharacters` + known vector `sha256("upstream-access-token")` → `7bcc86737e4b8043` |

Beyond the must-haves, the suite also pins: decoding a hand-written wire document (catches a rename in the read direction), `ent` emitted even when nil, `DefaultVersionSet()` mutation isolation, `Versions()` ordering, fail-closed on a nil/empty set, the version-drift error naming both sides, and that `Validate` never gates on `tok_ref`.

## Deviations from Plan

None affecting the contract. Three judgment calls inside the TRD's remit, each pinned by a test:

1. **`TokRef("")` returns `""`** rather than `e3b0c442...`. Hashing the empty string would stamp one identical constant onto every context with no upstream credential, which reads like a genuine correlation handle in a log. Pinned by `TestTokRefOfAnEmptyTokenIsEmpty`.
2. **Exported sentinel errors added.** The TRD required Validate to reject four conditions; sentinels let the table test assert the *reason* rather than merely non-nil, and give TRD 04 something to collapse. Pinned by `TestClaimsValidate`.
3. **`AAL1`/`AAL2`/`AAL3` constants defined here.** The field semantics enumerate them and the TRD forbids TRD 02 from redeclaring contract surface. Pinned by `TestFrozenAssuranceLevels`.

Unrelated working-tree change: `.planning/PROJECT.md` gained `org` / `github_repo` frontmatter, written by the DevFlow `init` bootstrap, not by this TRD. Carried in the docs commit.

## Authentication Gates

None.

## Repository Hygiene

Swept both new files for private repository/service/product names, internal ticket and design-document references, absolute local paths, branch names and commit hashes — no hits. The only external identifiers present are the module's own import path and `issuer.example` (RFC 2606 reserved). Doc comments were written fresh against the contract's own terms; no other repository was consulted.

## Notes for Downstream TRDs

- **02 (minter):** use `JWTType` for the `typ` header, `Version` for `CtxVer`, the `AAL*` constants for honest assurance, and `TokRef()` for `tok_ref`. `Claims` already satisfies `jwt.Claims`.
- **04 (verifier):** call `Claims.Validate(acceptedSet)` after the parser has checked signature/issuer/expiry — do not re-implement the checks. The accepted set is injected per-issuer configuration; the zero value fails closed. Collapse the four sentinels into the single sentinel error the verifier exposes.
- Anything that changes a JSON tag must instead bump `Version` and widen consumers' sets first.

## Post-TRD Verification

- Auto-fix cycles used: 0
- Must-haves verified: 9/9
- Gate failures: None
- Test count: 20 functions / 38 PASS assertions / 0 SKIP / 0 FAIL
- Line counts: `claims.go` 238, `claims_test.go` 427

## Self-Check: PASSED

- `platform/identity/claims.go` — FOUND
- `platform/identity/claims_test.go` — FOUND
- Commit `8682b90` (RED) — FOUND, contains only `claims_test.go`
- Commit `1c79f9e` (GREEN) — FOUND, contains only `claims.go`
- `go.mod` / `go.sum` — unchanged (`git diff --exit-code` returned 0)

## State Tracking Note

This TRD executed in an isolated worktree branched off `main`, which does not carry
this objective's planning state — `.planning/objectives/platform-identity-context/`
did not exist here and `.planning/REQUIREMENTS.md` is absent on this branch. The
STATE.md / ROADMAP.md / REQUIREMENTS.md mutators (`state advance-job`,
`state update-progress`, `roadmap update-job-progress`,
`requirements mark-complete IC-01`) were therefore deliberately NOT run: against
this branch's state they would have advanced an unrelated objective's counters.
They should be run once this work is merged onto the branch holding the objective's
planning state. `requirements-completed: [IC-01]` in this file's frontmatter is the
record to reconcile from.
