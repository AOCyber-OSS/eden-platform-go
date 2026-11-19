---
objective: platform-identity-issuer
trd: 01
subsystem: platform/identity
tags: [identity, authentication, seams, generics]
requires: []
provides:
  - Authentication (Subject, Factors, PhishingResistant, HardwareBacked)
  - Factor / FactorKind (knowledge, possession, inherence)
  - Authentication.Validate, Authentication.Kinds
  - CredentialVerifier[C any], ClaimsResolver, Grant
affects: []
tech-stack:
  added: []
  patterns:
    - generic seam over a consumer-supplied type, following the PrincipalLoader[P any] precedent already in this repository
key-files:
  created:
    - platform/identity/authentication.go
    - platform/identity/authentication_test.go
  modified: []
decisions:
  - Kinds reports categories in a fixed canonical order rather than first-appearance order, so one authentication described two ways yields one answer
  - Kinds reports only recognised categories, so an unrecognised one can never inflate a level even if a caller skips Validate; Validate is what rejects it outright
  - Validation failures are separately matchable with errors.Is — they surface to the code assembling the authentication, not across a trust boundary
metrics:
  tasks: 1
  tests-added: 27
completed: 2026-08-19
---

# Objective platform-identity-issuer TRD 01: Issuance Seams Summary

Two narrow seams an application issues identity contexts through, plus the
authentication result that records what a credential verification actually
established — with category deduplication living in `Kinds()` so assurance is
derived from independent lines of defence rather than from prompt count.

## What Was Built

`platform/identity/authentication.go` adds, additively and without touching any
existing file:

- `FactorKind` with the three classical categories. Doc comments call out the
  category most often mis-assigned: a one-time code and a printed recovery code
  are both **possession**, because what is demonstrated is custody of the seed
  or the code sheet, not memory of a secret.
- `Factor` — a category plus a free-form `Method`. `Method` exists for audit
  records; no decision in the package is made by matching on it, which is the
  guess the type is shaped to prevent.
- `Authentication` — subject, the factors exercised, and the two properties a
  verifier **asserts** (`PhishingResistant`, `HardwareBacked`). Both are
  documented as assertions from the verifier that saw the exchange, never
  inferences from a method name.
- `Validate()` — rejects a nil authentication, an empty subject, an empty
  factor slice, an unrecognised or empty category, and a factor with no method.
  Five separately matchable sentinel errors.
- `Kinds()` — distinct recognised categories, canonical order, freshly
  allocated. Deduplication happens here once, so TRD 02 only counts.
- `CredentialVerifier[C any]`, `ClaimsResolver`, `Grant{Tenant, Entitlements}`.

## Deviations from Plan

None — TRD executed exactly as written.

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1 (RED) | `go test ./platform/identity/ -count=1` | 1 | FAIL as intended (build failed: undefined Authentication, Grant, CredentialVerifier, ClaimsResolver, Factor) |
| 1 (GREEN) | `go test ./platform/identity/ -race -count=1` | 0 | PASS |
| 1 | `go vet ./platform/identity/` | 0 | PASS |
| 1 | `gofmt -l platform/identity/` | 0 | PASS (empty) |
| 1 | `git diff --exit-code go.mod go.sum` | 0 | PASS (unchanged) |

## TDD Evidence

| Phase | Command | Exit Code | Expected |
|---|---|---|---|
| RED | `go test ./platform/identity/ -count=1` | 1 | FAIL (correct) |
| GREEN | `go test ./platform/identity/ -race -count=1` | 0 | PASS (correct) |
| REFACTOR | not needed | — | — |

Test count moved 225 → 252 PASS, 0 SKIP, 0 FAIL. All 225 pre-existing tests
still pass.

## Post-TRD Verification

- Auto-fix cycles used: 0
- Must-haves verified: 10/10
- Gate failures: None

## Commits

- `a44af6b` test(platform-identity-issuer-01): specify the issuance seams and the authentication result
- `d0f8cce` feat(platform-identity-issuer-01): add the authentication result and the issuance seams

## Self-Check: PASSED
