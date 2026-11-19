---
objective: platform-identity-issuer
trd: 03
subsystem: platform/identity
tags: [identity, issuer, ordering, key-rotation, health-check]
requires:
  - platform-identity-issuer-01 (CredentialVerifier, ClaimsResolver, Authentication, Grant)
  - platform-identity-issuer-02 (DeriveAssurance)
  - platform/identity Minter (NewMinter, MintInput, Mint)
  - platform/kms (KMSSigner)
provides:
  - Issuer[C any] with Issue(ctx, credential) (string, error)
  - NewIssuer[C any](ctx, kms.KMSSigner, issuer, CredentialVerifier[C], ClaimsResolver, ...MinterOption)
  - ErrNilCredentialVerifier, ErrNilClaimsResolver, ErrSignerUnhealthy, ErrVerifierReportedNoAuthentication
affects: []
tech-stack:
  added: []
  patterns:
    - the key id is derived from the signer, never accepted as a parameter, so a constant one is unrepresentable
    - construction proves signing with a real round trip before the object exists
    - seam call ORDER asserted by recording fakes, not inferred from outcomes
key-files:
  created:
    - platform/identity/issuer.go
    - platform/identity/issuer_test.go
  modified: []
decisions:
  - NewIssuer takes kms.KMSSigner and reads KeyID() off it; there is no key-id parameter, so a deployment cannot pin a constant id that would survive the key material being replaced and permanently defeat a consumer's cache-miss recovery
  - NewIssuer runs HealthCheck before building anything, because reading a public key and signing with it are separately authorized on a hosted key service and a sign-denied config looks healthy until the first login
  - A verifier returning (nil, nil) gets its own sentinel rather than falling through to Validate's ErrNilAuthentication, because a broken verifier and a malformed record have different remedies
  - Validate is called explicitly even though DeriveAssurance validates too, so the gate does not depend on another function's internals
  - Issue is the only exported method on *Issuer, asserted by reflection, so no second path can reach the minter without a verification
metrics:
  tasks: 1
  tests-added: 36
completed: 2026-08-19
---

# Objective platform-identity-issuer TRD 03: The Issuer Summary

`Issuer[C]` composes the two consumer seams, the assurance derivation and the
existing minter into one path from credential to signed context — with the
ordering of that path treated as the security property it is, and asserted as
such.

## What Was Built

`platform/identity/issuer.go` — one type, one constructor, one method.

### The key id is not a parameter

`NewIssuer` takes a `kms.KMSSigner` and reads `KeyID()` off it. There is no
key-id argument, which is what makes a pinned constant unrepresentable rather
than merely discouraged.

The failure this closes: a deployment pins a constant key id and later replaces
the key material behind it. A consumer's key cache only re-fetches on an id it
does not recognise, so a constant id that now names different material never
misses — every request is refused indefinitely with no cache miss to trigger
recovery. An id derived from the key changes when the key does, producing
exactly the miss that heals. An empty `KeyID()` is a construction error.

`kms.KMSSigner` is a superset of the minter's `kmssigner.Signer` (it adds
`KeyID()` and `HealthCheck(ctx)`), so it passes straight through to `NewMinter`
with no adapter.

### Signing is proved before the issuer exists

`NewIssuer` runs `signer.HealthCheck(ctx)` and refuses to construct on error,
wrapping the cause in `ErrSignerUnhealthy`. The check is a real sign-and-verify
round trip. It runs at construction because reading a public key and signing
with it are separately authorized operations on a hosted key service: a
configuration permitting the first while denying the second looks perfectly
healthy until the first login. This turns that into a start-up failure an
operator sees rather than an outage a user finds.

### The order in `Issue`

Exactly this, stopping at the first failure:

| # | Step | Why it is here and not later |
|---|---|---|
| 1 | `VerifyCredential` | Nothing else happens until this succeeds. A `(nil, nil)` return is a broken verifier and yields `ErrVerifierReportedNoAuthentication` — reading it as success would mint a context for nobody. |
| 2 | `Authentication.Validate` | Success with no subject or no factor establishes nothing mintable. |
| 3 | `DeriveAssurance` | The level comes from the factors exercised. Not a parameter, not a field, not a default. |
| 4 | `ResolveClaims` | Only for a subject that actually authenticated. Resolving entitlements for an unauthenticated identifier is a disclosure even when nothing is minted after. |
| 5 | `Mint` | Subject taken from the AUTHENTICATION, never the credential — the credential says who the caller claims to be, the authentication says who they proved to be. |

Construction-time validation reports each omission distinctly:
`ErrNilCredentialVerifier`, `ErrNilClaimsResolver`, `ErrNilSigner`,
`ErrMissingIssuer`, `ErrMissingKeyID`.

## Testing

`issuer_test.go` uses recording fakes for both seams and the signer, all writing
to one shared call log, so "the resolver was never reached" is an assertion
rather than an inference. Coverage beyond the must-haves: the caller's context
reaching all three seams; the kid changing when the signing key is replaced;
each rung of the assurance ladder reaching the minted claim; a minted context
round-tripping through the shipped `Verifier`; an empty tenant surfacing as
`ErrMissingTenant` rather than an unscopable context; entitlements emitted as
`[]` rather than `null`; minter options forwarded; concurrent issuance under the
race detector.

Two structural guards: a reflection test asserting `NewIssuer` takes exactly one
string parameter (a second would let a caller pin a key id), and one asserting
`*Issuer` exports only `Issue` (any other exported method would be a mint path
not beginning with a verification). Plus a build-constraint scan mirroring the
package's existing one.

## TDD Evidence

| Phase | Command | Exit | Result |
|---|---|---|---|
| RED | `go test ./platform/identity/ -count=1` | 1 | `undefined: Issuer`, `undefined: NewIssuer`, `undefined: ErrNilCredentialVerifier`, `undefined: ErrNilClaimsResolver`, `undefined: ErrSignerUnhealthy` — build failed, as required |
| GREEN | `go test ./platform/identity/ -race -count=1 -v` | 0 | 318 PASS / 0 SKIP / 0 FAIL |

RED commit `cf38904`, GREEN commit `1aa02d7`.

## Mutation Check

Each break was applied to `issuer.go`, the suite run, then restored via
`git checkout` with `git status --porcelain` confirmed empty.

| Mutation | Killed by | Observed |
|---|---|---|
| (a) `ResolveClaims` before `VerifyCredential` | `TestIssueConsultsTheSeamsInOrder` + 5 more | `call sequence = [ResolveClaims VerifyCredential ResolveClaims], want [VerifyCredential ResolveClaims]`; resolver called for `unverified-identifier` |
| (b) accept `(nil, nil)` as success | `TestIssueTreatsANilAuthenticationAsFailure` | error became `identity: authentication is nil` instead of the verifier-broken sentinel — the distinct sentinel is what detects it |
| (c) skip `HealthCheck` in the constructor | `TestNewIssuerProvesSigningAtConstruction`, `TestNewIssuerRefusesAnUnhealthySigner`, `TestNewIssuerPassesTheCallersContextToTheHealthCheck` | `HealthCheck called 0 times during construction, want 1`; `NewIssuer returned an issuer despite a failing health check` |

## Task Evidence

| Gate | Command | Exit | Status |
|---|---|---|---|
| tests | `go test ./platform/identity/ -race -count=1 -v` | 0 | PASS — 318 PASS / 0 SKIP / 0 FAIL (282 pre-existing + 36 new) |
| vet | `go vet ./platform/identity/` | 0 | PASS |
| format | `gofmt -l platform/identity/` | 0 | PASS (no output) |
| deps | `git diff --exit-code go.mod go.sum` | 0 | PASS (unchanged) |

## Deviations from Plan

None. The TRD was executed as written; no existing file was modified.

## Post-TRD Verification

- Auto-fix cycles used: 0
- Must-haves verified: 11/11
- Gate failures: None
