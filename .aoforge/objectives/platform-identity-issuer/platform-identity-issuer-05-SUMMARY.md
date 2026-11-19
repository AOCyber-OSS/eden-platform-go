---
objective: platform-identity-issuer
trd: 05
subsystem: auth
tags: [integration, documentation, assurance, go]

requires: [01, 02, 03, 04]
provides:
  - "platform/identity end-to-end issuance proof across a real HTTP boundary"
  - "platform/identity/README.md — the issuer half: seams, assurance ladder, key id, start-up proof"
affects: [downstream-consumers]

tech-stack:
  added: []
  patterns:
    - "Fake only the consumer seams; every layer this package owns is the real one"
    - "Verify with the DEFAULT accepted-version set, so version drift cannot hide"

requirements-completed: [IS-05]
---

# TRD 05 — End-to-end proof and documentation

## What shipped

`platform/identity/issuer_e2e_test.go` and the issuer half of the package
README. Executed directly rather than delegated: the two prior attempts at this
shape of task ran out of budget mid-flight.

## What may be faked, and what may not

Only the two consumer seams — credential verification and claims resolution —
because a consumer supplies those and this package has no implementation of
them. Everything else on the path is real: the real issuer, the real minter, the
real key-set handler over a real server, the real remote key source, the real
verifier. A round trip substituting any of those would prove only that the
substitutes agree with each other.

## The version assertion

The far-end verifier is built on the **default** accepted-version set, not a
widened one. That is the assertion that an issuer emits a version
already-deployed consumers take. Widening it here would conceal exactly the
mismatch this package exists to surface.

## Coverage

- A credential goes in one end and a verified claim set comes out the other,
  carrying the original tenant, entitlements and derived assurance — and a
  subject that is the one **proved**, explicitly asserted not to be the handle
  the caller claimed.
- A rejected credential yields no token, never reaches the resolver, and the far
  end refuses the empty string as an ordinary invalid context.
- Every rung of the assurance ladder survives the round trip: a password-only
  login still reads as single-factor after crossing the wire; two prompts in one
  category stay AAL1; multi-factor without both asserted properties stops at
  AAL2.

## Verified

`go test ./platform/identity/... -race -count=1 -v` → 356 PASS / 0 SKIP / 0 FAIL.
`go vet` clean, `gofmt` clean, `go build ./...` clean, `go.mod`/`go.sum`
unchanged.

Mutation-tested: overwriting the derived assurance with a constant top rung
killed four of the five ladder rows — correctly not the row that expects the top
rung. An earlier attempt at that mutation was invalid (it left a variable
unused, so the package did not build and no test ran); the run was repeated with
a mutation that actually compiles, because a build failure is not a passing test.
