---
objective: platform-identity-context
trd: 04
subsystem: auth
tags: [jwt, verification, multi-issuer, error-opacity, go]

# Dependency graph
requires: [01, 03]
provides:
  - "platform/identity.Verifier / NewVerifier — verification against a configured SET of trusted issuers"
  - "platform/identity.TrustedIssuer — an issuer name paired with its own KeySource"
  - "platform/identity.ErrInvalidContext — the single, uniform rejection"
  - "An operator-facing rejection sink carrying the real cause, never returned to a caller"
affects: [identity-roundtrip-tests, downstream-consumers]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Single-exit error collapse: a thin exported wrapper over a rich unexported worker"
    - "Unverified iss used ONLY to select a key set, never as an identity or authorization input"
    - "Trusted-issuer rejection BEFORE any key resolution or signature work"
    - "Per-verifier accepted-version set rather than a package-level default"

requirements-completed: [IC-04]
---

# TRD 04 — The verifier

## What shipped

`platform/identity/verifier.go` + `verifier_test.go` (38 test functions).
`NewVerifier` takes a SET of trusted issuers, each pairing an issuer name with
its own `KeySource`, and rejects an empty set, an empty issuer name, a nil key
source, a duplicate issuer, and an empty accepted-version set — each
distinguishably, because those are start-up misconfigurations an operator has to
diagnose.

Written test-first; RED was a build failure naming every undefined symbol.

## Why the issuer set is plural

The same service verifies an in-process issuer now and an external provider
later. A verifier built around one pinned issuer would need rewriting for that,
and the rewrite is where independent copies of this contract drifted apart. A
plural set also rules out the library's single-issuer parser option, so `iss` is
matched manually against the trust set.

## The unverified-issuer discipline

Selecting a key set requires reading `iss` before the signature is checked. That
is safe under one rule, and only that rule: the unverified `iss` chooses which
trusted key set to verify against, and is used for nothing else — never an
identity, never a tenant, never an authorization input. An issuer outside the
trust set is refused before a key is resolved or a signature checked.

A forged `iss` can therefore only ever select a key set that will refuse the
signature. A context signed with one issuer's key but claiming another's name is
checked against the claimed issuer's keys, and fails. The claim set decoded for
this purpose is local and discarded; the claims returned to a caller come only
from the verified parse.

## One uniform rejection, made structural

Every failure returns `ErrInvalidContext` — that exact value, never wrapped,
never a different one. A per-reason error becomes a per-reason HTTP response,
which is an oracle: it tells a prober whether it guessed a trusted issuer, or
whether it holds a structurally valid but expired token.

The collapse is structural rather than a rule each path must remember. The
exported `Verify` is a thin wrapper over an unexported worker that returns rich,
specific errors; the wrapper hands those to an operator sink and returns the
sentinel from a single exit. This matters because `Claims.Validate` deliberately
returns NAMED errors — propagating or wrapping them would leak the reason
straight back out through `errors.Is`.

## Verified

`go test ./platform/identity/ -race -count=1 -v` → 215 PASS / 0 SKIP / 0 FAIL
(143 pre-existing unchanged, 72 new). `go vet` clean, `gofmt` clean,
`go build ./...` clean, `go.mod`/`go.sum` unchanged.

Coverage includes: both admitted algorithms; two issuers each accepted by one
verifier; untrusted issuer; a token signed by another issuer's key; a key id
belonging to another issuer; unknown, empty, absent and non-string key ids; the
`none` algorithm; an HMAC-signed context; five wrong-token-type cases; expiry and
not-yet-valid on both sides of the leeway; missing required claims; a version
outside the accepted set; per-verifier version negotiation; and three separate
non-leakage assertions.

Mutation-tested after the fact: wrapping the real cause into the returned error
failed a broad set of assertions (the tests require the error to be exactly the
sentinel, so even wrapping is caught); removing the trust-set check failed the
"before any key work" assertion, which is the one that proves the key source was
never consulted; removing the token-type assertion failed all five type cases.
Each mutation was restored byte-identically.
