---
objective: platform-identity-issuer
trd: 04
subsystem: auth
tags: [jwks, publication, http, go]

requires: [03]
provides:
  - "platform/identity.KeySetHandler / NewKeySetHandler — the issuer's public key served as a key set"
  - "platform/identity.KeySetSigner — the publication view of a signing key"
  - "WithKeySetMaxAge — the cache lifetime offered to consumers"
affects: [identity-issuer-e2e, downstream-consumers]

tech-stack:
  added: []
  patterns:
    - "Render once at construction; the handler retains bytes, not the signer"
    - "Close the loop in test: serve, then read back through this package's own remote key source"
    - "Assert the absence of private key components on the served bytes"

requirements-completed: [IS-04]
---

# TRD 04 — Key set publication

## What shipped

`platform/identity/keyset.go` + `keyset_test.go` (16 test functions). An
`http.Handler` that serves the issuer's public key as an RFC 7517 document,
built on the platform's existing key-set type — `Set`, `AddSigningKey`,
`MarshalJSON` — rather than hand-assembled JSON. That is what keeps it from
becoming a second key path.

Written test-first; RED was a build failure naming every undefined symbol.

## The loop closes here

The package already contains the consumer of these bytes, so the test that
matters most serves the handler on a test server, points `NewRemoteJWKS` at it,
and resolves the signer's own key id from the result. That turns two separate
assumptions — "we publish a valid key set" and "we can read a published key set"
— into one demonstrated fact.

## Render once, and why it is structural

The handler stores `document []byte` and does **not** retain the signer. So
re-rendering per request is not a discipline to remember; there is nothing to
re-render from.

The supporting test is sharper than a byte-identical comparison would be. Key-set
marshalling is deterministic, so a handler that re-read its key would still emit
identical bytes and a naive comparison would pass vacuously. The fixture is a
signer that returns a **brand-new key on every read**, so a second read would
produce a document naming different key material — visible, and counted.

## Verified

`go test ./platform/identity/ -race -count=1 -v` → 348 PASS / 0 SKIP / 0 FAIL
(318 pre-existing unchanged, 30 new). `go vet` clean, `gofmt` clean,
`go.mod`/`go.sum` unchanged.

Mutation-tested after the fact, since the executing agent stopped before
reporting: publishing under a hardcoded key id instead of the signer's own killed
four tests including the round-trip resolution. The "re-render per request"
mutation could not be expressed at all — the handler has no signer to re-render
from — which is a stronger outcome than the mutation failing. Restored
byte-identically.

## Also asserted

No private key component reaches the wire — the served document is decoded and
checked for `d` (EC) and `d`/`p`/`q`/`dp`/`dq`/`qi` (RSA). The publication
surface renders public halves only, so this should never fail; it exists because
the cost of being wrong once is a forged identity for every principal the issuer
serves, and a future change to what gets published would otherwise be silent.
