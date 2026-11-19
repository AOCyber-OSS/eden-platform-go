---
objective: platform-identity-context
trd: 03
subsystem: auth
tags: [jwks, key-resolution, caching, rotation, go]

# Dependency graph
requires: [01]
provides:
  - "platform/identity.KeySource — the per-issuer key-resolution seam (KeyForKID)"
  - "platform/identity.StaticKeys — in-memory key set for in-process issuers and tests"
  - "platform/identity.RemoteJWKS / NewRemoteJWKS — stdlib JWKS fetcher with a cache"
  - "WithJWKSHTTPClient / WithJWKSCacheTTL / WithJWKSMinRefetchInterval / WithJWKSClock"
  - "Distinct start-up misconfiguration sentinels (ErrMissingJWKSURL, ErrInvalidJWKSURL, ...)"
affects: [identity-verifier, identity-roundtrip-tests]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Key resolution as an injected seam, so a consumer with an existing key cache plugs it in"
    - "Two independent refetch triggers: unknown-kid miss AND cache-TTL expiry"
    - "Refetch floor anchored on last ATTEMPT, so a failing upstream is not hammered"
    - "Mutex held across the fetch, collapsing a burst of concurrent misses into one request"
    - "Mutation testing to prove cache assertions actually bite"

requirements-completed: [IC-03]
---

# TRD 03 — Key sources

## What shipped

`platform/identity/keysource.go` + `keysource_test.go`. `KeySource` is the interface
a verifier resolves a signing key through, with two implementations: `StaticKeys`
(in-memory, defensive map copy, drops empty-kid and nil-key entries) and
`RemoteJWKS` (stdlib `net/http` fetch of an RFC 7517 document, with a cache).

Written test-first; RED was a build failure naming every undefined symbol.

## The failure this type exists to prevent

A JWKS cache that refetches ONLY on an unknown `kid` looks correct — rotation
introduces a new kid, the cache misses, it refetches. But an issuer that
publishes a FIXED kid and regenerates the key behind it (a restart with an
ephemeral key does exactly this) never changes the kid, so the cache never
misses, and the verifier keeps checking signatures against a public key whose
private half no longer exists. Every request is rejected, indefinitely, with no
cache miss to trigger recovery.

`RemoteJWKS` therefore carries BOTH triggers: refetch on unknown kid, and
refetch after a cache TTL. The TTL is what heals a key rotated under an
unchanged kid.

An unknown kid is attacker-controllable, so unbounded refetch-per-unknown-kid
would turn a verifier into a request amplifier aimed at the issuer. A minimum
interval between unknown-kid-triggered fetches bounds that; inside the interval
an unknown kid resolves to an error from the cached set instead of a new
upstream request. `minRefetch <= ttl` is enforced at construction so the floor
can never delay the scheduled refresh that heals the rotation trap.

## Interop detail worth keeping

EC coordinates are rebuilt with `big.Int.SetBytes`, NOT a fixed 32-byte length
check. RFC 7518 says a P-256 coordinate SHOULD be zero-left-padded to 32 bytes
and this platform's own publisher does that, but issuers that encode with
`big.Int.Bytes()` omit leading zero bytes — so roughly one key in 128 arrives
short. A strict length check rejects a valid key set intermittently, and the
failure looks random.

## Key-set entry skip rules

An entry is skipped when it has no `kid`, when `use` is present and is not
`sig`, when its `kid` duplicates an earlier entry (first entry wins — this stops
an appended entry displacing a real key), when its type or curve is unsupported,
or when an RSA modulus is under 2048 bits. A set with no usable entry is an
error; a partial skip is silent and surfaces later as an unknown-kid rejection.
Documented in the package README for that reason.

## Verified

`go test ./platform/identity/ -race -count=1 -v` → 143 PASS / 0 SKIP / 0 FAIL
(99 pre-existing unchanged, 44 new). `go vet` clean, `gofmt` clean, `go build ./...`
clean, `go.mod`/`go.sum` unchanged. Repeated at `-count=5` because the
short-coordinate search is randomized.

Mutation-tested: removing the TTL trigger reproduced the fixed-kid rotation trap
(1 fetch where 2 were required); removing the refetch floor produced 501 upstream
fetches from 500 distinct unknown kids; tightening the coordinate check to an
exact width rejected a valid short coordinate. Each mutation was restored
byte-identically.
