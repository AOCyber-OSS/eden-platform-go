---
objective: platform-identity-context
trd: 03
type: tdd
wave: 2
depends_on: [01]
files_modified:
  - platform/identity/keysource.go
  - platform/identity/keysource_test.go
autonomous: true
requirements: [IC-03]
must_haves:
  truths:
    - "KeySource is an interface resolving a kid to a public key: KeyForKID(ctx, kid) (crypto.PublicKey, error)"
    - "StaticKeys resolves a kid present in its map and returns an error for an absent kid"
    - "RemoteJWKS fetches an RFC 7517 {\"keys\":[...]} document over stdlib net/http and parses EC (P-256) and RSA keys"
    - "RemoteJWKS caches the parsed set; a second lookup of a KNOWN kid performs NO second HTTP request"
    - "RemoteJWKS refetches when asked for an UNKNOWN kid (key rotation introduces new kids)"
    - "RemoteJWKS enforces a minimum interval between unknown-kid refetches, so unknown kids cannot amplify into unbounded upstream requests"
    - "RemoteJWKS re-fetches after its cache TTL expires, so a key ROTATED UNDER AN UNCHANGED KID heals instead of 401ing forever"
    - "A non-2xx response, an unparseable body, or a transport error surfaces as an error and does NOT poison the cached set"
    - "RemoteJWKS is safe for concurrent use (proven under -race with concurrent lookups)"
  artifacts:
    - platform/identity/keysource.go
    - platform/identity/keysource_test.go
  key_links:
    - "KeySource is the per-issuer seam the verifier (TRD 04) resolves signing keys through"
    - "StaticKeys serves in-process issuers and tests; RemoteJWKS serves an external issuer's published JWKS URL"
    - "JWK parsing mirrors the shape platform/auth/jwks emits, so a set published by this platform is readable by this consumer"
---

<objective>
Supply the key-resolution seam a verifier trusts an issuer through: an in-memory
set for in-process issuers and tests, and a remote JWKS fetcher for an external
issuer's published key set.

A seam rather than a hard-wired fetcher, for two reasons: a consumer that already
operates a JWKS cache can plug it in instead of running a second one, and the
package stays free of a new module dependency.
</objective>

<file_tree>
platform/identity/
├── claims.go           (TRD 01)
├── keysource.go        ← CREATE (KeySource, StaticKeys, RemoteJWKS)
└── keysource_test.go   ← CREATE (httptest-backed; NEVER a fixed port)
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_rotation_trap>
This is the failure this type exists to prevent, and it is subtle enough that it
has bitten a shipped deployment.

A cache that ONLY refetches on an unknown kid appears correct: rotation
introduces a new kid, the cache misses, it refetches, everything heals. But if an
issuer publishes a FIXED kid and regenerates the key behind it — a restart with an
ephemeral key does exactly this — the kid never changes, the cache never misses,
and the verifier keeps validating against a public key whose private half no
longer exists. Every request 401s, indefinitely, with no cache miss to trigger
recovery.

RemoteJWKS therefore needs BOTH triggers:
1. refetch on unknown kid — handles rotation that changes the kid
2. refetch after a cache TTL — handles a key rotated UNDER AN UNCHANGED KID

And a guard on (1): an unknown kid is attacker-controllable, so unbounded
refetch-per-unknown-kid turns a verifier into a request amplifier pointed at the
issuer. Enforce a minimum interval between unknown-kid-triggered fetches; inside
that interval an unknown kid resolves to an error from the cached set instead of
a new upstream request.
</the_rotation_trap>

<jwk_parsing>
Parse the RFC 7517 document shape `{"keys":[ {...}, ... ]}`.

Support the two key types this contract signs with:
- `kty: "EC"`, `crv: "P-256"` → rebuild *ecdsa.PublicKey from base64url `x` and `y`
- `kty: "RSA"` → rebuild *rsa.PublicKey from base64url `n` and `e`

Coordinates are base64url WITHOUT padding (`base64.RawURLEncoding`). Skip a key
entry whose type or curve is unsupported rather than failing the whole document —
an issuer may publish keys this consumer does not use.
</jwk_parsing>

<test_first>
Write keysource_test.go FIRST.

Use `httptest.NewServer` — it binds an OS-assigned free port. NEVER hardcode a
port; port 8080 in particular is unavailable in this environment.

Drive the cache behaviours with a request COUNTER in the test handler, so the
assertions are about how many upstream fetches actually happened:
- known kid twice   → exactly 1 fetch
- unknown kid       → a second fetch occurs
- unknown kid again, inside the minimum interval → NO further fetch
- key swapped under an unchanged kid, TTL elapsed → refetch, and the NEW key verifies
- non-2xx / malformed body → error returned AND the previously cached set intact
- concurrent lookups under -race → no data race
</test_first>

<constraints>
- PUBLIC REPO — see TRD 01 constraints.
- stdlib only: net/http, encoding/json, encoding/base64, crypto/*, sync, time.
  No new module dependencies.
- Accept an injectable *http.Client and a clock/time seam so TTL expiry is
  testable without sleeping in tests.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/ -race -count=1 -v -run KeySource
go vet ./platform/identity/
git diff --exit-code go.mod go.sum
</verify>
