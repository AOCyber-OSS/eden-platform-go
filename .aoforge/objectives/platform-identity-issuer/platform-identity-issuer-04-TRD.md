---
objective: platform-identity-issuer
trd: 04
type: tdd
wave: 4
depends_on: [03]
files_modified:
  - platform/identity/keyset.go
  - platform/identity/keyset_test.go
autonomous: true
requirements: [IS-04]
must_haves:
  truths:
    - "The published document is built with platform/auth/jwks — Set + AddSigningKey + MarshalJSON — not hand-assembled"
    - "The published key id matches the signer's KeyID(), so a context's kid resolves against the document"
    - "The handler serves application/jwk-set+json"
    - "The handler answers GET and HEAD, and rejects other methods with 405"
    - "The handler sets a Cache-Control max-age so a consumer does not refetch per request"
    - "The document is marshalled ONCE at construction, not per request — key sets do not change between rotations"
    - "Construction fails when the signer is nil, when KeyID() is empty, or when the key cannot be rendered"
    - "The served bytes parse back through this package's own remote key source and resolve the signer's key id"
    - "Only PUBLIC key material is served — the response contains no private key components (asserted explicitly)"
  artifacts:
    - platform/identity/keyset.go
    - platform/identity/keyset_test.go
  key_links:
    - "Built on platform/auth/jwks.Set — the existing publication surface, not a second one"
    - "Closes the loop with NewRemoteJWKS: what an issuer publishes is what a verifier fetches"
---

<objective>
Serve the issuer's public key so a verifier can fetch it.

This is HTTP plumbing over the existing key-set type. It renders no key material
of its own: the bytes come from the platform's publication surface, which is
what keeps this from becoming a second key path.
</objective>

<file_tree>
platform/identity/
├── issuer.go          (TRD 03)
├── keysource.go       (existing — NewRemoteJWKS, the consumer of these bytes)
├── keyset.go          ← CREATE
└── keyset_test.go     ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_loop_closes_here>
This package already contains the consumer of these bytes. The test that matters
most is therefore the one that feeds the handler's own output back into
`NewRemoteJWKS` and resolves the signer's key id from it.

That turns two separate assumptions — "we publish a valid key set" and "we can
read a published key set" — into one demonstrated fact. Serve the handler on a
test server, point a remote key source at it, and resolve the key.
</the_loop_closes_here>

<marshal_once>
A key set changes only when keys rotate, which is not per request. Render it at
construction and serve the same immutable bytes.

Beyond the wasted work, re-rendering per request would make the response able to
vary under load or partial failure, which is precisely the property a key
document must not have.
</marshal_once>

<no_private_material>
Assert it rather than assume it. Decode the served body and fail on any private
component — for an EC key that is `d`, for RSA `d`, `p`, `q`, `dp`, `dq`, `qi`.
The publication surface renders public halves only, so this test should never
fail; it exists because the consequence if it ever does is unbounded, and a
future change to what gets published would otherwise be silent.
</no_private_material>

<test_first>
Write keyset_test.go FIRST and watch it fail.

Cover: content type; GET and HEAD accepted; a non-GET method rejected with 405
(and HEAD returning headers without a body); Cache-Control present; the served
document parsing back through the remote key source and resolving the key id; the
private-material assertion; construction failures for a nil signer and an empty
key id; and that two requests produce byte-identical bodies.

Use httptest, which binds an OS-assigned port. NEVER hardcode a port; 8080 in
particular is permanently occupied in this environment.
</test_first>

<constraints>
- PUBLIC REPO. No private repo/service/product names, no internal ticket or
  design-doc references, no absolute local paths, no branch names or hashes.
  Write doc comments fresh. Do NOT read other repositories on this machine.
- No new module dependencies — net/http, encoding/json and the existing jwks
  package are enough.
- Do not modify any existing file in the package. This TRD is additive.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/ -race -count=1 -v
go vet ./platform/identity/
gofmt -l platform/identity/
git diff --exit-code go.mod go.sum
</verify>
