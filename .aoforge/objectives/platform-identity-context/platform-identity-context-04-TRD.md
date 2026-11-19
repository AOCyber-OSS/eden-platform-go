---
objective: platform-identity-context
trd: 04
type: tdd
wave: 3
depends_on: [01, 03]
files_modified:
  - platform/identity/verifier.go
  - platform/identity/verifier_test.go
autonomous: true
requirements: [IC-04]
must_haves:
  truths:
    - "NewVerifier accepts a SET of trusted issuers, each pairing an issuer string with its own KeySource"
    - "NewVerifier rejects an empty issuer set, an empty issuer string, and a nil KeySource"
    - "Verify resolves the token's iss and rejects an UNTRUSTED issuer before any signature work"
    - "The unverified iss is used ONLY to select which trusted key source to verify against — never as an identity claim"
    - "Verify accepts ONLY ES256 and RS256 (jwt.WithValidMethods) — alg none and HS256 are rejected"
    - "Verify asserts the typ header == identity-context+jwt and rejects a token without it"
    - "Verify applies 5s leeway to exp/iat/nbf"
    - "Verify enforces Claims.Validate against the CONFIGURED accepted-version set (per-verifier, not global)"
    - "EVERY failure path returns the SAME sentinel error — bad signature, unknown issuer, unknown kid, expired, wrong alg, wrong typ, bad ctx_ver, empty sub/tnt/aal are indistinguishable to a caller"
    - "A token signed by issuer A's key but claiming issuer B is REJECTED (cross-issuer key confusion)"
    - "A verifier trusting two issuers accepts a valid token from EACH"
  artifacts:
    - platform/identity/verifier.go
    - platform/identity/verifier_test.go
  key_links:
    - "Verifier resolves keys through the KeySource seam from TRD 03 — one per trusted issuer"
    - "Verifier calls Claims.Validate from TRD 01 rather than re-implementing semantic rules"
    - "Plural issuers rules OUT jwt.WithIssuer, which pins exactly one — iss is matched manually against the trusted set"
---

<objective>
Verify a signed identity context against a **configured set** of trusted issuers,
each with its own key source, and collapse every failure into one sentinel error.

Plural from day one is the point: the same service verifies an in-process issuer
now and an external provider later. A verifier built around one pinned issuer
would have to be rewritten for that, and the rewrite is exactly where the
existing consumers drifted apart.
</objective>

<file_tree>
platform/identity/
├── claims.go            (TRD 01 — Claims, Validate, VersionSet)
├── keysource.go         (TRD 03 — KeySource)
├── verifier.go          ← CREATE (TrustedIssuer, Verifier, NewVerifier, Verify, ErrInvalidContext)
└── verifier_test.go     ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<why_not_jwt_with_issuer>
`jwt.WithIssuer` pins EXACTLY ONE issuer string, so it cannot express a trusted
SET. The issuer must therefore be matched manually:

1. Parse the token's claims WITHOUT verifying, to read `iss`. Use the library's
   non-verifying parse path for this.
2. Look `iss` up in the trusted set. NOT PRESENT → return the sentinel
   immediately, before any signature or key work.
3. Verify with THAT issuer's KeySource and no other.

The discipline that makes step 1 safe: the unverified `iss` selects which
trusted key set to check the signature against, and is used for NOTHING else. It
never becomes an identity, a tenant, or an authorization input. If the signature
does not verify under that issuer's keys, the token is rejected — so a forged
`iss` only ever selects a key set that will fail to verify it.

This is what makes the cross-issuer confusion case in must_haves a REQUIRED test:
a token signed with issuer A's key but claiming `iss: B` must be rejected,
because it is checked against B's keys, not A's.
</why_not_jwt_with_issuer>

<one_sentinel_error>
Export ONE error value (e.g. `ErrInvalidContext`) and return it — unwrapped and
un-annotated — from every failure path. A caller must not be able to distinguish
"bad signature" from "expired" from "unknown issuer" from "wrong ctx_ver".

Reason: a per-reason error becomes a per-reason HTTP response, and that is an
oracle. "unknown issuer" versus "bad signature" tells a prober whether it has
guessed a trusted issuer; "expired" versus "bad signature" confirms it has a
structurally valid token.

Detail for the OPERATOR, not the caller: if the package logs, it may log the
specific cause. The returned error stays uniform. Do not wrap the underlying
error with %w — wrapping re-exposes the cause through errors.Is/As.
</one_sentinel_error>

<parser_configuration>
```go
parser := jwt.NewParser(
	jwt.WithValidMethods([]string{"ES256", "RS256"}),
	jwt.WithLeeway(5 * time.Second),
)
```

`WithValidMethods` is what rejects `alg: none` and an HMAC-signed token whose
"key" is the public key — both are must-have test cases.

The `typ` header assertion is NOT performed by the parser and must be done
explicitly after parsing: reject anything whose `typ` is not
`identity-context+jwt`. It is what stops an access token being replayed into the
identity-context slot.

Semantic validation (`ctx_ver` in the accepted set; non-empty sub/tnt/aal) is
also not performed by the parser — delegate it to `Claims.Validate` with THIS
verifier's configured version set. Do not re-implement those rules here, and do
not consult a package-level default: the accepted set is per-verifier
configuration.
</parser_configuration>

<test_first>
Write verifier_test.go FIRST. Mint fixtures with the TRD 02 minter over an
in-test signer, and resolve keys through StaticKeys from TRD 03.

Required cases:
- happy path: valid token from a trusted issuer → claims returned
- multi-issuer: verifier trusting A and B accepts a valid token from EACH
- untrusted issuer → sentinel
- cross-issuer confusion: signed by A's key, claims iss B → sentinel
- unknown kid → sentinel
- alg none → sentinel
- HS256 signed → sentinel
- missing/wrong typ → sentinel
- expired beyond leeway → sentinel; within leeway → accepted
- ctx_ver outside the configured set → sentinel; a verifier configured {1,2}
  accepts a v2 token that a verifier configured {1} rejects (same token, both
  verifiers — this is the version-negotiation proof)
- empty sub / tnt / aal → sentinel
- every rejection above returns an error that is errors.Is(err, ErrInvalidContext)
  and carries no distinguishing text
</test_first>

<constraints>
- PUBLIC REPO — see TRD 01 constraints.
- No new module dependencies.
- Nothing about WHICH issuer is trusted may be compiled in — no default issuer
  string, no built-in trusted list.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/ -race -count=1 -v -run Verif
go vet ./platform/identity/
git diff --exit-code go.mod go.sum
</verify>
