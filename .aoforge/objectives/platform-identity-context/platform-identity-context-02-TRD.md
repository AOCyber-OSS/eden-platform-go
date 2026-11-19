---
objective: platform-identity-context
trd: 02
type: tdd
wave: 2
depends_on: [01]
files_modified:
  - platform/identity/minter.go
  - platform/identity/minter_test.go
autonomous: true
requirements: [IC-02]
must_haves:
  truths:
    - "NewMinter rejects: nil signer, empty kid, empty issuer — each with a distinct error"
    - "Minted token header carries typ == \"identity-context+jwt\" AND kid == the configured kid"
    - "Minted token header alg matches the signer's SigningAlgorithm() (ES256 or RS256)"
    - "Minted claims carry ctx_ver == Version (1), iss == configured issuer, and the caller's sub/tnt/ent/aal"
    - "iat and exp are stamped; exp-iat == the configured TTL; DefaultTTL is 15 minutes"
    - "Mint REQUIRES non-empty subject, tenant and assurance — it refuses to mint an unvalidatable context"
    - "Mint does NOT default assurance upward: no assurance supplied is an error, never a silent AAL1/AAL2"
    - "A minted token parses and validates against a verifier trusting that issuer (proven in TRD 05)"
    - "There is NO exported or build-tagged path that mints without caller-supplied authenticated subject data"
  artifacts:
    - platform/identity/minter.go
    - platform/identity/minter_test.go
  key_links:
    - "Minter signs via kmssigner.Signer (Public/Sign/SigningAlgorithm) — the KMS-or-local seam"
    - "kmssigner.RegisterAll() registers the ES256/RS256 jwt.SigningMethod implementations"
    - "Minter reuses Claims/JWTType/Version from claims.go — redeclaring any of them is a defect"
---

<objective>
Mint a signed identity context: build a `Claims` set from caller-supplied
authenticated subject data, stamp the required `typ` and `kid` headers, and sign
it through the existing `kmssigner.Signer` seam.

The minter is deliberately dumb about *how* the principal was authenticated — it
takes the result. The follow-on first-party-issuer objective supplies the
authentication step on top of this, and must not have to reshape it.
</objective>

<file_tree>
platform/identity/
├── claims.go        (from TRD 01 — reuse, never redeclare)
├── minter.go        ← CREATE (Minter, NewMinter, MintInput, Mint)
└── minter_test.go   ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_signing_seam>
Sign through `platform/auth/kmssigner`, NOT through a locally-generated key and
NOT through `platform/auth.JWTManager`.

```go
// platform/auth/kmssigner
type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	SigningAlgorithm() string   // "ES256" | "RS256"
}
```

`kmssigner.RegisterAll()` registers the matching `jwt.SigningMethod`
implementations, so a `*jwt.Token` can be signed with a Signer as the key.

DO NOT reuse `platform/auth.JWTManager`. It is ML-DSA-65 and is the access-token
path — a different algorithm for a different purpose. Using it here would emit a
token no identity-context verifier can read.
</the_signing_seam>

<headers_are_load_bearing>
Two header parameters are mandatory and neither is set by the JWT library
by default:

- `typ` MUST be `identity-context+jwt`. Verifiers assert it as defence in depth,
  so that an ACCESS token presented in the identity-context slot is rejected on
  its type rather than on its signature. Omitting it means every verifier
  rejects the token.
- `kid` MUST be the configured key id, and must resolve against whatever key set
  the verifier trusts for this issuer.

Set both explicitly on the token header before signing.
</headers_are_load_bearing>

<honest_assurance>
The assurance level lands in a downstream audit record. It must reflect the
factors ACTUALLY used and must never be defaulted upward.

Concretely: `Mint` takes assurance as required caller input and returns an error
when it is absent. It does NOT fall back to a constant. A caller that
authenticated with a single factor passes the single-factor level and the record
says so.
</honest_assurance>

<no_unauthenticated_mint>
There must be no path — exported, build-tagged, or environment-gated — that
mints a context without caller-supplied authenticated subject data. Do not add a
convenience constructor that fabricates a subject or an entitlement set. Test
fixtures construct a Minter with a test signer and pass explicit input like any
other caller.
</no_unauthenticated_mint>

<test_first>
Write minter_test.go FIRST. Use a small in-test ES256 signer implementing
kmssigner.Signer over a generated P-256 key — that is a TEST fixture, not a
shipped convenience.

Assert on the DECODED header and claims, not on the opaque token string: parse
the minted token and check typ, kid, alg, then ctx_ver, iss, sub, tnt, ent, aal,
and that exp-iat equals the configured TTL. Cover each constructor rejection and
each Mint input rejection, including the "assurance absent is an error" case.
</test_first>

<constraints>
- PUBLIC REPO — see TRD 01 constraints. Same rules apply to test names.
- No new module dependencies.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/ -race -count=1 -v -run Mint
go vet ./platform/identity/
git diff --exit-code go.mod go.sum
</verify>
