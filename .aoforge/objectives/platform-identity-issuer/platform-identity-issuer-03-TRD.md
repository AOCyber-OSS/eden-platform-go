---
objective: platform-identity-issuer
trd: 03
type: tdd
wave: 3
depends_on: [01, 02]
files_modified:
  - platform/identity/issuer.go
  - platform/identity/issuer_test.go
autonomous: true
requirements: [IS-03]
must_haves:
  truths:
    - "NewIssuer takes a kms.KMSSigner — NOT a bare signer plus a caller-supplied key id"
    - "The key id stamped on every context is the signer's own KeyID(); no key id parameter is accepted"
    - "NewIssuer calls the signer's HealthCheck and FAILS construction when it errors"
    - "NewIssuer rejects a nil credential verifier, a nil claims resolver, a nil signer, an empty issuer name, and an empty KeyID() — each distinguishably"
    - "Issue calls VerifyCredential FIRST; a verification error returns that error and NOTHING is minted"
    - "A verifier returning (nil, nil) is treated as a failure, not as a successful authentication"
    - "Issue calls ResolveClaims only AFTER a successful verification, and a resolver error mints nothing"
    - "The minted assurance is DeriveAssurance applied to the returned Authentication — never a constant, never caller-supplied"
    - "An authentication that fails Validate mints nothing"
    - "The minted context carries the resolved tenant and entitlements, and the subject from the Authentication, not from the credential"
    - "The package contains no exported, build-tagged or environment-gated path that mints without a successful VerifyCredential"
  artifacts:
    - platform/identity/issuer.go
    - platform/identity/issuer_test.go
  key_links:
    - "Issuer composes CredentialVerifier + ClaimsResolver (TRD 01) + DeriveAssurance (TRD 02) + the existing Minter"
    - "kms.KMSSigner is a superset of the minter's signer interface, so it is passed straight through"
    - "KeyID() is derived from the key by construction, which is what makes a constant key id unrepresentable"
---

<objective>
The issuer: authenticate through the consumer's seam, resolve what the subject is
entitled to, derive an honest assurance level, and mint a context.

Every ordering rule here is a security property, not a style preference. The
tests assert the order, not merely the outcome.
</objective>

<file_tree>
platform/identity/
├── authentication.go     (TRD 01 — seams, Authentication)
├── assurance.go          (TRD 02 — DeriveAssurance)
├── minter.go             (existing — NewMinter, MintInput, Mint)
├── issuer.go             ← CREATE
└── issuer_test.go        ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_key_id_is_not_a_parameter>
This is the load-bearing design decision, and it is enforced by the SIGNATURE
rather than by documentation.

The failure it prevents: a deployment pins a constant key id and then replaces
the key material behind it. A consumer's key cache only re-fetches on an
*unknown* key id, so a constant one that now names different material never
misses, and every request is refused indefinitely with no cache miss to trigger
recovery.

So the issuer does not accept a key id. It reads `KeyID()` off the signer, which
the key surface derives from the key itself — an ARN, a key URL, a label, a
generated identifier. Replace the key and the identifier changes with it, which
produces exactly the miss that heals a consumer. A caller cannot pin a constant
because there is nowhere to pass one.

An empty `KeyID()` is a construction error: it would mint contexts no verifier
can resolve a key for.
</the_key_id_is_not_a_parameter>

<prove_signing_at_startup>
`NewIssuer` runs the signer's `HealthCheck` and refuses to construct if it fails.

That check performs a real sign-and-verify round trip. It exists because reading
a public key and signing with it are separately authorized operations on every
hosted key service, and a configuration that permits the first while denying the
second looks perfectly healthy until the first login attempt. Failing at
construction turns that into a start-up failure an operator sees immediately,
rather than an authentication outage discovered by a user.
</prove_signing_at_startup>

<the_order_is_the_security_property>
`Issue` does exactly this, in this order, and stops at the first failure:

1. `VerifyCredential`. On error, or on a nil authentication, return without
   minting. A verifier that returns `(nil, nil)` is a broken verifier, and
   treating that as success would mint a context for nobody.
2. `Authentication.Validate`. A verifier that reports success with no subject or
   no factors has not established anything mintable.
3. `DeriveAssurance`. The level comes from the factors that were exercised. It is
   not a parameter, not a field on the issuer, and not a default.
4. `ResolveClaims`. Only for a subject that has actually authenticated. Resolving
   entitlements for an unauthenticated identifier is a disclosure even when
   nothing is minted afterwards.
5. Mint, taking the subject from the AUTHENTICATION rather than from the
   credential. The credential says who the caller claims to be; the
   authentication says who they proved to be, and only the latter belongs in a
   context.

Test the ORDER, not just the outcomes: use seam fakes that record calls, and
assert that a failing verifier leaves the resolver untouched.
</the_order_is_the_security_property>

<test_first>
Write issuer_test.go FIRST and watch it fail. Fakes for both seams, plus an
in-test signer that satisfies the key surface (Public, Sign, SigningAlgorithm,
KeyID, HealthCheck) so the health check and key id are drivable.

Beyond the must-haves, cover: a health check that fails at construction; a
minted context that verifies through the existing verifier and carries the
derived assurance; a resolver returning an empty tenant surfacing as a mint
failure rather than an invalid context; and a table proving each rung of the
assurance ladder reaches the minted claim intact.

Include a test asserting the package declares no build-tagged files, mirroring
the equivalent already in the package.
</test_first>

<constraints>
- PUBLIC REPO. No private repo/service/product names, no internal ticket or
  design-doc references, no absolute local paths, no branch names or hashes.
  Write doc comments fresh. Do NOT read other repositories on this machine.
- No new module dependencies.
- Do not modify any existing file in the package. This TRD is additive.
- Never bind or reference port 8080 (permanently occupied here).
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/ -race -count=1 -v
go vet ./platform/identity/
gofmt -l platform/identity/
git diff --exit-code go.mod go.sum
</verify>
