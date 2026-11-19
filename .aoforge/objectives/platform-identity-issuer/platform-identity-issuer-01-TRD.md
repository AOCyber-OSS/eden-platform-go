---
objective: platform-identity-issuer
trd: 01
type: tdd
wave: 1
depends_on: []
files_modified:
  - platform/identity/authentication.go
  - platform/identity/authentication_test.go
autonomous: true
requirements: [IS-01]
must_haves:
  truths:
    - "FactorKind enumerates the three categories: knowledge, possession, inherence"
    - "Factor pairs a Kind with a Method string naming the concrete mechanism"
    - "Authentication carries Subject, the Factors actually exercised, and the two asserted properties (PhishingResistant, HardwareBacked)"
    - "Authentication.Validate rejects an empty Subject and an empty Factors slice — an authentication with no factor is not an authentication"
    - "Authentication.Validate rejects a Factor with an empty or unknown Kind, and a Factor with an empty Method"
    - "Authentication.Kinds returns the DISTINCT factor categories present, which is what assurance is derived from"
    - "CredentialVerifier[C any] has VerifyCredential(ctx, credential C) (*Authentication, error) — the credential type is the consumer's"
    - "ClaimsResolver has ResolveClaims(ctx, subject string) (Grant, error)"
    - "Grant carries Tenant and Entitlements and nothing else"
    - "Neither seam mentions companies, roles, sessions or refresh tokens"
  artifacts:
    - platform/identity/authentication.go
    - platform/identity/authentication_test.go
  key_links:
    - "CredentialVerifier is generic over the consumer's credential type, mirroring the PrincipalLoader[P any] precedent in this repository"
    - "Grant supplies exactly the two claims the minter needs beyond the subject: tenant and entitlements"
---

<objective>
Define the two seams an application issues contexts through, and the
authentication result that carries what actually happened.

These are deliberately narrow. The credential primitives this composes over are
already pure functions, and the store-shaped interface next door is welded to a
company/role model an application may not share. The seams here mention no
storage, no schema and no tenancy model — a consumer implements them against
whatever it has.
</objective>

<file_tree>
platform/identity/
├── claims.go                    (existing — Claims, AAL constants)
├── minter.go                    (existing — MintInput)
├── authentication.go            ← CREATE
└── authentication_test.go       ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_shape>
```go
type FactorKind string

const (
	FactorKnowledge  FactorKind = "knowledge"   // something the principal knows
	FactorPossession FactorKind = "possession"  // something the principal has
	FactorInherence  FactorKind = "inherence"   // something the principal is
)

// Factor is one authentication factor actually exercised.
type Factor struct {
	Kind   FactorKind
	Method string // "password", "totp", "lookup_secret", "webauthn", ...
}

// Authentication is what a credential verification established.
type Authentication struct {
	Subject string
	Factors []Factor

	// Properties a verifier ASSERTS about how the principal authenticated.
	// They are not inferable from a factor's name and are never assumed.
	PhishingResistant bool
	HardwareBacked    bool
}

type CredentialVerifier[C any] interface {
	VerifyCredential(ctx context.Context, credential C) (*Authentication, error)
}

type ClaimsResolver interface {
	ResolveClaims(ctx context.Context, subject string) (Grant, error)
}

type Grant struct {
	Tenant       string
	Entitlements []string
}
```
</the_shape>

<why_kind_and_method_are_separate>
Assurance is about how many INDEPENDENT categories were exercised, not how many
secrets were typed. Two knowledge factors — a password and a security question —
are one category and do not make an authentication multi-factor, however many
prompts the user saw.

So `Kind` is what assurance is derived from, and `Method` is what an audit record
and an operator want to read. `Kinds()` returning the DISTINCT set is the
function the next TRD builds on; deduplication happens here, once, rather than in
the derivation.

Categorise carefully: a TOTP code and a look-up secret (recovery code) are both
POSSESSION — the principal holds the seed or the code sheet — not knowledge.
</why_kind_and_method_are_separate>

<why_generic>
The credential a consumer presents is its own business: an identifier and a
password, a bearer assertion, a signed challenge. Making the verifier generic
over that type keeps it compile-time checked at the consumer's call site instead
of pushing a type assertion into every implementation. This repository already
uses the same pattern for a consumer-supplied principal type.
</why_generic>

<test_first>
Write authentication_test.go FIRST and watch it fail.

Cover: Validate accepting a well-formed authentication; rejecting empty subject,
empty factor slice, empty Kind, unknown Kind, empty Method. Kinds() returning
distinct categories in a stable order, collapsing duplicates (two knowledge
factors yield one category), and returning empty for no factors.

Add a compile-time assertion that a small in-test type satisfies each seam, so a
signature change is a build failure rather than a surprise at the consumer.
</test_first>

<constraints>
- PUBLIC REPO. No private repo/service/product names, no internal ticket or
  design-doc references, no absolute local paths, no branch names or hashes —
  code, comments, test names and commit messages alike. Write doc comments fresh.
  Do NOT read other repositories on this machine.
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
