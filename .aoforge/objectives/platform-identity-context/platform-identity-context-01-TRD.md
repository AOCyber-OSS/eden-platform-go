---
objective: platform-identity-context
trd: 01
type: tdd
wave: 1
depends_on: []
files_modified:
  - platform/identity/claims.go
  - platform/identity/claims_test.go
autonomous: true
requirements: [IC-01]
must_haves:
  truths:
    - "Claims marshals to EXACTLY these JSON keys: tnt, ent, aal, ctx_ver, tok_ref, plus registered iss/sub/iat/exp/jti"
    - "JWTType const == \"identity-context+jwt\" byte-for-byte"
    - "Version const == 1 (the version this package EMITS)"
    - "VersionSet is a configurable set type; DefaultVersionSet() accepts exactly {1}"
    - "VersionSet.Accepts(v) reports membership; a set built with {1,2} accepts both and rejects 3"
    - "Claims.Validate(VersionSet) rejects: ctx_ver not in set, empty sub, empty tnt, empty aal"
    - "Claims.Validate returns nil for a fully-populated claim set whose ctx_ver is in the accepted set"
    - "An empty ent slice is VALID (entitlements may legitimately be empty)"
    - "TokRef(token) returns the first 8 bytes of sha256(token) hex-encoded == exactly 16 lowercase hex chars"
  artifacts:
    - platform/identity/claims.go
    - platform/identity/claims_test.go
  key_links:
    - "Claims embeds jwt.RegisteredClaims from github.com/golang-jwt/jwt/v5 (already a direct dep)"
    - "Validate is the ONLY place semantic claim rules live; the verifier calls it rather than re-implementing"
---

<objective>
Define the frozen identity-context claim contract: the `Claims` type with its exact
JSON tags, the token type, the emitted schema version, a configurable
accepted-version set, and the semantic validation a JWT parser does not perform.

This is the foundation TRD — the minter (02) and verifier (04) both build on it and
neither may redeclare any of it.
</objective>

<file_tree>
platform/identity/
├── claims.go        ← CREATE (Claims, JWTType, Version, VersionSet, Validate, TokRef)
└── claims_test.go   ← CREATE (tag-level marshal assertions + validation table)
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_frozen_wire_format>
This shape is already mirrored byte-for-byte by multiple independent consumers.
A field rename or JSON-tag change is a SILENT wire break — it does not fail to
compile, it fails to authorize, at runtime, in production. Reproduce it exactly:

```go
type Claims struct {
	jwt.RegisteredClaims          // supplies iss, sub, iat, exp, jti
	Tenant       string   `json:"tnt"`
	Entitlements []string `json:"ent"`
	AAL          string   `json:"aal"`
	CtxVer       int      `json:"ctx_ver"`
	TokRef       string   `json:"tok_ref"`
}
```

Field semantics to capture in doc comments:
- `tnt` — tenant SLUG, human-readable. NEVER a UUID; never parse it as one.
- `ent` — entitlement strings resolved at issuance. MAY be empty.
- `aal` — authenticator assurance level: "AAL1" / "AAL2" / "AAL3".
- `ctx_ver` — schema version of this claim set.
- `tok_ref` — first 8 bytes of sha256(upstream access token), hex (16 chars).
  LOG / FORENSIC CORRELATION ONLY. A verifier never recomputes or gates on it —
  it generally cannot, because it does not see the upstream token.
</the_frozen_wire_format>

<version_negotiation>
The accepted-version set is CONFIGURATION, not a constant. This is the whole
reason the package exists: independent consumers drifted on this set and the
drift surfaced only as a runtime authorization failure.

- `Version = 1` is what this package EMITS.
- `DefaultVersionSet()` accepts exactly `{1}` — deliberately conservative, matching
  the strictest consumer. A consumer that must also accept a newer version widens
  the set EXPLICITLY at construction. Widening is a decision, never a default.
</version_negotiation>

<test_first>
Write claims_test.go FIRST and watch it fail.

The marshal test must assert on the JSON KEYS, not just round-trip through the
struct — a round-trip test passes even if every tag is renamed, so it cannot
catch the exact break this contract exists to prevent. Marshal a populated
Claims, unmarshal into map[string]any, and assert each expected key is present.

Validation is a table test: one row per rejection reason plus the happy path,
and an explicit row proving empty `ent` is accepted.
</test_first>

<constraints>
- PUBLIC REPO. Doc comments describe this contract on its own terms. No private
  repo/service/product names, no internal ticket or design-doc references, no
  absolute local paths, no branch names or hashes.
- No new module dependencies.
</constraints>

</embedded_context>

<verify>
go test ./platform/identity/ -race -count=1 -v
go vet ./platform/identity/
git diff --exit-code go.mod go.sum
</verify>
