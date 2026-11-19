---
objective: platform-identity-issuer
trd: 02
type: tdd
wave: 2
depends_on: [01]
files_modified:
  - platform/identity/assurance.go
  - platform/identity/assurance_test.go
autonomous: true
requirements: [IS-02]
must_haves:
  truths:
    - "DeriveAssurance returns an error for an authentication with no factors — absence of evidence is not a level"
    - "Exactly one DISTINCT factor category yields AAL1, however many methods were exercised within it"
    - "Two knowledge factors yield AAL1, NOT AAL2 — assurance counts categories, not prompts"
    - "Two or more DISTINCT categories yield AAL2"
    - "AAL3 is returned ONLY when two or more categories are present AND both HardwareBacked and PhishingResistant were asserted"
    - "AAL3 is never reached by factor count alone, and never inferred from a Method name"
    - "The result is always one of the ladder constants from the existing contract; the function never invents a level"
    - "DeriveAssurance is pure: same authentication, same level, no clock, no configuration, no package state"
  artifacts:
    - platform/identity/assurance.go
    - platform/identity/assurance_test.go
  key_links:
    - "Consumes Authentication.Kinds() from TRD 01, which already collapses duplicate categories"
    - "Returns the AAL1/AAL2/AAL3 constants already defined in the claim contract; does not redeclare them"
---

<objective>
Turn what actually happened during authentication into the assurance level the
context will carry.

This is the claim most likely to be wrong in a way nobody notices. It lands in a
downstream authorization decision and in an audit record, where a level nobody
achieved is indistinguishable from one that was.
</objective>

<file_tree>
platform/identity/
├── claims.go                 (existing — AAL1/AAL2/AAL3 constants; do not redeclare)
├── authentication.go         (TRD 01 — Authentication, Kinds)
├── assurance.go              ← CREATE
└── assurance_test.go         ← CREATE
</file_tree>

<execution_context>
@~/.claude/devflow/workflows/execute-trd.md
@~/.claude/devflow/templates/summary.md
</execution_context>

<embedded_context>

<the_ladder>
The derivation, and the reasoning each rung rests on:

- **No factors** → an error. Nothing was established, so no level describes it.
  Returning the lowest rung here would be the exact dishonesty this function
  exists to prevent: it would read as "authenticated weakly" when the truth is
  "not authenticated".

- **One distinct category** → AAL1. A password and a security question are two
  prompts and one category; the second adds friction, not assurance, because
  whatever compromises the first tends to compromise the second.

- **Two or more distinct categories** → AAL2. This is the multi-factor rung, and
  it is about independence: a knowledge factor and a possession factor fail in
  different ways.

- **Two or more categories, plus BOTH asserted properties** → AAL3. The top rung
  additionally requires a hardware-resident authenticator and resistance to
  verifier impersonation. Neither property is visible in a factor's name — a
  Method of "webauthn" may or may not be hardware-backed — so both must have been
  asserted by the verifier that saw the exchange. They are read here, never
  guessed.

Both properties asserted WITHOUT two categories does not reach AAL3. The
properties qualify a multi-factor authentication; they do not substitute for one.
</the_ladder>

<never_upward>
The whole function fails safe. Every unknown, every ambiguity and every gap
resolves DOWNWARD to the lower rung, never upward. An issuer that overstates
assurance is worse than one that understates it: understating costs a user an
extra prompt, overstating silently grants access that a policy intended to
withhold, and leaves an audit trail asserting a control that was never applied.

Consumers whose policy differs may map the level themselves before minting. What
must not happen is this function quietly doing it for them.
</never_upward>

<test_first>
Write assurance_test.go FIRST and watch it fail. A table test is the right shape,
with a row per rung and a row per way of NOT reaching the next one.

The rows that matter most, because they are the ones a careless implementation
gets wrong:
- two knowledge factors (password + security question) → AAL1, not AAL2
- three methods within one category → still AAL1
- knowledge + possession → AAL2
- knowledge + possession + both properties asserted → AAL3
- knowledge + possession + only ONE property asserted → AAL2
- one category + both properties asserted → AAL1, not AAL3
- no factors → error, and no level returned alongside it

Assert the returned level is one of the ladder constants in every accepting case.
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
