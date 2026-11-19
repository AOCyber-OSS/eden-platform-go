---
objective: platform-identity-issuer
status: passed
requirements-verified: [IS-01, IS-02, IS-03, IS-04, IS-05]
gaps: []
---

# Verification — platform-identity-issuer

Verified against the working tree, not against the execution reports. One of the
four executing agents stopped before reporting, so its work was re-established
directly, and the final TRD was executed in-session for the same reason.

## Acceptance criteria (issue #52)

| Criterion | Evidence |
|---|---|
| An application can authenticate a user with the existing credential stack and mint a verifiable context | `Issue` composes the two consumer seams with the existing minter; the end-to-end test drives a credential in and a verified claim set out across a real HTTP boundary |
| Key set published through the existing signer/key-set surfaces — no second key path | `KeySetHandler` renders via the platform key-set type; the issuer takes a platform signing key and never loads, generates, parses or persists key material |
| Claim names and version set shared with the verifier, not redeclared | Nothing in this objective declares a claim or a version; the contract is consumed unchanged, and the end-to-end verifier runs on the DEFAULT accepted set |
| Assurance reflects the factors actually used | Derived from distinct factor categories, never supplied by a caller; every rung asserted end to end |
| Round trip: mint → publish → verify | The key set is served over a real server, fetched by the package's own remote key source, and the context verified |

## Locked decisions

- **No dependency on the store-shaped auth interface.** Neither seam mentions
  storage, companies, roles, sessions or refresh tokens.
- **No second key path.** The issuer takes a platform signing key; the published
  document and the signature come from that one value with no adapter between.
- **The key id is not a parameter.** Read off the signing key, so a constant one
  is unrepresentable. Guarded by a test asserting the constructor takes exactly
  one string parameter.
- **Signing proved at start-up.** Construction runs the key's health check and
  fails if it errors.
- **Assurance never rounds upward.** Categories, not prompts; the top rung needs
  two asserted properties and is never inferred from a factor name.
- **No unauthenticated mint path.** No build-tagged files; the issuer exports
  only `Issue`, guarded by a test.
- **No new module dependency.** `go.mod` / `go.sum` unchanged across the branch.

## Gates

`go test ./platform/identity/... -race -count=1 -v` → **356 PASS / 0 SKIP / 0 FAIL**.
`go vet` clean · `gofmt` empty · `go build ./...` clean · `go.mod`/`go.sum` unchanged.

## Mutation testing

| Mutation | Test that died |
|---|---|
| Resolve claims before verifying the credential | Six tests, including one showing the resolver asked about an unverified identifier — the disclosure the ordering exists to prevent |
| Accept a `(nil, nil)` verifier return as success | The distinct-sentinel test. Nothing was minted either way (validation is the backstop), but the specific error degraded — silently-safe and correctly-attributed are different things |
| Skip the start-up health check | Three tests, including the call count and the construct-anyway case |
| Publish under a hardcoded key id | Four tests, including the round-trip key resolution |
| Overwrite the derived assurance with a constant top rung | Four of the five ladder rows — correctly not the row expecting that rung |
| Count factors instead of distinct categories | Exactly two rows: two knowledge factors, and three methods in one category. Every other row passed, so those two are what carry the rule |

Two notes on method. A "re-render the key set per request" mutation could not be
expressed at all — the handler retains bytes, not the signer — which is a
stronger outcome than the mutation failing. And a first attempt at the assurance
mutation left a variable unused, so the package did not build and no test ran;
the run was repeated with a mutation that compiles, because a build failure is
not a passing test.

## Repository hygiene

This repository is public and `.planning/` is tracked in it. Package source,
tests, documentation, this objective's planning directory and every commit
message on the branch were swept for absolute local paths, internal ticket and
design-document reference patterns, private repository or service identifiers,
and the reserved port. All three sweeps clean.

## Out of scope, unchanged since the previous objective

`platform/auth/jwt.go` and `platform/auth/entitlements.go` still carry private
product names and an internal design-document reference in doc comments on the
default branch. Separately, the dependency scanner now reports substantially
more advisories on the default branch than the last recorded count. Neither is
touched by this objective; both are noted for a deliberate decision.
