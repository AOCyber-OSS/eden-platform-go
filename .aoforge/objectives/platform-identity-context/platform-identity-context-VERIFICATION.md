---
objective: platform-identity-context
status: passed
requirements-verified: [IC-01, IC-02, IC-03, IC-04, IC-05]
gaps: []
---

# Verification — platform-identity-context

Verified against the working tree, not against the execution reports. Two of the
five TRDs were executed by agents that stopped before reporting, so every claim
below was re-established directly.

## Acceptance criteria

| Criterion | Evidence |
|---|---|
| Claim type with an explicit, configurable supported-version set | All five frozen tags present in `claims.go`; `VersionSet` / `NewVersionSet` / `DefaultVersionSet` exported; `Validate` takes the accepted set as a parameter rather than reading package state |
| Verifier accepting multiple trusted issuers and JWKS URLs | `NewVerifier([]TrustedIssuer, ...)`, each entry carrying its own `KeySource`; `NewRemoteJWKS` for a published key set; **zero** uses of the library's single-issuer parser option |
| Minter producing a context the verifier accepts | `TestMintedTokenVerifiesAndValidates` and the full publish-and-fetch round trip both pass |
| Round-trip, multi-issuer and version-negotiation tests | `TestAMintedContextRoundTripsThroughAPublishedKeySet`, `TestOneVerifierAcceptsContextsFromTwoIssuers` (remote and in-process), `TestVersionNegotiationIsDecidedByTheVerifier` (one token, two verifiers, opposite outcomes) |
| Consumers can adopt without a wire-format change | `TestARawWireContextVerifies` accepts a hand-written document no struct tag produced; `TestAMintedContextIsByteCompatibleWithTheRawWire` pins the emitted keys, including the `tok_ref` present-when-empty / `jti` absent-when-empty asymmetry |

## Locked decisions

- **Emitted version is 1** — `const Version = 1`. Minting outside the set the
  strictest deployed consumer accepts would strand it in the field.
- **Default accepted set is `{1}`** — the strictest; widening is explicit,
  per verifier, via `WithAcceptedVersions`.
- **Issuer set plural from day one** — the single-issuer parser option appears
  nowhere; `iss` is matched against a configured set.
- **Nothing about trust compiled in** — no hardcoded issuer or trust list in
  non-test source.
- **No unauthenticated mint path** — no build tags and no environment reads
  anywhere in the package.
- **Assurance is honest** — required caller input; absent assurance is an error
  and is never defaulted, upward or otherwise.
- **No new module dependency** — `go.mod` / `go.sum` unchanged across the branch.

## Gates

`go test ./platform/identity/... -race -count=1 -v` → **225 PASS / 0 SKIP / 0 FAIL**.
`go vet ./platform/identity/...` clean · `gofmt -l platform/identity/` empty ·
`go build ./...` clean · `git diff go.mod go.sum` empty.

## Mutation testing

Passing tests were not taken on trust. Each mutation was restored
byte-identically and none entered a commit.

| Mutation | Test that died |
|---|---|
| Rename the frozen `tnt` tag | Tag-level contract tests **and** the raw-wire fixture. The two symmetric round-trip tests passed against the broken format — which is the argument for the fixture, demonstrated |
| Wrap the real rejection cause into the returned error | Broad failure: the tests require the error to be *exactly* the sentinel, so even wrapping is caught |
| Drop the trusted-issuer check | The "before any key work" assertion — the one proving the key source is never consulted for an untrusted issuer |
| Drop the token-type assertion | All five wrong-type cases |
| Remove the key cache's TTL trigger | Reproduced the fixed-key-id rotation trap (one fetch where two were required) |
| Remove the unknown-kid refetch floor | 501 upstream fetches from 500 invented key ids |
| Require an exact 32-byte EC coordinate | A valid short-coordinate key was rejected |

## A defect found and fixed during verification

`NewMinter` called the signing seam's global registration helper, which
**overrides the JWT library's ES256/RS256 methods for the whole process,
irreversibly**. Constructing a `Minter` would therefore have changed how
unrelated code in the same binary signs: anything resolving its method through
the registry and passing an in-memory private key would begin failing on a
key-type mismatch, far from the import that caused it. Nothing in this
repository broke, but this is a library other services import.

Fixed by passing the method value directly to the token constructor, which needs
no registry entry. Pinned by a test asserting the process-global methods are
unchanged after construction. Verification is unaffected — what is signed is
standard JWS, which the library's own methods verify against a public key, and
the pre-existing round-trip test proves it.

## Repository hygiene

This repository is public and `.planning/` is tracked in it, so package source,
tests, documentation, this objective's planning directory and every commit
message on the branch were swept for absolute local paths, internal ticket and
design-document reference patterns, and private repository or service
identifiers.

Clean. Two hits were judged and dismissed: one is a TRD's own list of the
patterns to search for, and one is a reference to this repository's own roadmap
numbering, already tracked here. The only external identifiers in the package
are the module's own import path and reserved example domains.

## Out of scope, worth a decision

`platform/auth/jwt.go` and `platform/auth/entitlements.go` — already on the
default branch — carry private product names and an internal design-document
reference in their doc comments. Pre-existing, untouched by this objective, and
noted here only because it is the same class of exposure this objective guarded
against.
