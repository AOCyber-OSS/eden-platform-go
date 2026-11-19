---
objective: platform-identity-context
trd: 05
subsystem: auth
tags: [integration, wire-contract, documentation, go]

# Dependency graph
requires: [01, 02, 03, 04]
provides:
  - "platform/identity end-to-end acceptance tests (raw wire, round trip, multi-issuer, negotiation, rotation)"
  - "platform/identity/README.md — the adoption and operations document"
affects: [downstream-consumers]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Raw-wire fixture: a token whose bytes no struct tag contributed to"
    - "Round trip through the platform's own key publication surface rather than a hand-built key set"
    - "Mutation testing to prove the wire fixture catches what symmetric tests cannot"

requirements-completed: [IC-05]
---

# TRD 05 — End-to-end proof and documentation

## What shipped

`platform/identity/identity_test.go` (six end-to-end cases) and
`platform/identity/README.md`. The package comment in `claims.go` was also
corrected: it still said signing, key resolution and verification were "the
callers' concern", which was true when that file stood alone and is not now that
all three live in the package.

No `doc.go` was added. `claims.go` already carries the package comment, and a
second one would be a duplicate package comment rather than documentation.

## The fixture that earns its place

Every other test in this package mints with this package and verifies with this
package. Both halves share one `Claims` struct, so a renamed JSON tag round-trips
between them perfectly while breaking every consumer that decodes the document by
key name — which is precisely the failure this package exists to prevent, and it
is invisible to a symmetric test.

`TestARawWireContextVerifies` is therefore built from a hand-written JSON literal
and a hand-assembled header, signed directly through the signing seam. No struct
tag contributes a byte of it.

This was verified rather than asserted. Renaming the `tnt` tag and re-running the
suite killed the tag-level contract tests and the raw-wire fixture — while
`TestAMintedContextRoundTripsThroughAPublishedKeySet` and
`TestOneVerifierAcceptsContextsFromTwoIssuers` both passed happily against a
broken wire format. That is the whole argument for the fixture, demonstrated.
The mutation was restored byte-identically and never entered a commit.

## What the end-to-end cases cover

- **Raw wire** — a hand-written context verifies, and each wire key lands in the
  expected Go field.
- **Byte compatibility** — a minted context carries every frozen key; `tok_ref`
  is present-and-empty when unset (no `omitempty`), `jti` is absent when unset
  (has `omitempty`), and `ent` encodes as `[]` rather than `null`. That
  asymmetry is contract, not accident.
- **Full round trip** — mint, publish the public half through the platform's own
  key publication surface, serve it over HTTP, fetch it through the remote key
  source, verify. Publishing through that surface is the point: it proves the
  bytes this platform publishes are the bytes this package reads, instead of
  assuming it. Asserts exactly one upstream fetch.
- **Multi-issuer** — two issuers with independent signers, one backed by a
  remote key set and one in-process, both accepted by a single verifier.
- **Version negotiation** — one token, two verifiers, opposite outcomes. Driven
  from the wire rather than from the minter, since nothing here will emit a
  version it does not stamp.
- **Rotation under an unchanged key id** — the deployment case the cache TTL
  exists for: a key replaced behind a fixed id never produces a cache miss, so
  only the time-based refresh recovers.

## Verified

`go test ./platform/identity/... -race -count=1 -v` → 225 PASS / 0 SKIP / 0 FAIL.
`go vet` clean, `gofmt` clean, `go build ./...` clean, `go.mod`/`go.sum` unchanged.

## Repository hygiene

Swept package source, tests, docs, this objective's planning directory and the
branch's commit messages for absolute local paths, internal ticket and
design-document reference patterns, and private repo or service identifiers.

Clean. Two hits were judged and dismissed: one is this TRD's own list of the
patterns to search for, and one is a reference to this repository's own roadmap
numbering, which is already tracked in this repository. The only external
identifiers in the package are the module's own import path and reserved
example domains.
