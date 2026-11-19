# Objective: platform-identity-context (the shared identity-context contract)

**Repo:** eden-platform-go. **Branch:** `feat/platform-identity-context` off origin/main.
**Work:** feature. **TDD:** strict. **Tracking:** #49.

## Goal

Create `platform/identity`: one shared definition of the signed identity-context
JWT — the claim type, one verifier that trusts a **configured set** of issuers,
and one minter. Today several services each carry a hand-maintained copy of this
claim schema; the copies have already diverged on which schema versions they
accept, and that divergence is only discoverable at runtime, as an authorization
failure.

## Why this shape

An identity context is a short-lived, signed assertion that a boundary or an
application has authenticated a principal. A consumer verifies it and maps it
onto its own authorization model. Because the token crosses service boundaries,
its wire format is a **frozen contract**: a field rename or a JSON-tag change is
a silent desync, not a compile error.

This package does not introduce a new crypto stack. It supplies the claim shape
between the existing signing seam (`platform/auth/kmssigner`) and the existing
key-publication surface (`platform/auth/jwks`).

## Scope (IN)

New package `platform/identity/`:

1. **The contract** — `Claims` (exact JSON tags, frozen), the `identity-context+jwt`
   token type, the emitted schema version, and a **configurable** accepted-version
   set. Semantic validation the JWT parser does not perform.
2. **The minter** — signs a context through a `kmssigner.Signer`, stamping the
   required `typ` and `kid` headers. Honest assurance. Short TTL.
3. **Key sources** — the seam a verifier resolves a signing key through: an
   in-memory set (in-process issuers, tests) and a remote JWKS fetcher with
   refetch-on-unknown-kid.
4. **The verifier** — accepts a **set** of trusted issuers, each with its own key
   source. Collapses every failure into one sentinel error.
5. **Round-trip, multi-issuer and version-negotiation tests**, plus a README.

## Out of scope

- Authenticating a user, serving JWKS over HTTP, and signing-key persistence
  requirements. That is the follow-on first-party-issuer objective (#52). Build
  the minter so that work sits on top of it without reshaping it.
- Migrating any consumer onto this package. Consumers adopt separately, and must
  be able to do so **without a wire-format change**.

## Locked design decisions

- **The minter emits schema version 1.** The strictest consumer in the field
  accepts only `{1}`. Emitting outside the already-whitelisted set strands that
  consumer and turns a library change into a coordinated multi-service deploy.
- **The verifier's issuer set is plural from day one.** The same service will
  verify an in-process issuer now and an external provider later. One pinned
  issuer means a rewrite. This rules out `jwt.WithIssuer`, which pins exactly one.
- **Nothing about which issuer is trusted may be compiled in.** Trusted issuers,
  entitlement strings and the accepted version set are all configuration.
- **Assurance must be honest.** The assurance claim reflects the factors actually
  used and never defaults upward — it lands in a downstream audit record.
- **No unauthenticated mint path in any shipped build** — not behind a build tag,
  not behind an environment flag.
- **No new module dependency.** The remote key source is stdlib-only, so adopting
  this package does not force a dependency on a consumer.

## Requirements (each in a TRD)

- **IC-01** — The claim contract: frozen `Claims`, token type, emitted version,
  configurable accepted-version set, semantic validation.
- **IC-02** — The minter: sign through `kmssigner.Signer`; required `typ`/`kid`
  headers; honest assurance; short TTL; no unauthenticated path.
- **IC-03** — Key sources: static in-memory, and remote JWKS with
  refetch-on-unknown-kid and a negative-refetch floor.
- **IC-04** — The verifier: plural trusted issuers, per-issuer key source,
  single sentinel error, full semantic validation.
- **IC-05** — Round-trip / multi-issuer / version-negotiation coverage, README,
  and the public-repo hygiene sweep.

## Verification

`go test ./platform/identity/... -race -count=1 -v` — real PASS counts, SKIP == 0,
never a bare `ok`. `go vet ./platform/identity/...` clean. No new module
dependencies (`go.mod` unchanged).

## Repository hygiene (load-bearing)

This repository is **public**. The contract is drawn from implementations that
live in private repositories. Carry the **wire format** across; leave the
**provenance** behind. No private repo or service names, no internal ticket or
design-document references, no absolute local filesystem paths, no branch names
or commit hashes — in code, comments, test names, planning documents, or commit
messages. Doc comments are written fresh, describing the contract on its own
terms. IC-05 sweeps for this and the sweep is part of done.
