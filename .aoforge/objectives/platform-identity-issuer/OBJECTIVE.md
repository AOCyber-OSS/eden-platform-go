# Objective: platform-identity-issuer (application as first-party issuer)

**Repo:** eden-platform-go. **Branch:** `feat/platform-identity-issuer` off origin/main.
**Work:** feature. **TDD:** strict. **Tracking:** #52. **Builds on:** #49 (`platform/identity`).

## Goal

Let an application authenticate its own users and present that result as a
verifiable identity context — so a boundary, or a peer service, can consume it
exactly as it would one from a dedicated identity provider.

`platform/identity` already supplies the claim contract, a minter and a verifier.
`platform/auth` already supplies the credential primitives (Argon2id passwords,
TOTP, look-up secrets, WebAuthn) and `platform/kms` the signing keys. What is
missing is the piece that joins them: authenticate, resolve, mint, publish.

## Why the seams are narrow

`platform/auth.AuthStore` is not a dependency of this work, deliberately. It is a
25-method interface shaped around companies, roles, SSO configuration, OAuth
credentials and refresh tokens, keyed by company UUIDs. An application whose
tenancy is modelled differently would have to implement `CreateCompany` and
`GetUserRole(companyID, userID)` merely to mint a context.

The credential primitives underneath it are already store-free and pure
(`PasswordHasher.Verify`, `totp.Validate`, `totp.VerifyBackupCode`). So this
objective defines two narrow seams instead, and lets each consumer implement them
against its own model:

1. **Credential verification** — given a credential, is it valid, and which
   factors were actually used?
2. **Claims resolution** — given an authenticated subject, what tenant and
   entitlements apply?

## Scope (IN)

1. **The seams** — the two interfaces above, plus the authentication result that
   carries the factors actually exercised.
2. **Assurance derivation** — factors to assurance level, conservatively and
   honestly.
3. **The issuer** — composes the seams with the existing minter. Requires a
   signing key whose identifier is derived from the key, and proves at start-up
   that it can actually sign.
4. **Key set publication** — an HTTP surface over the existing key-set type.
5. **Round trip and documentation** — authenticate, mint, publish, verify.

## Out of scope

- Any credential *implementation*. The primitives exist; this objective consumes
  them through a seam and does not reimplement or wrap them.
- Session lifecycle, refresh tokens, login rate limiting, account lockout,
  registration, password reset. An application owns those and they are not part
  of presenting an authentication result as a context.
- Migrating any consumer onto this.

## Locked design decisions

- **No dependency on `AuthStore`.** See above. Two narrow seams, implemented by
  the consumer against its own model.
- **No second key path.** The issuer takes a signer from the existing KMS
  surface. It does not load, generate, parse or persist key material itself.
- **The key identifier must be derived from the key, never a constant.** A fixed
  identifier over a regenerated key is the failure mode that matters: a consumer's
  key cache only misses on an *unknown* identifier, so a constant one that now
  names different key material is never re-fetched and every request is refused
  indefinitely. A derived identifier changes when the key does, which produces the
  miss that heals it.
- **Prove signing at start-up.** The KMS surface offers a real sign-and-verify
  round trip; an issuer runs it before serving. It catches the configuration that
  permits reading a public key but denies signing — otherwise discovered at the
  first login attempt.
- **Assurance is derived, never asserted upward.** Single factor is single
  factor. The highest level is never inferred from a factor name, because the
  properties it requires are not observable from one.
- **No unauthenticated mint path.** Nothing exported, build-tagged or
  environment-gated may mint without a successful credential verification.

## Requirements (each in a TRD)

- **IS-01** — The two seams and the authentication result carrying the factors used.
- **IS-02** — Assurance derivation from factors: conservative, documented, never upward.
- **IS-03** — The issuer: compose seams with the minter; derived key identifier;
  start-up signing proof; no unauthenticated path.
- **IS-04** — Key set publication over HTTP, built on the existing key-set type.
- **IS-05** — End-to-end: authenticate → mint → publish → verify. README. Hygiene sweep.

## Verification

`go test ./platform/identity/... -race -count=1 -v` — real PASS counts, SKIP == 0.
The 225 tests already in the package must stay green. `go vet` clean. No new
module dependencies.

## Repository hygiene (load-bearing)

This repository is **public** and `.planning/` is tracked in it. No private repo
or service names, no internal ticket or design-document references, no absolute
local filesystem paths, no branch names or commit hashes — in code, comments,
test names, planning documents or commit messages. IS-05 sweeps and the sweep is
part of done.
