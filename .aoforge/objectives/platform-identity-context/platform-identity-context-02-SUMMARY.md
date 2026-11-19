---
objective: platform-identity-context
trd: 02
subsystem: platform/identity
tags: [identity-context, jwt, minting, signing-seam, assurance]
requirements-completed: [IC-02]
requires:
  - "platform/identity/claims.go (TRD 01) — Claims, JWTType, Version, AAL*, TokRef, DefaultVersionSet, sentinels"
  - "platform/auth/kmssigner — Signer seam, RegisterAll, ES256/RS256 signing methods"
provides:
  - "identity.Minter / NewMinter / MintInput / Mint — signed identity-context issuance"
  - "identity.DefaultTTL (15m), WithTTL, WithClock"
  - "construction sentinels: ErrNilSigner, ErrMissingKeyID, ErrMissingIssuer, ErrUnsupportedAlgorithm, ErrInvalidTTL, ErrInvalidClock"
  - "mint-input sentinels: ErrInvalidAssurance, ErrMalformedTokenRef (plus reused ErrMissingSubject/Tenant/Assurance)"
affects:
  - "TRD 04 (verifier) — mints its fixtures; WithClock/WithTTL are the seams for expiry cases"
  - "TRD 05 (round trip) — mints the token the JWKS round trip verifies"
tech-stack:
  added: []
  patterns:
    - "functional options validated centrally in the constructor, so a bad option fails at start-up"
    - "required caller input with no defaulting, for claims that must be honest"
    - "shape-validated correlation handle, to keep raw credentials out of a signed token"
key-files:
  created:
    - platform/identity/minter.go
    - platform/identity/minter_test.go
  modified: []
decisions:
  - "Signed through kmssigner, never through the ML-DSA access-token manager"
  - "typ and kid set explicitly — the library defaults typ to \"JWT\" and sets no kid at all"
  - "Assurance is required input, validated against the AAL ladder, never defaulted"
  - "jti is caller-supplied rather than generated, so it correlates with a record that exists"
  - "tok_ref must be a TokRef-shaped handle; the rejected value is kept out of the error text"
metrics:
  duration: ~35m
  tasks: 2
  files: 2
  completed: 2026-08-19
---

# Objective platform-identity-context TRD 02: The Minter Summary

A `Minter` that turns caller-supplied authenticated subject data into a signed
`identity-context+jwt`, stamping the mandatory `typ` and `kid` headers and
signing through the existing `kmssigner.Signer` seam — with assurance treated as
required, unvalidatable input refused rather than completed, and no path that
mints without a caller-supplied subject.

## What Was Built

`platform/identity/minter.go` (367 lines):

- **`Minter`** — immutable after construction, safe for concurrent use, one
  issuer and one signing key per instance.
- **`NewMinter(signer, keyID, issuer, opts...)`** — calls
  `kmssigner.RegisterAll()` so a Minter is correct standalone, then resolves the
  signing method via `jwt.GetSigningMethod(signer.SigningAlgorithm())`.
- **`MintInput`** — `Subject`, `Tenant`, `Entitlements`, `Assurance` (required
  trio plus entitlements), and optional `TokenID` (jti) / `TokenRef` (tok_ref).
- **`Mint`** — validates, assembles `Claims`, sets `typ`/`kid`, signs, returns
  the compact JWS. Returns an empty token on every error path.
- **`DefaultTTL`** = 15 minutes; **`WithTTL`**, **`WithClock`**.

## Task Evidence

| Task | Verify Command | Exit Code | Status |
|---|---|---|---|
| 1: RED — write `minter_test.go` first | `go test ./platform/identity/ -race -count=1 -v` | 1 (build failed) | PASS (correct RED) |
| 2: GREEN — implement `minter.go` | `go test ./platform/identity/ -race -count=1 -v` | 0 | PASS |

## TDD Evidence

| Phase | Command | Exit Code | Expected |
|---|---|---|---|
| RED | `go test ./platform/identity/ -race -count=1 -v` | 1 | FAIL (correct) |
| GREEN | `go test ./platform/identity/ -race -count=1 -v` | 0 | PASS (correct) |

RED output was a compile failure — the canonical Go RED, since the test names
symbols that do not exist yet:

```
# github.com/aocybersystems/eden-platform-go/platform/identity [.../platform/identity.test]
platform/identity/minter_test.go:87:42: undefined: MinterOption
platform/identity/minter_test.go:87:58: undefined: Minter
platform/identity/minter_test.go:91:17: undefined: NewMinter
platform/identity/minter_test.go:100:19: undefined: MintInput
platform/identity/minter_test.go:101:9: undefined: MintInput
platform/identity/minter_test.go:149:32: undefined: Minter
platform/identity/minter_test.go:149:43: undefined: MintInput
platform/identity/minter_test.go:202:17: undefined: NewMinter
platform/identity/minter_test.go:203:21: undefined: ErrNilSigner
platform/identity/minter_test.go:204:62: undefined: ErrNilSigner
platform/identity/minter_test.go:204:62: too many errors
FAIL	github.com/aocybersystems/eden-platform-go/platform/identity [build failed]
FAIL
```

## Validation Gate Results

| Gate | Command | Exit Code | Status |
|---|---|---|---|
| test | `go test ./platform/identity/ -race -count=1 -v` | 0 | PASS — 98 PASS / 0 SKIP / 0 FAIL |
| regression | same, `-run 'TestClaims\|TestFrozen\|TestTokRef\|TestVersionSet\|TestDefaultVersionSet'` | 0 | PASS — TRD 01's 38 still green |
| vet | `go vet ./platform/identity/` | 0 | PASS |
| format | `gofmt -l platform/identity/` | 0 | PASS (no files listed) |
| deps | `git diff --exit-code go.mod go.sum` | 0 | PASS (unchanged) |

98 total PASS = TRD 01's 38 + 60 from the 31 new minter test functions.

## Must-Haves

| Must-have | Where pinned |
|---|---|
| NewMinter rejects nil signer / empty kid / empty issuer, distinctly | `TestNewMinterRejectsANilSigner`, `...AnEmptyKeyID`, `...AnEmptyIssuer`, `TestNewMinterRejectionsAreDistinguishable` |
| Header `typ` == `identity-context+jwt` and `kid` == configured kid | `TestMintStampsTheIdentityContextTokenType`, `TestMintStampsTheConfiguredKeyID` |
| Header `alg` matches `SigningAlgorithm()` (ES256 or RS256) | `TestMintHeaderAlgFollowsTheSigner` (both subtests) |
| `ctx_ver` == Version, `iss` == configured, caller's sub/tnt/ent/aal | `TestMintStampsTheEmittedSchemaVersion`, `TestMintStampsTheConfiguredIssuer`, `TestMintCarriesTheCallerSuppliedSubjectData` |
| iat/exp stamped; exp-iat == TTL; DefaultTTL 15m | `TestMintExpiryIsExactlyTheConfiguredTTL`, `TestMintStampsIssuedAtFromTheClock`, `TestDefaultTTLIsFifteenMinutes` |
| Mint requires subject, tenant, assurance | `TestMintRequiresAuthenticatedSubjectData`, `TestMintRejectsTheZeroValueInput` |
| Assurance never defaulted upward | `TestMintDoesNotDefaultAssuranceUpward`, `TestMintReportsEachAssuranceLevelVerbatim` |
| Minted token parses and validates | `TestMintedTokenVerifiesAndValidates`, `TestMintedTokenIsRejectedByAnUnrelatedKey` |
| No unauthenticated / build-tagged mint path | `TestMintRejectsTheZeroValueInput`, `TestPackageHasNoBuildTaggedFiles` |

Assertions are made on the **decoded** header and payload — each JWS segment is
base64url-decoded into an untyped map — so a renamed JSON tag is visible. A
struct round trip would pass unchanged through exactly that break.

## Deviations from Plan

### Corrected test expectation (not an implementation change)

**`tok_ref` is emitted even when empty.** The first GREEN run produced one
failure: `TestMintOmitsTheOptionalCorrelationClaimsWhenAbsent` expected both
optional claims to disappear when unset. `jti` does — `jwt.RegisteredClaims.ID`
carries `omitempty` — but `tok_ref` does not, because TRD 01 froze it as
`json:"tok_ref"` with no `omitempty`.

The tempting fix was to add `omitempty` in `claims.go`. That would have been the
defect TRD 01 exists to prevent: a JSON-tag change compiles cleanly on both
sides and then desyncs a hand-maintained consumer at run time. The test was the
thing that was wrong, so the test was corrected — renamed to
`TestMintCarriesNoCorrelationHandlesWhenNoneAreSupplied`, now asserting the
asymmetry explicitly and recording that it is inherited from the frozen format
rather than chosen by the minter. `claims.go` is untouched.

### Additions beyond the literal must-haves

Each is a fail-fast guard rather than new capability:

1. **`ErrUnsupportedAlgorithm`.** `jwt.GetSigningMethod` returns a *non-nil*
   method for algorithms the seam does not implement (`HS256`, for instance, is
   registered by default), so a mis-wired signer would otherwise fail at the
   first mint with `ErrInvalidKeyType` rather than at start-up. The accepted set
   is read off the seam's own methods — `(&kmssigner.ES256SigningMethod{}).Alg()`
   — so it cannot drift from what is actually registered. This is also the check
   that refuses an ML-DSA access-token signer wired in here by mistake.
2. **`ErrInvalidTTL` / `ErrInvalidClock`.** A non-positive lifetime mints an
   already-expired context; a nil clock panics on first use.
3. **`ErrInvalidAssurance`.** Absent assurance is an error per the TRD; a level
   *outside* the AAL ladder is rejected too. Free text cannot be compared
   against a policy threshold, so a consumer would have to drop it or guess —
   neither acceptable for a value an audit record is built from.
4. **`ErrMalformedTokenRef`.** `TokenRef` must be a `TokRef`-shaped handle (16
   lowercase hex). The failure this catches is a raw upstream credential passed
   where its digest belongs, which would sign a live credential into a token
   that crosses service boundaries and is logged at every hop. **The rejected
   value is deliberately excluded from the error message** — quoting it back
   would copy that same credential into every log recording the error. The
   expected width is derived from `TokRef` itself, not restated as a literal.
5. **Entitlements copied, and non-nil when empty.** `make([]string, len(...))`
   plus `copy` gives a snapshot the caller cannot mutate afterwards, and
   marshals as `[]` rather than `null`, keeping "no entitlements" distinct from
   "issuer does not speak the claim". Pinned by
   `TestMintDoesNotAliasTheCallerEntitlementSlice` and
   `TestMintEmitsAnEmptyEntitlementArrayRatherThanNull`.
6. **Self-check before signing.** `Mint` runs `claims.Validate(DefaultVersionSet())`
   on the assembled set, so the minter cannot emit a context its own verifier
   would reject. Unreachable given the input checks; present so it stays that way.

### Design choices worth flagging

- **`jti` is caller-supplied, not generated.** Its value is correlating a
  context with a record the caller already holds; one invented here would
  correlate with nothing. `tok_ref` already covers upstream-credential
  correlation.
- **`MintInput.TokenRef` takes the derived handle, not the credential.** The
  minter never has to be handed an upstream credential at all, so a `MintInput`
  that ends up in a log or a crash dump cannot contain one.
- **The three required-claim rejections reuse TRD 01's sentinels**
  (`ErrMissingSubject` / `ErrMissingTenant` / `ErrMissingAssurance`) rather than
  defining a parallel mint-side family. One rule, stated once, matchable from
  either side of the wire.
- **`NewMinter` calls `RegisterAll()`.** Idempotent, but process-global — it
  overrides the default `ES256`/`RS256` methods. Documented on the constructor,
  and it is what makes a Minter correct without relying on a boot-time call
  elsewhere.
- **`WithClock` is exported.** TRD 03 asks for a clock seam in the same package,
  and TRD 04 needs backdated fixtures for its expiry cases. It weakens no input
  requirement: subject data is still required in full, so a controlled clock
  cannot mint a context that would not otherwise be minted.

## Notes for Downstream TRDs

- **04 (verifier):** mint fixtures with `NewMinter` + a local ES256
  `kmssigner.Signer`. For expired/leeway cases use
  `WithClock(func() time.Time { return past })` — `WithTTL` cannot be negative.
  The token's `typ` is already `JWTType` and `kid` is whatever was configured.
- **05 (round trip):** `Mint` emits `ent` as `[]` (never `null`) and `tok_ref`
  unconditionally (empty string when unset). The hand-written wire fixture
  should keep `tok_ref` present to match what the minter actually produces.
- No new module dependencies were introduced, and none are needed downstream for
  this path.

## Authentication Gates

None.

## Repository Hygiene

Both new files were swept for private repository/service/product names, internal
ticket and design-document references, absolute local paths, branch names and
commit hashes — no hits. The only external identifiers are the module's own
import path and `issuer.example` (RFC 2606 reserved). Doc comments were written
fresh against the contract's own terms; no other repository was consulted, and
the pre-existing private names in `platform/auth/jwt.go` comments were neither
imitated nor edited (out of scope).

## Post-TRD Verification

- Auto-fix cycles used: 1 (the `tok_ref` test expectation above)
- Must-haves verified: 9/9
- Gate failures: None
- Test count: 31 new functions / 60 new PASS assertions / 98 total PASS / 0 SKIP / 0 FAIL
- Line counts: `minter.go` 367, `minter_test.go` 806

## Self-Check: PASSED

- `platform/identity/minter.go` — FOUND
- `platform/identity/minter_test.go` — FOUND
- Commit `886f8b1` (RED) — FOUND, contains only `minter_test.go`
- Commit `49fe8da` (GREEN) — FOUND, contains `minter.go` + the corrected `minter_test.go`
- `platform/identity/claims.go` — unmodified by this TRD
- `go.mod` / `go.sum` — unchanged (`git diff --exit-code` returned 0)

## State Tracking Note

This TRD executed in an isolated worktree, reset onto TRD 01's tip so that
`platform/identity/claims.go` was present and this work builds directly on top
of it. That line of history does not carry the objective's planning state:
`.planning/STATE.md` and `.planning/ROADMAP.md` here describe an unrelated
position (Obj 33 / post-M9), and `.planning/REQUIREMENTS.md` does not exist, so
nothing tracks `IC-02`.

The state mutators (`state advance-job`, `state update-progress`,
`roadmap update-job-progress`, `requirements mark-complete IC-02`) were
therefore deliberately NOT run — against this state they would have advanced an
unrelated objective's counters. This matches the decision TRD 01 recorded. Run
them once this work lands on the branch holding the objective's planning state;
`requirements-completed: [IC-02]` in this file's frontmatter is the record to
reconcile from.
