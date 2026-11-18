# platform/auth Rollback Procedure

This document satisfies requirement R32.7 of objective 22 (auth absorption).
It is the authoritative procedure for rolling back to AODex's
`internal/auth/` package if anything in `platform/auth` regresses during
the migration window.

## When to use this

Use it when:
- A regression in `platform/auth` blocks an AODex deploy and a fix in
  `platform/auth` cannot be shipped within the SLA, OR
- A consumer (eden-biz, AOSentry, AO ID) reports a behavior change that
  cannot be replicated locally and bisecting points at this absorption, OR
- An auth-flow customer ticket needs immediate mitigation before root-cause
  is known.

This is a **last resort**. Always prefer fixing forward. The rollback exists
because the standardization plan (`§12 failure-mode #4`) requires AODex to
remain "the shim'd reference implementation" until every consumer has
landed on the platform.

## What this rollback DOES

It returns AODex to using its own pre-shim `internal/auth/` source as the
runtime authority while still allowing platform/auth to be developed and
fixed. It does NOT delete or modify `platform/auth` — that stays in place
for other consumers.

## What this rollback does NOT touch

- DNS, customer data, external credentials, repo archives.
- Tokens already issued to live users (existing JWTs and sessions remain
  valid; the JWT signing-key seeds are persisted, not regenerated).
- Other consumers of `platform/auth` (eden-biz, AOSentry, AO ID,
  AOFamily, etc.) — their migration timelines are independent.

## Procedure

1. **AODex side** — restore the original `internal/auth/` package from the
   commit immediately before the AODex shim refactor (workstream
   `ws-aodex-auth-donor-shim`). The donor source is preserved at the
   commit before that PR was merged; check `git log --oneline -- internal/auth`.

   ```bash
   cd aodex-go
   # Find the last commit before the shim refactor.
   PRESHIM=$(git log --pretty=%H -- internal/auth/ | tail -2 | head -1)
   git checkout "$PRESHIM" -- internal/auth/
   git commit -m "rollback: restore AODex internal/auth pending platform fix"
   ```

2. **Verify** AODex compiles and its existing test suite passes against
   the restored package:
   ```bash
   go test ./internal/auth/...
   go build ./...
   ```

3. **Deploy** AODex with the restored auth path. No platform/auth changes
   required.

4. **Open a tracking issue** in `eden-platform-go` describing the
   regression. The platform/auth change that caused the regression should
   be reverted or hotfixed before any other consumer (eden-biz, AOSentry,
   AO ID) proceeds with their migration.

5. **Re-apply the shim** once `platform/auth` is healthy:
   ```bash
   cd aodex-go
   git revert <rollback-commit>      # or restore the shim commit directly
   go test ./internal/auth/...
   ```

## Smoke checklist after rollback

- [ ] AODex login (email + password)
- [ ] AODex login with TOTP 2FA
- [ ] AODex login with WebAuthn (passkey)
- [ ] AODex login with email OTP
- [ ] AODex login via OAuth (Google + GitHub at minimum)
- [ ] AODex login via OIDC SSO (one tenant-configured IdP)
- [ ] AODex login via SAML SSO (one tenant-configured IdP)
- [ ] AODex API-key authentication (cli or programmatic client)
- [ ] AODex session listing + revocation endpoints
- [ ] No new ERRORs in the auth structured-log pipeline within 30 min

## Why this works

The platform/auth absorption is a **promotion**, not a rewrite. Every
public-API name and behavior in `oidc`, `saml`,
`webauthn`, `totp`, `emailotp`, `apikey`, `session`, and `legacy_bcrypt` is
either a 1:1 copy of the AODex source (with package-level imports adjusted)
or a strict superset (e.g. session manager exposes a `NewWithStore`
constructor for tests; the donor's API is preserved).
(`platform/auth/oauth` was promoted the same way and later removed: its
`FetchUserInfo` trusted unverified provider tokens, issue #75.)

This means a consumer using either path sees identical wire behavior. The
rollback is functionally equivalent to keeping the donor as the runtime,
even after the shim refactor.

## Removing this document

When all five workstream consumers (`ws-aodex-auth-donor-shim`,
`ws-eden-biz-d10-crypto-auth`, `ws-eden-biz-licensing-portal`,
`ws-ao-id-scaffold`, `ws-platform-aofamily-migrate`) have landed and the
30-day stability window after the last one closes, this document and the
preserved AODex `internal/auth/` source can be retired.

Until then, do not delete it — it is required by R32.7.
