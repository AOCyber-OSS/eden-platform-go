# platform/auth

Authentication primitives for the AOC platform. Used by AODex, AOSentry,
eden-biz, AO ID, and AOFamily backends.

## Layout

```
platform/auth/
├── (root package)        Service/JWT/SSOService/PasswordHasher/Require* —
│                          full-fat orchestration layer
│   ├── jwt.go            ML-DSA-65 (post-quantum) signed JWTs with rotation
│   ├── service.go        SignUp / Login / RefreshToken / Logout / UpdateProfile
│   ├── sso.go            OIDC + SAML SP wrapper using crewjam/saml + go-oidc
│   ├── password.go       Argon2id PasswordHasher (recommended for new work)
│   ├── legacy_bcrypt.go  bcrypt helpers (Devise-compatible) for migration
│   ├── require.go        HTTP middleware
│   ├── store.go          AuthStore / TxAuthStore interfaces
│   ├── context.go        Caller identity in request context
│   └── mldsa.go          ML-DSA-65 signing method registration
│
├── apikey/      Bcrypt-hashed API keys with prefix lookup + scopes
├── emailotp/    6-digit constant-time email OTPs
├── oauth/       Provider-userinfo fetchers (Google, GitHub, FB, X, Apple, MS)
├── oidc/        Standalone OIDC SP primitives (Auth URL, exchange, verify)
├── saml/        Standalone SAML SP primitives (AuthnRequest, attr extraction,
│                metadata, IdP cert parsing)
├── session/     scs/pgxstore-backed cookie sessions + per-session metadata
├── totp/        RFC 6238 TOTP + bcrypt-hashed backup codes
└── webauthn/    go-webauthn wrapper + User type implementing webauthn.User
```

## When to use what

| Need | Package |
|------|---------|
| Sign / verify access + refresh tokens | root `auth.JWTManager` |
| Password verification (new code) | root `auth.PasswordHasher` (Argon2id) |
| Password verification (Devise-compat) | root `auth.VerifyLegacyPassword` |
| Tenant-configured OIDC/SAML SSO | root `auth.SSOService` |
| Roll-your-own OIDC SP flow | `platform/auth/oidc` |
| Roll-your-own SAML SP flow | `platform/auth/saml` |
| SAML IdP issuance | `platform/auth/saml/idp` (added in obj 23) |
| Userinfo from generic OAuth providers | `platform/auth/oauth` |
| Cookie sessions (web) | `platform/auth/session` |
| API-key authentication (machine-to-machine) | `platform/auth/apikey` |
| Passkey / WebAuthn ceremonies | `platform/auth/webauthn` |
| Authenticator-app TOTP + backup codes | `platform/auth/totp` |
| One-time codes via email | `platform/auth/emailotp` |

## Migration from AODex `internal/auth`

This package was promoted wholesale from `aodex-go/internal/auth/` per
decision D9 in `PORTFOLIO_STANDARDIZATION_PLAN.md`. AODex retains
`internal/auth/ws_token.go` (in-memory WebSocket auth, AODex-specific) but
every other primitive lives here. AODex itself becomes a re-export shim in a
follow-up workstream (`ws-aodex-auth-donor-shim`).

If you're still calling `aodex-go/internal/auth.*` directly, switch to
`go.aocyber.ai/eden-platform-go/platform/auth` (or one of the
sub-packages above) at your earliest convenience.

## Household-aware claims (Obj 24a)

`platform/auth.Claims` hosts two orthogonal identity axes:

| Axis      | Fields                                          | Used by                          |
|-----------|-------------------------------------------------|----------------------------------|
| B2B       | `UserID`, `CompanyID`, `CompanyIDs`, `Role`, `RoleLevel` | AODex, eden-biz, AOSentry         |
| Household | `UserID`, `HouseholdID`, `ChildID`, `ChildMode` | AOFamily-AI/Browser/Connect, Eden Family |

The household fields are tagged `omitempty`, so B2B tokens carry an
identical wire format pre/post Obj 24a — no existing consumer is affected.

### Issuance

| Method                                              | Use case                          |
|-----------------------------------------------------|-----------------------------------|
| `JWTManager.CreateAccessToken(userID, companyID, role, roleLevel, companyIDs)` | B2B token (existing path) |
| `JWTManager.CreateHouseholdAccessToken(userID, householdID, childID, childMode)` | Household / parental-control token |

Both methods sign with the same ML-DSA-65 key. AOFamily backends inherit
key rotation, JWKS publication, and kid headers for free — no separate
signing path.

### Require helpers

`RequireHousehold(ctx) (uuid.UUID, error)` — returns the household UUID
or `ErrNoHousehold` (HTTP 401).

`RequireParentMode(ctx) (*Claims, error)` — succeeds when `ChildMode==false`.
Returns `ErrNotParentMode` (HTTP 403) when in child mode, or
`ErrNoHousehold` when no claims are present. B2B claims (ChildMode defaults
to false) pass through — this helper enforces "not in child mode," not
"has household." Pair with `RequireHousehold` when both invariants matter.

`RequireChildMode(ctx) (*Claims, error)` — succeeds only when
`ChildMode==true`. Use the returned `Claims` to read `ChildID` for the
active child identity.

```go
// Parent-only endpoint (e.g., adding a child account):
func (h *Handler) AddChild(w http.ResponseWriter, r *http.Request) {
    householdID, err := platformauth.RequireHousehold(r.Context())
    if err != nil { writeError(w, 401, "missing household"); return }
    if _, err := platformauth.RequireParentMode(r.Context()); err != nil {
        writeError(w, 403, "parent mode required")
        return
    }
    // ... add child to householdID
}

// Child-only endpoint (e.g., kid-safe AI chat):
func (h *Handler) Chat(w http.ResponseWriter, r *http.Request) {
    claims, err := platformauth.RequireChildMode(r.Context())
    if err != nil { writeError(w, 403, "child mode required"); return }
    // claims.ChildID is the active child's UUID
}
```

## Rollback

See [ROLLBACK.md](./ROLLBACK.md) for the documented procedure if anything
in `platform/auth` regresses during the migration window.

## Test coverage

Every sub-package has standalone unit tests. Run them with:

```
go test ./platform/auth/...
```

Production-equivalent verification (with a real PostgreSQL pool for the
pgxstore-backed `session` and `apikey` packages) belongs in the consuming
service's e2e test suite — neither sub-package requires Postgres in unit
tests, so CI can run them anywhere.
