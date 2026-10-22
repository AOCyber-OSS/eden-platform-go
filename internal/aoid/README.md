# aoid — AO ID identity service

`aoid` is the standalone Go service that hosts the AO Cyber portfolio's
identity stack. It composes three platform packages —
[`platform/auth`](../../platform/auth), [`platform/household`](../../platform/household)
and [`platform/consent`](../../platform/consent) — behind a single deployable
HTTP service that products federate into.

As of Objective 30 the service is a **working OIDC issuer**: the
authorization-code + PKCE flow lives at `/oauth2/authorize`, token
issuance + refresh rotation at `/oauth2/token`, and bearer-token user
claims at `/oauth2/userinfo`. AODex is registered as the pilot client.
The discovery doc reports `service_status: "active"`.

## Service location

`aoid` lives inside `eden-platform-go` as a second `cmd/` binary
(sibling of `cmd/eden-platform-dev`) rather than its own repository.
Rationale and trade-offs are documented in
[`.planning/objectives/29-aoid-service-scaffold/29-01-TRD.md`](../../../.planning/objectives/29-aoid-service-scaffold/29-01-TRD.md).
Promoting to a dedicated repo is mechanical when the service stabilises;
keeping it co-located now means platform package changes flow without a
release dance.

## Boot

```bash
# Local dev — in-memory devstore, seeded fixtures, ephemeral JWT keys.
go run ./cmd/aoid

# Production / staging — Postgres-backed.
export AOID_DATABASE_URL=postgres://aoid:secret@db:5432/aoid?sslmode=require
export AOID_ISSUER=https://auth.aocyber.ai
export AOID_JWT_KEY_SEED_PATHS="2026-Q2=/etc/aoid/q2.seed,2026-Q3=/etc/aoid/q3.seed"
export AOID_JWT_ACTIVE_KID="2026-Q3"
./aoid
```

> **The production issuer is `https://auth.aocyber.ai`.** Confirmed live: its
> discovery document returns 200 and self-reports
> `"issuer": "https://auth.aocyber.ai"`.
>
> This example previously read `https://id.aocyber.ai`, which **has no DNS at
> all** — it was a placeholder that was never stood up. The same placeholder
> reached production config elsewhere and broke real flows: AOID's
> `portalBaseUrl` was unset and fell back to it, so every account-recovery email
> linked to a host that does not resolve; the WebAuthn RPID was set to it, which
> cannot be a registrable suffix of `auth.aocyber.ai`, so passkey registration
> could never validate. Both are fixed in `opscluster-gitops`
> (`charts/aoid/values.production.yaml`). Do not reintroduce the placeholder.
>
> Note that `auth.aocyber.ai` is served by the **standalone `aoid` deployment**
> (its own repo; Helm chart at `opscluster-gitops/charts/aoid`), which exposes
> `/oauth/*`. The co-located binary documented here exposes `/oauth2/*`. Point
> `AOID_ISSUER` at a host this process actually serves — the issuer value is
> emitted in discovery and baked into JWTs, so claiming a host you do not serve
> produces tokens relying parties will reject.

A graceful shutdown is triggered by SIGINT or SIGTERM; the server stops
accepting new connections, in-flight requests have `AOID_SHUTDOWN_TIMEOUT`
to drain (default 5s), and the audit logger flushes its event channel.

## Configuration

All configuration is environment-variable driven. See
[`internal/aoid/config/config.go`](./config/config.go) for the full surface.
Highlights:

| Env var | Default | Purpose |
|---|---|---|
| `AOID_LISTEN_ADDR` | `:8090` | HTTP bind address |
| `AOID_ISSUER` | `http://localhost:8090` | Canonical issuer URL emitted in discovery + JWTs |
| `AOID_DATABASE_URL` | empty (devstore) | Postgres DSN; empty selects the in-memory backend |
| `AOID_JWT_KEY_SEED_PATH` | empty | Single-key fallback path to a 32-byte ML-DSA-65 seed |
| `AOID_JWT_KEY_SEED_PATHS` | empty | Multi-key rotation map: `kid1=/path1,kid2=/path2` |
| `AOID_JWT_ACTIVE_KID` | empty | Required when `AOID_JWT_KEY_SEED_PATHS` is set; signs new tokens |
| `AOID_LOG_LEVEL` | `info` | slog level (`debug`, `info`, `warn`, `error`) |
| `AOID_LOG_FORMAT` | `text` | slog format (`text` or `json`) |
| `AOID_SENTRY_DSN` | empty | Forwards error-level logs to Sentry; empty = no-op |
| `AOID_SHUTDOWN_TIMEOUT` | `5s` | Graceful-shutdown deadline |

Empty `JWT_KEY_SEED_PATH(S)` puts the JWT manager in **ephemeral** mode —
tokens signed with a freshly-generated key per process. Useful for tests;
NEVER do this in production.

## Endpoints

| Path | Status | Behaviour |
|---|---|---|
| `/healthz` | 200 / 503 | JSON health document; 503 when any registered component is unhealthy |
| `/readyz` | 200 / 503 | 200 once the listener is up; 503 during startup or shutdown |
| `/.well-known/openid-configuration` | 200 | OIDC discovery doc with `service_status: "active"` |
| `/.well-known/jwks.json` | 200 | JSON Web Key Set — one entry per registered ML-DSA-65 key |
| `/oauth2/authorize` | 200 / 302 | OIDC authorization endpoint (auth-code + PKCE flow); renders the AO ID login form when the session is unauthenticated |
| `/oauth2/token` | 200 | OIDC token endpoint (`authorization_code` + `refresh_token` grants) |
| `/oauth2/userinfo` | 200 | OIDC userinfo endpoint — Bearer access token in `Authorization` header |

### OIDC issuer flows

#### Authorization code + PKCE (curl walk-through)

```bash
# 1. Build a PKCE pair.
VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr -d '=' | tr '/+' '_-')

# 2. Hit /oauth2/authorize. With no AO ID session this renders an HTML
#    login form whose POST submits back to /oauth2/authorize with the
#    same params + email/password.
curl -s "http://localhost:8090/oauth2/authorize?response_type=code&client_id=aodex-pilot&redirect_uri=http://localhost:8080/auth/aoid/callback&scope=openid+email+profile+offline_access&state=s1&nonce=n1&code_challenge=$CHALLENGE&code_challenge_method=S256"

# 3. Submit credentials. 302 to redirect_uri with ?code=...
curl -s -i -X POST "http://localhost:8090/oauth2/authorize"   -d "aoid_login=1"   -d "response_type=code"   -d "client_id=aodex-pilot"   -d "redirect_uri=http://localhost:8080/auth/aoid/callback"   -d "scope=openid email profile offline_access"   -d "state=s1"   -d "nonce=n1"   -d "code_challenge=$CHALLENGE"   -d "code_challenge_method=S256"   -d "email=parent@aoid.local"   -d "password=fixtures-pw-1234"

# 4. Exchange the code for tokens.
CODE=...   # from step 3 redirect
curl -s -X POST "http://localhost:8090/oauth2/token"   -u "aodex-pilot:dev-aodex-client-secret-do-not-use-in-prod"   -d "grant_type=authorization_code"   -d "code=$CODE"   -d "redirect_uri=http://localhost:8080/auth/aoid/callback"   -d "code_verifier=$VERIFIER"

# 5. Use the access token at /userinfo.
ACCESS=...  # from step 4 response
curl -s "http://localhost:8090/oauth2/userinfo" -H "Authorization: Bearer $ACCESS"
```

#### Refresh rotation

```bash
REFRESH=...  # from step 4 response
curl -s -X POST "http://localhost:8090/oauth2/token"   -u "aodex-pilot:dev-aodex-client-secret-do-not-use-in-prod"   -d "grant_type=refresh_token"   -d "refresh_token=$REFRESH"
```

The old refresh token is single-use; a second redemption returns `400
invalid_grant`.

### Client registration

For Phase A the AODex client (`client_id: aodex-pilot`) is seeded at
boot from `AOID_AODEX_CLIENT_SECRET` + `AOID_AODEX_REDIRECT_URIS`. The
in-memory `internal/aoid/clients.MemoryRegistry` is the source of
truth. A pgstore-backed registry + admin API for additional clients
lands in Objective 31.

## JWKS rotation

Key rotation is supported without restart:

1. Add a new `kid=path` entry to `AOID_JWT_KEY_SEED_PATHS` in your secret
   store.
2. Reload aoid (rolling deploy is sufficient — every replica picks up
   the new map at boot).
3. The new kid appears in `/.well-known/jwks.json` immediately.
4. Once all relying parties have re-fetched JWKS (within the
   `Cache-Control: max-age=300` window) flip `AOID_JWT_ACTIVE_KID` to the
   new kid in another rolling deploy.

Old kids stay in JWKS as long as their seed file is on disk so existing
tokens still verify; rotate them out of the map only after the relevant
token expiry has passed.

## Hand-off to objective 31

Objective 31 ("AO ID Federation + per-product migrations") covers:

- Federated identity: SAML SP imports for customer Okta / Azure AD,
  SAML IdP-mode for enterprise tenants, SCIM provisioning.
- pgstore-backed client registry + admin Connect API for client CRUD.
- Per-product migrations beyond AODex (AOSentry, AOFamily, AOCodex
  marketing apps). For each, the same OIDC-client-of-AO-ID pattern
  AODex follows in Obj 30 Phase B applies.
- Consent UI surfaced at `/oauth2/authorize` for non-pilot clients.
- MFA on the AO ID login page (currently password-only; underlying
  `platform/auth` already supports WebAuthn / TOTP / email-OTP, but
  the AO ID login template doesn't expose them yet).

## Testing

```bash
go test ./cmd/aoid/... ./internal/aoid/...
go vet ./cmd/aoid/... ./internal/aoid/...
```

CI runs the full module test suite plus a smoke step that boots the
binary and curls every endpoint. See
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).
