-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token_hash = $1 AND revoked = false AND expires_at > now();

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1;

-- name: ConsumeRefreshToken :execrows
UPDATE refresh_tokens SET revoked = true
WHERE token_hash = $1 AND revoked = false AND expires_at > now();

-- name: RevokeAllUserTokens :exec
UPDATE refresh_tokens SET revoked = true WHERE user_id = $1;

-- name: GetSSOConfig :one
SELECT * FROM sso_configs
WHERE company_id = $1 AND provider = $2 AND is_active = true;

-- name: CreateSSOConfig :one
INSERT INTO sso_configs (company_id, provider, issuer_url, client_id, client_secret, metadata_url)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: ListSSOConfigs :many
SELECT * FROM sso_configs WHERE company_id = $1 ORDER BY provider;

-- name: UpsertSSOConfig :exec
INSERT INTO sso_configs (company_id, provider, issuer_url, client_id, client_secret, metadata_url, display_name, extra_scopes, enforce_sso, is_active, email_domain_allowlist, jit_default_role, jit_enabled, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())
ON CONFLICT (company_id, provider) DO UPDATE SET
    issuer_url = EXCLUDED.issuer_url,
    client_id = EXCLUDED.client_id,
    client_secret = EXCLUDED.client_secret,
    metadata_url = EXCLUDED.metadata_url,
    display_name = EXCLUDED.display_name,
    extra_scopes = EXCLUDED.extra_scopes,
    enforce_sso = EXCLUDED.enforce_sso,
    is_active = EXCLUDED.is_active,
    email_domain_allowlist = EXCLUDED.email_domain_allowlist,
    jit_default_role = EXCLUDED.jit_default_role,
    jit_enabled = EXCLUDED.jit_enabled,
    updated_at = now();

-- name: ListJITCompaniesByIssuerDomain :many
-- COMPANION-AV05-AOID-JIT TRD-06: every ACTIVE, jit_enabled SSOConfig whose
-- issuer matches AND whose email_domain_allowlist contains the given domain.
-- The pgstore wrapper enforces the single-match / ambiguity rule in Go so it
-- can distinguish zero (ErrNoJITMatch) from many (ErrAmbiguousJITMatch).
SELECT company_id, jit_default_role FROM sso_configs
WHERE issuer_url = $1
  AND is_active = true
  AND jit_enabled = true
  AND sqlc.arg(email_domain)::text = ANY(email_domain_allowlist);

-- name: DeleteSSOConfig :exec
DELETE FROM sso_configs WHERE company_id = $1 AND provider = $2;

-- name: HasEnforcedSSO :one
SELECT EXISTS(
    SELECT 1 FROM sso_configs
    WHERE company_id = $1 AND enforce_sso = true AND is_active = true
) AS enforced;

-- name: UpsertOAuthCredential :exec
INSERT INTO oauth_credentials (company_id, user_id, provider, access_token, refresh_token, token_expiry, scopes, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (company_id, user_id, provider) DO UPDATE SET
    access_token = EXCLUDED.access_token,
    refresh_token = EXCLUDED.refresh_token,
    token_expiry = EXCLUDED.token_expiry,
    scopes = EXCLUDED.scopes,
    updated_at = now();

-- name: GetOAuthCredential :one
SELECT * FROM oauth_credentials WHERE user_id = $1 AND provider = $2;
