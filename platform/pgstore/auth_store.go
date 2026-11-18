package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.aocyber.ai/eden-platform-go/internal/db"
	"go.aocyber.ai/eden-platform-go/platform/auth"
)

var _ auth.TxAuthStore = (*AuthStore)(nil)
var _ auth.SocialStore = (*AuthStore)(nil)

// AuthStore implements auth.TxAuthStore backed by PostgreSQL via pgx and sqlc.
type AuthStore struct {
	pool *pgxpool.Pool // nil when wrapping a transaction
	dbtx db.DBTX
	tx   pgx.Tx // non-nil only for transactional instances
}

// NewAuthStore creates a new PostgreSQL-backed auth store.
func NewAuthStore(pool *pgxpool.Pool) *AuthStore {
	return &AuthStore{pool: pool, dbtx: pool}
}

func (s *AuthStore) queries() *db.Queries {
	return db.New(s.dbtx)
}

// -- User operations --

func (s *AuthStore) GetUserByEmail(ctx context.Context, email string) (auth.User, error) {
	row, err := s.queries().GetUserByEmail(ctx, email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.User{}, fmt.Errorf("user not found")
		}
		return auth.User{}, fmt.Errorf("get user by email: %w", err)
	}
	return dbUserToAuth(row), nil
}

func (s *AuthStore) GetUserByID(ctx context.Context, id uuid.UUID) (auth.User, error) {
	row, err := s.queries().GetUserByID(ctx, id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.User{}, fmt.Errorf("user not found")
		}
		return auth.User{}, fmt.Errorf("get user by id: %w", err)
	}
	return dbUserToAuth(row), nil
}

func (s *AuthStore) CreateUser(ctx context.Context, email, passwordHash, displayName string) (auth.User, error) {
	row, err := s.queries().CreateUser(ctx, db.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		DisplayName:  displayName,
	})
	if err != nil {
		return auth.User{}, fmt.Errorf("create user: %w", err)
	}
	return dbUserToAuth(row), nil
}

func (s *AuthStore) UpdateUser(ctx context.Context, id uuid.UUID, displayName, avatarURL string) (auth.User, error) {
	row, err := s.queries().UpdateUser(ctx, db.UpdateUserParams{
		ID:          id,
		DisplayName: displayName,
		AvatarUrl:   avatarURL,
	})
	if err != nil {
		return auth.User{}, fmt.Errorf("update user: %w", err)
	}
	return dbUserToAuth(row), nil
}

// -- Company operations --

func (s *AuthStore) CreateCompany(ctx context.Context, name, slug, companyType string) (uuid.UUID, error) {
	if companyType == "" {
		companyType = "standalone"
	}
	id := uuid.New()
	row, err := s.queries().CreateCompany(ctx, db.CreateCompanyParams{
		ID:          id,
		Name:        name,
		Slug:        slug,
		CompanyType: companyType,
		Settings:    json.RawMessage(`{"enabled_features":[]}`),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create company: %w", err)
	}
	return row.ID, nil
}

func (s *AuthStore) CreateCompanyMembership(ctx context.Context, companyID, userID, roleID uuid.UUID) error {
	return s.queries().CreateMembership(ctx, db.CreateMembershipParams{
		CompanyID: companyID,
		UserID:    userID,
		RoleID:    roleID,
	})
}

// -- Membership & role operations --

// ListUserCompanyIDs implements auth.MembershipLister.
func (s *AuthStore) ListUserCompanyIDs(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	return s.queries().ListUserCompanyIDs(ctx, userID)
}

func (s *AuthStore) GetCompanyMembershipByUser(ctx context.Context, userID uuid.UUID) (auth.Membership, error) {
	// Get first company membership for this user
	companyIDs, err := s.queries().ListUserCompanyIDs(ctx, userID)
	if err != nil {
		return auth.Membership{}, fmt.Errorf("list user companies: %w", err)
	}
	if len(companyIDs) == 0 {
		return auth.Membership{}, fmt.Errorf("membership not found")
	}

	// Get membership details for first company
	row, err := s.queries().GetMembership(ctx, db.GetMembershipParams{
		CompanyID: companyIDs[0],
		UserID:    userID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.Membership{}, fmt.Errorf("membership not found")
		}
		return auth.Membership{}, fmt.Errorf("get membership: %w", err)
	}
	return auth.Membership{
		CompanyID: row.CompanyID,
		UserID:    row.UserID,
		RoleID:    row.RoleID,
		RoleName:  row.RoleName,
	}, nil
}

func (s *AuthStore) GetRoleByID(ctx context.Context, roleID uuid.UUID) (auth.Role, error) {
	row, err := s.queries().GetRoleByID(ctx, roleID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.Role{}, fmt.Errorf("role not found")
		}
		return auth.Role{}, fmt.Errorf("get role: %w", err)
	}
	return auth.Role{
		ID:          row.ID,
		Name:        row.Name,
		Description: row.Description,
		RoleLevel:   int(row.Level),
	}, nil
}

func (s *AuthStore) GetUserRole(ctx context.Context, companyID, userID uuid.UUID) (auth.Role, error) {
	row, err := s.queries().GetUserRole(ctx, db.GetUserRoleParams{
		CompanyID: companyID,
		UserID:    userID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.Role{}, fmt.Errorf("role not found")
		}
		return auth.Role{}, fmt.Errorf("get user role: %w", err)
	}
	return auth.Role{
		ID:          row.ID,
		Name:        row.Name,
		Description: row.Description,
		RoleLevel:   int(row.Level),
	}, nil
}

// -- Refresh token operations --

func (s *AuthStore) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	return s.queries().CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	})
}

func (s *AuthStore) GetRefreshToken(ctx context.Context, tokenHash string) (auth.RefreshTokenRecord, error) {
	row, err := s.queries().GetRefreshToken(ctx, tokenHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.RefreshTokenRecord{}, fmt.Errorf("refresh token not found")
		}
		return auth.RefreshTokenRecord{}, fmt.Errorf("get refresh token: %w", err)
	}
	return auth.RefreshTokenRecord{
		UserID:    row.UserID,
		TokenHash: row.TokenHash,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

// ConsumeRefreshToken implements auth.RefreshTokenConsumer with a
// conditional UPDATE (revoked = false, unexpired); zero rows affected is
// auth.ErrRefreshTokenNotActive. Row locking makes concurrent consumers of
// one token serialise, and only the first sees a row.
func (s *AuthStore) ConsumeRefreshToken(ctx context.Context, tokenHash string) error {
	n, err := s.queries().ConsumeRefreshToken(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("consume refresh token: %w", err)
	}
	if n == 0 {
		return auth.ErrRefreshTokenNotActive
	}
	return nil
}

func (s *AuthStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return s.queries().RevokeRefreshToken(ctx, tokenHash)
}

// -- SSO operations --

func (s *AuthStore) GetSSOConfig(ctx context.Context, companyID uuid.UUID, provider string) (auth.SSOConfig, error) {
	row, err := s.queries().GetSSOConfig(ctx, db.GetSSOConfigParams{
		CompanyID: companyID,
		Provider:  provider,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.SSOConfig{}, fmt.Errorf("sso config not found")
		}
		return auth.SSOConfig{}, fmt.Errorf("get sso config: %w", err)
	}
	return auth.SSOConfig{
		CompanyID:            row.CompanyID,
		Provider:             row.Provider,
		IssuerURL:            row.IssuerUrl,
		ClientID:             row.ClientID,
		ClientSecret:         row.ClientSecret,
		MetadataURL:          row.MetadataUrl,
		DisplayName:          row.DisplayName,
		ExtraScopes:          row.ExtraScopes,
		EnforceSSO:           row.EnforceSso,
		IsActive:             row.IsActive,
		EmailDomainAllowlist: row.EmailDomainAllowlist,
		JITDefaultRole:       row.JitDefaultRole,
		JITEnabled:           row.JitEnabled,
	}, nil
}

// -- SSO Config (extended) --

func (s *AuthStore) ListSSOConfigs(ctx context.Context, companyID uuid.UUID) ([]auth.SSOConfig, error) {
	rows, err := s.dbtx.Query(ctx, `
		SELECT company_id, provider, issuer_url, client_id, client_secret, metadata_url,
		       COALESCE(display_name,''), COALESCE(extra_scopes,'{}'), COALESCE(enforce_sso,false), is_active,
		       COALESCE(email_domain_allowlist,'{}'), COALESCE(jit_default_role,''), COALESCE(jit_enabled,false)
		FROM sso_configs WHERE company_id = $1 ORDER BY provider`, companyID)
	if err != nil {
		return nil, fmt.Errorf("list sso configs: %w", err)
	}
	defer rows.Close()

	var configs []auth.SSOConfig
	for rows.Next() {
		var c auth.SSOConfig
		if err := rows.Scan(&c.CompanyID, &c.Provider, &c.IssuerURL, &c.ClientID, &c.ClientSecret,
			&c.MetadataURL, &c.DisplayName, &c.ExtraScopes, &c.EnforceSSO, &c.IsActive,
			&c.EmailDomainAllowlist, &c.JITDefaultRole, &c.JITEnabled); err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}
	return configs, rows.Err()
}

func (s *AuthStore) UpsertSSOConfig(ctx context.Context, cfg auth.SSOConfig) error {
	extraScopes := cfg.ExtraScopes
	if extraScopes == nil {
		extraScopes = []string{}
	}
	allowlist := cfg.EmailDomainAllowlist
	if allowlist == nil {
		allowlist = []string{}
	}
	_, err := s.dbtx.Exec(ctx, `
		INSERT INTO sso_configs (company_id, provider, issuer_url, client_id, client_secret, metadata_url,
		            display_name, extra_scopes, enforce_sso, is_active,
		            email_domain_allowlist, jit_default_role, jit_enabled, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now())
		ON CONFLICT (company_id, provider) DO UPDATE SET
		    issuer_url = EXCLUDED.issuer_url, client_id = EXCLUDED.client_id,
		    client_secret = EXCLUDED.client_secret, metadata_url = EXCLUDED.metadata_url,
		    display_name = EXCLUDED.display_name, extra_scopes = EXCLUDED.extra_scopes,
		    enforce_sso = EXCLUDED.enforce_sso, is_active = EXCLUDED.is_active,
		    email_domain_allowlist = EXCLUDED.email_domain_allowlist,
		    jit_default_role = EXCLUDED.jit_default_role, jit_enabled = EXCLUDED.jit_enabled,
		    updated_at = now()`,
		cfg.CompanyID, cfg.Provider, cfg.IssuerURL, cfg.ClientID, cfg.ClientSecret,
		cfg.MetadataURL, cfg.DisplayName, extraScopes, cfg.EnforceSSO, cfg.IsActive,
		allowlist, cfg.JITDefaultRole, cfg.JITEnabled)
	return err
}

func (s *AuthStore) DeleteSSOConfig(ctx context.Context, companyID uuid.UUID, provider string) error {
	_, err := s.dbtx.Exec(ctx, `DELETE FROM sso_configs WHERE company_id = $1 AND provider = $2`, companyID, provider)
	return err
}

func (s *AuthStore) HasEnforcedSSO(ctx context.Context, companyID uuid.UUID) (bool, error) {
	var enforced bool
	err := s.dbtx.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM sso_configs WHERE company_id = $1 AND enforce_sso = true AND is_active = true)`,
		companyID).Scan(&enforced)
	return enforced, err
}

// ResolveJITCompanyByIssuerDomain returns the single ACTIVE, jit_enabled
// SSOConfig whose issuer_url = issuer AND emailDomain ∈ email_domain_allowlist,
// yielding its company_id + jit_default_role (COMPANION-AV05-AOID-JIT TRD-06 —
// the issuer+domain company derivation that replaces the biz AOID_JIT_* env
// vars). It fetches ALL matches so it can distinguish zero (auth.ErrNoJITMatch)
// from more-than-one (auth.ErrAmbiguousJITMatch) — the resolver NEVER
// arbitrarily picks between ambiguous same-issuer configs (fail-secure).
func (s *AuthStore) ResolveJITCompanyByIssuerDomain(ctx context.Context, issuer, emailDomain string) (uuid.UUID, string, error) {
	rows, err := s.queries().ListJITCompaniesByIssuerDomain(ctx, db.ListJITCompaniesByIssuerDomainParams{
		IssuerUrl:   issuer,
		EmailDomain: emailDomain,
	})
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("resolve jit company by issuer+domain: %w", err)
	}
	switch len(rows) {
	case 0:
		return uuid.Nil, "", auth.ErrNoJITMatch
	case 1:
		return rows[0].CompanyID, rows[0].JitDefaultRole, nil
	default:
		return uuid.Nil, "", auth.ErrAmbiguousJITMatch
	}
}

// -- OAuth Credentials --

func (s *AuthStore) UpsertOAuthCredential(ctx context.Context, cred auth.OAuthCredential) error {
	_, err := s.dbtx.Exec(ctx, `
		INSERT INTO oauth_credentials (company_id, user_id, provider, access_token, refresh_token, token_expiry, scopes, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (company_id, user_id, provider) DO UPDATE SET
		    access_token = EXCLUDED.access_token, refresh_token = EXCLUDED.refresh_token,
		    token_expiry = EXCLUDED.token_expiry, scopes = EXCLUDED.scopes, updated_at = now()`,
		cred.CompanyID, cred.UserID, cred.Provider, cred.AccessToken, cred.RefreshToken,
		cred.TokenExpiry, cred.Scopes)
	return err
}

func (s *AuthStore) GetOAuthCredential(ctx context.Context, userID uuid.UUID, provider string) (auth.OAuthCredential, error) {
	var c auth.OAuthCredential
	err := s.dbtx.QueryRow(ctx, `
		SELECT company_id, user_id, provider, access_token, refresh_token, token_expiry, scopes
		FROM oauth_credentials WHERE user_id = $1 AND provider = $2`, userID, provider,
	).Scan(&c.CompanyID, &c.UserID, &c.Provider, &c.AccessToken, &c.RefreshToken, &c.TokenExpiry, &c.Scopes)
	if err != nil {
		return auth.OAuthCredential{}, fmt.Errorf("get oauth credential: %w", err)
	}
	return c, nil
}

// -- Social identity operations (user-scoped; NO company_id) --

func (s *AuthStore) UpsertUserIdentity(ctx context.Context, identity auth.UserIdentity) (auth.UserIdentity, error) {
	row, err := s.queries().UpsertUserIdentity(ctx, db.UpsertUserIdentityParams{
		UserID:      identity.UserID,
		Provider:    identity.Provider,
		ProviderSub: identity.ProviderSub,
		Email:       identity.Email,
		IsVerified:  identity.IsVerified,
		DisplayName: strPtrOrNil(identity.DisplayName),
		AvatarUrl:   strPtrOrNil(identity.AvatarURL),
		RawClaims:   identity.RawClaims,
	})
	if err != nil {
		return auth.UserIdentity{}, fmt.Errorf("upsert user identity: %w", err)
	}
	return dbUserIdentityToAuth(row), nil
}

func (s *AuthStore) GetUserIdentityByProviderSub(ctx context.Context, provider, sub string) (auth.UserIdentity, error) {
	row, err := s.queries().GetUserIdentityByProviderSub(ctx, db.GetUserIdentityByProviderSubParams{
		Provider:    provider,
		ProviderSub: sub,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.UserIdentity{}, fmt.Errorf("user identity not found")
		}
		return auth.UserIdentity{}, fmt.Errorf("get user identity by provider sub: %w", err)
	}
	return dbUserIdentityToAuth(row), nil
}

func (s *AuthStore) GetUserIdentityByEmail(ctx context.Context, email string) (auth.UserIdentity, error) {
	row, err := s.queries().GetUserIdentityByEmail(ctx, &email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return auth.UserIdentity{}, fmt.Errorf("user identity not found")
		}
		return auth.UserIdentity{}, fmt.Errorf("get user identity by email: %w", err)
	}
	return dbUserIdentityToAuth(row), nil
}

func (s *AuthStore) ListUserIdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]auth.UserIdentity, error) {
	rows, err := s.queries().ListUserIdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user identities: %w", err)
	}
	out := make([]auth.UserIdentity, 0, len(rows))
	for _, row := range rows {
		out = append(out, dbUserIdentityToAuth(row))
	}
	return out, nil
}

func (s *AuthStore) DeleteUserIdentity(ctx context.Context, id uuid.UUID) error {
	return s.queries().DeleteUserIdentity(ctx, id)
}

// -- Audit --

func (s *AuthStore) CreateAuditLog(ctx context.Context, companyID, actorID uuid.UUID, action, resource, resourceID, ipAddress string, details []byte) error {
	return s.queries().CreateAuditLog(ctx, db.CreateAuditLogParams{
		CompanyID:  auditCompanyID(companyID),
		ActorID:    actorID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    json.RawMessage(details),
		IpAddress:  ipAddress,
	})
}

// -- Transaction support --

func (s *AuthStore) BeginTx(ctx context.Context) (auth.TxAuthStore, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("cannot begin transaction: no pool available")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	return &AuthStore{pool: nil, dbtx: tx, tx: tx}, nil
}

func (s *AuthStore) Commit(ctx context.Context) error {
	if s.tx == nil {
		return fmt.Errorf("not in a transaction")
	}
	return s.tx.Commit(ctx)
}

func (s *AuthStore) Rollback(ctx context.Context) error {
	if s.tx == nil {
		return nil
	}
	return s.tx.Rollback(ctx)
}

// -- Type conversion helpers --

func dbUserToAuth(u db.User) auth.User {
	return auth.User{
		ID:           u.ID,
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		DisplayName:  u.DisplayName,
		AvatarURL:    u.AvatarUrl,
		IsActive:     u.IsActive,
		CreatedAt:    u.CreatedAt,
	}
}

func dbUserIdentityToAuth(u db.UserIdentity) auth.UserIdentity {
	return auth.UserIdentity{
		ID:          u.ID,
		UserID:      u.UserID,
		Provider:    u.Provider,
		ProviderSub: u.ProviderSub,
		Email:       u.Email,
		IsVerified:  u.IsVerified,
		DisplayName: strPtrToStr(u.DisplayName),
		AvatarURL:   strPtrToStr(u.AvatarUrl),
		RawClaims:   json.RawMessage(u.RawClaims),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

// strPtrToStr dereferences a nullable *string into a plain string ("" when nil).
func strPtrToStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// strPtrOrNil converts a plain string into a nullable *string (nil when empty),
// so empty display_name / avatar_url are stored as SQL NULL.
func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// pgtypeUUID converts a pgtype.UUID to *uuid.UUID.
func pgtypeUUID(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	id := uuid.UUID(u.Bytes)
	return &id
}

// uuidToPgtype converts a *uuid.UUID to pgtype.UUID.
func uuidToPgtype(u *uuid.UUID) pgtype.UUID {
	if u == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *u, Valid: true}
}

// auditCompanyID maps an audit event's company scope onto the nullable
// audit_logs.company_id column (migration 018). A zero (uuid.Nil) company means
// "no company" — an identity-space event (household / COPPA audit) that has no
// companies(id) — and is stored as SQL NULL, exempt from the company FK. Any
// real company id is stored unchanged and stays FK-validated against
// companies(id). Centralizing the zero->NULL mapping here keeps the shared
// audit.AuditStore interface a plain uuid.UUID for every caller.
func auditCompanyID(companyID uuid.UUID) pgtype.UUID {
	if companyID == uuid.Nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: companyID, Valid: true}
}
