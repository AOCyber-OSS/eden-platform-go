package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// COMPANION-AV05-AOID-JIT TRD-06 — sentinels for the issuer+domain JIT company
// resolver (ResolveJITCompanyByIssuerDomain). Zero matching active/jit_enabled
// SSOConfigs ⇒ ErrNoJITMatch; more than one ⇒ ErrAmbiguousJITMatch (fail-secure —
// the resolver never arbitrarily picks between ambiguous same-issuer configs).
var (
	ErrNoJITMatch        = errors.New("auth: no jit-enabled sso_config matches issuer+domain")
	ErrAmbiguousJITMatch = errors.New("auth: ambiguous jit-enabled sso_config match for issuer+domain")
)

// User represents a platform user. Consuming apps may extend this.
type User struct {
	ID           uuid.UUID
	Email        string
	PasswordHash string
	DisplayName  string
	AvatarURL    string
	IsActive     bool
	CreatedAt    time.Time
}

// Membership represents a user's membership in a company.
type Membership struct {
	CompanyID uuid.UUID
	UserID    uuid.UUID
	RoleID    uuid.UUID
	RoleName  string
}

// Role represents a role in the RBAC system.
type Role struct {
	ID          uuid.UUID
	Name        string
	Description string
	RoleLevel   int // 20=viewer, 40=member, 60=manager, 80=admin, 90=owner, 100=super_admin
}

// SSOConfig holds SSO provider configuration.
type SSOConfig struct {
	CompanyID    uuid.UUID
	Provider     string // "oidc", "saml", "microsoft", "google"
	IssuerURL    string
	ClientID     string
	ClientSecret string
	MetadataURL  string
	DisplayName  string
	ExtraScopes  []string
	EnforceSSO   bool
	IsActive     bool

	// COMPANION-AV05-AOID-JIT TRD-06 — per-company JIT provisioning policy,
	// moved OFF biz env vars ONTO this row (biz-managed, admin-editable). The
	// company binding is DERIVED from (IssuerURL + EmailDomainAllowlist) match.
	//
	//   - EmailDomainAllowlist: verified-email domains this SSOConfig admits for
	//     JIT (fail-secure — empty allows nothing).
	//   - JITDefaultRole: the is_system role name a JIT membership is granted
	//     (empty/unknown ⇒ deny; never super_admin).
	//   - JITEnabled: master switch for JIT on this SSOConfig (false ⇒ deny).
	EmailDomainAllowlist []string
	JITDefaultRole       string
	JITEnabled           bool
}

// OAuthCredential stores a provider's access/refresh tokens for API use.
type OAuthCredential struct {
	CompanyID    uuid.UUID
	UserID       uuid.UUID
	Provider     string
	AccessToken  string
	RefreshToken string
	TokenExpiry  time.Time
	Scopes       []string
}

// RefreshTokenRecord represents a stored refresh token.
type RefreshTokenRecord struct {
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
}

// UserIdentity represents a user's link to an external social-login provider.
//
// User-scoped only — there is NO company_id. This is consumer social login,
// explicitly NOT the company-scoped SSOService. One row exists per
// (Provider, ProviderSub) pair; a single user may own several identities.
//
// Email is a pointer because some providers never return one (X/Twitter
// always; Facebook when the user declines), in which case the column is NULL.
// RawClaims holds the provider's identity claims for audit — it MUST NOT
// store provider access/refresh tokens.
type UserIdentity struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Provider    string  // "google"|"apple"|"microsoft"|"facebook"|"x"
	ProviderSub string  // provider's stable user identifier (sub/id)
	Email       *string // nil when the provider returned no email
	IsVerified  bool    // did the provider mark the email verified
	DisplayName string
	AvatarURL   string
	RawClaims   json.RawMessage
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SocialStore defines the database operations for user-scoped social
// identities (consumer social login). NO company_id appears in any
// signature — this is deliberately separate from the company-scoped SSO
// operations on AuthStore.
type SocialStore interface {
	UpsertUserIdentity(ctx context.Context, identity UserIdentity) (UserIdentity, error)
	GetUserIdentityByProviderSub(ctx context.Context, provider, sub string) (UserIdentity, error)
	GetUserIdentityByEmail(ctx context.Context, email string) (UserIdentity, error)
	ListUserIdentitiesByUser(ctx context.Context, userID uuid.UUID) ([]UserIdentity, error)
	DeleteUserIdentity(ctx context.Context, id uuid.UUID) error
}

// ErrRefreshTokenNotActive is returned by RefreshTokenConsumer when no
// active (unrevoked, unexpired) refresh token matched: it was already used,
// revoked, expired or never issued.
var ErrRefreshTokenNotActive = errors.New("refresh token not active")

// RefreshTokenConsumer is an optional AuthStore capability: revoke a refresh
// token only if it is still active, atomically, reporting
// ErrRefreshTokenNotActive otherwise. Service refresh rotation uses it so two
// concurrent redeems of one token cannot both succeed. Stores without it fall
// back to RevokeRefreshToken, which keeps that race.
type RefreshTokenConsumer interface {
	ConsumeRefreshToken(ctx context.Context, tokenHash string) error
}

// AuthStore defines the database operations needed by the auth package.
// Consuming apps implement this with their sqlc-generated code.
type AuthStore interface {
	// User operations
	GetUserByEmail(ctx context.Context, email string) (User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (User, error)
	CreateUser(ctx context.Context, email, passwordHash, displayName string) (User, error)
	UpdateUser(ctx context.Context, id uuid.UUID, displayName, avatarURL string) (User, error)

	// Company operations (replaces eden-circle's Org)
	CreateCompany(ctx context.Context, name, slug, companyType string) (uuid.UUID, error)
	CreateCompanyMembership(ctx context.Context, companyID, userID, roleID uuid.UUID) error

	// Membership & role operations
	GetCompanyMembershipByUser(ctx context.Context, userID uuid.UUID) (Membership, error)
	GetRoleByID(ctx context.Context, roleID uuid.UUID) (Role, error)
	GetUserRole(ctx context.Context, companyID, userID uuid.UUID) (Role, error)

	// Refresh token operations
	CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (RefreshTokenRecord, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error

	// SSO operations
	GetSSOConfig(ctx context.Context, companyID uuid.UUID, provider string) (SSOConfig, error)
	ListSSOConfigs(ctx context.Context, companyID uuid.UUID) ([]SSOConfig, error)
	UpsertSSOConfig(ctx context.Context, cfg SSOConfig) error
	DeleteSSOConfig(ctx context.Context, companyID uuid.UUID, provider string) error
	HasEnforcedSSO(ctx context.Context, companyID uuid.UUID) (bool, error)
	// ResolveJITCompanyByIssuerDomain returns the single ACTIVE, jit_enabled
	// SSOConfig whose issuer_url = issuer AND emailDomain = ANY(email_domain_allowlist),
	// yielding its company_id + jit_default_role. Zero matches ⇒ ErrNoJITMatch;
	// more than one ⇒ ErrAmbiguousJITMatch (fail-secure, no arbitrary pick).
	// COMPANION-AV05-AOID-JIT TRD-06 — the issuer+domain company derivation.
	ResolveJITCompanyByIssuerDomain(ctx context.Context, issuer, emailDomain string) (companyID uuid.UUID, jitDefaultRole string, err error)

	// OAuth credential operations (provider access/refresh tokens for API use)
	UpsertOAuthCredential(ctx context.Context, cred OAuthCredential) error
	GetOAuthCredential(ctx context.Context, userID uuid.UUID, provider string) (OAuthCredential, error)

	// Audit (optional -- noop if nil)
	CreateAuditLog(ctx context.Context, companyID, actorID uuid.UUID, action, resource, resourceID, ipAddress string, details []byte) error
}

// TxAuthStore extends AuthStore with transaction support.
type TxAuthStore interface {
	AuthStore
	BeginTx(ctx context.Context) (TxAuthStore, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}
