package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/audit"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"github.com/google/uuid"
)

// Bridge ties an external assertion to an AO ID native token pair. It
// performs JIT provisioning (when policy allows), mints access +
// refresh tokens via the same JWTManager the OIDC issuer uses, and
// emits federation audit log entries.
type Bridge struct {
	// AuthService is the AO ID platform/auth service whose store backs
	// the user table.
	AuthService *auth.Service

	// SPRegistry resolves TenantExternalIdP records by ID.
	SPRegistry SPRegistry

	// Audit, when non-nil, receives federation login events. The
	// bridge will fall back to slog if Audit is nil — but the
	// composition layer always wires a non-nil logger.
	Audit *audit.Logger

	// JWT lets the bridge mint tokens directly. Required.
	JWT *auth.JWTManager

	// RefreshTokenTTL is the lifetime of the refresh token persisted in
	// the auth store. Defaults to 7 days when zero.
	RefreshTokenTTL time.Duration

	// ClockSkew is the maximum allowable assertion clock-skew window.
	// Defaults to 5 minutes.
	ClockSkew time.Duration
}

// NewBridge constructs a Bridge with the required wiring. Returns an
// error when AuthService, SPRegistry, or JWT is nil.
func NewBridge(authSvc *auth.Service, reg SPRegistry, jwt *auth.JWTManager, auditLog *audit.Logger) (*Bridge, error) {
	if authSvc == nil {
		return nil, fmt.Errorf("federation: NewBridge: AuthService required")
	}
	if reg == nil {
		return nil, fmt.Errorf("federation: NewBridge: SPRegistry required")
	}
	if jwt == nil {
		return nil, fmt.Errorf("federation: NewBridge: JWT manager required")
	}
	return &Bridge{
		AuthService:     authSvc,
		SPRegistry:      reg,
		JWT:             jwt,
		Audit:           auditLog,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		ClockSkew:       5 * time.Minute,
	}, nil
}

// BridgeResult is the outcome of HandleAssertion: the AO ID user, the
// minted tokens, and a flag indicating whether the user was created in
// this call.
type BridgeResult struct {
	User           auth.User
	AccessToken    string
	RefreshToken   string
	ProvisionedNew bool
}

// HandleAssertion drives one external-IdP login → AO ID token flow.
// The assertion is assumed to be validated (signature verified, audience
// matched) by the caller — the bridge re-applies JIT policy gates for
// defense-in-depth but does not re-verify cryptographic signatures.
func (b *Bridge) HandleAssertion(ctx context.Context, tenantID, externalIdPID uuid.UUID, a *Assertion) (*BridgeResult, error) {
	if a == nil {
		return nil, errInvalid("HandleAssertion: nil assertion")
	}
	cfg, err := b.SPRegistry.Get(ctx, externalIdPID)
	if err != nil {
		return nil, err
	}
	if cfg.TenantID != tenantID {
		// A tenant tried to use another tenant's external IdP. Treat as
		// not-found rather than leaking existence.
		return nil, ErrExternalIdPNotFound
	}
	if !cfg.IsActive {
		return nil, ErrTenantInactive
	}

	// Build an ExternalIdP wrapper just to reuse EnforceJITPolicy.
	wrapper, err := NewExternalIdP(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("federation: build IdP wrapper: %w", err)
	}
	if err := wrapper.EnforceJITPolicy(a); err != nil {
		b.logFailedLogin(tenantID, cfg, a, err)
		return nil, err
	}

	// Clock skew check.
	if !a.ExpiresAt.IsZero() && time.Now().After(a.ExpiresAt.Add(b.ClockSkew)) {
		err := errors.New("federation: assertion expired")
		b.logFailedLogin(tenantID, cfg, a, err)
		return nil, err
	}

	user, isNew, err := Provision(ctx, b.AuthService, tenantID, a.Email, a.DisplayName, cfg.JITPolicy)
	if err != nil {
		b.logFailedLogin(tenantID, cfg, a, err)
		return nil, err
	}

	// An existing member signs in with their own role in this tenant; only
	// a freshly provisioned user gets the IdP's JIT default role.
	roleName, roleLevel := jitRole(cfg.JITPolicy), jitRoleLevel(cfg.JITPolicy)
	if !isNew {
		role, err := b.AuthService.GetUserRole(ctx, tenantID, user.ID)
		if err != nil {
			b.logFailedLogin(tenantID, cfg, a, ErrFederationEmailNotMember)
			return nil, ErrFederationEmailNotMember
		}
		roleName, roleLevel = role.Name, role.RoleLevel
	}

	// Mint tokens.
	companyIDStr := tenantID.String()
	access, err := b.JWT.CreateAccessToken(
		user.ID.String(),
		companyIDStr,
		roleName,
		roleLevel,
		[]string{companyIDStr},
	)
	if err != nil {
		return nil, fmt.Errorf("federation: mint access token: %w", err)
	}
	// Bound to the tenant (a refresh re-mints for it only, never the user's
	// oldest company) and marked as a federation token: the flow knows no
	// OAuth client, so the first client to redeem it at /oauth2/token binds
	// it from then on (auth.Service.RefreshTokenForClient).
	refresh, err := b.JWT.CreateClientCompanyRefreshToken(user.ID.String(), auth.FederationRefreshAudience, companyIDStr)
	if err != nil {
		return nil, fmt.Errorf("federation: mint refresh token: %w", err)
	}
	if err := b.AuthService.RememberRefreshToken(ctx, user.ID, refresh, time.Now().Add(b.RefreshTokenTTL)); err != nil {
		// Non-fatal — the refresh token will simply fail to rotate.
		// Log and continue so the user still gets an access token.
		_ = err
	}

	b.logSuccessfulLogin(tenantID, cfg, a, user, isNew)

	return &BridgeResult{
		User:           user,
		AccessToken:    access,
		RefreshToken:   refresh,
		ProvisionedNew: isNew,
	}, nil
}

func (b *Bridge) logSuccessfulLogin(tenantID uuid.UUID, cfg TenantExternalIdP, a *Assertion, user auth.User, isNew bool) {
	if b.Audit == nil {
		return
	}
	evt := audit.Event{
		CompanyID:  tenantID.String(),
		ActorID:    user.ID.String(),
		Action:     "auth.federation.login",
		Resource:   "external_idp",
		ResourceID: cfg.ID.String(),
		Details: map[string]any{
			"provider":         cfg.Provider,
			"external_idp":     cfg.DisplayName,
			"subject":          a.Subject,
			"authn_context":    a.AuthnContext,
			"jit_provisioned":  isNew,
			"succeeded":        true,
		},
	}
	b.Audit.Log(evt)
}

func (b *Bridge) logFailedLogin(tenantID uuid.UUID, cfg TenantExternalIdP, a *Assertion, failure error) {
	if b.Audit == nil {
		return
	}
	subject := ""
	authn := ""
	if a != nil {
		subject = a.Subject
		authn = a.AuthnContext
	}
	evt := audit.Event{
		CompanyID:  tenantID.String(),
		ActorID:    uuid.Nil.String(),
		Action:     "auth.federation.login_failed",
		Resource:   "external_idp",
		ResourceID: cfg.ID.String(),
		Details: map[string]any{
			"provider":      cfg.Provider,
			"external_idp":  cfg.DisplayName,
			"subject":       subject,
			"authn_context": authn,
			"reason":        failure.Error(),
			"succeeded":     false,
		},
	}
	b.Audit.Log(evt)
}

func jitRole(p JITPolicy) string {
	if p.DefaultRole == "" {
		return "member"
	}
	return p.DefaultRole
}

func jitRoleLevel(p JITPolicy) int {
	switch jitRole(p) {
	case "owner":
		return 90
	case "admin":
		return 80
	case "manager":
		return 60
	case "viewer":
		return 20
	default:
		return 40
	}
}
