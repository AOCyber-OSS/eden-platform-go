package federation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/audit"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

func newTestBridge(t *testing.T) (*Bridge, *InMemorySPRegistry, *auth.Service, *audit.Logger) {
	t.Helper()
	backend := devstore.NewMemoryBackend()
	store := backend.AuthStore()
	auditStore := backend.AuditStore()
	auditLog := audit.NewLogger(auditStore)
	auditLog.Start()

	jwtCfg := auth.DefaultJWTConfig()
	jwtCfg.Issuer = "https://aoid.test"
	jwt, err := auth.NewJWTManager(jwtCfg)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	hasher := auth.NewPasswordHasher()
	authSvc := auth.NewService(store, jwt, hasher)

	reg := NewInMemorySPRegistry()
	bridge, err := NewBridge(authSvc, reg, jwt, auditLog)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	t.Cleanup(auditLog.Stop)
	return bridge, reg, authSvc, auditLog
}

func TestBridge_HandleAssertion_NewUser(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantID)
	if err := reg.Register(ctx, cfg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	a := &Assertion{
		Subject:      "user@acme.com",
		Email:        "user@acme.com",
		DisplayName:  "User Foo",
		Attributes:   map[string][]string{"email": {"user@acme.com"}},
		AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract",
		IssuedAt:     time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute),
	}

	res, err := b.HandleAssertion(ctx, tenantID, cfg.ID, a)
	if err != nil {
		t.Fatalf("HandleAssertion: %v", err)
	}
	if !res.ProvisionedNew {
		t.Errorf("expected ProvisionedNew=true")
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Errorf("tokens not minted")
	}
	if res.User.Email != "user@acme.com" {
		t.Errorf("unexpected email: %q", res.User.Email)
	}
}

// An existing MEMBER of the asserting tenant resolves without provisioning.
// An email match on a non-member is refused (#74, jit_tenant_scope_test.go).
func TestBridge_HandleAssertion_ExistingUser(t *testing.T) {
	w := newFedWorld(t)
	existing := w.member(w.A.ID, "existing@acme.com", rbac.MemberRoleID)

	res, err := w.loginVia(w.A, existing.Email)
	if err != nil {
		t.Fatalf("HandleAssertion: %v", err)
	}
	if res.ProvisionedNew {
		t.Errorf("expected ProvisionedNew=false for existing user")
	}
	if res.User.ID != existing.ID {
		t.Errorf("resolved %s, want %s", res.User.ID, existing.ID)
	}
}

func TestBridge_HandleAssertion_JITDisabled(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantID)
	cfg.JITPolicy.Enabled = false
	cfg.JITPolicy.AllowedDomains = nil
	cfg.JITPolicy.RequireMFA = false
	_ = reg.Register(ctx, cfg)

	a := &Assertion{Email: "unknown@anywhere.com"}
	if _, err := b.HandleAssertion(ctx, tenantID, cfg.ID, a); !errors.Is(err, ErrFederationUserNotFound) {
		t.Errorf("expected ErrFederationUserNotFound, got %v", err)
	}
}

func TestBridge_HandleAssertion_DomainViolation(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantID)
	cfg.JITPolicy.RequireMFA = false
	_ = reg.Register(ctx, cfg)

	a := &Assertion{Email: "user@evil.com"}
	if _, err := b.HandleAssertion(ctx, tenantID, cfg.ID, a); !errors.Is(err, ErrJITDomainNotAllowed) {
		t.Errorf("expected ErrJITDomainNotAllowed, got %v", err)
	}
}

func TestBridge_HandleAssertion_WrongTenant(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantA := uuid.New()
	tenantB := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantA)
	cfg.JITPolicy.RequireMFA = false
	_ = reg.Register(ctx, cfg)

	a := &Assertion{Email: "user@acme.com"}
	_, err := b.HandleAssertion(ctx, tenantB, cfg.ID, a)
	if !errors.Is(err, ErrExternalIdPNotFound) {
		t.Errorf("expected ErrExternalIdPNotFound for cross-tenant, got %v", err)
	}
}

func TestBridge_HandleAssertion_ExpiredAssertion(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantID)
	cfg.JITPolicy.RequireMFA = false
	_ = reg.Register(ctx, cfg)

	a := &Assertion{
		Email:     "user@acme.com",
		ExpiresAt: time.Now().Add(-30 * time.Minute),
	}
	_, err := b.HandleAssertion(ctx, tenantID, cfg.ID, a)
	if err == nil || !contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestBridge_HandleAssertion_InactiveTenant(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantID)
	cfg.IsActive = false
	cfg.JITPolicy.RequireMFA = false
	_ = reg.Register(ctx, cfg)
	a := &Assertion{Email: "u@acme.com"}
	_, err := b.HandleAssertion(ctx, tenantID, cfg.ID, a)
	if !errors.Is(err, ErrTenantInactive) {
		t.Errorf("expected ErrTenantInactive, got %v", err)
	}
}

func TestBridge_NewBridge_NilArgs(t *testing.T) {
	if _, err := NewBridge(nil, nil, nil, nil); err == nil {
		t.Errorf("expected error for nil args")
	}
}

func TestBridge_TokensValidate(t *testing.T) {
	b, reg, _, _ := newTestBridge(t)
	ctx := context.Background()
	tenantID := uuid.New()
	cfg := newExternalIdPConfig(t, ProviderSAML, tenantID)
	cfg.JITPolicy.RequireMFA = false
	_ = reg.Register(ctx, cfg)
	a := &Assertion{
		Email:    "user@acme.com",
		IssuedAt: time.Now(),
	}
	res, err := b.HandleAssertion(ctx, tenantID, cfg.ID, a)
	if err != nil {
		t.Fatalf("HandleAssertion: %v", err)
	}
	if _, err := b.JWT.ValidateAccessToken(res.AccessToken); err != nil {
		t.Errorf("ValidateAccessToken: %v", err)
	}
}

func TestProvision_DirectInvalidEmail(t *testing.T) {
	_, _, svc, _ := newTestBridge(t)
	_, _, err := Provision(context.Background(), svc, uuid.New(), "not-an-email", "", JITPolicy{Enabled: true})
	if err == nil {
		t.Errorf("expected invalid-email error")
	}
}

func TestProvision_DirectMissingEmail(t *testing.T) {
	_, _, svc, _ := newTestBridge(t)
	_, _, err := Provision(context.Background(), svc, uuid.New(), "", "", JITPolicy{Enabled: true})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// contains is a tiny stand-in for strings.Contains to keep imports lean.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
