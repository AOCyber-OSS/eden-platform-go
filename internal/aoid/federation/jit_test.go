package federation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

func newProvisionSvc(t *testing.T) *auth.Service {
	t.Helper()
	svc, _ := newProvisionSvcAndStore(t)
	return svc
}

func newProvisionSvcAndStore(t *testing.T) (*auth.Service, auth.AuthStore) {
	t.Helper()
	store := devstore.NewMemoryBackend().AuthStore()
	jwtCfg := auth.DefaultJWTConfig()
	jwt, err := auth.NewJWTManager(jwtCfg)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return auth.NewService(store, jwt, auth.NewPasswordHasher()), store
}

// provisionTenant is the asserting tenant in the single-tenant Provision tests.
var provisionTenant = uuid.MustParse("11111111-1111-1111-1111-111111111111")

func TestProvision_NewUser(t *testing.T) {
	svc := newProvisionSvc(t)
	user, isNew, err := Provision(context.Background(), svc, provisionTenant, "u@acme.com", "U User", JITPolicy{Enabled: true})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !isNew {
		t.Errorf("expected isNew=true")
	}
	if user.Email != "u@acme.com" {
		t.Errorf("Email: %q", user.Email)
	}
	if user.DisplayName != "U User" {
		t.Errorf("DisplayName: %q", user.DisplayName)
	}
	if !contains(user.PasswordHash, "fed:") {
		t.Errorf("PasswordHash should be unusable (got %q)", user.PasswordHash)
	}
}

// An existing MEMBER of the asserting tenant resolves, even with JIT off.
func TestProvision_ExistingUser(t *testing.T) {
	svc, store := newProvisionSvcAndStore(t)
	existing, _ := svc.CreateUser(context.Background(), "u@acme.com", "$2a$10$dummy", "Original")
	if err := store.CreateCompanyMembership(context.Background(), provisionTenant, existing.ID, rbac.MemberRoleID); err != nil {
		t.Fatalf("CreateCompanyMembership: %v", err)
	}
	user, isNew, err := Provision(context.Background(), svc, provisionTenant, "u@acme.com", "Original", JITPolicy{Enabled: false})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if isNew {
		t.Errorf("expected isNew=false")
	}
	if user.Email != "u@acme.com" {
		t.Errorf("Email: %q", user.Email)
	}
}

func TestProvision_JITDisabled(t *testing.T) {
	svc := newProvisionSvc(t)
	_, _, err := Provision(context.Background(), svc, provisionTenant, "unknown@acme.com", "", JITPolicy{Enabled: false})
	if !errors.Is(err, ErrFederationUserNotFound) {
		t.Errorf("expected ErrFederationUserNotFound, got %v", err)
	}
}

func TestProvision_DomainRejected(t *testing.T) {
	svc := newProvisionSvc(t)
	policy := JITPolicy{Enabled: true, AllowedDomains: []string{"acme.com"}}
	_, _, err := Provision(context.Background(), svc, provisionTenant, "user@evil.com", "", policy)
	if !errors.Is(err, ErrJITDomainNotAllowed) {
		t.Errorf("expected ErrJITDomainNotAllowed, got %v", err)
	}
}

func TestProvision_DefaultDisplayName(t *testing.T) {
	svc := newProvisionSvc(t)
	user, _, err := Provision(context.Background(), svc, provisionTenant, "u@acme.com", "", JITPolicy{Enabled: true})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if user.DisplayName != "u" {
		t.Errorf("DisplayName default: got %q, want %q", user.DisplayName, "u")
	}
}

func TestDomainAllowed(t *testing.T) {
	cases := []struct {
		domains []string
		email   string
		ok      bool
	}{
		{nil, "a@b.com", true},
		{[]string{}, "a@b.com", true},
		{[]string{"acme.com"}, "u@acme.com", true},
		{[]string{"ACME.com"}, "u@acme.com", true},
		{[]string{"acme.com"}, "u@evil.com", false},
		{[]string{"acme.com"}, "no-at-sign", false},
		{[]string{"acme.com"}, "u@", false},
	}
	for _, tc := range cases {
		if got := domainAllowed(JITPolicy{AllowedDomains: tc.domains}, tc.email); got != tc.ok {
			t.Errorf("domainAllowed(%v, %q) = %v, want %v", tc.domains, tc.email, got, tc.ok)
		}
	}
}
