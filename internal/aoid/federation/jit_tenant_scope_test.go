package federation

// Issue #74, federation half: Provision resolved an inbound external-IdP login
// to an existing user by EMAIL ONLY and returned it unconditionally; JITPolicy
// gated only creation. The Bridge then minted a token for the asserting tenant
// carrying the JIT default role. Tenant A's external IdP could sign in as a
// tenant-B user, and a low-privilege member came back with the JIT default role.
//
// Hand-built fixture: one in-memory AuthStore, two tenants, each with its own
// registered external IdP, and users seeded with explicit memberships.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

type fedTenant struct {
	ID  uuid.UUID
	IdP TenantExternalIdP
}

type fedWorld struct {
	t      *testing.T
	store  auth.AuthStore
	bridge *Bridge
	A, B   fedTenant
}

func newFedWorld(t *testing.T) *fedWorld {
	t.Helper()
	store := devstore.NewMemoryBackend().AuthStore()
	jwtCfg := auth.DefaultJWTConfig()
	jwtCfg.Issuer = "https://aoid.test"
	jwt, err := auth.NewJWTManager(jwtCfg)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	reg := NewInMemorySPRegistry()
	bridge, err := NewBridge(auth.NewService(store, jwt, auth.NewPasswordHasher()), reg, jwt, nil)
	if err != nil {
		t.Fatalf("NewBridge: %v", err)
	}
	w := &fedWorld{t: t, store: store, bridge: bridge}
	w.A = w.addTenant(reg)
	w.B = w.addTenant(reg)
	return w
}

// addTenant registers an external IdP whose JIT default role is "admin", so a
// test can tell the JIT default apart from a member's own role.
func (w *fedWorld) addTenant(reg *InMemorySPRegistry) fedTenant {
	w.t.Helper()
	id := uuid.New()
	cfg := newExternalIdPConfig(w.t, ProviderSAML, id)
	cfg.JITPolicy = JITPolicy{Enabled: true, DefaultRole: "admin"}
	if err := reg.Register(context.Background(), cfg); err != nil {
		w.t.Fatalf("Register: %v", err)
	}
	return fedTenant{ID: id, IdP: cfg}
}

func (w *fedWorld) user(email string) auth.User {
	w.t.Helper()
	u, err := w.store.CreateUser(context.Background(), email, "$2a$10$fixture-hash-not-a-real-password", "Fixture User")
	if err != nil {
		w.t.Fatalf("CreateUser(%s): %v", email, err)
	}
	return u
}

func (w *fedWorld) member(tenantID uuid.UUID, email string, roleID uuid.UUID) auth.User {
	w.t.Helper()
	u := w.user(email)
	if err := w.store.CreateCompanyMembership(context.Background(), tenantID, u.ID, roleID); err != nil {
		w.t.Fatalf("CreateCompanyMembership: %v", err)
	}
	return u
}

func (w *fedWorld) isMember(tenantID, userID uuid.UUID) bool {
	_, err := w.store.GetUserRole(context.Background(), tenantID, userID)
	return err == nil
}

func (w *fedWorld) loginVia(ten fedTenant, email string) (*BridgeResult, error) {
	return w.bridge.HandleAssertion(context.Background(), ten.ID, ten.IdP.ID, &Assertion{
		Subject:   "idp-subject-" + email,
		Email:     email,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	})
}

func (w *fedWorld) assertRefused(res *BridgeResult, err error, via fedTenant, victim auth.User) {
	w.t.Helper()
	if !errors.Is(err, ErrFederationEmailNotMember) {
		w.t.Errorf("err = %v, want ErrFederationEmailNotMember", err)
	}
	if res != nil {
		w.t.Errorf("SECURITY (#74): a refused federation login minted tokens for %s", res.User.Email)
	}
	if w.isMember(via.ID, victim.ID) {
		w.t.Errorf("SECURITY (#74): the victim was added to the asserting tenant")
	}
}

func TestFederationTenantScope_OtherTenantsUserIsRefused(t *testing.T) {
	w := newFedWorld(t)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	res, err := w.loginVia(w.A, victim.Email)

	w.assertRefused(res, err, w.A, victim)
}

func TestFederationTenantScope_AccountWithNoTenantIsRefused(t *testing.T) {
	w := newFedWorld(t)
	loner := w.user("loner@nowhere.example")

	res, err := w.loginVia(w.A, loner.Email)

	w.assertRefused(res, err, w.A, loner)
}

// A member signs in with their own role, not the IdP's JIT default role, and
// the token names only the asserting tenant.
func TestFederationTenantScope_MemberGetsOwnRoleNotJITDefault(t *testing.T) {
	w := newFedWorld(t)
	viewer := w.member(w.A.ID, "viewer@tenant-a.example", rbac.ViewerRoleID)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	res, err := w.loginVia(w.A, viewer.Email)
	if err != nil {
		t.Fatalf("HandleAssertion: %v", err)
	}
	if res.ProvisionedNew || res.User.ID != viewer.ID {
		t.Fatalf("resolved %s (new=%v), want the existing viewer %s", res.User.ID, res.ProvisionedNew, viewer.ID)
	}
	claims, err := w.bridge.JWT.ValidateAccessToken(res.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Role != "viewer" || claims.RoleLevel != 20 {
		t.Errorf("role = %s/%d, want the member's own viewer/20, not the JIT default admin", claims.Role, claims.RoleLevel)
	}
	if claims.CompanyID != w.A.ID.String() || len(claims.CompanyIDs) != 1 {
		t.Errorf("company claims = %s %v, want only tenant A", claims.CompanyID, claims.CompanyIDs)
	}
	if w.isMember(w.A.ID, victim.ID) {
		t.Errorf("SECURITY (#74): tenant A's login touched the tenant-B user")
	}
}

// A new JIT user is created WITH a membership in the asserting tenant, so the
// second login is the member path: same user, same (JIT default) role. Before
// this, the user had no membership and the second login was refused.
func TestFederationTenantScope_JITUserSecondLoginSucceeds(t *testing.T) {
	w := newFedWorld(t)
	const email = "newhire@tenant-a.example"

	first, err := w.loginVia(w.A, email)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	if !first.ProvisionedNew {
		t.Fatalf("first login did not provision")
	}
	if !w.isMember(w.A.ID, first.User.ID) {
		t.Fatalf("JIT user has no membership in the asserting tenant")
	}

	second, err := w.loginVia(w.A, email)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if second.ProvisionedNew || second.User.ID != first.User.ID {
		t.Errorf("second login resolved %s (new=%v), want existing %s", second.User.ID, second.ProvisionedNew, first.User.ID)
	}
	for i, res := range []*BridgeResult{first, second} {
		claims, err := w.bridge.JWT.ValidateAccessToken(res.AccessToken)
		if err != nil {
			t.Fatalf("login %d ValidateAccessToken: %v", i+1, err)
		}
		if claims.Role != "admin" || claims.RoleLevel != 80 || claims.CompanyID != w.A.ID.String() {
			t.Errorf("login %d claims = %s/%d/%s, want the JIT default admin/80 in tenant A", i+1, claims.Role, claims.RoleLevel, claims.CompanyID)
		}
	}

	// Wrong-tenant isolation: the JIT user did not land in B, and B's IdP
	// cannot claim them.
	if w.isMember(w.B.ID, first.User.ID) {
		t.Errorf("SECURITY (#74): JIT user leaked into tenant B")
	}
	res, err := w.loginVia(w.B, email)
	w.assertRefused(res, err, w.B, first.User)
}

// racingStore hides an existing user from the FIRST GetUserByEmail, modelling
// a concurrent first login that created the account between our lookup and
// our CreateUser (which then fails on the unique email).
type racingStore struct {
	auth.TxAuthStore
	hidden bool
}

func (s *racingStore) GetUserByEmail(ctx context.Context, email string) (auth.User, error) {
	if !s.hidden {
		s.hidden = true
		return auth.User{}, errors.New("user not found")
	}
	return s.TxAuthStore.GetUserByEmail(ctx, email)
}

func TestFederationTenantScope_CreateRaceResolvesInsteadOfFailing(t *testing.T) {
	ctx := context.Background()
	base := devstore.NewMemoryBackend().AuthStore()
	tenantA, tenantB := uuid.New(), uuid.New()
	mk := func(email string, tenant uuid.UUID) auth.User {
		u, err := base.CreateUser(ctx, email, "fed:fixture", "Racer")
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := base.CreateCompanyMembership(ctx, tenant, u.ID, rbac.MemberRoleID); err != nil {
			t.Fatalf("CreateCompanyMembership: %v", err)
		}
		return u
	}
	jwt, err := auth.NewJWTManager(auth.DefaultJWTConfig())
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	policy := JITPolicy{Enabled: true}

	t.Run("winner is a member of this tenant: resolves to it", func(t *testing.T) {
		winner := mk("racer-a@tenant-a.example", tenantA)
		svc := auth.NewService(&racingStore{TxAuthStore: base}, jwt, auth.NewPasswordHasher())
		u, isNew, err := Provision(ctx, svc, tenantA, winner.Email, "", policy)
		if err != nil {
			t.Fatalf("Provision after a create race: %v", err)
		}
		if isNew || u.ID != winner.ID {
			t.Errorf("resolved %s (new=%v), want the race winner %s", u.ID, isNew, winner.ID)
		}
	})
	t.Run("winner belongs to another tenant: refused, not a store error", func(t *testing.T) {
		victim := mk("racer-b@tenant-b.example", tenantB)
		svc := auth.NewService(&racingStore{TxAuthStore: base}, jwt, auth.NewPasswordHasher())
		_, _, err := Provision(ctx, svc, tenantA, victim.Email, "", policy)
		if !errors.Is(err, ErrFederationEmailNotMember) {
			t.Errorf("err = %v, want ErrFederationEmailNotMember", err)
		}
	})
}

// failMembershipStore fails the next `fail` CreateCompanyMembership calls,
// inside or outside a transaction (a tx shares the counter).
type failMembershipStore struct {
	auth.TxAuthStore
	fail *int
}

func (s *failMembershipStore) BeginTx(ctx context.Context) (auth.TxAuthStore, error) {
	tx, err := s.TxAuthStore.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &failMembershipStore{TxAuthStore: tx, fail: s.fail}, nil
}

func (s *failMembershipStore) CreateCompanyMembership(ctx context.Context, companyID, userID, roleID uuid.UUID) error {
	if *s.fail > 0 {
		*s.fail--
		return errors.New("injected membership failure")
	}
	return s.TxAuthStore.CreateCompanyMembership(ctx, companyID, userID, roleID)
}

// A failed membership create must not strand a user row: under the refuse
// rule, a user with no membership could never sign in again.
func TestFederationTenantScope_MembershipFailureLeavesNoUserAndRetrySucceeds(t *testing.T) {
	ctx := context.Background()
	base := devstore.NewMemoryBackend().AuthStore()
	fail := 1
	jwt, err := auth.NewJWTManager(auth.DefaultJWTConfig())
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	svc := auth.NewService(&failMembershipStore{TxAuthStore: base, fail: &fail}, jwt, auth.NewPasswordHasher())
	tenantA, tenantB := uuid.New(), uuid.New()
	const email = "newhire@tenant-a.example"

	if _, _, err := Provision(ctx, svc, tenantA, email, "", JITPolicy{Enabled: true}); err == nil {
		t.Fatalf("Provision succeeded despite the membership failure")
	}
	if u, err := base.GetUserByEmail(ctx, email); err == nil {
		t.Fatalf("SECURITY/lockout: user %s was left without a membership", u.ID)
	}

	u, isNew, err := Provision(ctx, svc, tenantA, email, "", JITPolicy{Enabled: true})
	if err != nil {
		t.Fatalf("retry Provision: %v", err)
	}
	if !isNew {
		t.Errorf("retry did not provision")
	}
	if _, err := base.GetUserRole(ctx, tenantA, u.ID); err != nil {
		t.Errorf("retried user is not a member of tenant A: %v", err)
	}
	if _, err := base.GetUserRole(ctx, tenantB, u.ID); err == nil {
		t.Errorf("SECURITY (#74): retried user leaked into tenant B")
	}
}
