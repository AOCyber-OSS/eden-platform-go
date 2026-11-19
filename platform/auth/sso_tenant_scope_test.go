package auth_test

// Issue #74 (same class as aodex#1119): SSOService.jitProvision resolved an SSO
// login to an existing user by EMAIL ONLY, then added that user to the
// asserting company and issued tokens. Whoever controls company A's IdP could
// therefore assert a company-B user's email and sign in as that user.
//
// These tests drive the real HTTP seam: InitiateOIDC mints the signed state,
// GET /auth/oidc/callback runs the code exchange against a fake OP that signs
// a real RS256 id_token (fakePKCEOP, sso_pkce_test.go), and the JSON branch
// returns the token pair. Fixtures are hand-built: two companies, each with
// its own OIDC SSOConfig and its own OP, sharing one in-memory AuthStore.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

const tenantScopeClientID = "eden-biz-client"

// recordingStore wraps the in-memory AuthStore and records the writes the
// memory store drops on the floor, so a test can prove that a refused login
// issued no refresh token, stored no provider credential, and was audited.
type recordingStore struct {
	auth.AuthStore

	mu            sync.Mutex
	refreshTokens []uuid.UUID // user ids a refresh token was stored for
	oauthCreds    []auth.OAuthCredential
	audits        []recordedAudit
}

type recordedAudit struct {
	CompanyID uuid.UUID
	ActorID   uuid.UUID
	Action    string
	Details   map[string]any
}

func (s *recordingStore) CreateRefreshToken(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	s.mu.Lock()
	s.refreshTokens = append(s.refreshTokens, userID)
	s.mu.Unlock()
	return s.AuthStore.CreateRefreshToken(ctx, userID, tokenHash, expiresAt)
}

func (s *recordingStore) UpsertOAuthCredential(ctx context.Context, cred auth.OAuthCredential) error {
	s.mu.Lock()
	s.oauthCreds = append(s.oauthCreds, cred)
	s.mu.Unlock()
	return s.AuthStore.UpsertOAuthCredential(ctx, cred)
}

func (s *recordingStore) CreateAuditLog(ctx context.Context, companyID, actorID uuid.UUID, action, resource, resourceID, ipAddress string, details []byte) error {
	rec := recordedAudit{CompanyID: companyID, ActorID: actorID, Action: action}
	_ = json.Unmarshal(details, &rec.Details)
	s.mu.Lock()
	s.audits = append(s.audits, rec)
	s.mu.Unlock()
	return s.AuthStore.CreateAuditLog(ctx, companyID, actorID, action, resource, resourceID, ipAddress, details)
}

func (s *recordingStore) refreshTokenIssuedFor(userID uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range s.refreshTokens {
		if id == userID {
			return true
		}
	}
	return false
}

func (s *recordingStore) oauthCredentialStoredFor(userID uuid.UUID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.oauthCreds {
		if c.UserID == userID {
			return true
		}
	}
	return false
}

func (s *recordingStore) auditsWithAction(action string) []recordedAudit {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []recordedAudit
	for _, a := range s.audits {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

// tenant is one company with its own OIDC SSOConfig and its own IdP.
type tenant struct {
	ID  uuid.UUID
	IdP *fakePKCEOP
}

// ssoTenantWorld is two tenants on one SSOService.
type ssoTenantWorld struct {
	t     *testing.T
	store *recordingStore
	jwt   *auth.JWTManager
	svc   *auth.SSOService
	mux   *http.ServeMux
	A, B  tenant
}

func newSSOTenantWorld(t *testing.T) *ssoTenantWorld {
	t.Helper()
	store := &recordingStore{AuthStore: devstore.NewMemoryBackend().AuthStore()}
	jwtManager, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer:             "eden-platform-test",
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	w := &ssoTenantWorld{t: t, store: store, jwt: jwtManager}
	w.A = w.addTenant("Tenant A", "tenant-a")
	w.B = w.addTenant("Tenant B", "tenant-b")
	w.svc = auth.NewSSOService(store, jwtManager, "https://api.example.test")
	allowLoopbackIdPForTest(w.svc)
	w.mux = http.NewServeMux()
	w.svc.RegisterHTTPHandlers(w.mux)
	return w
}

func (w *ssoTenantWorld) addTenant(name, slug string) tenant {
	w.t.Helper()
	ctx := context.Background()
	id, err := w.store.CreateCompany(ctx, name, slug, "standalone")
	if err != nil {
		w.t.Fatalf("CreateCompany(%s): %v", slug, err)
	}
	op := newFakePKCEOP(w.t, tenantScopeClientID, "", "")
	// Each tenant's IdP may JIT-provision its own domain only (#89).
	if err := w.store.UpsertSSOConfig(ctx, auth.SSOConfig{
		CompanyID:            id,
		Provider:             "oidc",
		IssuerURL:            op.srv.URL,
		ClientID:             tenantScopeClientID,
		ClientSecret:         "test-client-secret",
		IsActive:             true,
		JITEnabled:           true,
		EmailDomainAllowlist: []string{slug + ".example"},
	}); err != nil {
		w.t.Fatalf("UpsertSSOConfig(%s): %v", slug, err)
	}
	return tenant{ID: id, IdP: op}
}

// member creates a user who belongs to company with roleID.
func (w *ssoTenantWorld) member(company uuid.UUID, email string, roleID uuid.UUID) auth.User {
	w.t.Helper()
	u := w.userWithoutCompany(email)
	if err := w.store.CreateCompanyMembership(context.Background(), company, u.ID, roleID); err != nil {
		w.t.Fatalf("CreateCompanyMembership: %v", err)
	}
	return u
}

// userWithoutCompany creates a user with no membership anywhere.
func (w *ssoTenantWorld) userWithoutCompany(email string) auth.User {
	w.t.Helper()
	u, err := w.store.CreateUser(context.Background(), email, "$2a$10$fixture-hash-not-a-real-password", "Fixture User")
	if err != nil {
		w.t.Fatalf("CreateUser(%s): %v", email, err)
	}
	return u
}

func (w *ssoTenantWorld) isMember(company, userID uuid.UUID) bool {
	_, err := w.store.GetUserRole(context.Background(), company, userID)
	return err == nil
}

// ssoLogin is the outcome of one login through the HTTP callback.
type ssoLogin struct {
	Status       int
	AccessToken  string
	RefreshToken string
	Claims       *auth.Claims
}

// loginVia has ten's IdP assert email, then completes the login through
// GET /auth/oidc/callback (the JSON branch, so the token pair is in the body).
func (w *ssoTenantWorld) loginVia(ten tenant, email string) ssoLogin {
	w.t.Helper()
	ten.IdP.email = email
	ten.IdP.name = "Asserted Name"
	_, state, err := w.svc.InitiateOIDC(context.Background(), ten.ID, "oidc", "json")
	if err != nil {
		w.t.Fatalf("InitiateOIDC: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=fixture-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, req)

	out := ssoLogin{Status: rec.Code}
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			w.t.Fatalf("decode token body %q: %v", rec.Body.String(), err)
		}
		out.AccessToken, out.RefreshToken = body.AccessToken, body.RefreshToken
		claims, err := w.jwt.ValidateAccessToken(body.AccessToken)
		if err != nil {
			w.t.Fatalf("ValidateAccessToken: %v", err)
		}
		out.Claims = claims
	} else if bodyHasToken(rec.Body.Bytes()) {
		w.t.Fatalf("a refused login returned a token body: %q", rec.Body.String())
	}
	return out
}

func bodyHasToken(b []byte) bool {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	_, a := m["access_token"]
	_, r := m["refresh_token"]
	return a || r
}

// assertRefused checks every consequence of a refused cross-tenant login.
func (w *ssoTenantWorld) assertRefused(got ssoLogin, via tenant, victim auth.User) {
	w.t.Helper()
	if got.Status != http.StatusForbidden {
		w.t.Errorf("status = %d, want 403 for an email owned by a non-member", got.Status)
	}
	if got.AccessToken != "" || got.RefreshToken != "" {
		w.t.Errorf("a refused login returned tokens")
	}
	if w.isMember(via.ID, victim.ID) {
		w.t.Errorf("SECURITY (#74): the victim was silently added to the asserting company")
	}
	if w.store.refreshTokenIssuedFor(victim.ID) {
		w.t.Errorf("SECURITY (#74): a refresh token was stored for the victim")
	}
	if w.store.oauthCredentialStoredFor(victim.ID) {
		w.t.Errorf("SECURITY (#74): the asserting IdP's OAuth tokens were stored against the victim")
	}
}

// 1. The attack: an existing tenant-B user's email asserted by tenant A's IdP.
func TestSSOTenantScope_OtherTenantsUserIsRefused(t *testing.T) {
	w := newSSOTenantWorld(t)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	got := w.loginVia(w.A, victim.Email)

	w.assertRefused(got, w.A, victim)
	if !w.isMember(w.B.ID, victim.ID) {
		t.Errorf("the victim's own tenant-B membership must be untouched")
	}
}

// Service-level contract behind the 403: callers can tell a refusal apart.
func TestSSOTenantScope_RefusalIsATypedError(t *testing.T) {
	w := newSSOTenantWorld(t)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	w.A.IdP.email = victim.Email
	_, state, err := w.svc.InitiateOIDC(context.Background(), w.A.ID, "oidc", "json")
	if err != nil {
		t.Fatalf("InitiateOIDC: %v", err)
	}
	resp, _, err := w.svc.HandleOIDCCallbackWithState(context.Background(), "fixture-code", state)
	if !errors.Is(err, auth.ErrSSOEmailNotMember) {
		t.Fatalf("err = %v, want ErrSSOEmailNotMember", err)
	}
	if resp != nil {
		t.Fatalf("a refused login returned an AuthResponse")
	}
}

// 2. Happy path: a member of A signs in through A's IdP with their own role,
// and the token is scoped to A only.
func TestSSOTenantScope_MemberSignsInWithOwnRole(t *testing.T) {
	w := newSSOTenantWorld(t)
	alice := w.member(w.A.ID, "alice@tenant-a.example", rbac.AdminRoleID)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	got := w.loginVia(w.A, alice.Email)

	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if got.Claims.UserID != alice.ID.String() {
		t.Errorf("uid = %s, want alice %s", got.Claims.UserID, alice.ID)
	}
	if got.Claims.CompanyID != w.A.ID.String() || len(got.Claims.CompanyIDs) != 1 || got.Claims.CompanyIDs[0] != w.A.ID.String() {
		t.Errorf("company claims = %s %v, want only tenant A %s", got.Claims.CompanyID, got.Claims.CompanyIDs, w.A.ID)
	}
	if got.Claims.Role != "admin" || got.Claims.RoleLevel != 80 {
		t.Errorf("role = %s/%d, want alice's own admin/80", got.Claims.Role, got.Claims.RoleLevel)
	}
	if !w.store.refreshTokenIssuedFor(alice.ID) {
		t.Errorf("no refresh token stored for alice")
	}
	// Wrong-tenant isolation: the tenant-B user is untouched by A's login.
	if w.isMember(w.A.ID, victim.ID) || w.store.refreshTokenIssuedFor(victim.ID) {
		t.Errorf("SECURITY (#74): tenant A's login touched the tenant-B user")
	}
}

// 3. Edge: a user in BOTH tenants signs in through A and gets an A token only.
func TestSSOTenantScope_MultiTenantMemberGetsOnlyTheAssertingTenant(t *testing.T) {
	w := newSSOTenantWorld(t)
	both := w.member(w.A.ID, "both@shared.example", rbac.MemberRoleID)
	if err := w.store.CreateCompanyMembership(context.Background(), w.B.ID, both.ID, rbac.OwnerRoleID); err != nil {
		t.Fatalf("CreateCompanyMembership(B): %v", err)
	}

	got := w.loginVia(w.A, both.Email)

	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if got.Claims.CompanyID != w.A.ID.String() || len(got.Claims.CompanyIDs) != 1 {
		t.Errorf("company claims = %s %v, want only tenant A", got.Claims.CompanyID, got.Claims.CompanyIDs)
	}
	if got.Claims.Role != "member" {
		t.Errorf("role = %s, want the tenant-A role (member), not the tenant-B owner role", got.Claims.Role)
	}
}

// 4. Edge: case and whitespace variants of the victim's email are refused too.
func TestSSOTenantScope_EmailVariantsOfOtherTenantsUserAreRefused(t *testing.T) {
	for _, variant := range []string{"VICTIM@Tenant-B.example", "  victim@tenant-b.example  "} {
		t.Run(variant, func(t *testing.T) {
			w := newSSOTenantWorld(t)
			victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

			w.assertRefused(w.loginVia(w.A, variant), w.A, victim)
		})
	}
}

// 5. New email: JIT still creates the account as a member of A, and of A only.
func TestSSOTenantScope_UnknownEmailIsProvisionedIntoTheAssertingTenantOnly(t *testing.T) {
	w := newSSOTenantWorld(t)

	got := w.loginVia(w.A, "newhire@tenant-a.example")

	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	u, err := w.store.GetUserByEmail(context.Background(), "newhire@tenant-a.example")
	if err != nil {
		t.Fatalf("JIT user not created: %v", err)
	}
	if !w.isMember(w.A.ID, u.ID) {
		t.Errorf("JIT user is not a member of tenant A")
	}
	if w.isMember(w.B.ID, u.ID) {
		t.Errorf("SECURITY (#74): JIT user leaked into tenant B")
	}
	if got.Claims.UserID != u.ID.String() || got.Claims.CompanyID != w.A.ID.String() || got.Claims.Role != "member" {
		t.Errorf("claims = %s/%s/%s, want the new user as a tenant-A member", got.Claims.UserID, got.Claims.CompanyID, got.Claims.Role)
	}
}

// 6. Edge: an account with no company at all is not adopted by A's IdP either.
// Joining a company takes an explicit membership, never an email match.
func TestSSOTenantScope_AccountWithNoCompanyIsRefused(t *testing.T) {
	w := newSSOTenantWorld(t)
	loner := w.userWithoutCompany("loner@nowhere.example")

	w.assertRefused(w.loginVia(w.A, loner.Email), w.A, loner)
}

// 7. Failure mode: a refusal is audited against the asserting company, with
// no actor and without naming the other account.
func TestSSOTenantScope_RefusalIsAudited(t *testing.T) {
	w := newSSOTenantWorld(t)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	w.loginVia(w.A, victim.Email)

	audits := w.store.auditsWithAction("auth.sso.login_refused")
	if len(audits) != 1 {
		t.Fatalf("got %d auth.sso.login_refused audits, want 1", len(audits))
	}
	a := audits[0]
	if a.CompanyID != w.A.ID {
		t.Errorf("audit company = %s, want the asserting tenant A %s", a.CompanyID, w.A.ID)
	}
	if a.ActorID != uuid.Nil {
		t.Errorf("audit actor = %s, want none (uuid.Nil): nobody signed in", a.ActorID)
	}
	if a.Details["reason"] != "login_refused" || a.Details["provider"] != "oidc" {
		t.Errorf("audit details = %v, want reason=login_refused provider=oidc", a.Details)
	}
	for k, v := range a.Details {
		if s, ok := v.(string); ok && s == victim.ID.String() {
			t.Errorf("SECURITY: audit detail %q names the other tenant's user id; tenant A's audit log must not", k)
		}
	}
}

// raceOnceStore hides an existing user from the first GetUserByEmail, as if a
// concurrent first login created the account between lookup and CreateUser.
type raceOnceStore struct {
	*recordingStore
	hidden bool
}

func (s *raceOnceStore) GetUserByEmail(ctx context.Context, email string) (auth.User, error) {
	if !s.hidden {
		s.hidden = true
		return auth.User{}, errors.New("user not found")
	}
	return s.recordingStore.GetUserByEmail(ctx, email)
}

// 8. Failure mode: the lookup/create race resolves under the same rule (a
// member signs in, a non-member gets 403) instead of a 500 on the unique email.
func TestSSOTenantScope_CreateRaceResolvesUnderTheSameRule(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inTenantA  bool
		wantStatus int
	}{
		{"winner is a member of A", true, http.StatusOK},
		{"winner belongs to B", false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSSOTenantWorld(t)
			target := w.B.ID
			if tc.inTenantA {
				target = w.A.ID
			}
			u := w.member(target, "racer@tenant-a.example", rbac.MemberRoleID)
			w.svc = auth.NewSSOService(&raceOnceStore{recordingStore: w.store}, w.jwt, "https://api.example.test")
			allowLoopbackIdPForTest(w.svc)
			w.mux = http.NewServeMux()
			w.svc.RegisterHTTPHandlers(w.mux)

			got := w.loginVia(w.A, u.Email)

			if got.Status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", got.Status, tc.wantStatus)
			}
			if !tc.inTenantA {
				w.assertRefused(got, w.A, u)
			}
		})
	}
}

// failMembershipTxStore is a transactional store that fails the next `fail`
// CreateCompanyMembership calls, inside or outside a transaction.
type failMembershipTxStore struct {
	auth.TxAuthStore
	fail *int
}

func (s *failMembershipTxStore) BeginTx(ctx context.Context) (auth.TxAuthStore, error) {
	tx, err := s.TxAuthStore.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	return &failMembershipTxStore{TxAuthStore: tx, fail: s.fail}, nil
}

func (s *failMembershipTxStore) CreateCompanyMembership(ctx context.Context, companyID, userID, roleID uuid.UUID) error {
	if *s.fail > 0 {
		*s.fail--
		return errors.New("injected membership failure")
	}
	return s.TxAuthStore.CreateCompanyMembership(ctx, companyID, userID, roleID)
}

// 9. Failure mode: a failed membership create leaves no user row (which the
// refuse rule would lock out forever), and the next login provisions cleanly.
func TestSSOTenantScope_MembershipFailureLeavesNoUserAndRetrySucceeds(t *testing.T) {
	ctx := context.Background()
	backend := devstore.NewMemoryBackend()
	base := backend.AuthStore()
	jwtManager, err := auth.NewJWTManager(auth.JWTConfig{Issuer: "eden-platform-test", AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	fail := 1
	store := &failMembershipTxStore{TxAuthStore: base, fail: &fail}
	w := &ssoTenantWorld{t: t, store: &recordingStore{AuthStore: store}, jwt: jwtManager}
	w.A = w.addTenant("Tenant A", "tenant-a")
	w.B = w.addTenant("Tenant B", "tenant-b")
	// The SSOService sees the transactional store directly.
	w.svc = auth.NewSSOService(store, jwtManager, "https://api.example.test")
	allowLoopbackIdPForTest(w.svc)
	w.mux = http.NewServeMux()
	w.svc.RegisterHTTPHandlers(w.mux)
	const email = "newhire@tenant-a.example"

	if got := w.loginVia(w.A, email); got.Status == http.StatusOK {
		t.Fatalf("login succeeded despite the membership failure")
	}
	if u, err := base.GetUserByEmail(ctx, email); err == nil {
		t.Fatalf("lockout: user %s was left without a membership", u.ID)
	}

	got := w.loginVia(w.A, email)
	if got.Status != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", got.Status)
	}
	u, err := base.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("retry created no user: %v", err)
	}
	if !w.isMember(w.A.ID, u.ID) || w.isMember(w.B.ID, u.ID) {
		t.Errorf("retried user membership: A=%v B=%v, want A only", w.isMember(w.A.ID, u.ID), w.isMember(w.B.ID, u.ID))
	}
}
