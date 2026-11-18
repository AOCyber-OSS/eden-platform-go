package auth_test

// Refresh must stay in the company the session was issued for (wrong-tenant
// escalation found in review of PR #82).

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/google/uuid"
	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

// setupTenantService is setupAuthService with the legacy window explicitly
// open, so the legacy-token cases do not depend on today's date.
func setupTenantService(t *testing.T) (*auth.Service, *devstore.Backend) {
	t.Helper()
	backend := devstore.NewMemoryBackend()
	jm, err := auth.NewJWTManager(auth.JWTConfig{
		Issuer: "test", AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour,
		LegacyUntypedCutoff: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return auth.NewService(backend.AuthStore(), jm, auth.NewPasswordHasher()), backend
}

// ownerOfBMemberOfA signs a user up (owner of their own company B, the oldest
// membership) and signs them in to company A, where they are only a member,
// through SSO JIT. It returns the service, the A session and both company ids.
func ownerOfBMemberOfA(t *testing.T) (*auth.Service, *auth.JWTManager, *auth.AuthResponse, uuid.UUID, uuid.UUID) {
	t.Helper()
	svc, backend := setupTenantService(t)
	jm := svc.JWTManagerForTest()
	ctx := context.Background()
	up, err := svc.SignUp(ctx, "owner-b@example.com", "password123", "Owner B")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	upClaims, err := jm.ValidateAccessToken(up.AccessToken)
	if err != nil {
		t.Fatalf("validate signup token: %v", err)
	}
	companyB := uuid.MustParse(upClaims.CompanyID)

	store := backend.AuthStore()
	companyA, err := store.CreateCompany(ctx, "Company A", "company-a", "standalone")
	if err != nil {
		t.Fatalf("CreateCompany A: %v", err)
	}
	// Since #83 (SSO JIT refuses non-members), joining A takes an explicit
	// membership (an invite); an email match alone no longer links.
	if err := store.CreateCompanyMembership(ctx, companyA, uuid.MustParse(upClaims.UserID), rbac.MemberRoleID); err != nil {
		t.Fatalf("invite owner-b into A: %v", err)
	}
	sso := auth.NewSSOService(store, jm, "http://sso.test")
	sessA, err := sso.JITProvisionForTest(ctx, "owner-b@example.com", "Owner B", companyA)
	if err != nil {
		t.Fatalf("JIT into A: %v", err)
	}
	aClaims, err := jm.ValidateAccessToken(sessA.AccessToken)
	if err != nil || aClaims.CompanyID != companyA.String() || aClaims.Role != "member" {
		t.Fatalf("A session claims = %+v, err %v; want company A, role member", aClaims, err)
	}
	return svc, jm, sessA, companyA, companyB
}

// TestRefresh_StaysInIssuingCompany: refreshing the company-A session must
// re-mint for A with the A role, never for the user's oldest company B.
func TestRefresh_StaysInIssuingCompany(t *testing.T) {
	svc, jm, sessA, companyA, companyB := ownerOfBMemberOfA(t)

	next, err := svc.RefreshToken(context.Background(), sessA.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	c, err := jm.ValidateAccessToken(next.AccessToken)
	if err != nil {
		t.Fatalf("validate refreshed token: %v", err)
	}
	if c.CompanyID == companyB.String() || c.Role == "owner" {
		t.Fatalf("refresh escalated into company B: company=%s role=%s", c.CompanyID, c.Role)
	}
	if c.CompanyID != companyA.String() || c.Role != "member" {
		t.Errorf("refreshed claims company=%s role=%s, want %s/member", c.CompanyID, c.Role, companyA)
	}
	for _, cid := range c.CompanyIDs {
		if cid == companyB.String() {
			t.Errorf("refreshed CompanyIDs include company B: %v", c.CompanyIDs)
		}
	}
}

// legacyRefresh signs a pre-#80 refresh token (no token_use, no cid) for the
// user and remembers it, as the previous release did at login.
func legacyRefresh(t *testing.T, svc *auth.Service, jm *auth.JWTManager, user auth.User) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.GetSigningMethod("ML-DSA-65"), jwt.MapClaims{
		"sub": user.ID.String(), "iss": "test", "jti": "legacy-" + user.ID.String(),
		"exp": now.Add(7 * 24 * time.Hour).Unix(), "iat": now.Unix(),
	})
	tok.Header["kid"] = jm.ActiveKID()
	s, err := tok.SignedString(jm.ActivePrivateKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := svc.RememberRefreshToken(context.Background(), user.ID, s, now.Add(time.Hour)); err != nil {
		t.Fatalf("remember: %v", err)
	}
	return s
}

// TestRefresh_LegacyTokenMultiMembershipRefused: a pre-#80 refresh token
// names no company. With two memberships the issuing company is unknowable,
// so the refresh is refused rather than guessed (and the token not burned).
func TestRefresh_LegacyTokenMultiMembershipRefused(t *testing.T) {
	svc, jm, sessA, _, _ := ownerOfBMemberOfA(t)
	user := sessA.User
	rt := legacyRefresh(t, svc, jm, user)
	if resp, err := svc.RefreshToken(context.Background(), rt); err == nil {
		c, _ := jm.ValidateAccessToken(resp.AccessToken)
		t.Fatalf("legacy refresh with 2 memberships accepted: company=%s role=%s", c.CompanyID, c.Role)
	}
}

// TestRefresh_LegacyTokenSingleMembership: with exactly one membership the
// company is unambiguous; the legacy token re-mints for it and the rotated
// token is company-bound.
func TestRefresh_LegacyTokenSingleMembership(t *testing.T) {
	svc, _ := setupTenantService(t)
	jm := svc.JWTManagerForTest()
	ctx := context.Background()
	up, err := svc.SignUp(ctx, "solo@example.com", "password123", "Solo")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	upc, _ := jm.ValidateAccessToken(up.AccessToken)
	next, err := svc.RefreshToken(ctx, legacyRefresh(t, svc, jm, up.User))
	if err != nil {
		t.Fatalf("legacy single-membership refresh: %v", err)
	}
	c, _ := jm.ValidateAccessToken(next.AccessToken)
	if c.CompanyID != upc.CompanyID || c.Role != "owner" {
		t.Errorf("company=%s role=%s, want %s/owner", c.CompanyID, c.Role, upc.CompanyID)
	}
	rc, err := jm.ValidateRefreshTokenClaims(next.RefreshToken)
	if err != nil || rc.CompanyID != upc.CompanyID {
		t.Errorf("rotated refresh cid=%q err=%v, want %s", rc.CompanyID, err, upc.CompanyID)
	}
}

// TestRefresh_NotAMemberRefused: a company-bound token for a company the user
// does not (or no longer does) belong to is refused, and not burned.
func TestRefresh_NotAMemberRefused(t *testing.T) {
	svc, _ := setupTenantService(t)
	jm := svc.JWTManagerForTest()
	ctx := context.Background()
	up, err := svc.SignUp(ctx, "nm@example.com", "password123", "NM")
	if err != nil {
		t.Fatalf("SignUp: %v", err)
	}
	rt, err := jm.CreateCompanyRefreshToken(up.User.ID.String(), uuid.New().String())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := svc.RememberRefreshToken(ctx, up.User.ID, rt, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if _, err := svc.RefreshToken(ctx, rt); err == nil {
		t.Fatal("refresh for a non-member company accepted")
	}
}
