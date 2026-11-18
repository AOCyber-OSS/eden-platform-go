package auth_test

// Composed security tests for the integration of #82 (typed, company-bound
// refresh tokens), #83 (SSO JIT tenant scope) and #85 (SSO egress policy).
// Each asserts a property that only holds with all of them merged: the SSO
// login runs a real OIDC discovery + callback against each tenant's own IdP
// through the egress client (#85), the tenant rule decides who gets tokens
// (#83), and the refresh token those logins mint stays in the asserting
// tenant and is typed (#82).

import (
	"context"
	"net/http"
	"testing"

	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

func TestComposed_SSOTenantScopeAndRefreshStayInAssertingTenant(t *testing.T) {
	w := newSSOTenantWorld(t)
	ctx := context.Background()
	// The same backing store the SSO service writes to (the recording
	// wrapper only observes writes).
	txStore, ok := w.store.AuthStore.(auth.TxAuthStore)
	if !ok {
		t.Fatal("devstore AuthStore is not a TxAuthStore")
	}
	svc := auth.NewService(txStore, w.jwt, auth.NewPasswordHasher())

	// 1. #83: tenant A's IdP asserting the email of a tenant-B member is
	// refused: 403, no tokens, not added to A, no stored refresh token.
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)
	w.assertRefused(w.loginVia(w.A, victim.Email), w.A, victim)

	// 2. A legitimate A member who OWNS B, where B is the OLDEST membership
	// (the company the pre-#82 refresh re-minted into).
	both := w.userWithoutCompany("both@shared.example")
	if err := w.store.CreateCompanyMembership(ctx, w.B.ID, both.ID, rbac.OwnerRoleID); err != nil {
		t.Fatalf("membership B: %v", err)
	}
	if err := w.store.CreateCompanyMembership(ctx, w.A.ID, both.ID, rbac.MemberRoleID); err != nil {
		t.Fatalf("membership A: %v", err)
	}
	login := w.loginVia(w.A, both.Email)
	if login.Status != http.StatusOK {
		t.Fatalf("member login via A: status %d, want 200", login.Status)
	}
	if login.Claims.CompanyID != w.A.ID.String() || login.Claims.Role != "member" {
		t.Fatalf("login claims = %s/%s, want A/member", login.Claims.CompanyID, login.Claims.Role)
	}

	// 3. #82: the SSO refresh token is typed and bound to A.
	requireRefreshInCompany(t, w.jwt, login.RefreshToken, w.A.ID.String())
	// ...and type confusion is refused both ways.
	if _, err := w.jwt.ValidateAccessToken(login.RefreshToken); err == nil {
		t.Error("SECURITY (#80): the SSO refresh token was accepted as an access token")
	}
	if _, err := w.jwt.ValidateRefreshTokenClaims(login.AccessToken); err == nil {
		t.Error("SECURITY (#80): the SSO access token was accepted as a refresh token")
	}

	// 4. Refresh stays in A with the A role — twice, so the rotated token
	// carries the binding forward.
	rt := login.RefreshToken
	for hop := 1; hop <= 2; hop++ {
		next, err := svc.RefreshToken(ctx, rt)
		if err != nil {
			t.Fatalf("hop %d: RefreshToken: %v", hop, err)
		}
		c, err := w.jwt.ValidateAccessToken(next.AccessToken)
		if err != nil {
			t.Fatalf("hop %d: validate access: %v", hop, err)
		}
		if c.CompanyID != w.A.ID.String() || c.Role != "member" {
			t.Fatalf("SECURITY (#82): hop %d re-minted into %s/%s, want tenant A/member (B is %s)", hop, c.CompanyID, c.Role, w.B.ID)
		}
		if len(c.CompanyIDs) != 1 || c.CompanyIDs[0] != w.A.ID.String() {
			t.Fatalf("hop %d: company ids = %v, want only A", hop, c.CompanyIDs)
		}
		requireRefreshInCompany(t, w.jwt, next.RefreshToken, w.A.ID.String())
		rt = next.RefreshToken
	}

	// 5. The victim's B membership is untouched and they are still not in A.
	if !w.isMember(w.B.ID, victim.ID) || w.isMember(w.A.ID, victim.ID) {
		t.Error("victim memberships changed")
	}
}

func requireRefreshInCompany(t *testing.T, jm *auth.JWTManager, refresh, companyID string) {
	t.Helper()
	rc, err := jm.ValidateRefreshTokenClaims(refresh)
	if err != nil {
		t.Fatalf("ValidateRefreshTokenClaims: %v", err)
	}
	if rc.TokenUse != auth.TokenUseRefresh {
		t.Errorf("refresh token_use = %q, want %q", rc.TokenUse, auth.TokenUseRefresh)
	}
	if rc.CompanyID != companyID {
		t.Errorf("SECURITY (#82): refresh cid = %q, want %q", rc.CompanyID, companyID)
	}
}
