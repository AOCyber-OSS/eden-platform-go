package auth_test

import (
	"net/http"
	"reflect"
	"testing"

	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

// 7. Consumer case (#89): eden-biz's AOID console login
// (go/internal/portal/aoid_login.go) runs InitiateOIDC for the AOCyber
// company and completes on the shared /auth/oidc/callback JIT. That company's
// SSOConfig is JITEnabled with EmailDomainAllowlist ["aocyber.ai"]
// (eden-biz cmd/ensure-aocyber-sso). Before #89 any AOID account able to finish
// the flow, e.g. a gmail password account, was JIT-created as an AOCyber
// member.
//
// The allowlist gates CREATION only (SSOConfig docs: "domains this SSOConfig
// admits for JIT"), so an existing member on another domain still signs in.
func TestSSOJITPolicy_AOCyberConsoleLoginAdmitsOnlyAOCyberDomain(t *testing.T) {
	w := newSSOTenantWorld(t)
	aocyber := w.A
	w.setJITPolicy(aocyber, true, "aocyber.ai")

	// alice@gmail.com, no account: refused, no user, no membership.
	w.assertJITRefused(w.loginVia(aocyber, "alice@gmail.com"), "alice@gmail.com")

	// bob@aocyber.ai, no account: created as an AOCyber member only.
	w.assertJITProvisioned(w.loginVia(aocyber, "bob@aocyber.ai"), aocyber, w.B, "bob@aocyber.ai")
	bob, _ := w.store.GetUserByEmail(t.Context(), "bob@aocyber.ai")
	if got := w.loginVia(aocyber, "bob@aocyber.ai"); got.Status != http.StatusOK || got.Claims.UserID != bob.ID.String() {
		t.Errorf("bob's second login = %d, want 200 as the same user", got.Status)
	}

	// Existing AOCyber member on a non-allowed domain: still signs in.
	contractor := w.member(aocyber.ID, "contractor@partner.example", rbac.MemberRoleID)
	got := w.loginVia(aocyber, contractor.Email)
	if got.Status != http.StatusOK || got.Claims.UserID != contractor.ID.String() || got.Claims.CompanyID != aocyber.ID.String() {
		t.Errorf("existing member on a non-allowed domain: status %d, want 200 as that member of AOCyber", got.Status)
	}

	// No oracle: an unknown gmail address and a gmail address that has an
	// account in another tenant are refused identically.
	other := w.member(w.B.ID, "carol@gmail.com", rbac.OwnerRoleID)
	noAccount := observeRefusal(t, w, aocyber, "dave@gmail.com")
	elsewhere := observeRefusal(t, w, aocyber, other.Email)
	if !reflect.DeepEqual(noAccount, elsewhere) {
		t.Errorf("SECURITY (#89): no-account vs account-elsewhere differ:\n%+v\n%+v", noAccount, elsewhere)
	}
	if w.userExists("dave@gmail.com") {
		t.Errorf("SECURITY (#89): an account was created for dave@gmail.com")
	}
	// Wrong tenant: the refusal touched nothing of tenant B's user.
	if w.isMember(aocyber.ID, other.ID) || w.store.refreshTokenIssuedFor(other.ID) {
		t.Errorf("SECURITY: the AOCyber login touched the tenant-B user")
	}
}
