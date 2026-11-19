package auth_test

// Issue #89: after #74, SSO JIT provisioning still ignored the asserting
// tenant's own SSOConfig policy (JITEnabled, EmailDomainAllowlist), so a
// tenant's IdP could create an account for any address inside that tenant,
// and the 403-vs-provision difference told it whether an address already had
// an account elsewhere.
//
// Policy semantics under test (SSOConfig docs, platform/auth/store.go):
//   - JITEnabled=false denies JIT. Existing members still sign in.
//   - EmailDomainAllowlist is fail-secure: an empty list admits nothing.
//   - A domain matches exactly, case-insensitively. No subdomain wildcard:
//     "example.com" does not admit "eng.example.com".
//
// Same harness as sso_tenant_scope_test.go: real HTTP callback, fake OP.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/rbac"
)

// setJITPolicy rewrites ten's OIDC SSOConfig JIT policy, keeping the rest.
func (w *ssoTenantWorld) setJITPolicy(ten tenant, enabled bool, domains ...string) {
	w.t.Helper()
	ctx := context.Background()
	cfg, err := w.store.GetSSOConfig(ctx, ten.ID, "oidc")
	if err != nil {
		w.t.Fatalf("GetSSOConfig: %v", err)
	}
	cfg.JITEnabled = enabled
	cfg.EmailDomainAllowlist = domains
	if err := w.store.UpsertSSOConfig(ctx, cfg); err != nil {
		w.t.Fatalf("UpsertSSOConfig: %v", err)
	}
}

func (w *ssoTenantWorld) userExists(email string) bool {
	_, err := w.store.GetUserByEmail(context.Background(), email)
	return err == nil
}

// assertJITRefused checks a refused JIT login: 403, no tokens, no account.
func (w *ssoTenantWorld) assertJITRefused(got ssoLogin, email string) {
	w.t.Helper()
	if got.Status != http.StatusForbidden {
		w.t.Errorf("status = %d, want 403", got.Status)
	}
	if got.AccessToken != "" || got.RefreshToken != "" {
		w.t.Errorf("a refused login returned tokens")
	}
	if w.userExists(email) {
		w.t.Errorf("SECURITY (#89): an account was created for %q", email)
	}
}

func (w *ssoTenantWorld) assertJITProvisioned(got ssoLogin, ten, other tenant, email string) {
	w.t.Helper()
	if got.Status != http.StatusOK {
		w.t.Fatalf("status = %d, want 200", got.Status)
	}
	u, err := w.store.GetUserByEmail(context.Background(), email)
	if err != nil {
		w.t.Fatalf("JIT user %q not created: %v", email, err)
	}
	if !w.isMember(ten.ID, u.ID) {
		w.t.Errorf("JIT user is not a member of the asserting tenant")
	}
	if w.isMember(other.ID, u.ID) {
		w.t.Errorf("SECURITY: JIT user leaked into the other tenant")
	}
}

// 1. JIT disabled: an unknown email is refused and no account is created.
func TestSSOJITPolicy_DisabledRefusesUnknownEmail(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.setJITPolicy(w.A, false, "tenant-a.example")

	w.assertJITRefused(w.loginVia(w.A, "newhire@tenant-a.example"), "newhire@tenant-a.example")

	// Wrong tenant: B (JIT on for its own domain) is unaffected by A's switch.
	w.assertJITProvisioned(w.loginVia(w.B, "newhire@tenant-b.example"), w.B, w.A, "newhire@tenant-b.example")
}

// 1b. JIT disabled: an existing member still signs in.
func TestSSOJITPolicy_DisabledStillSignsInExistingMember(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.setJITPolicy(w.A, false)
	alice := w.member(w.A.ID, "alice@tenant-a.example", rbac.AdminRoleID)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	got := w.loginVia(w.A, alice.Email)

	if got.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", got.Status)
	}
	if got.Claims.UserID != alice.ID.String() || got.Claims.CompanyID != w.A.ID.String() {
		t.Errorf("claims = %s/%s, want alice in tenant A", got.Claims.UserID, got.Claims.CompanyID)
	}
	if w.isMember(w.A.ID, victim.ID) || w.store.refreshTokenIssuedFor(victim.ID) {
		t.Errorf("SECURITY: tenant A's login touched the tenant-B user")
	}
}

// 2. In-domain unknown email is created; out-of-domain is refused.
func TestSSOJITPolicy_AllowlistAdmitsOnlyListedDomains(t *testing.T) {
	w := newSSOTenantWorld(t)

	w.assertJITProvisioned(w.loginVia(w.A, "newhire@tenant-a.example"), w.A, w.B, "newhire@tenant-a.example")
	w.assertJITRefused(w.loginVia(w.A, "squat@unclaimed.example"), "squat@unclaimed.example")
	// Wrong tenant: A's IdP cannot JIT into B's domain.
	w.assertJITRefused(w.loginVia(w.A, "squat@tenant-b.example"), "squat@tenant-b.example")
}

// 3. Domain match is case-insensitive on both sides and exact otherwise.
func TestSSOJITPolicy_DomainMatchRules(t *testing.T) {
	for _, tc := range []struct {
		name    string
		domains []string
		email   string
		admit   bool
	}{
		{"email domain upper case", []string{"tenant-a.example"}, "Mixed@TENANT-A.Example", true},
		{"allowlist entry upper case and padded", []string{"  Tenant-A.EXAMPLE "}, "x@tenant-a.example", true},
		{"subdomain is not admitted by parent", []string{"tenant-a.example"}, "x@eng.tenant-a.example", false},
		{"parent is not admitted by subdomain", []string{"eng.tenant-a.example"}, "x@tenant-a.example", false},
		{"suffix lookalike", []string{"tenant-a.example"}, "x@eviltenant-a.example", false},
		{"second @ smuggles a listed domain", []string{"tenant-a.example"}, "x@evil.example@tenant-a.example", false},
		{"empty local part", []string{"tenant-a.example"}, "@tenant-a.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newSSOTenantWorld(t)
			w.setJITPolicy(w.A, true, tc.domains...)
			got := w.loginVia(w.A, tc.email)
			if tc.admit {
				w.assertJITProvisioned(got, w.A, w.B, tc.email)
			} else {
				w.assertJITRefused(got, tc.email)
			}
		})
	}
}

// 4. Empty allowlist with JIT enabled admits nothing (fail-secure, per docs).
func TestSSOJITPolicy_EmptyAllowlistAdmitsNothing(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.setJITPolicy(w.A, true)

	w.assertJITRefused(w.loginVia(w.A, "newhire@tenant-a.example"), "newhire@tenant-a.example")
	// Wrong tenant: B keeps its own allowlist.
	w.assertJITProvisioned(w.loginVia(w.B, "newhire@tenant-b.example"), w.B, w.A, "newhire@tenant-b.example")
}

// 5. Wrong tenant: A's config never governs B's sign-in, either direction.
func TestSSOJITPolicy_PolicyIsTheAssertingTenantsOwn(t *testing.T) {
	w := newSSOTenantWorld(t)
	w.setJITPolicy(w.A, true, "shared.example")
	w.setJITPolicy(w.B, false, "shared.example")

	// B has JIT off: A's permissive policy for the same domain does not apply.
	w.assertJITRefused(w.loginVia(w.B, "one@shared.example"), "one@shared.example")
	// A has JIT on for the domain: A provisions, into A only.
	w.assertJITProvisioned(w.loginVia(w.A, "two@shared.example"), w.A, w.B, "two@shared.example")
}

// refusal is everything about a refused login the asserting tenant can see.
type refusal struct {
	Status      int
	Body        string
	ContentType string
	Err         string
	Audit       map[string]any
}

func observeRefusal(t *testing.T, w *ssoTenantWorld, ten tenant, email string) refusal {
	t.Helper()
	ten.IdP.email = email
	ten.IdP.name = "Asserted Name"
	before := len(w.store.auditsWithAction("auth.sso.login_refused"))

	_, state, err := w.svc.InitiateOIDC(context.Background(), ten.ID, "oidc", "json")
	if err != nil {
		t.Fatalf("InitiateOIDC: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback?code=fixture-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()
	w.mux.ServeHTTP(rec, req)

	_, state, err = w.svc.InitiateOIDC(context.Background(), ten.ID, "oidc", "json")
	if err != nil {
		t.Fatalf("InitiateOIDC: %v", err)
	}
	_, _, svcErr := w.svc.HandleOIDCCallbackWithState(context.Background(), "fixture-code", state)
	if !errors.Is(svcErr, auth.ErrSSOLoginRefused) || !errors.Is(svcErr, auth.ErrSSOEmailNotMember) {
		t.Errorf("%q: err = %v, want ErrSSOLoginRefused (== ErrSSOEmailNotMember)", email, svcErr)
	}

	audits := w.store.auditsWithAction("auth.sso.login_refused")
	if len(audits) != before+2 {
		t.Fatalf("%q: got %d new refusal audits, want 2", email, len(audits)-before)
	}
	errText := ""
	if svcErr != nil {
		errText = svcErr.Error()
	}
	return refusal{
		Status:      rec.Code,
		Body:        rec.Body.String(),
		ContentType: rec.Header().Get("Content-Type"),
		Err:         errText,
		Audit:       audits[len(audits)-1].Details,
	}
}

// 6. No enumeration oracle: the asserting IdP (and its tenant's audit log)
// sees the same refusal whether the email belongs to another tenant's
// account, is outside the allowlist, or JIT is off.
func TestSSOJITPolicy_RefusalsAreIndistinguishable(t *testing.T) {
	w := newSSOTenantWorld(t)
	victim := w.member(w.B.ID, "victim@tenant-b.example", rbac.OwnerRoleID)

	existsElsewhere := observeRefusal(t, w, w.A, victim.Email)
	outOfDomain := observeRefusal(t, w, w.A, "nobody@tenant-b.example")
	w.setJITPolicy(w.A, false, "tenant-a.example")
	jitOff := observeRefusal(t, w, w.A, "nobody@tenant-a.example")

	if existsElsewhere.Status != http.StatusForbidden {
		t.Errorf("status = %d, want 403", existsElsewhere.Status)
	}
	if !reflect.DeepEqual(existsElsewhere, outOfDomain) {
		t.Errorf("SECURITY (#89): exists-elsewhere vs out-of-domain differ:\n%+v\n%+v", existsElsewhere, outOfDomain)
	}
	if !reflect.DeepEqual(existsElsewhere, jitOff) {
		t.Errorf("SECURITY (#89): exists-elsewhere vs JIT-disabled differ:\n%+v\n%+v", existsElsewhere, jitOff)
	}
	// Wrong tenant: none of this touched B's account or B's audit trail.
	if w.isMember(w.A.ID, victim.ID) || w.store.refreshTokenIssuedFor(victim.ID) {
		t.Errorf("SECURITY: refused logins touched the tenant-B user")
	}
	for _, a := range w.store.auditsWithAction("auth.sso.login_refused") {
		if a.CompanyID != w.A.ID {
			t.Errorf("refusal audited against %s, want only the asserting tenant A", a.CompanyID)
		}
	}
}
