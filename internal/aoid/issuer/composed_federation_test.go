package issuer

// Composed security tests for the integration of #67 (federation SAML
// refuses unverified assertions), #83 (federation JIT tenant scope) and #82
// (typed, client- and company-bound refresh tokens). They drive the real
// federation HTTP surface (/federation/{tenant}/start, /oidc/callback,
// /saml/acs) and the real /oauth2/token endpoint.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"go.aocyber.ai/eden-platform-go/internal/aoid/federation"
	"go.aocyber.ai/eden-platform-go/platform/auth"
)

type fedWorld struct {
	h       *testHarness
	fedSrv  *httptest.Server
	tenantA uuid.UUID
	tenantB uuid.UUID
	oidcIdP uuid.UUID // tenant A's external OIDC IdP
	samlIdP uuid.UUID // tenant A's external SAML IdP, with a signing cert
}

func newFedWorld(t *testing.T) *fedWorld {
	t.Helper()
	h := newHarness(t)
	ctx := t.Context()
	w := &fedWorld{h: h}

	// Tenant A: owner@acme.com signs up and owns it.
	w.tenantA = w.companyOf(t, "owner@acme.com", "Owner A")
	// Tenant B: victim@beta.com signs up and owns it.
	w.tenantB = w.companyOf(t, "victim@beta.com", "Victim B")

	// Tenant A's external IdPs. The JIT policy admits BOTH domains, so a
	// refusal of the B user can only come from the tenant-membership rule
	// (#83), never from the domain allow-list.
	jit := federation.JITPolicy{Enabled: true, DefaultRole: "admin", AllowedDomains: []string{"acme.com", "beta.com"}}
	w.oidcIdP = uuid.New()
	if err := h.svcs.Federation.SPRegistry.Register(ctx, federation.TenantExternalIdP{
		ID: w.oidcIdP, TenantID: w.tenantA, Provider: federation.ProviderOIDC,
		DisplayName: "Acme OIDC", EntityID: "https://idp.acme.test", ClientID: "acme", ClientSecret: "shh",
		JITPolicy: jit, IsActive: true,
	}); err != nil {
		t.Fatalf("register OIDC idp: %v", err)
	}
	w.samlIdP = uuid.New()
	if err := h.svcs.Federation.SPRegistry.Register(ctx, federation.TenantExternalIdP{
		ID: w.samlIdP, TenantID: w.tenantA, Provider: federation.ProviderSAML,
		DisplayName: "Acme SAML", EntityID: "https://saml.acme.test/idp", MetadataURL: "https://saml.acme.test/sso",
		SigningCertificatePEM: selfSignedCertPEM(t),
		JITPolicy:             jit, IsActive: true,
	}); err != nil {
		t.Fatalf("register SAML idp: %v", err)
	}

	mux := http.NewServeMux()
	h.svcs.Federation.Mount(mux)
	w.fedSrv = httptest.NewServer(mux)
	t.Cleanup(w.fedSrv.Close)
	return w
}

func (w *fedWorld) companyOf(t *testing.T, email, name string) uuid.UUID {
	t.Helper()
	up, err := w.h.svcs.Auth.SignUp(t.Context(), email, "password123", name)
	if err != nil {
		t.Fatalf("SignUp(%s): %v", email, err)
	}
	c, err := w.h.svcs.JWTManager.ValidateAccessToken(up.AccessToken)
	if err != nil {
		t.Fatalf("validate signup token: %v", err)
	}
	return uuid.MustParse(c.CompanyID)
}

// start runs /federation/{A}/start and returns the signed state the
// redirect carries (OIDC: state, SAML: RelayState).
func (w *fedWorld) start(t *testing.T, idpID uuid.UUID, param string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Get(w.fedSrv.URL + "/federation/" + w.tenantA.String() + "/start?external_idp_id=" + idpID.String())
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("start: status %d %q, want 302", res.StatusCode, b)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatalf("start Location: %v", err)
	}
	state := loc.Query().Get(param)
	if state == "" {
		t.Fatalf("start Location %q carries no %s", loc, param)
	}
	return state
}

type fedTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func decodeFed(t *testing.T, res *http.Response) (int, fedTokens, string) {
	t.Helper()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var tok fedTokens
	_ = json.Unmarshal(b, &tok)
	return res.StatusCode, tok, string(b)
}

// oidcLogin completes a federation OIDC login via tenant A's IdP, the IdP
// asserting email.
func (w *fedWorld) oidcLogin(t *testing.T, email string) (int, fedTokens, string) {
	t.Helper()
	w.h.svcs.Federation.Exchanger = &federation.StubOIDCExchanger{FixedAssertion: &federation.Assertion{
		Subject: "sub-" + email, Email: email, DisplayName: "Asserted",
		Attributes: map[string][]string{}, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(5 * time.Minute),
		AuthnContext: "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract",
	}}
	state := w.start(t, w.oidcIdP, "state")
	res, err := http.Get(w.fedSrv.URL + "/federation/" + w.tenantA.String() + "/oidc/callback?code=fixture&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("oidc callback: %v", err)
	}
	return decodeFed(t, res)
}

func (w *fedWorld) isMember(t *testing.T, company uuid.UUID, email string) bool {
	t.Helper()
	u, err := w.h.svcs.Auth.GetUserByEmail(t.Context(), email)
	if err != nil {
		return false
	}
	_, err = w.h.svcs.Auth.GetUserRole(t.Context(), company, u.ID)
	return err == nil
}

// TestComposed_FederationTenantScopeAndRefreshAtTokenEndpoint: #83 + #82
// through the real HTTP seams.
func TestComposed_FederationTenantScopeAndRefreshAtTokenEndpoint(t *testing.T) {
	w := newFedWorld(t)
	jm := w.h.svcs.JWTManager

	// 1. #83: tenant A's IdP asserting a tenant-B owner is refused with a
	// 403 (a policy refusal, not a server fault), no tokens, and the
	// victim is not added to A.
	status, tok, body := w.oidcLogin(t, "victim@beta.com")
	if status != http.StatusForbidden {
		t.Errorf("cross-tenant federation login: status %d (%q), want 403", status, body)
	}
	if tok.AccessToken != "" || tok.RefreshToken != "" {
		t.Fatalf("SECURITY (#74): cross-tenant federation login returned tokens")
	}
	if w.isMember(t, w.tenantA, "victim@beta.com") {
		t.Fatal("SECURITY (#74): the tenant-B user was added to tenant A")
	}

	// 2. A's own member signs in; the bridge refresh token is typed,
	// bound to A, and marked as a federation token.
	status, tok, body = w.oidcLogin(t, "owner@acme.com")
	if status != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("member federation login: status %d (%q), want 200 with tokens", status, body)
	}
	rc, err := jm.ValidateRefreshTokenClaims(tok.RefreshToken)
	if err != nil {
		t.Fatalf("bridge refresh token: %v", err)
	}
	if rc.TokenUse != auth.TokenUseRefresh || rc.CompanyID != w.tenantA.String() {
		t.Fatalf("bridge refresh = token_use %q cid %q, want refresh / tenant A", rc.TokenUse, rc.CompanyID)
	}
	if len(rc.Audience) != 1 || rc.Audience[0] != auth.FederationRefreshAudience {
		t.Fatalf("bridge refresh aud = %v, want [%s]", rc.Audience, auth.FederationRefreshAudience)
	}
	ac, err := jm.ValidateAccessToken(tok.AccessToken)
	if err != nil || ac.CompanyID != w.tenantA.String() || ac.Role != "owner" {
		t.Fatalf("member access = %+v (%v), want tenant A with the member's own role (owner), not the JIT default", ac, err)
	}

	// 3. #82: the refresh is redeemable at /oauth2/token, stays in A, and
	// the rotated token is typed, bound to A AND to the redeeming client.
	st, tr := w.h.postToken(t, refreshForm(tok.RefreshToken), w.h.client, w.h.secret)
	if st != http.StatusOK {
		t.Fatalf("federation refresh at /oauth2/token: status %d error %q, want 200", st, tr.Error)
	}
	c, err := jm.ValidateAccessToken(tr.AccessToken)
	if err != nil || c.CompanyID != w.tenantA.String() || c.Role != "owner" {
		t.Fatalf("refreshed access = %+v (%v), want tenant A / owner", c, err)
	}
	if c.CompanyID == w.tenantB.String() {
		t.Fatal("SECURITY (#82): refresh moved into tenant B")
	}
	rc2, err := jm.ValidateRefreshTokenClaims(tr.RefreshToken)
	if err != nil {
		t.Fatalf("rotated refresh: %v", err)
	}
	if rc2.TokenUse != auth.TokenUseRefresh || rc2.CompanyID != w.tenantA.String() || len(rc2.Audience) != 1 || rc2.Audience[0] != w.h.client {
		t.Fatalf("rotated refresh = use %q cid %q aud %v, want refresh / A / [%s]", rc2.TokenUse, rc2.CompanyID, rc2.Audience, w.h.client)
	}
	// The consumed bridge token is single-use.
	if st, _ := w.h.postToken(t, refreshForm(tok.RefreshToken), w.h.client, w.h.secret); st == http.StatusOK {
		t.Fatal("SECURITY (#82): the bridge refresh token was redeemable twice")
	}
}

// TestComposed_FederationSAMLWithoutValidSignatureIsRefused: #67 + #83.
// An unsigned SAML response asserting a real member of tenant A, with a
// valid RelayState, through /saml/acs mints nothing.
func TestComposed_FederationSAMLWithoutValidSignatureIsRefused(t *testing.T) {
	w := newFedWorld(t)
	for name, email := range map[string]string{
		"asserting A's own member":    "owner@acme.com",
		"asserting a tenant-B member": "victim@beta.com",
		"asserting a brand-new user":  "newcomer@acme.com",
	} {
		t.Run(name, func(t *testing.T) {
			relay := w.start(t, w.samlIdP, "RelayState")
			form := url.Values{"SAMLResponse": {unsignedSAMLResponse(email)}, "RelayState": {relay}}
			res, err := http.PostForm(w.fedSrv.URL+"/federation/"+w.tenantA.String()+"/saml/acs", form)
			if err != nil {
				t.Fatalf("POST acs: %v", err)
			}
			status, tok, body := decodeFed(t, res)
			if status == http.StatusOK || tok.AccessToken != "" || tok.RefreshToken != "" {
				t.Fatalf("SECURITY (#67): unsigned SAML for %s accepted: status %d, tokens returned=%t", email, status, tok.AccessToken != "" || tok.RefreshToken != "")
			}
			if status != http.StatusBadRequest {
				t.Errorf("status %d (%q), want 400", status, body)
			}
			if email == "newcomer@acme.com" {
				if _, err := w.h.svcs.Auth.GetUserByEmail(t.Context(), email); err == nil {
					t.Error("SECURITY (#67): an unsigned assertion JIT-created an account")
				}
			}
		})
	}
}

// unsignedSAMLResponse is a well-formed SAML 2.0 Response with no
// signature on the Response or the Assertion.
func unsignedSAMLResponse(email string) string {
	now := time.Now().UTC()
	ts := now.Format(time.RFC3339)
	xml := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="` + ts + `">` +
		`<saml:Issuer>https://saml.acme.test/idp</saml:Issuer>` +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`<saml:Assertion ID="_a1" Version="2.0" IssueInstant="` + ts + `">` +
		`<saml:Issuer>https://saml.acme.test/idp</saml:Issuer>` +
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + email + `</saml:NameID></saml:Subject>` +
		`<saml:Conditions NotBefore="` + now.Add(-time.Minute).Format(time.RFC3339) + `" NotOnOrAfter="` + now.Add(5*time.Minute).Format(time.RFC3339) + `"/>` +
		`<saml:AuthnStatement AuthnInstant="` + ts + `"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorContract</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
		`<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>` + email + `</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
		`</saml:Assertion></samlp:Response>`
	return base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(xml)))
}

func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "saml.acme.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
