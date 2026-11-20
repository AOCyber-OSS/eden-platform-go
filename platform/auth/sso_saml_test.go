package auth_test

// Issue #87: SSOService's SAML SP (InitiateSAML + POST /auth/saml/acs) moves
// to the gosaml2-backed verifier. These tests drive the real HTTP seam with a
// tenant IdP served over TLS (metadata from the in-repo saml/idp toolkit)
// and responses that toolkit signs. They run unchanged against the previous
// and the new verifier.
//
// Test list:
//   - InitiateSAML redirects to the IdP's HTTP-Redirect SSO endpoint with a
//     DEFLATE-encoded AuthnRequest naming this SP (issuer, ACS, destination)
//   - ACS: the service tracks no AuthnRequest IDs, so it refuses every
//     response: unsolicited, one naming a request ID, unsigned, and tenant A's
//     response posted with tenant B's RelayState; no account is created
//   - the metadata fetch for ACS still goes through the egress guard

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"go.aocyber.ai/eden-platform-go/platform/auth"
	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
	"go.aocyber.ai/eden-platform-go/platform/auth/saml/idp"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
)

const (
	ssoSPBase     = "https://sp.example.com"
	ssoSPEntityID = ssoSPBase + "/auth/saml/metadata"
	ssoSPACS      = ssoSPBase + "/auth/saml/acs"
)

// samlTenantIdP is one tenant's upstream IdP, serving its metadata over TLS.
type samlTenantIdP struct {
	srv    *httptest.Server
	issuer *idp.IdentityProvider
	key    *platsaml.SigningKey
}

func newSAMLTenantIdP(t *testing.T, name string) *samlTenantIdP {
	t.Helper()
	key, err := platsaml.GenerateSigningKey(name+"-idp", time.Hour)
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	ti := &samlTenantIdP{key: key}
	ti.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata" {
			http.NotFound(w, r)
			return
		}
		raw, err := ti.issuer.Metadata()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(ti.srv.Close)
	ti.issuer, err = idp.New(idp.Config{
		EntityID:          ti.srv.URL + "/idp/" + name,
		SSOURL:            ti.srv.URL + "/sso",
		CurrentKey:        key,
		AssertionLifetime: 5 * time.Minute,
		AllowedSPs: map[string]idp.SPRegistration{
			ssoSPEntityID: {EntityID: ssoSPEntityID, ACSURL: ssoSPACS},
		},
	})
	if err != nil {
		t.Fatalf("idp.New: %v", err)
	}
	return ti
}

func (ti *samlTenantIdP) mint(t *testing.T, email string, in idp.AssertionInput) string {
	t.Helper()
	in.SPEntityID = ssoSPEntityID
	in.NameID = email
	in.Attributes = map[string][]string{"email": {email}, "displayName": {"Test User"}}
	raw, err := ti.issuer.IssueAssertion(in)
	if err != nil {
		t.Fatalf("IssueAssertion: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// newSAMLSSO builds the service with tenants' IdPs reachable through the
// egress guard (loopback allow-listed, the IdPs' TLS roots trusted).
func newSAMLSSO(t *testing.T, tenants ...*samlTenantIdP) (*auth.SSOService, *devstore.Backend, map[*samlTenantIdP]uuid.UUID) {
	t.Helper()
	svc, backend := newEgressSSOService(t)
	pool := x509.NewCertPool()
	for _, ti := range tenants {
		pool.AddCert(ti.srv.Certificate())
	}
	svc.SetEgressForTest(func(h string) bool { return h == "127.0.0.1" }, false, pool, nil)
	ids := map[*samlTenantIdP]uuid.UUID{}
	for _, ti := range tenants {
		company := uuid.New()
		backend.SetSSOConfig(company, "saml", auth.SSOConfig{CompanyID: company, Provider: "saml", MetadataURL: ti.srv.URL + "/metadata", IsActive: true})
		ids[ti] = company
	}
	return svc, backend, ids
}

func postACS(t *testing.T, svc *auth.SSOService, relayState, samlResponse string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	svc.RegisterHTTPHandlers(mux)
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	req := httptest.NewRequest(http.MethodPost, ssoSPACS, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestSSOSAML_InitiateRedirectsWithAcceptableAuthnRequest(t *testing.T) {
	ti := newSAMLTenantIdP(t, "acme")
	svc, _, ids := newSAMLSSO(t, ti)

	redirect, err := svc.InitiateSAML(fetchCtx(t), ids[ti])
	if err != nil {
		t.Fatalf("InitiateSAML: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != ti.srv.URL+"/sso" {
		t.Fatalf("redirect target = %q, want the IdP SSO endpoint", got)
	}
	// HTTP-Redirect binding: base64 of raw DEFLATE.
	deflated, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("SAMLRequest base64: %v", err)
	}
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatalf("SAMLRequest inflate: %v", err)
	}
	var req struct {
		XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
		ID      string   `xml:"ID,attr"`
		ACS     string   `xml:"AssertionConsumerServiceURL,attr"`
		Dest    string   `xml:"Destination,attr"`
		Issuer  string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	}
	if err := xml.Unmarshal(inflated, &req); err != nil {
		t.Fatalf("AuthnRequest: %v\n%s", err, inflated)
	}
	if req.ID == "" || req.Issuer != ssoSPEntityID || req.ACS != ssoSPACS || req.Dest != ti.srv.URL+"/sso" {
		t.Fatalf("AuthnRequest = %+v", req)
	}
}

func TestSSOSAML_ACSRefusesResponsesItCannotBindToARequest(t *testing.T) {
	a := newSAMLTenantIdP(t, "tenant-a")
	b := newSAMLTenantIdP(t, "tenant-b")
	svc, backend, ids := newSAMLSSO(t, a, b)
	const email = "alice@tenant-a.example.com"

	unsigned := func() string {
		raw, _ := base64.StdEncoding.DecodeString(a.mint(t, email, idp.AssertionInput{}))
		s := string(raw)
		i, j := strings.Index(s, "<ds:Signature"), strings.Index(s, "</ds:Signature>")
		if i < 0 || j < 0 {
			t.Fatal("fixture has no signature to strip")
		}
		return base64.StdEncoding.EncodeToString([]byte(s[:i] + s[j+len("</ds:Signature>"):]))
	}

	cases := map[string]struct {
		relay uuid.UUID
		resp  string
	}{
		"unsolicited, own tenant":            {ids[a], a.mint(t, email, idp.AssertionInput{})},
		"names a request ID, own tenant":     {ids[a], a.mint(t, email, idp.AssertionInput{InResponseTo: "_guessed"})},
		"unsigned, own tenant":               {ids[a], unsigned()},
		"tenant A response at tenant B":      {ids[b], a.mint(t, email, idp.AssertionInput{})},
		"tenant A request-bound at tenant B": {ids[b], a.mint(t, email, idp.AssertionInput{InResponseTo: "_guessed"})},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := postACS(t, svc, tc.relay.String(), tc.resp)
			if rec.Code == http.StatusOK {
				t.Fatalf("ACS accepted the response: %d %s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "access_token") {
				t.Fatal("ACS issued a token")
			}
			if _, err := backend.AuthStore().GetUserByEmail(context.Background(), email); err == nil {
				t.Fatal("ACS created an account")
			}
		})
	}
}

func TestSSOSAML_ACSMetadataFetchIsEgressGuarded(t *testing.T) {
	ti := newSAMLTenantIdP(t, "acme")
	svc, backend := newEgressSSOService(t) // production egress policy: loopback refused
	company := uuid.New()
	backend.SetSSOConfig(company, "saml", auth.SSOConfig{CompanyID: company, Provider: "saml", MetadataURL: ti.srv.URL + "/metadata", IsActive: true})

	form := url.Values{"SAMLResponse": {ti.mint(t, "x@acme.example.com", idp.AssertionInput{})}}
	req := httptest.NewRequest(http.MethodPost, ssoSPACS, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := svc.HandleSAMLCallback(req, company)
	requireBlocked(t, err)
}
