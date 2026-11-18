package auth_test

// Issue #85: the SAML IdP metadata fetch and OIDC discovery fetch
// tenant-controlled URLs (SSOConfig.MetadataURL / IssuerURL, editable by a
// tenant admin). Both must go through the platform/netguard egress policy:
// https only, no loopback / RFC1918 / link-local / metadata destinations, the
// connected address re-checked at dial, and every redirect hop re-checked.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"go.aocyber.ai/eden-platform-go/platform/auth"
	"go.aocyber.ai/eden-platform-go/platform/devstore"
	"go.aocyber.ai/eden-platform-go/platform/netguard"
)

// egressResolver is a hand-built stub resolver: host -> fixed IPs.
type egressResolver map[string][]string

func (r egressResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(ips))
	for _, s := range ips {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out, nil
}

// idpMetadataXML is a minimal SAML IdP EntityDescriptor that crewjam/saml
// can build an AuthnRequest from.
func idpMetadataXML(base string) string {
	return fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%[1]s/idp">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%[1]s/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, base)
}

// fakeIdP serves both SAML metadata (/metadata) and OIDC discovery
// (/.well-known/openid-configuration) and counts every request it gets, so
// a refusal can be proven to have happened before any connection.
type fakeIdP struct {
	srv  *httptest.Server
	hits atomic.Int32
	// redirectTo, when set, makes every request a 302 to this URL.
	redirectTo string
}

func newFakeIdP(t *testing.T, useTLS bool) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.hits.Add(1)
		if idp.redirectTo != "" {
			http.Redirect(w, r, idp.redirectTo+r.URL.Path, http.StatusFound)
			return
		}
		base := idp.srv.URL
		switch r.URL.Path {
		case "/metadata":
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			_, _ = w.Write([]byte(idpMetadataXML(base)))
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                base,
				"authorization_endpoint":                base + "/auth",
				"token_endpoint":                        base + "/token",
				"jwks_uri":                              base + "/jwks",
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
			})
		default:
			http.NotFound(w, r)
		}
	})
	if useTLS {
		idp.srv = httptest.NewTLSServer(h)
	} else {
		idp.srv = httptest.NewServer(h)
	}
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) port(t *testing.T) string {
	t.Helper()
	_, p, err := net.SplitHostPort(idp.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (idp *fakeIdP) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(idp.srv.Certificate())
	return pool
}

// ssoFetch drives the tenant-controlled fetch for one protocol: SAML through
// InitiateSAML (metadata fetch), OIDC through InitiateOIDC (discovery).
type ssoFetch func(ctx context.Context, t *testing.T, svc *auth.SSOService, backend *devstore.Backend, rawURL string) error

var ssoFetches = map[string]ssoFetch{
	"saml": func(ctx context.Context, t *testing.T, svc *auth.SSOService, backend *devstore.Backend, rawURL string) error {
		company := uuid.New()
		backend.SetSSOConfig(company, "saml", auth.SSOConfig{CompanyID: company, Provider: "saml", MetadataURL: rawURL + "/metadata", IsActive: true})
		redirect, err := svc.InitiateSAML(ctx, company)
		if err == nil && redirect == "" {
			t.Fatal("InitiateSAML returned no error and no redirect")
		}
		return err
	},
	"oidc": func(ctx context.Context, t *testing.T, svc *auth.SSOService, backend *devstore.Backend, rawURL string) error {
		company := uuid.New()
		backend.SetSSOConfig(company, "oidc", auth.SSOConfig{CompanyID: company, Provider: "oidc", IssuerURL: rawURL, ClientID: "c", ClientSecret: "s", IsActive: true})
		authURL, _, err := svc.InitiateOIDC(ctx, company, "oidc", "https://app.example.com/cb")
		if err == nil && authURL == "" {
			t.Fatal("InitiateOIDC returned no error and no auth URL")
		}
		return err
	},
}

func newEgressSSOService(t *testing.T) (*auth.SSOService, *devstore.Backend) {
	t.Helper()
	backend := devstore.NewMemoryBackend()
	jm, err := auth.NewJWTManager(auth.JWTConfig{Issuer: "test", AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour})
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}
	return auth.NewSSOService(backend.AuthStore(), jm, "https://sp.example.com"), backend
}

func requireBlocked(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("fetch succeeded; want refusal by the egress policy")
	}
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Fatalf("err = %v; want it to wrap netguard.ErrBlocked", err)
	}
}

func fetchCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// Refusals use the PRODUCTION egress policy (no test hook): only the
// resolver is stubbed where a hostname is needed.
func TestSSOEgress_RefusesInternalDestinations(t *testing.T) {
	for proto, fetch := range ssoFetches {
		t.Run(proto, func(t *testing.T) {
			t.Run("loopback literal, server never reached", func(t *testing.T) {
				idp := newFakeIdP(t, true)
				svc, backend := newEgressSSOService(t)
				requireBlocked(t, fetch(fetchCtx(t), t, svc, backend, idp.srv.URL))
				if n := idp.hits.Load(); n != 0 {
					t.Fatalf("loopback IdP got %d requests; want 0", n)
				}
			})
			t.Run("plain http is refused", func(t *testing.T) {
				idp := newFakeIdP(t, false)
				svc, backend := newEgressSSOService(t)
				requireBlocked(t, fetch(fetchCtx(t), t, svc, backend, idp.srv.URL))
				if n := idp.hits.Load(); n != 0 {
					t.Fatalf("http IdP got %d requests; want 0", n)
				}
			})
			for name, u := range map[string]string{
				"RFC1918 10/8":        "https://10.0.0.1",
				"RFC1918 192.168/16":  "https://192.168.1.10",
				"cloud metadata IP":   "https://169.254.169.254",
				"IPv6 loopback":       "https://[::1]",
				"v4-mapped metadata":  "https://[::ffff:169.254.169.254]",
				"localhost name":      "https://localhost",
				"metadata name (GCP)": "https://metadata.google.internal",
			} {
				t.Run(name, func(t *testing.T) {
					svc, backend := newEgressSSOService(t)
					requireBlocked(t, fetch(fetchCtx(t), t, svc, backend, u))
				})
			}
			t.Run("hostname resolving to loopback, server never reached", func(t *testing.T) {
				idp := newFakeIdP(t, true)
				svc, backend := newEgressSSOService(t)
				svc.SetEgressForTest(nil, false, idp.roots(), egressResolver{"idp.rebind.test": {"127.0.0.1"}})
				requireBlocked(t, fetch(fetchCtx(t), t, svc, backend, "https://idp.rebind.test:"+idp.port(t)))
				if n := idp.hits.Load(); n != 0 {
					t.Fatalf("loopback IdP got %d requests; want 0", n)
				}
			})
		})
	}
}

// A redirect from an allowed IdP to an internal destination is re-checked
// and refused before the second hop is dialled.
func TestSSOEgress_RefusesRedirectToPrivate(t *testing.T) {
	for proto, fetch := range ssoFetches {
		t.Run(proto, func(t *testing.T) {
			for name, target := range map[string]func(internal *fakeIdP) string{
				"to localhost name":  func(i *fakeIdP) string { return "https://localhost:" + i.port(t) },
				"to RFC1918 literal": func(*fakeIdP) string { return "https://10.1.2.3" },
				"to metadata IP":     func(*fakeIdP) string { return "https://169.254.169.254" },
				"https to http":      func(i *fakeIdP) string { return "http://localhost:" + i.port(t) },
			} {
				t.Run(name, func(t *testing.T) {
					internal := newFakeIdP(t, true)
					public := newFakeIdP(t, true)
					public.redirectTo = target(internal)
					svc, backend := newEgressSSOService(t)
					// Only the "public" IdP's host is allow-listed (it is a
					// loopback httptest server standing in for a public IdP).
					svc.SetEgressForTest(func(h string) bool { return h == "127.0.0.1" }, false, public.roots(), nil)
					requireBlocked(t, fetch(fetchCtx(t), t, svc, backend, public.srv.URL))
					if public.hits.Load() == 0 {
						t.Fatal("the allowed IdP was never reached; the test proves nothing")
					}
					if n := internal.hits.Load(); n != 0 {
						t.Fatalf("redirect target got %d requests; want 0", n)
					}
				})
			}
		})
	}
}

// A public https IdP still works through the guarded client.
func TestSSOEgress_PublicHTTPSIdPWorks(t *testing.T) {
	for proto, fetch := range ssoFetches {
		t.Run(proto, func(t *testing.T) {
			idp := newFakeIdP(t, true)
			svc, backend := newEgressSSOService(t)
			svc.SetEgressForTest(func(h string) bool { return h == "127.0.0.1" }, false, idp.roots(), nil)
			if err := fetch(fetchCtx(t), t, svc, backend, idp.srv.URL); err != nil {
				t.Fatalf("public https IdP refused: %v", err)
			}
			if idp.hits.Load() == 0 {
				t.Fatal("IdP never reached")
			}
		})
	}
}

// The address allow-list does not relax the scheme: an allow-listed host is
// still refused over plain http unless http is explicitly allowed.
func TestSSOEgress_AllowListDoesNotPermitHTTP(t *testing.T) {
	for proto, fetch := range ssoFetches {
		t.Run(proto, func(t *testing.T) {
			idp := newFakeIdP(t, false)
			svc, backend := newEgressSSOService(t)
			svc.SetEgressForTest(func(h string) bool { return h == "127.0.0.1" }, false, nil, nil)
			requireBlocked(t, fetch(fetchCtx(t), t, svc, backend, idp.srv.URL))
			if n := idp.hits.Load(); n != 0 {
				t.Fatalf("http IdP got %d requests; want 0", n)
			}
		})
	}
}

// ValidateSSOConfigURLs is the save-time check a consumer's SSO admin
// handler calls before UpsertSSOConfig. It needs no DNS.
func TestValidateSSOConfigURLs(t *testing.T) {
	ok := []auth.SSOConfig{
		{Provider: "oidc", IssuerURL: "https://login.microsoftonline.com/tenant/v2.0"},
		{Provider: "saml", MetadataURL: "https://idp.example.com/metadata"},
		{Provider: "google"}, // preset issuer, nothing to check
	}
	for _, c := range ok {
		if err := auth.ValidateSSOConfigURLs(c); err != nil {
			t.Errorf("ValidateSSOConfigURLs(%+v) = %v; want nil", c, err)
		}
	}
	bad := map[string]auth.SSOConfig{
		"http issuer":        {Provider: "oidc", IssuerURL: "http://idp.example.com"},
		"loopback issuer":    {Provider: "oidc", IssuerURL: "https://127.0.0.1:8443"},
		"RFC1918 metadata":   {Provider: "saml", MetadataURL: "https://10.0.0.5/metadata"},
		"metadata IP":        {Provider: "saml", MetadataURL: "https://169.254.169.254/latest/meta-data"},
		"localhost metadata": {Provider: "saml", MetadataURL: "https://localhost/metadata"},
		"garbage":            {Provider: "saml", MetadataURL: "::not a url"},
		"no host":            {Provider: "oidc", IssuerURL: "https:///path"},
		"userinfo smuggling": {Provider: "oidc", IssuerURL: "https://idp.example.com@127.0.0.1/"},
	}
	for name, c := range bad {
		err := auth.ValidateSSOConfigURLs(c)
		if err == nil {
			t.Errorf("%s: ValidateSSOConfigURLs(%+v) = nil; want refusal", name, c)
			continue
		}
		if !errors.Is(err, netguard.ErrBlocked) {
			t.Errorf("%s: err = %v; want it to wrap netguard.ErrBlocked", name, err)
		}
	}
}
