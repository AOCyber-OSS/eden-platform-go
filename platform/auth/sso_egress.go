package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"go.aocyber.ai/eden-platform-go/platform/netguard"
)

// SSO egress policy (issue #85).
//
// SSOConfig.IssuerURL (OIDC discovery, and through it the JWKS and token
// endpoints) and SSOConfig.MetadataURL (SAML IdP metadata) are per-company
// values a tenant admin can edit. Fetching them with http.DefaultClient let a
// tenant admin make this server request loopback, in-cluster or cloud
// metadata addresses. Every SSO fetch now goes through a platform/netguard
// Guard: https only, the URL host checked before DNS, the resolved and the
// connected address checked at dial (no DNS-rebinding window), no
// environment proxy, and every redirect hop re-checked.

const (
	// ssoEgressTimeout bounds one SSO metadata/discovery/JWKS/token request.
	ssoEgressTimeout = 15 * time.Second
	// ssoEgressMaxRedirects caps redirects on an SSO fetch.
	ssoEgressMaxRedirects = 3
)

type ssoEgressOptions struct {
	// allowHost bypasses the address policy for a host (tests only; there
	// is no production setter).
	allowHost func(host string) bool
	// allowHTTP permits plain http (tests only).
	allowHTTP bool
	rootCAs   *x509.CertPool
	resolver  netguard.Resolver
}

type ssoEgress struct {
	opts   ssoEgressOptions
	client *http.Client
}

func newSSOEgress(opts ssoEgressOptions) *ssoEgress {
	guard := &netguard.Guard{Resolver: opts.resolver, AllowHost: opts.allowHost}
	transport := guard.Transport()
	if opts.rootCAs != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: opts.rootCAs, MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	e := &ssoEgress{opts: opts}
	e.client = &http.Client{
		Transport: transport,
		Timeout:   ssoEgressTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= ssoEgressMaxRedirects {
				return fmt.Errorf("%w: sso fetch stopped after %d redirects", netguard.ErrBlocked, ssoEgressMaxRedirects)
			}
			return e.checkURL(req.URL)
		},
	}
	return e
}

// checkURL applies the pre-DNS part of the policy to a URL: a parseable
// absolute URL with a host and no userinfo, https (unless allowHTTP), and a
// host netguard.CheckHost accepts (unless allowHost). The dial-time checks in
// the Guard still apply to whatever passes here.
func (e *ssoEgress) checkURL(u *url.URL) error {
	if u == nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%w: sso URL has no host", netguard.ErrBlocked)
	}
	if u.User != nil {
		return fmt.Errorf("%w: sso URL must not carry userinfo", netguard.ErrBlocked)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && e.opts.allowHTTP:
	default:
		return fmt.Errorf("%w: sso URL scheme %q (https required)", netguard.ErrBlocked, u.Scheme)
	}
	host := u.Hostname()
	if e.opts.allowHost != nil && e.opts.allowHost(host) {
		return nil
	}
	return netguard.CheckHost(host)
}

func (e *ssoEgress) checkRawURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse sso URL: %v", netguard.ErrBlocked, err)
	}
	if err := e.checkURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// defaultSSOEgress is the production policy: no allow-list, https only,
// system roots and resolver.
func defaultSSOEgress() *ssoEgress { return newSSOEgress(ssoEgressOptions{}) }

// ValidateSSOConfigURLs checks the tenant-supplied URLs of an SSO config
// against the egress policy without any DNS lookup: IssuerURL and
// MetadataURL, when set, must be https URLs whose host is not a literal
// internal address or a well-known internal name. Call it in the handler
// that saves an SSOConfig, before UpsertSSOConfig, so a bad URL is refused
// at save time with a clear error. The fetch path enforces the full policy
// (including the resolved and connected address) regardless.
func ValidateSSOConfigURLs(cfg SSOConfig) error {
	e := defaultSSOEgress()
	if cfg.IssuerURL != "" {
		if _, err := e.checkRawURL(cfg.IssuerURL); err != nil {
			return fmt.Errorf("sso issuer URL: %w", err)
		}
	}
	if cfg.MetadataURL != "" {
		if _, err := e.checkRawURL(cfg.MetadataURL); err != nil {
			return fmt.Errorf("sso metadata URL: %w", err)
		}
	}
	return nil
}
