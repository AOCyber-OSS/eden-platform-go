package federation

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	platsaml "go.aocyber.ai/eden-platform-go/platform/auth/saml"
)

// Errors specific to inbound (external-IdP) federation flows.
var (
	// ErrJITDisabled — JIT policy explicitly disabled and the asserted
	// user is not already provisioned in AO ID.
	ErrJITDisabled = errors.New("federation: JIT provisioning disabled")
	// ErrJITDomainNotAllowed — email domain not in policy allowlist.
	ErrJITDomainNotAllowed = errors.New("federation: email domain not allowed by JIT policy")
	// ErrJITMFARequired — assertion lacks an MFA AuthnContextClassRef
	// while policy.RequireMFA is true.
	ErrJITMFARequired = errors.New("federation: MFA required by JIT policy")
	// ErrUnsupportedFlow — caller invoked an OIDC-only method on a
	// SAML IdP or vice-versa.
	ErrUnsupportedFlow = errors.New("federation: unsupported flow for this provider")
	// ErrFederationUserNotFound — JIT disabled and user not found.
	ErrFederationUserNotFound = errors.New("federation: user not found and JIT disabled")
	// ErrFederationEmailNotMember — the asserted email belongs to an
	// existing account that is not a member of the asserting tenant (#74).
	ErrFederationEmailNotMember = errors.New("federation: email belongs to an account that is not a member of this tenant")
)

// Provider identifies the external-IdP protocol family.
const (
	ProviderSAML = "saml"
	ProviderOIDC = "oidc"
)

// TenantExternalIdP is one customer IdP that an AO ID tenant has
// registered. A tenant may have multiple entries (e.g. Okta for
// employees + Google Workspace for contractors).
type TenantExternalIdP struct {
	// ID is the synthetic identifier used in URLs (e.g.
	// /federation/{tenant}/start?external_idp_id=<ID>). Required.
	ID uuid.UUID

	// TenantID is the AO ID tenant that owns this entry. Required.
	TenantID uuid.UUID

	// Provider is ProviderSAML or ProviderOIDC. Required.
	Provider string

	// DisplayName is the admin label (e.g. "Acme Corp Okta").
	DisplayName string

	// EntityID:
	//   - SAML: the external IdP's entity ID.
	//   - OIDC: the issuer URL.
	// Required.
	EntityID string

	// MetadataURL:
	//   - SAML: the IdP metadata URL.
	//   - OIDC: the discovery URL (issuer + /.well-known/...).
	// SAML requires non-empty; OIDC may derive from EntityID.
	MetadataURL string

	// ClientID is the OIDC client ID issued by the external IdP.
	ClientID string

	// ClientSecret is the OIDC client secret.
	ClientSecret string

	// SigningCertificatePEM is the external IdP's SAML signing cert
	// (PEM-encoded) for assertion signature verification. Required
	// for SAML; ignored for OIDC.
	SigningCertificatePEM string

	// AttributeMapping maps target claim name -> source attribute name.
	// Standard targets: "email", "display_name", "first_name",
	// "last_name", "subject". Empty mapping uses defaults (see
	// extractAssertion).
	AttributeMapping map[string]string

	// JITPolicy controls auto-provisioning behavior.
	JITPolicy JITPolicy

	// IsActive is the on/off switch.
	IsActive bool

	// CreatedAt + UpdatedAt are stamped by the registry.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// JITPolicy describes Just-In-Time provisioning behavior.
type JITPolicy struct {
	// Enabled gates auto-provisioning. When false, unknown users are
	// rejected with ErrFederationUserNotFound.
	Enabled bool

	// DefaultRole is the AO ID role assigned to JIT-provisioned users
	// (e.g. "member"). Empty defaults to "member".
	DefaultRole string

	// AllowedDomains is an optional email-domain allowlist. Empty list
	// = all domains allowed. Comparison is case-insensitive.
	AllowedDomains []string

	// RequireMFA, when true, rejects assertions lacking a
	// recognized-MFA AuthnContextClassRef.
	RequireMFA bool
}

// Validate returns ErrInvalidConfig for missing required fields. Same
// shape as TenantIdPConfig.Validate.
func (c *TenantExternalIdP) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}
	if c.ID == uuid.Nil {
		return errInvalid("ID is required")
	}
	if c.TenantID == uuid.Nil {
		return errInvalid("TenantID is required")
	}
	switch c.Provider {
	case ProviderSAML:
		if c.EntityID == "" {
			return errInvalid("SAML EntityID is required")
		}
		if c.MetadataURL == "" {
			return errInvalid("SAML MetadataURL is required")
		}
	case ProviderOIDC:
		if c.EntityID == "" {
			return errInvalid("OIDC EntityID (issuer URL) is required")
		}
		if c.ClientID == "" {
			return errInvalid("OIDC ClientID is required")
		}
	default:
		return errInvalid("Provider must be \"saml\" or \"oidc\"")
	}
	return nil
}

// Assertion is the federation-internal normalized result of an
// external-IdP authentication. Distinct from saml.Assertion so callers
// don't need to import the SAML XML types.
type Assertion struct {
	// Subject is the IdP-side opaque user identifier (NameID for SAML,
	// sub claim for OIDC).
	Subject string

	// Email is the user's email address (normalized to lowercase).
	Email string

	// DisplayName is the user's full name, if available.
	DisplayName string

	// Attributes carries the raw assertion attributes for callers who
	// want more than email/name. Always non-nil (may be empty).
	Attributes map[string][]string

	// AuthnContext is the AuthnContextClassRef (SAML) or amr claim
	// (OIDC) describing the strength of authentication.
	AuthnContext string

	// IssuedAt is when the assertion was issued.
	IssuedAt time.Time

	// ExpiresAt is when the assertion stops being valid.
	ExpiresAt time.Time
}

// Domain returns the lowercase domain portion of Email (empty if
// missing or malformed).
func (a *Assertion) Domain() string {
	if a == nil {
		return ""
	}
	idx := strings.LastIndexByte(a.Email, '@')
	if idx < 0 || idx == len(a.Email)-1 {
		return ""
	}
	return strings.ToLower(a.Email[idx+1:])
}

// HasMFA is a coarse heuristic: returns true if AuthnContext contains
// known MFA markers. Used by JITPolicy.RequireMFA.
func (a *Assertion) HasMFA() bool {
	if a == nil {
		return false
	}
	ctx := strings.ToLower(a.AuthnContext)
	// Standard SAML MFA classrefs + OIDC amr values that indicate MFA.
	markers := []string{
		"multifactor",
		"multi-factor",
		"mfa",
		"smartcard",
		"hardwaretoken",
		"timesynctoken",
		"mobilecontract",
		"mobiletwofactorunregistered",
		"x509",
		"webauthn",
	}
	for _, m := range markers {
		if strings.Contains(ctx, m) {
			return true
		}
	}
	return false
}

// ExternalIdP wraps a TenantExternalIdP with the runtime primitives
// needed to drive a federation flow (build AuthnRequest / authorization
// URL, parse the response).
type ExternalIdP struct {
	cfg TenantExternalIdP

	// httpClient is used for OIDC discovery + token exchange. Tests
	// inject a httptest.Server-backed client; production uses the
	// default client.
	httpClient OIDCExchanger
}

// OIDCExchanger is the slim surface ExternalIdP uses to talk to an
// OIDC IdP. The production implementation in oidc.go wraps coreos
// go-oidc; tests inject a fake.
type OIDCExchanger interface {
	BuildAuthURL(ctx context.Context, cfg TenantExternalIdP, redirectURI, state string) (string, error)
	ExchangeCode(ctx context.Context, cfg TenantExternalIdP, code, redirectURI string) (*Assertion, error)
}

// NewExternalIdP constructs an ExternalIdP from a registry entry. The
// exchanger may be nil for SAML-only callers; OIDC calls will return
// ErrUnsupportedFlow without it.
func NewExternalIdP(cfg TenantExternalIdP, exchanger OIDCExchanger) (*ExternalIdP, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &ExternalIdP{cfg: cfg, httpClient: exchanger}, nil
}

// Config returns a copy of the underlying registry entry. Useful for
// downstream callers that want to read the JITPolicy.
func (e *ExternalIdP) Config() TenantExternalIdP {
	return e.cfg
}

// AuthorizationURL builds the URL the browser should redirect to in
// order to begin the federation flow.
//   - SAML: returns the AuthnRequest redirect URL using
//     platform/auth/saml.BuildAuthnRequestRedirectURL.
//   - OIDC: delegates to the injected exchanger.
//
// `redirectURI` is the AO ID-side ACS / callback URL; `state` is the
// opaque CSRF token the caller will validate on the return leg.
func (e *ExternalIdP) AuthorizationURL(ctx context.Context, redirectURI, state string) (string, error) {
	switch e.cfg.Provider {
	case ProviderSAML:
		samlCfg := platsaml.Config{
			IDPSSOUrl:   e.cfg.EntityID, // for HTTP-Redirect we use the SSO URL as IDPSSOUrl
			IDPEntityID: e.cfg.EntityID,
			SPEntityID:  redirectURI, // SP entity = AO ID's ACS URL
			ACSURL:      redirectURI,
		}
		if e.cfg.MetadataURL != "" {
			samlCfg.IDPSSOUrl = e.cfg.MetadataURL
		}
		urlStr, err := platsaml.BuildAuthnRequestRedirectURL(samlCfg)
		if err != nil {
			return "", fmt.Errorf("federation: build SAML redirect: %w", err)
		}
		// Append RelayState carrying the state token so the ACS can
		// validate it. crewjam-style SP libraries place RelayState in
		// either query or form depending on binding; for HTTP-Redirect
		// it's a query param.
		u, parseErr := url.Parse(urlStr)
		if parseErr != nil {
			return "", fmt.Errorf("federation: parse SAML URL: %w", parseErr)
		}
		q := u.Query()
		q.Set("RelayState", state)
		u.RawQuery = q.Encode()
		return u.String(), nil
	case ProviderOIDC:
		if e.httpClient == nil {
			return "", ErrUnsupportedFlow
		}
		return e.httpClient.BuildAuthURL(ctx, e.cfg, redirectURI, state)
	default:
		return "", ErrUnsupportedFlow
	}
}

// ExchangeAuthCode swaps an OIDC authorization code for a validated
// Assertion. Returns ErrUnsupportedFlow for SAML providers.
func (e *ExternalIdP) ExchangeAuthCode(ctx context.Context, code, redirectURI string) (*Assertion, error) {
	if e.cfg.Provider != ProviderOIDC {
		return nil, ErrUnsupportedFlow
	}
	if e.httpClient == nil {
		return nil, ErrUnsupportedFlow
	}
	return e.httpClient.ExchangeCode(ctx, e.cfg, code, redirectURI)
}

// EnforceJITPolicy returns an error when the assertion fails the
// policy's allowlist or MFA gates. The Bridge calls this as a
// defense-in-depth check after the assertion has been validated.
func (e *ExternalIdP) EnforceJITPolicy(a *Assertion) error {
	if a == nil {
		return errInvalid("nil assertion")
	}
	p := e.cfg.JITPolicy
	if p.RequireMFA && !a.HasMFA() {
		return ErrJITMFARequired
	}
	if len(p.AllowedDomains) > 0 {
		domain := a.Domain()
		ok := false
		for _, d := range p.AllowedDomains {
			if strings.EqualFold(d, domain) {
				ok = true
				break
			}
		}
		if !ok {
			return ErrJITDomainNotAllowed
		}
	}
	return nil
}
