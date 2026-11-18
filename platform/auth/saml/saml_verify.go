package saml

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/crewjam/saml"
)

// VerifyResponse decodes and cryptographically VERIFIES a base64-encoded SAML
// Response against the configured IdP signing certificate BEFORE returning any
// attribute. It is the authentication primitive for this package: any code path
// that treats a SAML response as proof of identity must use VerifyResponse
// (never ParseResponseUnverified).
//
// VerifyResponse never returns attributes from an unsigned, wrong-signer,
// tampered, or expired response — those are rejected with an error.
//
// Verification is delegated to crewjam/saml's ServiceProvider.ParseResponse —
// the same hardened primitive the platform's higher-level SSOService uses — which
// performs XML-DSig signature validation, XSW-safe canonicalization, and
// Conditions (NotBefore/NotOnOrAfter) + audience checks in ONE call. Callers
// store a raw per-tenant PEM certificate (Config.IDPCert) rather than an IdP
// metadata URL, so the *saml.EntityDescriptor is built in memory instead of
// fetched over HTTP.
//
// A Config with an empty or unparseable IDPCert cannot verify anything and is
// REJECTED (returns an error) — it is never verify-skipped. On success it returns
// the SAME attribute-map shape ParseResponseUnverified returns (default mapping
// overlaid by cfg.AttributeMapping, with a guarded NameID fallback for email), only now
// computed over cryptographically-verified data.
func VerifyResponse(samlResponse string, cfg Config) (map[string]string, error) {
	sp, err := buildVerifyingSP(cfg)
	if err != nil {
		return nil, err
	}

	// Reconstruct the POST form crewjam's parser reads from (SAMLResponse).
	req, err := http.NewRequest(http.MethodPost, cfg.ACSURL, strings.NewReader(url.Values{
		"SAMLResponse": {samlResponse},
	}.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building SAML verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		return nil, fmt.Errorf("parsing SAML form: %w", err)
	}

	// The single verifying call: signature + XSW + Conditions + audience.
	// possibleRequestIDs is nil and AllowIDPInitiated is set because these SP
	// callers are stateless — they do not persist the AuthnRequest ID across the
	// IdP round-trip.
	assertion, err := sp.ParseResponse(req, nil)
	if err != nil {
		return nil, fmt.Errorf("SAML signature verification failed: %w", err)
	}

	return mapVerifiedAttributes(assertion, cfg), nil
}

// buildVerifyingSP constructs a crewjam ServiceProvider that trusts EXACTLY the
// tenant's configured IdP certificate. An empty or unparseable IDPCert yields an
// error rather than a verify-skip.
func buildVerifyingSP(cfg Config) (*saml.ServiceProvider, error) {
	cert, err := ParseIDPCertificate(cfg.IDPCert)
	if err != nil {
		return nil, fmt.Errorf("SAML config has no verifiable IdP certificate: %w", err)
	}

	acsURL, err := url.Parse(cfg.ACSURL)
	if err != nil {
		return nil, fmt.Errorf("parsing ACS URL: %w", err)
	}
	spEntityURL, err := url.Parse(cfg.SPEntityID)
	if err != nil {
		return nil, fmt.Errorf("parsing SP entity ID: %w", err)
	}

	ed := &saml.EntityDescriptor{
		EntityID: cfg.IDPEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{
			{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: saml.KeyInfo{
									X509Data: saml.X509Data{
										X509Certificates: []saml.X509Certificate{
											{Data: base64.StdEncoding.EncodeToString(cert.Raw)},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	sp := &saml.ServiceProvider{
		EntityID:          cfg.SPEntityID,
		MetadataURL:       *spEntityURL,
		AcsURL:            *acsURL,
		IDPMetadata:       ed,
		AllowIDPInitiated: true,
	}
	return sp, nil
}

// mapVerifiedAttributes projects a VERIFIED crewjam Assertion into the same
// attribute-map shape ParseResponseUnverified produces: the package default
// mapping (target -> source) overlaid by cfg.AttributeMapping, honouring both the
// attribute Name and FriendlyName as source keys, with a NameID fallback for
// email (see nameIDEmail for when it applies). It runs only on
// cryptographically-verified data.
func mapVerifiedAttributes(assertion *saml.Assertion, cfg Config) map[string]string {
	raw := make(map[string]string)
	if assertion != nil {
		for _, stmt := range assertion.AttributeStatements {
			for _, attr := range stmt.Attributes {
				if len(attr.Values) == 0 {
					continue
				}
				val := attr.Values[0].Value
				if attr.Name != "" {
					raw[attr.Name] = val
				}
				if attr.FriendlyName != "" {
					raw[attr.FriendlyName] = val
				}
			}
		}
	}

	mapping := defaultAttributeMapping()
	for target, source := range cfg.AttributeMapping {
		mapping[target] = source
	}

	result := make(map[string]string)
	for target, source := range mapping {
		if v, ok := raw[source]; ok {
			result[target] = v
		}
	}

	if _, ok := result["email"]; !ok {
		if email, ok := nameIDEmail(assertion); ok {
			result["email"] = email
		}
	}
	return result
}

// nameIDFormatEmailAddress is the SAML 1.1 NameID format an IdP uses to say the
// NameID value is an email address (saml-core-2.0-os §8.3.2).
const nameIDFormatEmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

// nameIDEmail returns the NameID as an email only when that is what the IdP
// signed (#73, GO-2026-6909):
//
//   - the NameID is the saml-namespaced element: crewjam/saml >= v0.6 binds
//     Subject.NameID to the SAML assertion namespace, so a foreign <NameID>
//     can no longer fill it;
//   - its Format is emailAddress, the IdP's own statement that the value is an
//     address. A persistent or transient NameID is an opaque per-IdP handle;
//     treating one as an email would let an IdP name any account by choosing
//     an address-shaped handle;
//   - the value parses as a bare address.
//
// Many IdPs (Okta and Entra defaults) send the address only as an emailAddress
// NameID, so dropping the fallback entirely would break real logins.
func nameIDEmail(assertion *saml.Assertion) (string, bool) {
	if assertion == nil || assertion.Subject == nil || assertion.Subject.NameID == nil {
		return "", false
	}
	nameID := assertion.Subject.NameID
	if nameID.Format != nameIDFormatEmailAddress {
		return "", false
	}
	value := strings.TrimSpace(nameID.Value)
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Address != value {
		return "", false
	}
	return value, true
}
