package saml

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/mail"
	"strings"
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
// Verification is done by Verifier (gosaml2 + goxmldsig): signature, issuer,
// audience, destination/recipient, validity window. Callers store a raw
// per-tenant PEM certificate (Config.IDPCert) rather than an IdP metadata URL.
//
// VerifyResponse is stateless: it accepts unsolicited (IdP-initiated)
// responses and refuses any InResponseTo, because it issued no request. Use
// VerifyResponseWithOptions to bind request IDs or refuse replays.
//
// A Config with an empty or unparseable IDPCert cannot verify anything and is
// REJECTED (returns an error) — it is never verify-skipped. On success it returns
// the SAME attribute-map shape ParseResponseUnverified returns (default mapping
// overlaid by cfg.AttributeMapping, with a guarded NameID fallback for email), only now
// computed over cryptographically-verified data.
func VerifyResponse(samlResponse string, cfg Config) (map[string]string, error) {
	return VerifyResponseWithOptions(context.Background(), samlResponse, cfg, VerifyOptions{})
}

// VerifyResponseWithOptions is VerifyResponse with request-ID binding, replay
// refusal and clock control (see VerifyOptions).
func VerifyResponseWithOptions(ctx context.Context, samlResponse string, cfg Config, opts VerifyOptions) (map[string]string, error) {
	v, err := verifierFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	assertion, err := v.Verify(ctx, samlResponse, opts)
	if err != nil {
		return nil, fmt.Errorf("SAML signature verification failed: %w", err)
	}
	return mapVerifiedAttributes(assertion, cfg), nil
}

// verifierFromConfig builds a Verifier that trusts EXACTLY the tenant's
// configured IdP certificate. An empty or unparseable IDPCert yields an error
// rather than a verify-skip.
func verifierFromConfig(cfg Config) (Verifier, error) {
	cert, err := ParseIDPCertificate(cfg.IDPCert)
	if err != nil {
		return Verifier{}, fmt.Errorf("SAML config has no verifiable IdP certificate: %w", err)
	}
	return Verifier{
		IDPEntityID:     cfg.IDPEntityID,
		IDPCertificates: []*x509.Certificate{cert},
		SPEntityID:      cfg.SPEntityID,
		ACSURL:          cfg.ACSURL,
	}, nil
}

// mapVerifiedAttributes projects a VERIFIED assertion into the same
// attribute-map shape ParseResponseUnverified produces: the package default
// mapping (target -> source) overlaid by cfg.AttributeMapping, honouring both the
// attribute Name and FriendlyName as source keys, with a NameID fallback for
// email (see nameIDEmail for when it applies). It runs only on
// cryptographically-verified data.
func mapVerifiedAttributes(assertion *VerifiedAssertion, cfg Config) map[string]string {
	raw := make(map[string]string)
	if assertion != nil {
		for _, attr := range assertion.Attributes {
			if len(attr.Values) == 0 {
				continue
			}
			val := attr.Values[0]
			if attr.Name != "" {
				raw[attr.Name] = val
			}
			if attr.FriendlyName != "" {
				raw[attr.FriendlyName] = val
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
//   - the NameID is the saml-namespaced element: the verifier's types bind
//     Subject.NameID to the SAML assertion namespace, so a foreign <NameID>
//     cannot fill it;
//   - its Format is emailAddress, the IdP's own statement that the value is an
//     address. A persistent or transient NameID is an opaque per-IdP handle;
//     treating one as an email would let an IdP name any account by choosing
//     an address-shaped handle;
//   - the value parses as a bare address.
//
// Many IdPs (Okta and Entra defaults) send the address only as an emailAddress
// NameID, so dropping the fallback entirely would break real logins.
func nameIDEmail(assertion *VerifiedAssertion) (string, bool) {
	if assertion == nil || assertion.NameID == "" {
		return "", false
	}
	if assertion.NameIDFormat != nameIDFormatEmailAddress {
		return "", false
	}
	value := strings.TrimSpace(assertion.NameID)
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Address != value {
		return "", false
	}
	return value, true
}
