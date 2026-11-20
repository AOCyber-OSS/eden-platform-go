// Package saml provides standalone SAML 2.0 Service Provider primitives:
// AuthnRequest construction, SP metadata generation, response parsing with
// attribute mapping, and IdP certificate handling.
//
// Response verification (Verifier, VerifyResponse) is built on
// russellhaering/gosaml2 and is shared with the higher-level auth.SSOService;
// this package also exposes lower-level primitives for callers
// (and is the foundation for the IdP support added in objective 23 under the
// saml/idp/ subpackage).
package saml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Config holds the configuration for a SAML Service Provider, mapped from
// an sso_configurations row.
type Config struct {
	IDPSSOUrl        string
	IDPEntityID      string
	IDPCert          string
	SPEntityID       string
	ACSURL           string
	AttributeMapping map[string]string // target -> source
}

// AuthnRequest represents a SAML 2.0 AuthnRequest (HTTP-Redirect binding).
type AuthnRequest struct {
	XMLName                     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string   `xml:"ID,attr"`
	Version                     string   `xml:"Version,attr"`
	IssueInstant                string   `xml:"IssueInstant,attr"`
	AssertionConsumerServiceURL string   `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string   `xml:"Destination,attr"`
	Issuer                      Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
}

// Issuer represents the SAML Issuer element.
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// BuildAuthnRequestRedirectURL creates a SAML AuthnRequest and returns the
// IdP redirect URL with the SAMLRequest query parameter (HTTP-Redirect
// binding).
func BuildAuthnRequestRedirectURL(cfg Config) (string, error) {
	requestID := "_" + uuid.New().String()

	req := AuthnRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now().UTC().Format(time.RFC3339),
		AssertionConsumerServiceURL: cfg.ACSURL,
		Destination:                 cfg.IDPSSOUrl,
		Issuer:                      Issuer{Value: cfg.SPEntityID},
	}

	xmlBytes, err := xml.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshaling AuthnRequest: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(xmlBytes)
	return fmt.Sprintf("%s?SAMLRequest=%s", cfg.IDPSSOUrl, url.QueryEscape(encoded)), nil
}

// ResponseXML represents the top-level SAML Response element used for
// attribute extraction. It intentionally tolerates schema variation — if the
// XML doesn't match this struct, ParseResponseUnverified returns an empty
// attribute map (matching the donor's graceful-degradation behavior).
type ResponseXML struct {
	XMLName    xml.Name       `xml:"Response"`
	Assertions []AssertionXML `xml:"Assertion"`
}

// AssertionXML represents a SAML Assertion.
type AssertionXML struct {
	Subject             SubjectXML              `xml:"Subject"`
	AttributeStatements []AttributeStatementXML `xml:"AttributeStatement"`
}

// SubjectXML represents the SAML Subject element.
type SubjectXML struct {
	NameID NameIDXML `xml:"NameID"`
}

// NameIDXML represents the SAML NameID element.
type NameIDXML struct {
	Value string `xml:",chardata"`
}

// AttributeStatementXML represents a SAML AttributeStatement.
type AttributeStatementXML struct {
	Attributes []AttributeXML `xml:"Attribute"`
}

// AttributeXML represents a SAML Attribute.
type AttributeXML struct {
	Name   string              `xml:"Name,attr"`
	Values []AttributeValueXML `xml:"AttributeValue"`
}

// AttributeValueXML represents a SAML AttributeValue.
type AttributeValueXML struct {
	Value string `xml:",chardata"`
}

// ParseResponseUnverified decodes a Base64-encoded SAML response and extracts
// user attributes using the configured attribute mapping (target -> source).
//
// CRITICAL: This function performs NO signature verification whatsoever — it
// does NOT validate the XML-DSig signature, the signing certificate, the
// Conditions (NotBefore/NotOnOrAfter), or the audience. The attributes it
// returns are therefore UNTRUSTED and MUST NOT be used to authenticate a user.
// Any code path that needs authentication MUST use VerifyResponse (this
// package), which pins the tenant's IdP certificate and rejects unsigned,
// wrong-signer, tampered, or expired responses.
//
// Use ParseResponseUnverified ONLY for non-authentication purposes — e.g.
// inspecting attributes of a response whose signature has ALREADY been verified
// upstream, or for debugging/tooling — never as the sole gate on a login path.
// It was renamed from ParseResponse to make its unverified nature impossible to
// mistake for authentication.
func ParseResponseUnverified(samlResponse string, cfg Config) (map[string]string, error) {
	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("decoding SAML response: %w", err)
	}

	var response ResponseXML
	if err := xml.Unmarshal(xmlBytes, &response); err != nil {
		// Valid XML that doesn't match our struct → empty map (Rails parity).
		// Invalid XML → still empty map; the upstream SP would have rejected
		// the request before this point.
		return map[string]string{}, nil
	}

	// Extract raw attributes from assertions.
	rawAttrs := make(map[string]string)
	for _, assertion := range response.Assertions {
		for _, stmt := range assertion.AttributeStatements {
			for _, attr := range stmt.Attributes {
				if len(attr.Values) > 0 {
					rawAttrs[attr.Name] = attr.Values[0].Value
				}
			}
		}
	}

	// Apply attribute mapping (target -> source) on top of defaults.
	mapping := defaultAttributeMapping()
	for k, v := range cfg.AttributeMapping {
		mapping[k] = v
	}

	result := make(map[string]string)
	for target, source := range mapping {
		if val, ok := rawAttrs[source]; ok {
			result[target] = val
		}
	}

	// NameID fallback for email.
	if _, hasEmail := result["email"]; !hasEmail {
		for _, assertion := range response.Assertions {
			if assertion.Subject.NameID.Value != "" {
				result["email"] = assertion.Subject.NameID.Value
				break
			}
		}
	}

	return result, nil
}

// BuildSPMetadata generates the SP metadata XML for the given configuration.
// This is served at the SP metadata endpoint for IdP configuration.
func BuildSPMetadata(cfg Config) ([]byte, error) {
	metadata := fmt.Sprintf(`<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  entityID="%s">
  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true"
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="%s"
      index="1" />
  </md:SPSSODescriptor>
</md:EntityDescriptor>`,
		xmlEscapeString(cfg.SPEntityID),
		xmlEscapeString(cfg.ACSURL),
	)
	return []byte(metadata), nil
}

// ParseIDPCertificate parses a PEM-encoded X.509 certificate. Accepts both
// raw PEM and certificate data without PEM headers.
func ParseIDPCertificate(certData string) (*x509.Certificate, error) {
	certData = strings.TrimSpace(certData)
	if !strings.HasPrefix(certData, "-----BEGIN") {
		certData = "-----BEGIN CERTIFICATE-----\n" + certData + "\n-----END CERTIFICATE-----"
	}
	block, _ := pem.Decode([]byte(certData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

func defaultAttributeMapping() map[string]string {
	return map[string]string{
		"email":      "email",
		"name":       "name",
		"first_name": "first_name",
		"last_name":  "last_name",
	}
}

func xmlEscapeString(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
