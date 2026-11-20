package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/russellhaering/gosaml2/types"
)

// SAML 2.0 binding URIs used in IdP metadata.
const (
	BindingHTTPRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingHTTPPost     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

const metadataNS = "urn:oasis:names:tc:SAML:2.0:metadata"

// IDPMetadata is the part of an IdP's SAML metadata an SP needs.
type IDPMetadata struct {
	EntityID string
	// SigningCertificates are the certificates in KeyDescriptors whose use is
	// "signing" or unspecified.
	SigningCertificates []*x509.Certificate
	SSOServices         []Endpoint
}

// Endpoint is a SingleSignOnService binding and location.
type Endpoint struct {
	Binding  string
	Location string
}

// SSOLocation returns the SingleSignOnService location for binding, or "".
func (m *IDPMetadata) SSOLocation(binding string) string {
	for _, e := range m.SSOServices {
		if e.Binding == binding {
			return e.Location
		}
	}
	return ""
}

// Verifier returns a Verifier trusting this IdP's signing certificates for the
// given SP entity ID and ACS URL.
func (m *IDPMetadata) Verifier(spEntityID, acsURL string) Verifier {
	return Verifier{
		IDPEntityID:     m.EntityID,
		IDPCertificates: m.SigningCertificates,
		SPEntityID:      spEntityID,
		ACSURL:          acsURL,
	}
}

type entitiesDescriptor struct {
	XMLName            xml.Name                 `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
	EntityDescriptors  []types.EntityDescriptor `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntitiesDescriptor []entitiesDescriptor     `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntitiesDescriptor"`
}

func (e *entitiesDescriptor) firstIDP() *types.EntityDescriptor {
	for i := range e.EntityDescriptors {
		if e.EntityDescriptors[i].IDPSSODescriptor != nil {
			return &e.EntityDescriptors[i]
		}
	}
	for i := range e.EntitiesDescriptor {
		if ed := e.EntitiesDescriptor[i].firstIDP(); ed != nil {
			return ed
		}
	}
	return nil
}

// ParseIDPMetadata parses IdP metadata XML: a single EntityDescriptor, or an
// EntitiesDescriptor whose first entity with an IDPSSODescriptor is used. It
// errors when there is no IdP entity, no entity ID, or a certificate does not
// parse. It does not fetch anything.
func ParseIDPMetadata(raw []byte) (*IDPMetadata, error) {
	root, err := rootElementName(raw)
	if err != nil {
		return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
	}
	var ed *types.EntityDescriptor
	switch {
	case root.Space == metadataNS && root.Local == "EntityDescriptor":
		ed = &types.EntityDescriptor{}
		if err := xml.Unmarshal(raw, ed); err != nil {
			return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
		}
	case root.Space == metadataNS && root.Local == "EntitiesDescriptor":
		var all entitiesDescriptor
		if err := xml.Unmarshal(raw, &all); err != nil {
			return nil, fmt.Errorf("saml: parse IdP metadata: %w", err)
		}
		ed = all.firstIDP()
	default:
		return nil, fmt.Errorf("saml: parse IdP metadata: unexpected root element %s %s", root.Space, root.Local)
	}
	if ed == nil || ed.IDPSSODescriptor == nil {
		return nil, errors.New("saml: IdP metadata has no IDPSSODescriptor")
	}
	if ed.EntityID == "" {
		return nil, errors.New("saml: IdP metadata has no entityID")
	}

	md := &IDPMetadata{EntityID: ed.EntityID}
	for _, kd := range ed.IDPSSODescriptor.KeyDescriptors {
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
			if err != nil {
				return nil, fmt.Errorf("saml: IdP metadata certificate: %w", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("saml: IdP metadata certificate: %w", err)
			}
			md.SigningCertificates = append(md.SigningCertificates, cert)
		}
	}
	for _, s := range ed.IDPSSODescriptor.SingleSignOnServices {
		md.SSOServices = append(md.SSOServices, Endpoint{Binding: s.Binding, Location: s.Location})
	}
	return md, nil
}

func rootElementName(raw []byte) (xml.Name, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.Name{}, err
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name, nil
		}
	}
}
